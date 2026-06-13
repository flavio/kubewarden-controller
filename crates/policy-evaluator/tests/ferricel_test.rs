use std::{collections::BTreeSet, path::Path};

use ferricel_core::compiler::Builder as CompilerBuilder;
use hyper::{Request, Response};
use kube::{Client, client::Body};
use policy_evaluator::{
    admission_request::AdmissionRequest,
    callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse},
    evaluation_context::EvaluationContext,
    ferricel_compiler_builder_chains, ferricel_compiler_extension_decls,
    host_capabilities::HostCapabilities,
    policy_evaluator::{PolicyExecutionMode, PolicySettings, ValidateRequest},
    policy_evaluator_builder::PolicyEvaluatorBuilder,
    policy_metadata::ContextAwareResource,
};
use rstest::rstest;
use serde_json::json;
use tokio::sync::mpsc;
use tower_test::mock::Handle;

mod common;

use crate::common::setup_callback_handler;

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn data_path(filename: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/ferricel")
        .join(filename)
}

fn compile_vap(vap_yaml: &str) -> Vec<u8> {
    let mut builder = CompilerBuilder::new();
    for chain in ferricel_compiler_builder_chains() {
        builder = builder.with_builder_chain(chain);
    }
    for decl in ferricel_compiler_extension_decls() {
        builder = builder.with_extension(decl);
    }
    builder
        .build()
        .compile_vap(vap_yaml)
        .unwrap_or_else(|e| panic!("cannot compile VAP: {e}"))
}

fn load_admission_request(request_filename: &str) -> AdmissionRequest {
    let data = std::fs::read(data_path(request_filename))
        .unwrap_or_else(|e| panic!("cannot read {request_filename}: {e}"));
    serde_json::from_slice(&data)
        .unwrap_or_else(|e| panic!("cannot deserialize {request_filename}: {e}"))
}

fn build_evaluator(
    wasm: &[u8],
    callback_channel: Option<tokio::sync::mpsc::Sender<CallbackRequest>>,
    ctx_aware_resources: BTreeSet<ContextAwareResource>,
) -> policy_evaluator::policy_evaluator::PolicyEvaluator {
    let pre = PolicyEvaluatorBuilder::new()
        .policy_contents(wasm)
        .execution_mode(PolicyExecutionMode::Ferricel)
        .build_pre()
        .unwrap_or_else(|e| panic!("cannot build PolicyEvaluatorPre: {e}"));
    let eval_ctx = EvaluationContext {
        policy_id: "test-ferricel".to_owned(),
        callback_channel,
        ctx_aware_resources_allow_list: ctx_aware_resources,
        epoch_deadline: None,
        host_capabilities: HostCapabilities::AllowAll,
    };
    pre.rehydrate(&eval_ctx)
        .unwrap_or_else(|e| panic!("cannot rehydrate evaluator: {e}"))
}

/// Mock scenario that handles:
/// - GET /api/v1  -- API discovery requests made by the kube client on startup
/// - GET /api/v1/namespaces/{name}  -- namespace fetch requests from ferricel runtime
///
/// The loop exits cleanly when the mock `Handle` is dropped (i.e., when the test
/// ends and the underlying mock service is torn down).
/// Unexpected requests result in an HTTP 500 response so that the error propagates
/// back to the ferricel runtime and surfaces in the test as a meaningful failure
/// rather than a silent panic inside a detached task.
async fn namespace_scenario(handle: Handle<Request<Body>, Response<Body>>) {
    tokio::spawn(async move {
        let mut handle = handle;
        while let Some((request, send)) = handle.next_request().await {
            let path = request.uri().path().to_owned();

            if request.method() == hyper::Method::GET && path == "/api/v1" {
                let body = serde_json::to_vec(&serde_json::json!({
                    "kind": "APIResourceList",
                    "apiVersion": "v1",
                    "groupVersion": "v1",
                    "resources": [{
                        "name": "namespaces",
                        "singularName": "namespace",
                        "namespaced": false,
                        "kind": "Namespace",
                        "verbs": ["get", "list"]
                    }]
                }))
                .unwrap();
                send.send_response(Response::builder().body(Body::from(body)).unwrap());
            } else if request.method() == hyper::Method::GET
                && path.starts_with("/api/v1/namespaces/")
                && !path.ends_with('/')
            {
                let namespace_name = path.trim_start_matches("/api/v1/namespaces/").to_owned();
                let ns = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": { "name": namespace_name, "resourceVersion": "1" }
                });
                let body = serde_json::to_vec(&ns).unwrap();
                send.send_response(Response::builder().body(Body::from(body)).unwrap());
            } else {
                // Return HTTP 500 so the error propagates back to the runtime and
                // surfaces in the test as a clear failure.
                let body = serde_json::to_vec(&serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": format!("unexpected mock request: {} {}", request.method(), path),
                    "code": 500
                }))
                .unwrap();
                send.send_response(
                    Response::builder()
                        .status(500)
                        .body(Body::from(body))
                        .unwrap(),
                );
            }
        }
        // Handle dropped -- mock service torn down, exit gracefully.
    });
}

/// Mock scenario that handles namespace and ConfigMap GET requests.
/// Used by the params test, which needs both namespaceObject and params fetching.
///
/// Handles:
/// - GET /api/v1            -- API discovery
/// - GET /api/v1/namespaces/{name}        -- namespace fetch
/// - GET /api/v1/namespaces/{ns}/configmaps/{name}  -- ConfigMap fetch for params
async fn params_scenario(handle: Handle<Request<Body>, Response<Body>>) {
    tokio::spawn(async move {
        let mut handle = handle;
        while let Some((request, send)) = handle.next_request().await {
            let path = request.uri().path().to_owned();

            if request.method() == hyper::Method::GET && path == "/api/v1" {
                let body = serde_json::to_vec(&serde_json::json!({
                    "kind": "APIResourceList",
                    "apiVersion": "v1",
                    "groupVersion": "v1",
                    "resources": [
                        {
                            "name": "namespaces",
                            "singularName": "namespace",
                            "namespaced": false,
                            "kind": "Namespace",
                            "verbs": ["get", "list"]
                        },
                        {
                            "name": "configmaps",
                            "singularName": "configmap",
                            "namespaced": true,
                            "kind": "ConfigMap",
                            "verbs": ["get", "list"]
                        }
                    ]
                }))
                .unwrap();
                send.send_response(Response::builder().body(Body::from(body)).unwrap());
            } else if request.method() == hyper::Method::GET
                && path.starts_with("/api/v1/namespaces/")
                && path.contains("/configmaps/")
            {
                // ConfigMap fetch for params, e.g. /api/v1/namespaces/default/configmaps/replica-limit
                let name = path.rsplit('/').next().unwrap_or("unknown");
                let ns = path
                    .trim_start_matches("/api/v1/namespaces/")
                    .split('/')
                    .next()
                    .unwrap_or("default");
                let cm = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": { "name": name, "namespace": ns },
                    "data": { "maxReplicas": "50" }
                });
                let body = serde_json::to_vec(&cm).unwrap();
                send.send_response(Response::builder().body(Body::from(body)).unwrap());
            } else if request.method() == hyper::Method::GET
                && path.starts_with("/api/v1/namespaces/")
                && !path.ends_with('/')
                && !path.contains("/configmaps/")
            {
                let namespace_name = path.trim_start_matches("/api/v1/namespaces/").to_owned();
                let ns = serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": { "name": namespace_name, "resourceVersion": "1" }
                });
                let body = serde_json::to_vec(&ns).unwrap();
                send.send_response(Response::builder().body(Body::from(body)).unwrap());
            } else {
                let body = serde_json::to_vec(&serde_json::json!({
                    "kind": "Status",
                    "apiVersion": "v1",
                    "status": "Failure",
                    "message": format!("unexpected mock request: {} {}", request.method(), path),
                    "code": 500
                }))
                .unwrap();
                send.send_response(
                    Response::builder()
                        .status(500)
                        .body(Body::from(body))
                        .unwrap(),
                );
            }
        }
    });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// VAP_SIMPLE is shared by test_simple_validation and test_raw_request_is_rejected.
const VAP_SIMPLE: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: simple-replicas
spec:
  validations:
    - expression: "object.spec.replicas <= 50"
      message: "too many replicas"
"#;

/// requests: one within the replica limit (accept) and one exceeding it (reject).
#[rstest]
#[case::accept("deployment_accept.json", true, None)]
#[case::reject("deployment_reject.json", false, Some("too many replicas"))]
#[tokio::test(flavor = "multi_thread")]
async fn test_simple_validation(
    #[case] request_filename: &str,
    #[case] expected_allowed: bool,
    #[case] expected_message: Option<&str>,
) {
    let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(mocksvc, "default");
    namespace_scenario(handle).await;
    let (shutdown_tx, callback_channel) = setup_callback_handler(Some(client), None).await;

    let wasm = compile_vap(VAP_SIMPLE);
    let mut evaluator = build_evaluator(&wasm, Some(callback_channel), BTreeSet::new());
    let request =
        ValidateRequest::AdmissionRequest(Box::new(load_admission_request(request_filename)));

    let response =
        tokio::task::block_in_place(|| evaluator.validate(request, &PolicySettings::default()));

    assert_eq!(expected_allowed, response.allowed);
    if let Some(msg) = expected_message {
        let actual_msg = response
            .status
            .as_ref()
            .expect("expected a status")
            .message
            .as_deref()
            .unwrap_or("");
        assert!(
            actual_msg.contains(msg),
            "expected message to contain {msg:?}, got: {actual_msg:?}"
        );
    }

    let _ = shutdown_tx.send(());
}

const VAP_WITH_VARIABLES: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: replicas-with-variables
spec:
  variables:
    - name: replicas
      expression: "object.spec.replicas"
    - name: maxReplicas
      expression: "50"
  validations:
    - expression: "variables.replicas <= variables.maxReplicas"
      messageExpression: "'Deployment ' + object.metadata.name + ' has too many replicas'"
"#;

/// Compile and evaluate a VAP that uses CEL variables to compute intermediate
/// values before the final validation expression.
#[rstest]
#[case::accept("deployment_accept.json", true, None)]
#[case::reject("deployment_reject.json", false, Some("too many replicas"))]
#[tokio::test(flavor = "multi_thread")]
async fn test_with_variables(
    #[case] request_filename: &str,
    #[case] expected_allowed: bool,
    #[case] expected_message: Option<&str>,
) {
    let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(mocksvc, "default");
    namespace_scenario(handle).await;
    let (shutdown_tx, callback_channel) = setup_callback_handler(Some(client), None).await;

    let wasm = compile_vap(VAP_WITH_VARIABLES);
    let mut evaluator = build_evaluator(&wasm, Some(callback_channel), BTreeSet::new());
    let request =
        ValidateRequest::AdmissionRequest(Box::new(load_admission_request(request_filename)));

    let response =
        tokio::task::block_in_place(|| evaluator.validate(request, &PolicySettings::default()));

    assert_eq!(expected_allowed, response.allowed);
    if let Some(msg) = expected_message {
        let actual_msg = response
            .status
            .as_ref()
            .expect("expected a status")
            .message
            .as_deref()
            .unwrap_or("");
        assert!(
            actual_msg.contains(msg),
            "expected message to contain {msg:?}, got: {actual_msg:?}"
        );
    }

    let _ = shutdown_tx.send(());
}

const VAP_WITH_REQUEST_BINDING: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: request-binding
spec:
  validations:
    - expression: "request.operation == 'CREATE'"
      message: "only CREATE operations are allowed"
"#;

/// Compile and evaluate a VAP that accesses the `request` binding
/// (e.g., `request.operation`). The deployment fixtures use operation CREATE
/// so the policy accepts them.
#[tokio::test(flavor = "multi_thread")]
async fn test_request_binding_accept() {
    let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(mocksvc, "default");
    namespace_scenario(handle).await;
    let (shutdown_tx, callback_channel) = setup_callback_handler(Some(client), None).await;

    let wasm = compile_vap(VAP_WITH_REQUEST_BINDING);
    let mut evaluator = build_evaluator(&wasm, Some(callback_channel), BTreeSet::new());
    let request = ValidateRequest::AdmissionRequest(Box::new(load_admission_request(
        "deployment_accept.json",
    )));

    let response =
        tokio::task::block_in_place(|| evaluator.validate(request, &PolicySettings::default()));

    assert!(response.allowed);

    let _ = shutdown_tx.send(());
}

/// A `ValidateRequest::Raw` is not supported by the ferricel runtime and must
/// be rejected with a 500 internal server error.
#[tokio::test(flavor = "multi_thread")]
async fn test_raw_request_is_rejected() {
    let wasm = compile_vap(VAP_SIMPLE);
    let mut evaluator = build_evaluator(&wasm, None, BTreeSet::new());

    let raw_request = ValidateRequest::Raw(json!({"some": "payload"}));
    let response = evaluator.validate(raw_request, &PolicySettings::default());

    assert!(!response.allowed);
    let status = response.status.as_ref().expect("expected a status");
    assert_eq!(Some(500), status.code);
    let msg = status.message.as_deref().unwrap_or("");
    assert!(
        msg.contains("does not support raw"),
        "expected message to mention raw support, got: {msg:?}"
    );
}

const VAP_WITH_NAMESPACE_OBJECT: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: namespace-object-check
spec:
  validations:
    - expression: "namespaceObject.metadata.name == 'default'"
      message: "unexpected namespace"
"#;

/// On DELETE, Kubernetes typically sends `object: null` (the resource being
/// deleted is only available via `oldObject`), but `request.namespace` is
/// still populated. `namespaceObject` must be derived from `request.namespace`
/// rather than `object.metadata.namespace`, otherwise it would incorrectly be
/// treated as cluster-scoped and skipped for every DELETE of a namespaced
/// resource. This is a regression test for that behavior.
#[tokio::test(flavor = "multi_thread")]
async fn test_namespace_object_is_fetched_on_delete_with_null_object() {
    let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(mocksvc, "default");
    namespace_scenario(handle).await;
    let (shutdown_tx, callback_channel) = setup_callback_handler(Some(client), None).await;

    let wasm = compile_vap(VAP_WITH_NAMESPACE_OBJECT);
    let mut evaluator = build_evaluator(&wasm, Some(callback_channel), BTreeSet::new());
    let request = ValidateRequest::AdmissionRequest(Box::new(load_admission_request(
        "deployment_delete.json",
    )));

    let response =
        tokio::task::block_in_place(|| evaluator.validate(request, &PolicySettings::default()));

    assert!(
        response.allowed,
        "expected namespaceObject to be fetched from request.namespace on DELETE, got: {:?}",
        response.status
    );

    let _ = shutdown_tx.send(());
}

const VAP_WITH_PARAMS: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: params-replicas
spec:
  paramKind:
    apiVersion: v1
    kind: ConfigMap
  validations:
    - expression: "object.spec.replicas <= int(params.data.maxReplicas)"
      message: "too many replicas"
"#;

/// A VAP that uses `paramKind`/`paramRef` requires the `kw.k8s.get` extension.
/// The policy fetches a ConfigMap via the callback channel and uses its data
/// to evaluate the validation expression.
///
/// - accept case: 3 replicas <= 50 (from ConfigMap)
/// - reject case: 51 replicas > 50 (from ConfigMap)
#[rstest]
#[case::accept("deployment_accept.json", true, None)]
#[case::reject("deployment_reject.json", false, Some("too many replicas"))]
#[tokio::test(flavor = "multi_thread")]
async fn test_params(
    #[case] request_filename: &str,
    #[case] expected_allowed: bool,
    #[case] expected_message: Option<&str>,
) {
    let (mocksvc, handle) = tower_test::mock::pair::<Request<Body>, Response<Body>>();
    let client = Client::new(mocksvc, "default");
    params_scenario(handle).await;
    let (shutdown_tx, callback_channel) = setup_callback_handler(Some(client), None).await;

    let wasm = compile_vap(VAP_WITH_PARAMS);
    let ctx_aware_resources = BTreeSet::from([ContextAwareResource {
        api_version: "v1".to_owned(),
        kind: "ConfigMap".to_owned(),
    }]);
    let mut evaluator = build_evaluator(&wasm, Some(callback_channel), ctx_aware_resources);

    // paramRef is stored in the ClusterAdmissionPolicy settings and forwarded
    // to the wasm as a binding so it can call kw.k8s.get to fetch the param resource.
    let settings = PolicySettings::try_from(&json!({
        "paramRef": { "name": "replica-limit", "namespace": "default" }
    }))
    .unwrap();

    let request =
        ValidateRequest::AdmissionRequest(Box::new(load_admission_request(request_filename)));

    let response = tokio::task::block_in_place(|| evaluator.validate(request, &settings));

    assert_eq!(expected_allowed, response.allowed);
    if let Some(msg) = expected_message {
        let actual_msg = response
            .status
            .as_ref()
            .expect("expected a status")
            .message
            .as_deref()
            .unwrap_or("");
        assert!(
            actual_msg.contains(msg),
            "expected message to contain {msg:?}, got: {actual_msg:?}"
        );
    }

    let _ = shutdown_tx.send(());
}

// ─────────────────────────────────────────────────────────────────────────────
// Direct callback-channel mock helpers
//
// For kw.oci / kw.net / kw.crypto the ferricel runtime sends CallbackRequest
// objects directly on the mpsc channel (no Kubernetes API involved).  We
// bypass tower/kube entirely and handle the requests in a lightweight tokio
// task.
// ─────────────────────────────────────────────────────────────────────────────

/// Spawn a direct mock that handles CallbackRequests by calling `handler`
/// and replying on the oneshot channel. Returns the Sender end of the channel.
fn spawn_direct_mock<F>(handler: F) -> mpsc::Sender<CallbackRequest>
where
    F: Fn(CallbackRequestType) -> serde_json::Value + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<CallbackRequest>(8);
    tokio::spawn(async move {
        while let Some(req) = rx.recv().await {
            let response_json = handler(req.request);
            let payload = serde_json::to_vec(&response_json).unwrap();
            let _ = req.response_channel.send(Ok(CallbackResponse { payload }));
        }
    });
    tx
}

fn build_evaluator_with_channel(
    wasm: &[u8],
    callback_channel: mpsc::Sender<CallbackRequest>,
) -> policy_evaluator::policy_evaluator::PolicyEvaluator {
    build_evaluator(wasm, Some(callback_channel), BTreeSet::new())
}

/// Minimal cluster-scoped admission request (no namespace → no namespaceObject fetch).
fn cluster_scoped_request() -> AdmissionRequest {
    serde_json::from_value(json!({
        "uid": "test-uid",
        "kind": {"group": "", "version": "v1", "kind": "Namespace"},
        "resource": {"group": "", "version": "v1", "resource": "namespaces"},
        "name": "test",
        "operation": "CREATE",
        "userInfo": {"username": "admin", "groups": ["system:masters"]},
        "object": {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "test"}
        }
    }))
    .unwrap()
}

// ─── OCI tests ───────────────────────────────────────────────────────────────

const VAP_OCI_MANIFEST: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: oci-manifest
spec:
  validations:
    - expression: "kw.oci.image('image:latest').manifest().image.mediaType == 'application/vnd.oci.image.manifest.v1+json'"
      message: "unexpected media type"
"#;

#[tokio::test(flavor = "multi_thread")]
async fn test_oci_manifest() {
    let wasm = compile_vap(VAP_OCI_MANIFEST);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::OciManifest { .. } => json!({
            "image": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "schemaVersion": 2
            }
        }),
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(cluster_scoped_request())),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

const VAP_OCI_MANIFEST_DIGEST: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: oci-manifest-digest
spec:
  validations:
    - expression: "kw.oci.image('nginx:latest').manifestDigest().startsWith('sha256:')"
      message: "image must have a valid manifest digest"
"#;

#[tokio::test(flavor = "multi_thread")]
async fn test_oci_manifest_digest() {
    let wasm = compile_vap(VAP_OCI_MANIFEST_DIGEST);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::OciManifestDigest { .. } => json!("sha256:1234"),
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(cluster_scoped_request())),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

const VAP_OCI_MANIFEST_CONFIG: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: oci-manifest-config
spec:
  validations:
    - expression: "kw.oci.image('image:latest').manifestConfig().config.author == 'test-author'"
      message: "unexpected author"
"#;

#[tokio::test(flavor = "multi_thread")]
async fn test_oci_manifest_config() {
    let wasm = compile_vap(VAP_OCI_MANIFEST_CONFIG);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::OciManifestAndConfig { .. } => json!({
            "manifest": {},
            "config": {"author": "test-author"},
            "digest": "sha256:5678"
        }),
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(cluster_scoped_request())),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

// ─── Net tests ───────────────────────────────────────────────────────────────

const VAP_NET_LOOKUP_HOST: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: net-lookup-host
spec:
  validations:
    - expression: "size(kw.net.lookupHost('example.com')) >= 1"
      message: "host must resolve to at least one address"
"#;

/// Verifies that `size()` works directly on the array returned by
/// `kw.net.lookupHost` (i.e. `size(kw.net.lookupHost('example.com')) >= 1`).
/// The mock returns `{"ips": ["1.1.1.1", "2.2.2.2"]}`; the handler extracts
/// the `ips` array, giving `size == 2 >= 1` → allowed.
/// Fixed in ferricel-core; see FERRICEL_ISSUES.md Issue 1.
#[tokio::test(flavor = "multi_thread")]
async fn test_net_lookup_host() {
    let wasm = compile_vap(VAP_NET_LOOKUP_HOST);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::DNSLookupHost { .. } => json!({"ips": ["1.1.1.1", "2.2.2.2"]}),
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(cluster_scoped_request())),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

// ─── Crypto tests ─────────────────────────────────────────────────────────────

const VAP_CRYPTO_CERTIFICATE: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: crypto-certificate
spec:
  variables:
    - name: certPem
      expression: "object.metadata.annotations['cert']"
  validations:
    - expression: "kw.crypto.certificate(variables.certPem).verify().isTrusted()"
      message: "certificate must be trusted"
"#;

/// Mirrors the cel-policy Go test:
/// `kw.crypto.certificate('cert.pem').certificateChain('chain1.pem')
///    .certificateChain('chain2.pem').notAfter(timestamp('2000-01-01T00:00:00Z'))
///    .verify().isTrusted()`
#[tokio::test(flavor = "multi_thread")]
async fn test_crypto_verify_trusted() {
    let wasm = compile_vap(VAP_CRYPTO_CERTIFICATE);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::CryptoIsCertificateTrusted { .. } => {
            json!({"trusted": true, "reason": ""})
        }
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);

    // VAP reads `object.metadata.annotations['cert']` as the certificate PEM.
    let request: AdmissionRequest = serde_json::from_value(json!({
        "uid": "crypto-uid",
        "kind": {"group": "", "version": "v1", "kind": "ConfigMap"},
        "resource": {"group": "", "version": "v1", "resource": "configmaps"},
        "name": "test",
        "operation": "CREATE",
        "userInfo": {"username": "admin", "groups": []},
        "object": {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "name": "test",
                "annotations": { "cert": "cert.pem" }
            }
        }
    }))
    .unwrap();

    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(request)),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

// ─── Sigstore tests ───────────────────────────────────────────────────────────
//
// All sigstore tests share the same admission request shape: a Pod-like object
// whose `spec.image` field carries the image reference.  The mock always returns
// a trusted VerificationResponse `{"is_trusted": true, "digest": "sha256:abc"}`.

fn sigstore_request(image: &str) -> AdmissionRequest {
    serde_json::from_value(json!({
        "uid": "sigstore-uid",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "resource": {"group": "", "version": "v1", "resource": "pods"},
        "name": "test",
        "operation": "CREATE",
        "userInfo": {"username": "admin", "groups": []},
        "object": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "test"},
            "spec": {"image": image}
        }
    }))
    .unwrap()
}

fn trusted_sigstore_response() -> serde_json::Value {
    json!({"is_trusted": true, "digest": "sha256:abc123"})
}

const VAP_SIGSTORE_PUBKEY: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: sigstore-pubkey
spec:
  validations:
    - expression: >-
        kw.sigstore.image(object.spec.image)
          .annotation('env', 'prod')
          .pubKey('-----BEGIN PUBLIC KEY-----\nMFkwEwYH\n-----END PUBLIC KEY-----')
          .pubKey('-----BEGIN PUBLIC KEY-----\nMFkwEwYH2\n-----END PUBLIC KEY-----')
          .verify()
          .isTrusted()
      message: "image must be signed with a trusted public key"
"#;

/// `kw.sigstore.image(...).annotation(k,v).pubKey(p1).pubKey(p2).verify().isTrusted()`
/// Exercises MapEntry (annotation) + pubKey accumulation.
#[tokio::test(flavor = "multi_thread")]
async fn test_sigstore_pubkey_verify() {
    let wasm = compile_vap(VAP_SIGSTORE_PUBKEY);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::SigstorePubKeyVerify {
            image,
            pub_keys,
            annotations,
        } => {
            assert_eq!(image, "registry.example.com/app:latest");
            assert_eq!(pub_keys.len(), 2); // two .pubKey() calls accumulated
            assert_eq!(
                annotations
                    .as_ref()
                    .and_then(|a| a.get("env"))
                    .map(String::as_str),
                Some("prod")
            );
            trusted_sigstore_response()
        }
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(sigstore_request(
                "registry.example.com/app:latest",
            ))),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

const VAP_SIGSTORE_KEYLESS: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: sigstore-keyless
spec:
  validations:
    - expression: >-
        kw.sigstore.image(object.spec.image)
          .keyless('https://accounts.google.com', 'user@example.com')
          .keyless('https://token.actions.githubusercontent.com', 'bot@ci.example.com')
          .verify()
          .isTrusted()
      message: "image must be signed with a trusted keyless signature"
"#;

/// `kw.sigstore.image(...).keyless(i1,s1).keyless(i2,s2).verify().isTrusted()`
/// Exercises keyless accumulation + zip to Vec<KeylessInfo>.
#[tokio::test(flavor = "multi_thread")]
async fn test_sigstore_keyless_verify() {
    let wasm = compile_vap(VAP_SIGSTORE_KEYLESS);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::SigstoreKeylessVerify { image, keyless, .. } => {
            assert_eq!(image, "registry.example.com/app:latest");
            assert_eq!(keyless.len(), 2); // two .keyless() calls accumulated
            trusted_sigstore_response()
        }
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(sigstore_request(
                "registry.example.com/app:latest",
            ))),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

const VAP_SIGSTORE_KEYLESS_PREFIX: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: sigstore-keyless-prefix
spec:
  validations:
    - expression: >-
        kw.sigstore.image(object.spec.image)
          .keylessPrefix('https://accounts.google.com', 'https://github.com/myorg/')
          .keylessPrefix('https://token.actions.githubusercontent.com', 'https://github.com/myorg/myrepo/')
          .verify()
          .isTrusted()
      message: "image must be signed with a trusted keyless-prefix signature"
"#;

/// `kw.sigstore.image(...).keylessPrefix(i1,u1).keylessPrefix(i2,u2).verify().isTrusted()`
/// Exercises keylessPrefix accumulation + zip to Vec<KeylessPrefixInfo>.
#[tokio::test(flavor = "multi_thread")]
async fn test_sigstore_keyless_prefix_verify() {
    let wasm = compile_vap(VAP_SIGSTORE_KEYLESS_PREFIX);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::SigstoreKeylessPrefixVerify {
            image,
            keyless_prefix,
            ..
        } => {
            assert_eq!(image, "registry.example.com/app:latest");
            assert_eq!(keyless_prefix.len(), 2); // two .keylessPrefix() calls accumulated
            trusted_sigstore_response()
        }
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(sigstore_request(
                "registry.example.com/app:latest",
            ))),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

const VAP_SIGSTORE_GITHUB_ACTION_OWNER: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: sigstore-github-action-owner
spec:
  validations:
    - expression: >-
        kw.sigstore.image(object.spec.image)
          .githubAction('myorg')
          .verify()
          .isTrusted()
      message: "image must be signed via GitHub Actions for org myorg"
"#;

/// `kw.sigstore.image(...).githubAction('myorg').verify().isTrusted()`
/// Exercises the 1-arg githubAction overload (owner only, no repo).
#[tokio::test(flavor = "multi_thread")]
async fn test_sigstore_github_action_owner_only() {
    let wasm = compile_vap(VAP_SIGSTORE_GITHUB_ACTION_OWNER);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::SigstoreGithubActionsVerify {
            image, owner, repo, ..
        } => {
            assert_eq!(image, "registry.example.com/app:latest");
            assert_eq!(owner, "myorg");
            assert!(repo.is_none(), "expected no repo, got {repo:?}"); // 1-arg form
            trusted_sigstore_response()
        }
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(sigstore_request(
                "registry.example.com/app:latest",
            ))),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

const VAP_SIGSTORE_GITHUB_ACTION_OWNER_REPO: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: sigstore-github-action-owner-repo
spec:
  validations:
    - expression: >-
        kw.sigstore.image(object.spec.image)
          .githubAction('myorg', 'myrepo')
          .verify()
          .isTrusted()
      message: "image must be signed via GitHub Actions for myorg/myrepo"
"#;

/// `kw.sigstore.image(...).githubAction('myorg','myrepo').verify().isTrusted()`
/// Exercises the 2-arg githubAction overload (owner + repo).
#[tokio::test(flavor = "multi_thread")]
async fn test_sigstore_github_action_owner_repo() {
    let wasm = compile_vap(VAP_SIGSTORE_GITHUB_ACTION_OWNER_REPO);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::SigstoreGithubActionsVerify {
            image, owner, repo, ..
        } => {
            assert_eq!(image, "registry.example.com/app:latest");
            assert_eq!(owner, "myorg");
            assert_eq!(repo.as_deref(), Some("myrepo")); // 2-arg form
            trusted_sigstore_response()
        }
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(sigstore_request(
                "registry.example.com/app:latest",
            ))),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}

const VAP_SIGSTORE_CERTIFICATE: &str = r#"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicy
metadata:
  name: sigstore-certificate
spec:
  validations:
    - expression: >-
        kw.sigstore.image(object.spec.image)
          .certificate('-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----')
          .certificateChain('-----BEGIN CERTIFICATE-----\nMIIBchain1\n-----END CERTIFICATE-----')
          .certificateChain('-----BEGIN CERTIFICATE-----\nMIIBchain2\n-----END CERTIFICATE-----')
          .requireRekorBundle(true)
          .verify()
          .isTrusted()
      message: "image must be signed with the trusted certificate"
"#;

/// `kw.sigstore.image(...).certificate(pem).certificateChain(c1).certificateChain(c2)
///    .requireRekorBundle(true).verify().isTrusted()`
/// Exercises certificate + certificateChain accumulation + requireRekorBundle.
#[tokio::test(flavor = "multi_thread")]
async fn test_sigstore_certificate_verify() {
    let wasm = compile_vap(VAP_SIGSTORE_CERTIFICATE);
    let channel = spawn_direct_mock(|req| match req {
        CallbackRequestType::SigstoreCertificateVerify {
            image,
            certificate_chain,
            require_rekor_bundle,
            ..
        } => {
            assert_eq!(image, "registry.example.com/app:latest");
            // two .certificateChain() calls accumulated
            assert_eq!(certificate_chain.as_ref().map(Vec::len), Some(2));
            assert!(require_rekor_bundle);
            trusted_sigstore_response()
        }
        other => panic!("unexpected callback request: {other:?}"),
    });
    let mut evaluator = build_evaluator_with_channel(&wasm, channel);
    let response = tokio::task::block_in_place(|| {
        evaluator.validate(
            ValidateRequest::AdmissionRequest(Box::new(sigstore_request(
                "registry.example.com/app:latest",
            ))),
            &PolicySettings::default(),
        )
    });
    assert!(response.allowed, "expected allowed, got: {response:?}");
}
