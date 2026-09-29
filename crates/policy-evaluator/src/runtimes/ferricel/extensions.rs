mod crypto;
mod helpers;
mod kubernetes;
mod net;
mod oci;
mod sigstore;

use std::{
    collections::BTreeSet,
    sync::{Arc, LazyLock},
};

use ferricel_core::{ExtensionKey, runtime::Extensions};
use ferricel_types::extensions::{BuilderChainDecl, ExtensionDecl, UsedExtension};

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::{
        callback::host_capability_denied_message, ferricel::extensions::helpers::ExtensionSpec,
    },
};

// ─── The one list of extensions ───────────────────────────────────────────────

/// Every ferricel extension that Kubewarden provides, with its declaration,
/// its host capabilities, and its handler. See [`ExtensionSpec`].
///
/// This is the one list. [`build_extensions`], [`compiler_extension_decls`],
/// [`host_capabilities`], and [`authorize_extension_call`] all derive from
/// it. An extension that is not in this list does not exist for the
/// compiler, the runtime, the scaffold, or the authorizer.
///
/// The list is built once, on first use. [`authorize_extension_call`] reads
/// it on every host call, so a lookup must not allocate.
static ALL_SPECS: LazyLock<Vec<ExtensionSpec>> = LazyLock::new(|| {
    let mut specs = Vec::new();
    specs.extend(kubernetes::specs());
    specs.extend(oci::specs());
    specs.extend(net::specs());
    specs.extend(crypto::specs());
    specs.extend(sigstore::specs());
    specs
});

fn all_specs() -> &'static [ExtensionSpec] {
    &ALL_SPECS
}

/// The spec whose declaration matches `(namespace, function)`, if any.
fn spec_for(namespace: Option<&str>, function: &str) -> Option<&'static ExtensionSpec> {
    all_specs()
        .iter()
        .find(|spec| spec.decl.namespace.as_deref() == namespace && spec.decl.function == function)
}

// ─── Compile-time declarations (used by kwctl to configure the ferricel compiler) ─────

/// All `BuilderChainDecl`s that must be registered on the ferricel compiler
/// when compiling a VAP policy that may use Kubewarden host capabilities.
///
/// Note: `kw.k8s` is auto-registered by ferricel-core's `compile_vap_from_policy`
/// and must NOT be included here.
pub fn compiler_builder_chains() -> Vec<BuilderChainDecl> {
    vec![oci::chain(), crypto::chain(), sigstore::chain()]
}

/// All `ExtensionDecl`s that must be registered on the ferricel compiler
/// (flat extensions, not covered by builder chains).
///
/// The list comes from [`all_specs`], minus the two `kw.k8s` declarations.
/// ferricel-core registers those on the compiler on its own, with the
/// `kw.k8s` builder chain, so a second registration here is not needed.
pub fn compiler_extension_decls() -> Vec<ExtensionDecl> {
    all_specs()
        .iter()
        .map(|spec| spec.decl.clone())
        .filter(|decl| decl.namespace.as_deref() != Some("kw.k8s"))
        .collect()
}

// ─── Runtime extensions map ───────────────────────────────────────────────────

/// Build the [`Extensions`] registry that is passed to `EnginePre::rehydrate`
/// for every ferricel policy evaluation.
///
/// Every handler in [`all_specs`] is always registered. Handlers that
/// require a callback channel return an error if `eval_ctx.callback_channel`
/// is `None` rather than being omitted from the registry. This way CEL
/// expressions that call those functions receive a clear error message
/// instead of an "extension not found" error from the wasm runtime.
///
/// Every registration pairs the handler with the same [`ExtensionDecl`] that
/// [`compiler_extension_decls`] gives the compiler, because both read
/// [`all_specs`]. As a result, the compile-time and runtime argument counts
/// cannot drift apart. `ferricel-core` enforces `args.len() == decl.num_args`
/// for every guest call before it reaches a handler.
///
/// Every handler that performs a host call routes through
/// [`crate::runtimes::callback::host_callback_typed`] -- the single
/// authorization gate for the callback channel, which waPC/Wasi policies also
/// reach via their `host_callback` adapter. This enforces both the
/// host-capability allow list (`eval_ctx.host_capabilities`) and, for
/// `kw.k8s.get`/`kw.k8s.list`, the Kubernetes resource allow list
/// (`eval_ctx.ctx_aware_resources_allow_list`), so a ferricel policy can never
/// use a host capability or read a Kubernetes resource that its
/// `EvaluationContext` denies.
///
/// The registry also carries an `ExtensionAuthorizer` (see
/// [`authorize_extension_call`]). ferricel-core runs it before it parses the
/// arguments of a call. The authorizer rejects a call when the policy does
/// not hold the capability. As a result, a denied policy cannot make the
/// host parse a large argument list. The authorizer runs the capability
/// check of the gate above one step earlier. The gate still decides.
///
/// An `Err(String)` returned by any handler becomes a CEL runtime error at
/// the call site (unless absorbed by `||`/`&&`). A CEL runtime error inside
/// a VAP `matchCondition` or `validation` always fails the evaluation.
pub(crate) fn build_extensions(eval_ctx: &EvaluationContext) -> Extensions {
    let mut m = Extensions::new();
    let ctx = Arc::new(eval_ctx.clone());

    {
        let ctx = ctx.clone();
        m.set_extension_authorizer(move |key| authorize_extension_call(&ctx, key));
    }

    for spec in all_specs() {
        let ctx = ctx.clone();
        let handler = spec.handler;
        m.register(spec.decl.clone(), move |args: Vec<serde_json::Value>| {
            handler(&ctx, &args)
        });
    }

    m
}

// ─── Host-capability mapping ──────────────────────────────────────────────────

/// Map the host extensions a compiled ferricel module may call (as reported by
/// [`ferricel_core::extensions_used`]) to the Kubewarden host-capability path
/// strings used in policy metadata (`hostCapabilities`).
///
/// The paths come from [`all_specs`]. This function skips an extension that
/// is not in that list and logs a warning for it. The warning makes a gap
/// between the module and this crate visible in the logs. A gap can happen
/// when a module was built by a newer kwctl than the one that reads it.
pub fn host_capabilities(used: &[UsedExtension]) -> BTreeSet<String> {
    let mut caps = BTreeSet::new();
    for ext in used {
        match spec_for(ext.namespace.as_deref(), &ext.function) {
            Some(spec) => caps.extend(spec.capabilities.iter().map(|p| (*p).to_owned())),
            None => {
                tracing::warn!(
                    namespace = ext.namespace.as_deref().unwrap_or("(none)"),
                    function = ext.function.as_str(),
                    "ferricel host extension is not known to this crate; omitting from \
                     policy metadata hostCapabilities"
                );
            }
        }
    }
    caps
}

/// The `ExtensionAuthorizer` that [`build_extensions`] installs.
///
/// ferricel-core calls this function for every host call. It calls it after
/// it finds the extension and before it parses the arguments. That order is
/// the point. A policy that lacks a capability must not make the host parse
/// the arguments first. The guest controls the arguments, and they can be
/// large. Without this check, the host pays for the parse on every denied
/// call, until the epoch deadline stops the policy. The waPC and Wasi
/// runtimes already reject a denied call before the payload parse (see
/// `check_host_capability` in `runtimes::callback`). This function gives
/// the ferricel runtime the same order.
///
/// The check here is coarse on purpose. It sees only the `(namespace,
/// function)` pair. `kw.k8s/list` lists two capability paths. For that
/// call, the check passes when the policy holds either path. The check
/// cannot read the Kubernetes resource allow list, because that needs the
/// parsed `apiVersion` and `kind`. The exact check stays in
/// `check_authorization` in `runtimes::callback`. Every handler reaches
/// that gate through `call_host`. That gate decides. This function only
/// saves the work when the answer is already "no".
///
/// An in-Wasm accessor (an empty capability list) passes, because it makes
/// no host call.
///
/// An extension that is not in [`all_specs`] is denied. ferricel-core looks
/// an extension up in the registry before it calls this function, and the
/// registry comes from the same list. So this branch cannot run for a
/// registered extension. It stays as a guard against a future change that
/// breaks that link.
fn authorize_extension_call(
    eval_ctx: &EvaluationContext,
    key: &ExtensionKey,
) -> Result<(), String> {
    let Some(spec) = spec_for(key.namespace.as_deref(), &key.function) else {
        let name = match &key.namespace {
            Some(ns) => format!("{ns}.{}", key.function),
            None => key.function.clone(),
        };
        tracing::error!(
            policy = %eval_ctx.policy_id,
            extension = %name,
            "ferricel extension reached the authorizer but is not in all_specs"
        );
        return Err(format!(
            "{name}: this extension is not known to the host. The call is denied"
        ));
    };
    let paths = spec.capabilities;
    if paths.is_empty() || paths.iter().any(|p| eval_ctx.can_access_host_capability(p)) {
        return Ok(());
    }
    // The message names the first path. For an extension with one path,
    // that path is the only one. For `kw.k8s/list`, the first path is the
    // by-namespace variant. A policy needs that variant in the common case,
    // a namespaced request.
    Err(host_capability_denied_message(
        &eval_ctx.policy_id,
        paths[0],
        eval_ctx,
    ))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::host_capabilities::HostCapabilities;

    fn ext(namespace: Option<&str>, function: &str) -> UsedExtension {
        UsedExtension {
            namespace: namespace.map(str::to_owned),
            function: function.to_owned(),
        }
    }

    fn key(namespace: Option<&str>, function: &str) -> ferricel_core::ExtensionKey {
        ferricel_core::ExtensionKey::new(namespace.map(str::to_owned), function.to_owned())
    }

    fn ctx_with(host_capabilities: HostCapabilities) -> EvaluationContext {
        EvaluationContext {
            policy_id: "test-policy".to_owned(),
            host_capabilities,
            ..EvaluationContext::default()
        }
    }

    fn ctx_granting(patterns: &[&str]) -> EvaluationContext {
        ctx_with(HostCapabilities::new(patterns).expect("valid capability patterns"))
    }

    // ── authorizer: denied ─────────────────────────────────────────────────────

    /// The authorizer rejects every extension that makes a host call when
    /// the policy holds no capability. The message is the one the callback
    /// gate produces. It names the capability path.
    #[rstest]
    #[case(Some("kw.k8s"), "get", "kubernetes/get_resource")]
    #[case(Some("kw.k8s"), "list", "kubernetes/list_resources_by_namespace")]
    #[case(Some("kw.oci"), "manifest", "oci/v1/oci_manifest")]
    #[case(Some("kw.oci"), "manifestDigest", "oci/v1/manifest_digest")]
    #[case(Some("kw.oci"), "manifestConfig", "oci/v1/oci_manifest_config")]
    #[case(Some("kw.net"), "lookupHost", "net/v1/dns_lookup_host")]
    #[case(Some("kw.crypto"), "verify", "crypto/v1/is_certificate_trusted")]
    #[case(Some("kw.sigstore"), "pubKeyVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "keylessVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "keylessPrefixVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "githubActionsVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "certificateVerify", "oci/v2/verify")]
    fn authorizer_denies_a_host_call_without_the_capability(
        #[case] namespace: Option<&str>,
        #[case] function: &str,
        #[case] named_path: &str,
    ) {
        let ctx = ctx_with(HostCapabilities::DenyAll);
        let err = authorize_extension_call(&ctx, &key(namespace, function))
            .expect_err("a denied policy must be rejected");
        assert!(
            err.contains("has not been granted access"),
            "unexpected message: {err}"
        );
        assert!(
            err.contains(named_path),
            "expected the message to name {named_path:?}, got: {err}"
        );
    }

    // ── authorizer: allowed ────────────────────────────────────────────────────

    #[rstest]
    #[case::allow_all(HostCapabilities::AllowAll, Some("kw.oci"), "manifest")]
    #[case::exact_grant(
        HostCapabilities::new(["oci/v1/oci_manifest"]).unwrap(),
        Some("kw.oci"),
        "manifest"
    )]
    #[case::prefix_grant(
        HostCapabilities::new(["oci/*"]).unwrap(),
        Some("kw.sigstore"),
        "pubKeyVerify"
    )]
    fn authorizer_allows_a_host_call_with_the_capability(
        #[case] host_capabilities: HostCapabilities,
        #[case] namespace: Option<&str>,
        #[case] function: &str,
    ) {
        let ctx = ctx_with(host_capabilities);
        authorize_extension_call(&ctx, &key(namespace, function))
            .expect("a granted policy must pass the authorizer");
    }

    /// `kw.k8s/list` maps to two capability paths. The authorizer does not
    /// know which one the call needs. That depends on the builder map, and
    /// the authorizer has not seen it. The authorizer must accept the call
    /// when the policy holds either path. The callback gate makes the exact
    /// decision later.
    #[rstest]
    #[case::by_namespace_only("kubernetes/list_resources_by_namespace")]
    #[case::all_only("kubernetes/list_resources_all")]
    fn authorizer_allows_kw_k8s_list_with_either_list_capability(#[case] granted: &str) {
        let ctx = ctx_granting(&[granted]);
        authorize_extension_call(&ctx, &key(Some("kw.k8s"), "list"))
            .expect("one of the two list capabilities is enough for the authorizer");
    }

    /// The Kubernetes resource allow list is not the authorizer's job. A
    /// policy with the capability but with no resource grant passes here.
    /// The callback gate denies it later, once it holds the parsed
    /// `apiVersion` and `kind`.
    #[test]
    fn authorizer_does_not_check_the_kubernetes_resource_allow_list() {
        let ctx = ctx_granting(&["kubernetes/get_resource"]);
        assert!(ctx.ctx_aware_resources_allow_list.is_empty());
        authorize_extension_call(&ctx, &key(Some("kw.k8s"), "get"))
            .expect("the resource allow list is checked by the callback gate, not here");
    }

    // ── authorizer: no host call ───────────────────────────────────────────────

    /// An in-Wasm accessor reads a value the guest already holds. The
    /// accessor makes no host call, so it needs no capability. `DenyAll`
    /// must not stop it.
    #[rstest]
    #[case("isTrusted")]
    #[case("reason")]
    #[case("digest")]
    fn authorizer_allows_an_accessor_without_any_capability(#[case] function: &str) {
        let ctx = ctx_with(HostCapabilities::DenyAll);
        authorize_extension_call(&ctx, &key(None, function))
            .expect("an accessor makes no host call and must pass");
    }

    /// An extension that is not in `all_specs` is denied, whatever the
    /// policy holds. The registry comes from the same list, so this branch
    /// cannot run for a registered extension today. The test pins the
    /// fail-closed default in case a future change breaks that link.
    #[test]
    fn authorizer_denies_an_extension_that_is_not_in_all_specs() {
        let ctx = ctx_with(HostCapabilities::AllowAll);
        let err = authorize_extension_call(&ctx, &key(Some("kw.unknown"), "futureFn"))
            .expect_err("an extension outside all_specs must be denied, even under AllowAll");
        assert!(
            err.contains("kw.unknown.futureFn"),
            "expected the message to name the extension, got: {err}"
        );
        assert!(
            err.contains("not known to the host"),
            "expected the message to say the extension is unknown, got: {err}"
        );
    }

    // ── single-extension → single-capability mapping (rstest table) ───────────

    #[rstest]
    // kw.k8s
    #[case(Some("kw.k8s"), "get", "kubernetes/get_resource")]
    // kw.oci
    #[case(Some("kw.oci"), "manifest", "oci/v1/oci_manifest")]
    #[case(Some("kw.oci"), "manifestDigest", "oci/v1/manifest_digest")]
    #[case(Some("kw.oci"), "manifestConfig", "oci/v1/oci_manifest_config")]
    // kw.net
    #[case(Some("kw.net"), "lookupHost", "net/v1/dns_lookup_host")]
    // kw.crypto
    #[case(Some("kw.crypto"), "verify", "crypto/v1/is_certificate_trusted")]
    // kw.sigstore — all five verify variants map to oci/v2/verify
    #[case(Some("kw.sigstore"), "pubKeyVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "keylessVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "keylessPrefixVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "githubActionsVerify", "oci/v2/verify")]
    #[case(Some("kw.sigstore"), "certificateVerify", "oci/v2/verify")]
    fn single_extension_maps_to_expected_capability(
        #[case] namespace: Option<&str>,
        #[case] function: &str,
        #[case] expected_cap: &str,
    ) {
        let caps = host_capabilities(&[ext(namespace, function)]);
        assert_eq!(caps, BTreeSet::from([expected_cap.to_string()]));
    }

    // ── kw.k8s/list → two capabilities ───────────────────────────────────────

    #[test]
    fn kw_k8s_list_maps_to_both_list_variants() {
        let caps = host_capabilities(&[ext(Some("kw.k8s"), "list")]);
        assert_eq!(
            caps,
            BTreeSet::from([
                "kubernetes/list_resources_by_namespace".to_string(),
                "kubernetes/list_resources_all".to_string(),
            ])
        );
    }

    // ── sigstore deduplication ────────────────────────────────────────────────

    #[test]
    fn sigstore_deduplicates_oci_v2_verify() {
        // Multiple sigstore verify variants in one module → single "oci/v2/verify"
        let caps = host_capabilities(&[
            ext(Some("kw.sigstore"), "pubKeyVerify"),
            ext(Some("kw.sigstore"), "keylessVerify"),
        ]);
        assert_eq!(caps, BTreeSet::from(["oci/v2/verify".to_string()]));
    }

    // ── accessor extensions produce no capabilities ───────────────────────────

    #[test]
    fn accessors_produce_no_capabilities() {
        let caps = host_capabilities(&[
            ext(None, "isTrusted"),
            ext(None, "reason"),
            ext(None, "digest"),
        ]);
        assert!(caps.is_empty());
    }

    // ── unknown extension → empty + warn (no panic) ───────────────────────────

    #[test]
    fn unknown_extension_is_skipped_without_panic() {
        let caps = host_capabilities(&[ext(Some("kw.unknown"), "future_fn")]);
        assert!(caps.is_empty());
    }

    // ── empty input ───────────────────────────────────────────────────────────

    #[test]
    fn empty_used_list_produces_empty_capabilities() {
        let caps = host_capabilities(&[]);
        assert!(caps.is_empty());
    }

    // ── all_specs: the shape every spec must have ───────────────────────────────

    /// An extension with a namespace makes a host call and must list at
    /// least one capability. An extension without a namespace is an
    /// accessor and must list none.
    ///
    /// A registration cannot forget its capabilities any more: the field is
    /// not optional. What it can still get wrong is the shape, for example
    /// a host call with an empty list. That is what this test pins.
    #[test]
    fn every_spec_lists_capabilities_that_match_its_kind() {
        let specs = all_specs();
        assert!(!specs.is_empty(), "expected at least one extension spec");
        for spec in specs {
            match spec.decl.namespace {
                Some(_) => assert!(
                    !spec.capabilities.is_empty(),
                    "host-call extension {:?} lists no capability",
                    spec.decl
                ),
                None => assert!(
                    spec.capabilities.is_empty(),
                    "accessor {:?} must list no capability, got {:?}",
                    spec.decl,
                    spec.capabilities
                ),
            }
        }
    }

    /// Two specs with the same `(namespace, function)` would make the
    /// second one replace the first in the registry, without a sign.
    #[test]
    fn all_specs_has_no_duplicate_extension_key() {
        let mut seen = BTreeSet::new();
        for spec in all_specs() {
            let key = (spec.decl.namespace.clone(), spec.decl.function.clone());
            assert!(
                seen.insert(key.clone()),
                "extension {key:?} is declared more than once in all_specs"
            );
        }
    }

    // ── untrusted-guest arity guard ────────────────────────────────────────────

    #[test]
    fn every_registered_extension_rejects_empty_args_without_panicking() {
        // Ferricel-core rejects a call whose argument count doesn't
        // match the registered `ExtensionDecl::num_args` before it ever
        // reaches the closure, but this is a defense-in-depth test for the
        // closures themselves (see `builder_arg`'s doc comment): it protects
        // against a decl/handler mismatch and against the closures being
        // invoked directly, as done here.
        let exts = build_extensions(&EvaluationContext::default());
        let decls: Vec<ExtensionDecl> = exts.decls().cloned().collect();
        assert!(
            !decls.is_empty(),
            "expected at least one registered extension"
        );
        for decl in decls {
            let key =
                ferricel_core::ExtensionKey::new(decl.namespace.clone(), decl.function.clone());
            let ext = exts.get(&key).unwrap_or_else(|| {
                panic!("decl {decl:?} not found in its own Extensions registry")
            });
            let result = (ext.implementation)(vec![]);
            assert!(
                result.is_err(),
                "extension {decl:?} did not return Err when called with empty args"
            );
        }
    }

    // ── compile-time / runtime decl drift guard ────────────────────────────────

    #[test]
    fn runtime_decls_match_compiler_decls() {
        // Both lists come from `all_specs`, so they cannot drift on their
        // own. What this test pins is the one difference between them:
        // `compiler_extension_decls` must leave out exactly the two `kw.k8s`
        // declarations, because ferricel-core registers those on the
        // compiler on its own, and it must leave out nothing else.
        let runtime_decls: BTreeSet<ExtensionDecl> =
            build_extensions(&EvaluationContext::default())
                .decls()
                .cloned()
                .collect();

        let mut expected: BTreeSet<ExtensionDecl> =
            compiler_extension_decls().into_iter().collect();
        expected.insert(ferricel_core::compiler::vap::kw_k8s_get_extension());
        expected.insert(ferricel_core::compiler::vap::kw_k8s_list_extension());

        assert_eq!(runtime_decls, expected);
    }

    // ── every builder-handler decl expects at least one argument ───────────────

    #[test]
    fn every_registered_decl_has_at_least_one_arg() {
        // Every handler registered in `build_extensions` reads `args[0]` (via
        // `builder_arg` or, for `kw.net.lookupHost`/`isTrusted`/`reason`/
        // `digest`, via `.first()` directly). If a future decl were
        // registered with `num_args: 0`, ferricel-core's arity check would
        // let a zero-arg call reach the closure and `builder_arg` would then
        // (correctly) reject it -- but the decl itself would be wrong. This
        // test catches that class of mistake independently of arity
        // enforcement.
        for decl in build_extensions(&EvaluationContext::default()).decls() {
            assert!(
                decl.num_args >= 1,
                "decl {decl:?} declares num_args=0 but its handler expects an argument"
            );
        }
    }
}
