use kubewarden_policy_sdk::{
    response::ValidationResponse as PolicyValidationResponse, settings::SettingsValidationResponse,
};
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tracing::error;

use crate::{
    admission_response::AdmissionResponse,
    callback_requests::{CallbackRequest, CallbackRequestType},
    evaluation_context::EvaluationContext,
    policy_evaluator::{PolicySettings, ValidateRequest},
    runtimes::ferricel::stack::Stack,
};

pub(crate) struct Runtime<'a>(pub(crate) &'a Stack);

impl Runtime<'_> {
    pub fn validate(
        &self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> AdmissionResponse {
        let bindings = match self.build_bindings(settings, request) {
            Ok(b) => b,
            Err(response) => return *response,
        };

        let bindings_str = match serde_json::to_string(&bindings) {
            Ok(s) => s,
            Err(e) => {
                error!(
                    error = e.to_string().as_str(),
                    "cannot serialize ferricel bindings"
                );
                return AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    e.to_string(),
                );
            }
        };

        match self.0.eval(Some(&bindings_str)) {
            Ok(result_str) => match serde_json::from_str::<PolicyValidationResponse>(&result_str) {
                Ok(pvr) => {
                    let req_json_value = serde_json::to_value(request)
                        .expect("cannot convert request to json value");
                    let req_obj = req_json_value.get("object");

                    AdmissionResponse::from_policy_validation_response(
                        request.uid().to_string(),
                        req_obj,
                        &pvr,
                    )
                    .unwrap_or_else(|e| {
                        AdmissionResponse::reject_internal_server_error(
                            request.uid().to_string(),
                            format!("Cannot convert policy validation response: {e}"),
                        )
                    })
                }
                Err(e) => AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    format!("Cannot deserialize ferricel response: {e}"),
                ),
            },
            Err(e) => AdmissionResponse::reject_internal_server_error(
                request.uid().to_string(),
                e.to_string(),
            ),
        }
    }

    /// Build the JSON bindings object passed to the compiled VAP module.
    ///
    /// Bindings provided:
    ///   - `object`          The resource being admitted.
    ///   - `oldObject`       The previous version of the resource (UPDATE/DELETE) or null.
    ///   - `request`         The full AdmissionRequest map (operation, userInfo, etc.).
    ///   - `namespaceObject` The Namespace resource for `request.namespace`, fetched from
    ///     the cluster via the callback channel. null for cluster-scoped resources.
    ///     Error if the request is namespace-scoped but no callback channel is available.
    ///     Derived from `AdmissionRequest.namespace` rather than `object.metadata.namespace`
    ///     because `object` is null for DELETE requests, even though the request is
    ///     still namespace-scoped.
    ///   - `paramRef`        Forwarded from `settings["paramRef"]` when present, so that
    ///     the compiled wasm can use it to fetch the param resource via the
    ///     `kw.k8s.get` extension (registered in StackPre::rehydrate).
    ///
    /// Returns `Err(AdmissionResponse)` on failure so that `validate` can return the
    /// error response immediately.
    fn build_bindings(
        &self,
        settings: &PolicySettings,
        request: &ValidateRequest,
    ) -> Result<Value, Box<AdmissionResponse>> {
        match request {
            ValidateRequest::AdmissionRequest(admission_request) => {
                let object = admission_request.object.as_ref().map(|o| &o.0);
                let old_object = admission_request.old_object.as_ref().map(|o| &o.0);

                let request_map =
                    serde_json::to_value(admission_request.as_ref()).map_err(|e| {
                        error!(
                            error = e.to_string().as_str(),
                            "cannot serialize AdmissionRequest"
                        );
                        Box::new(AdmissionResponse::reject_internal_server_error(
                            request.uid().to_string(),
                            e.to_string(),
                        ))
                    })?;

                let namespace_object = fetch_namespace_object(
                    admission_request.namespace.as_deref(),
                    self.0.eval_ctx(),
                )
                .map_err(|e| {
                    error!(error = e.as_str(), "failed to fetch namespace object");
                    Box::new(AdmissionResponse::reject_internal_server_error(
                        request.uid().to_string(),
                        e,
                    ))
                })?;

                let param_ref = settings.0.get("paramRef").cloned().unwrap_or(Value::Null);

                Ok(json!({
                    "object":          object,
                    "oldObject":       old_object,
                    "request":         request_map,
                    "namespaceObject": namespace_object,
                    "paramRef":        param_ref,
                }))
            }
            ValidateRequest::Raw(_raw) => {
                error!("ferricel runtime does not support raw validation requests");
                Err(Box::new(AdmissionResponse::reject_internal_server_error(
                    request.uid().to_string(),
                    "ferricel runtime does not support raw validation requests".to_string(),
                )))
            }
        }
    }

    pub fn validate_settings(&self, _settings: String) -> SettingsValidationResponse {
        // Ferricel/VAP policies do not have runtime settings validation.
        // All validation logic is compiled into the Wasm module.
        SettingsValidationResponse {
            valid: true,
            message: None,
        }
    }
}

fn fetch_namespace_object(
    namespace: Option<&str>,
    eval_ctx: &EvaluationContext,
) -> Result<Value, String> {
    let namespace = namespace.unwrap_or("");

    if namespace.is_empty() {
        return Ok(Value::Null);
    }

    let channel = match &eval_ctx.callback_channel {
        Some(ch) => ch,
        None => {
            return Err(
                "cannot fetch namespaceObject: callback channel is not available".to_string(),
            );
        }
    };

    let (tx, rx) = oneshot::channel::<anyhow::Result<crate::callback_requests::CallbackResponse>>();
    let req = CallbackRequest {
        request: CallbackRequestType::KubernetesGetResource {
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
            name: namespace.to_string(),
            namespace: None,
            disable_cache: false,
            field_masks: None,
        },
        response_channel: tx,
    };

    channel
        .try_send(req)
        .map_err(|e| format!("failed to send namespace fetch request: {e}"))?;

    match rx.blocking_recv() {
        Ok(Ok(response)) => serde_json::from_slice(&response.payload)
            .map_err(|e| format!("failed to deserialize namespace object: {e}")),
        Ok(Err(e)) => Err(format!("failed to fetch namespace object: {e}")),
        Err(e) => Err(format!("namespace fetch channel closed: {e}")),
    }
}
