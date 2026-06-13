use serde_json::Value;

use super::helpers::{parse_field_masks, require_channel, send_and_recv, str_field};
use crate::{callback_requests::CallbackRequestType, evaluation_context::EvaluationContext};

const CHANNEL_ERR: &str = "kw.k8s: callback channel is not set";

pub(crate) fn get_handler(
    eval_ctx: &EvaluationContext,
    builder_map: &Value,
) -> Result<Value, String> {
    let channel = require_channel(eval_ctx).ok_or(CHANNEL_ERR)?;
    let api_version =
        str_field(builder_map, "apiVersion").map_err(|e| format!("kw.k8s.get: {e}"))?;
    let kind = str_field(builder_map, "kind").map_err(|e| format!("kw.k8s.get: {e}"))?;
    let name = str_field(builder_map, "name").map_err(|e| format!("kw.k8s.get: {e}"))?;
    let namespace = builder_map["namespace"].as_str().map(str::to_owned);
    let field_masks = parse_field_masks(builder_map);

    send_and_recv(
        channel,
        CallbackRequestType::KubernetesGetResource {
            api_version,
            kind,
            name,
            namespace,
            disable_cache: false,
            field_masks,
        },
    )
    .map_err(|e| format!("kw.k8s.get: {e}"))
}

pub(crate) fn list_handler(
    eval_ctx: &EvaluationContext,
    builder_map: &Value,
) -> Result<Value, String> {
    let channel = require_channel(eval_ctx).ok_or(CHANNEL_ERR)?;
    let api_version =
        str_field(builder_map, "apiVersion").map_err(|e| format!("kw.k8s.list: {e}"))?;
    let kind = str_field(builder_map, "kind").map_err(|e| format!("kw.k8s.list: {e}"))?;
    let label_selector = builder_map["labelSelector"].as_str().map(str::to_owned);
    let field_selector = builder_map["fieldSelector"].as_str().map(str::to_owned);
    let field_masks = parse_field_masks(builder_map);

    let request_type = if let Some(namespace) = builder_map["namespace"].as_str() {
        CallbackRequestType::KubernetesListResourceNamespace {
            api_version,
            kind,
            namespace: namespace.to_owned(),
            label_selector,
            field_selector,
            field_masks,
        }
    } else {
        CallbackRequestType::KubernetesListResourceAll {
            api_version,
            kind,
            label_selector,
            field_selector,
            field_masks,
        }
    };

    send_and_recv(channel, request_type).map_err(|e| format!("kw.k8s.list: {e}"))
}
