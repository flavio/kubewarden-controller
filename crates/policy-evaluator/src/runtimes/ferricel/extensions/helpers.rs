use serde_json::Value;
use tokio::sync::oneshot;

use crate::{
    callback_requests::{CallbackRequest, CallbackRequestType, CallbackResponse},
    evaluation_context::EvaluationContext,
};

// ─── Handler helpers ──────────────────────────────────────────────────────────

/// Extract a required string field from a builder map.
pub(crate) fn str_field(map: &Value, key: &str) -> Result<String, String> {
    map[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or non-string field '{key}' in builder map"))
}

/// Extract an optional field mask array from a builder map.
pub(crate) fn parse_field_masks(map: &Value) -> Option<std::collections::BTreeSet<String>> {
    map["fieldMasks"].as_array().map(|arr| {
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    })
}

/// Return the callback channel, or `None` if it is not set.
pub(crate) fn require_channel(
    eval_ctx: &EvaluationContext,
) -> Option<&tokio::sync::mpsc::Sender<CallbackRequest>> {
    eval_ctx.callback_channel.as_ref()
}

/// Send a `CallbackRequest` via the channel and synchronously wait for the response.
pub(crate) fn send_and_recv(
    channel: &tokio::sync::mpsc::Sender<CallbackRequest>,
    request_type: CallbackRequestType,
) -> Result<Value, String> {
    let (tx, rx) = oneshot::channel::<anyhow::Result<CallbackResponse>>();
    let req = CallbackRequest {
        request: request_type,
        response_channel: tx,
    };

    channel
        .try_send(req)
        .map_err(|e| format!("failed to send request via callback channel: {e}"))?;

    match rx.blocking_recv() {
        Ok(Ok(response)) => serde_json::from_slice(&response.payload)
            .map_err(|e| format!("failed to deserialize response: {e}")),
        Ok(Err(e)) => Err(format!("callback returned error: {e}")),
        Err(e) => Err(format!("callback channel closed: {e}")),
    }
}
