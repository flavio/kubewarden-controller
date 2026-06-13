use ferricel_types::extensions::ExtensionDecl;
use serde_json::Value;

use super::helpers::{require_channel, send_and_recv};
use crate::{callback_requests::CallbackRequestType, evaluation_context::EvaluationContext};

const CHANNEL_ERR: &str = "kw.net.lookupHost: callback channel is not set";

/// `ExtensionDecl` for `kw.net.lookupHost`.
///
/// `lookupHost` is a simple global function (not a fluent builder):
///
/// ```text
/// kw.net.lookupHost(<string>) → list<string>
/// ```
pub fn lookup_host_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.net".to_string()),
        function: "lookupHost".to_string(),
        global_style: true,
        receiver_style: false,
        num_args: 1,
    }
}

// ─── Handler ─────────────────────────────────────────────────────────────────

pub(crate) fn lookup_host_handler(
    eval_ctx: &EvaluationContext,
    args: &[Value],
) -> Result<Value, String> {
    let channel = require_channel(eval_ctx).ok_or(CHANNEL_ERR)?;
    let host = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| "kw.net.lookupHost: expected a string argument".to_string())?
        .to_owned();

    let response = send_and_recv(channel, CallbackRequestType::DNSLookupHost { host })
        .map_err(|e| format!("kw.net.lookupHost: {e}"))?;

    // The callback returns `{"ips": ["1.1.1.1", ...]}` (LookupHostResponse).
    // The CEL expression expects a list<string>, so unwrap the `ips` field.
    response
        .get("ips")
        .cloned()
        .ok_or_else(|| "kw.net.lookupHost: response missing 'ips' field".to_string())
}
