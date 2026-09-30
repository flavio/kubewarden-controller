use std::sync::Arc;

use ferricel_types::extensions::ExtensionDecl;
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType,
    evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::{ExtensionSpec, call_host},
};

// ─── Host capabilities ────────────────────────────────────────────────────────

const LOOKUP_HOST_CAPABILITY: &str = "net/v1/dns_lookup_host";

/// The `kw.net` extensions, with the capability each one needs.
pub(super) fn specs() -> Vec<ExtensionSpec> {
    vec![ExtensionSpec {
        decl: lookup_host_extension(),
        capabilities: &[LOOKUP_HOST_CAPABILITY],
        handler: lookup_host_handler,
    }]
}

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
    eval_ctx: &Arc<EvaluationContext>,
    args: &[Value],
) -> Result<Value, String> {
    let host = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| "expected a string argument".to_string())?
        .to_owned();

    let response = call_host(
        eval_ctx,
        LOOKUP_HOST_CAPABILITY,
        CallbackRequestType::DNSLookupHost { host },
    )?;

    // The callback returns `{"ips": ["1.1.1.1", ...]}` (LookupHostResponse).
    // The CEL expression expects a list<string>, so unwrap the `ips` field.
    response
        .get("ips")
        .cloned()
        .ok_or_else(|| "response missing 'ips' field".to_string())
}
