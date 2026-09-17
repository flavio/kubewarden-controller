use std::sync::Arc;

use ferricel_types::extensions::{BuilderChainDecl, BuilderStep, ExtensionDecl};
use kubewarden_policy_sdk::host_capabilities::{
    crypto::{Certificate, CertificateEncoding},
    crypto_v1::CertificateVerificationRequest,
};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType,
    evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::{call_host, parse_builder_map, reject_null},
};

/// `BuilderChainDecl` for the `kw.crypto` library.
///
/// ```text
/// kw.crypto.certificate(<string>)          → kw.crypto.Verifier
///   .certificateChain(<string>)            → kw.crypto.Verifier  (accumulates)
///   .notAfter(<google.protobuf.Timestamp>) → kw.crypto.Verifier  (RFC-3339 string)
///   .verify()                              → dyn  (host call: kw.crypto.verify)
/// ```
pub fn chain() -> BuilderChainDecl {
    BuilderChainDecl {
        steps: vec![
            BuilderStep::Entry {
                function: "kw.crypto.certificate".to_string(),
                state_keys: vec!["cert".to_string()],
                output_type: "kw.crypto.Verifier".to_string(),
            },
            BuilderStep::Chain {
                function: "certificateChain".to_string(),
                input_type: "kw.crypto.Verifier".to_string(),
                state_keys: vec!["certChain".to_string()],
                output_type: "kw.crypto.Verifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Chain {
                function: "notAfter".to_string(),
                input_type: "kw.crypto.Verifier".to_string(),
                state_keys: vec!["notAfter".to_string()],
                output_type: "kw.crypto.Verifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.crypto.Verifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.crypto".to_string(),
                host_function: "verify".to_string(),
            },
        ],
    }
}

// ─── Runtime extension declarations ──────────────────────────────────────────

pub fn verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.crypto".to_string()),
        function: "verify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

/// `.isTrusted()` -- receiver-style accessor that reads `trusted` from the
/// response map returned by `kw.crypto.verify`. No host call is made.
pub fn is_trusted_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: None,
        function: "isTrusted".to_string(),
        global_style: false,
        receiver_style: true,
        num_args: 1,
    }
}

/// `.reason()` -- receiver-style accessor that reads `reason` from the
/// response map returned by `kw.crypto.verify`. No host call is made.
pub fn reason_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: None,
        function: "reason".to_string(),
        global_style: false,
        receiver_style: true,
        num_args: 1,
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub(crate) fn verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    call_host(
        eval_ctx,
        "crypto",
        "v1/is_certificate_trusted",
        parse_verify(builder_map)?,
    )
}

/// Fields of the builder map that
/// `.certificate(...).certificateChain(...).notAfter(...).verify()`
/// produces. `#[serde(rename_all = "camelCase")]` matches the map's own
/// key names (`cert`, `certChain`, `notAfter`).
///
/// `certChain` absent, or never called, means "no chain"; the underlying
/// verifier then treats the certificate itself as trusted. A present
/// `certChain` element that is not a string is rejected instead of
/// dropped: dropping it, down to an empty array, would have the same
/// "trust the certificate" effect for a policy author who meant to
/// require a chain.
///
/// `notAfter` absent means "no expiry check". A present value must be a
/// string (ferricel serializes a CEL timestamp as an RFC-3339 string).
/// `notAfter` uses [`reject_null`]: a `null` from a CEL expression (for
/// example `object.spec.expiry`) must be rejected rather than treated
/// the same as never calling `.notAfter()`, and serde's own `Option`
/// rule does not make that distinction on its own.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VerifyArgs {
    cert: String,
    #[serde(default)]
    cert_chain: Option<Vec<String>>,
    #[serde(default, deserialize_with = "reject_null")]
    not_after: Option<String>,
}

fn parse_verify(builder_map: &Value) -> Result<CallbackRequestType, String> {
    let args: VerifyArgs = parse_builder_map(builder_map)?;

    let cert = Certificate {
        encoding: CertificateEncoding::Pem,
        data: args.cert.into_bytes(),
    };
    let cert_chain = args.cert_chain.map(|chain| {
        chain
            .into_iter()
            .map(|pem| Certificate {
                encoding: CertificateEncoding::Pem,
                data: pem.into_bytes(),
            })
            .collect()
    });

    Ok(CallbackRequestType::CryptoIsCertificateTrusted {
        request: CertificateVerificationRequest {
            cert,
            cert_chain,
            not_after: args.not_after,
        },
    })
}

/// Handler for `.isTrusted()` -- no host call. Returns the boolean trust field
/// from a verify response map. Accepts either:
/// - `{"trusted": bool, ...}` (kw.crypto response), or
/// - `{"is_trusted": bool, ...}` (kw.sigstore VerificationResponse).
pub(crate) fn is_trusted_handler(args: &[Value]) -> Result<Value, String> {
    let map = args
        .first()
        .ok_or_else(|| "isTrusted: expected at least one argument".to_string())?;
    // Try the crypto key first, then the sigstore key.
    map.get("trusted")
        .or_else(|| map.get("is_trusted"))
        .cloned()
        .ok_or_else(|| {
            "isTrusted: expected a response map with a 'trusted' or 'is_trusted' field".to_string()
        })
}

/// Handler for `.reason()` -- no host call. Returns the `reason` field from
/// the verify response map as a JSON string.
pub(crate) fn reason_handler(args: &[Value]) -> Result<Value, String> {
    args.first()
        .and_then(|v| v.get("reason"))
        .cloned()
        .ok_or_else(|| "reason: expected a response map with a 'reason' field".to_string())
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    /// A PEM-encoded `Certificate` whose bytes are `data`, for building the
    /// expected `CallbackRequestType` without repeating the encoding.
    fn pem(data: &str) -> Certificate {
        Certificate {
            encoding: CertificateEncoding::Pem,
            data: data.as_bytes().to_vec(),
        }
    }

    #[rstest]
    #[case::chain_and_not_after(
        json!({
            "cert": "cert-pem",
            "certChain": ["chain1", "chain2"],
            "notAfter": "2024-01-01T00:00:00Z"
        }),
        Some(vec![pem("chain1"), pem("chain2")]),
        Some("2024-01-01T00:00:00Z".to_string())
    )]
    #[case::no_chain_and_no_not_after(json!({"cert": "cert-pem"}), None, None)]
    fn parse_verify_accepts_a_well_formed_builder_map(
        #[case] builder_map: Value,
        #[case] expected_chain: Option<Vec<Certificate>>,
        #[case] expected_not_after: Option<String>,
    ) {
        let result =
            parse_verify(&builder_map).expect("expected a well-formed builder map to parse");

        assert_eq!(
            result,
            CallbackRequestType::CryptoIsCertificateTrusted {
                request: CertificateVerificationRequest {
                    cert: pem("cert-pem"),
                    cert_chain: expected_chain,
                    not_after: expected_not_after,
                }
            }
        );
    }

    /// A `null` `certChain` element must be rejected, not turned into an
    /// empty chain, which would have the same "trust the certificate"
    /// effect as no chain at all. A `null` or non-string `notAfter`, from
    /// a CEL expression like `object.spec.expiry`, must be rejected
    /// rather than treated the same as never calling `.notAfter()`.
    #[rstest]
    #[case::null_chain_element(
        json!({"cert": "cert-pem", "certChain": [null]}),
        "certChain[0]"
    )]
    #[case::null_not_after(json!({"cert": "cert-pem", "notAfter": null}), "notAfter")]
    #[case::non_string_not_after(json!({"cert": "cert-pem", "notAfter": 1}), "notAfter")]
    fn parse_verify_rejects_a_wrong_type_argument(
        #[case] builder_map: Value,
        #[case] needle: &str,
    ) {
        let err = parse_verify(&builder_map).expect_err("expected an error");
        assert!(
            err.contains(needle),
            "expected {needle:?} in the error, got: {err:?}"
        );
    }
}
