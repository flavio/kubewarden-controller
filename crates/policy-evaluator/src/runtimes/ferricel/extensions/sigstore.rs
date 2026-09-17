use std::{collections::BTreeMap, sync::Arc};

use ferricel_types::extensions::{BuilderChainDecl, BuilderStep, ExtensionDecl};
use kubewarden_policy_sdk::host_capabilities::verification::{KeylessInfo, KeylessPrefixInfo};
use serde::Deserialize;
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType,
    evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::{call_host, parse_builder_map, reject_null},
};

/// `BuilderChainDecl` for the `kw.sigstore` library.
///
/// ```text
/// kw.sigstore.image(<string>)                          → kw.sigstore.VerifierBuilder
///   .annotation(<string>, <string>)                    → kw.sigstore.VerifierBuilder  (map-entry)
///   .pubKey(<string>)                                  → kw.sigstore.PubKeysVerifier  (accumulate)
///     .pubKey(<string>)                                → kw.sigstore.PubKeysVerifier  (accumulate)
///     .verify()                                        → dyn  (host call: kw.sigstore/pubKeyVerify)
///   .keyless(<string>, <string>)                       → kw.sigstore.KeylessVerifier  (accumulate)
///     .keyless(<string>, <string>)                     → kw.sigstore.KeylessVerifier  (accumulate)
///     .verify()                                        → dyn  (host call: kw.sigstore/keylessVerify)
///   .keylessPrefix(<string>, <string>)                 → kw.sigstore.KeylessPrefixVerifier  (accumulate)
///     .keylessPrefix(<string>, <string>)               → kw.sigstore.KeylessPrefixVerifier  (accumulate)
///     .verify()                                        → dyn  (host call: kw.sigstore/keylessPrefixVerify)
///   .githubAction(<string>)                            → kw.sigstore.GitHubActionVerifier
///   .githubAction(<string>, <string>)                  → kw.sigstore.GitHubActionVerifier
///     .verify()                                        → dyn  (host call: kw.sigstore/githubActionsVerify)
///   .certificate(<string>)                             → kw.sigstore.CertificateVerifier
///     .certificateChain(<string>)                      → kw.sigstore.CertificateVerifier  (accumulate)
///     .requireRekorBundle(<bool>)                      → kw.sigstore.CertificateVerifier
///     .verify()                                        → dyn  (host call: kw.sigstore/certificateVerify)
/// ```
pub fn chain() -> BuilderChainDecl {
    BuilderChainDecl {
        steps: vec![
            // ── Entry ─────────────────────────────────────────────────────────
            BuilderStep::Entry {
                function: "kw.sigstore.image".to_string(),
                state_keys: vec!["image".to_string()],
                output_type: "kw.sigstore.VerifierBuilder".to_string(),
            },
            // ── annotation (map-entry) ────────────────────────────────────────
            // .annotation(key, value) accumulates into a nested "annotations" map.
            BuilderStep::MapEntry {
                function: "annotation".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_key: "annotations".to_string(),
                output_type: "kw.sigstore.VerifierBuilder".to_string(),
            },
            // ── pubKey (transition + accumulate) ─────────────────────────────
            // First .pubKey() transitions VerifierBuilder → PubKeysVerifier.
            BuilderStep::Chain {
                function: "pubKey".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["pubKeys".to_string()],
                output_type: "kw.sigstore.PubKeysVerifier".to_string(),
                accumulate: true,
            },
            // Subsequent .pubKey() calls accumulate on PubKeysVerifier.
            BuilderStep::Chain {
                function: "pubKey".to_string(),
                input_type: "kw.sigstore.PubKeysVerifier".to_string(),
                state_keys: vec!["pubKeys".to_string()],
                output_type: "kw.sigstore.PubKeysVerifier".to_string(),
                accumulate: true,
            },
            // Terminal for PubKeysVerifier.
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.PubKeysVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "pubKeyVerify".to_string(),
            },
            // ── keyless (transition + accumulate) ────────────────────────────
            // First .keyless(issuer, subject) transitions VerifierBuilder → KeylessVerifier.
            BuilderStep::Chain {
                function: "keyless".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["keylessIssuers".to_string(), "keylessSubjects".to_string()],
                output_type: "kw.sigstore.KeylessVerifier".to_string(),
                accumulate: true,
            },
            // Subsequent .keyless() calls accumulate on KeylessVerifier.
            BuilderStep::Chain {
                function: "keyless".to_string(),
                input_type: "kw.sigstore.KeylessVerifier".to_string(),
                state_keys: vec!["keylessIssuers".to_string(), "keylessSubjects".to_string()],
                output_type: "kw.sigstore.KeylessVerifier".to_string(),
                accumulate: true,
            },
            // Terminal for KeylessVerifier.
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.KeylessVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "keylessVerify".to_string(),
            },
            // ── keylessPrefix (transition + accumulate) ───────────────────────
            BuilderStep::Chain {
                function: "keylessPrefix".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec![
                    "keylessPrefixIssuers".to_string(),
                    "keylessPrefixUrls".to_string(),
                ],
                output_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Chain {
                function: "keylessPrefix".to_string(),
                input_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                state_keys: vec![
                    "keylessPrefixIssuers".to_string(),
                    "keylessPrefixUrls".to_string(),
                ],
                output_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.KeylessPrefixVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "keylessPrefixVerify".to_string(),
            },
            // ── githubAction (1-arg: owner only) ─────────────────────────────
            BuilderStep::Chain {
                function: "githubAction".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["owner".to_string()],
                output_type: "kw.sigstore.GitHubActionVerifier".to_string(),
                accumulate: false,
            },
            // ── githubAction (2-arg: owner + repo) ───────────────────────────
            BuilderStep::Chain {
                function: "githubAction".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["owner".to_string(), "repo".to_string()],
                output_type: "kw.sigstore.GitHubActionVerifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.GitHubActionVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "githubActionsVerify".to_string(),
            },
            // ── certificate chain ─────────────────────────────────────────────
            BuilderStep::Chain {
                function: "certificate".to_string(),
                input_type: "kw.sigstore.VerifierBuilder".to_string(),
                state_keys: vec!["certificate".to_string()],
                output_type: "kw.sigstore.CertificateVerifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Chain {
                function: "certificateChain".to_string(),
                input_type: "kw.sigstore.CertificateVerifier".to_string(),
                state_keys: vec!["certificateChain".to_string()],
                output_type: "kw.sigstore.CertificateVerifier".to_string(),
                accumulate: true,
            },
            BuilderStep::Chain {
                function: "requireRekorBundle".to_string(),
                input_type: "kw.sigstore.CertificateVerifier".to_string(),
                state_keys: vec!["requireRekorBundle".to_string()],
                output_type: "kw.sigstore.CertificateVerifier".to_string(),
                accumulate: false,
            },
            BuilderStep::Terminal {
                function: "verify".to_string(),
                input_type: "kw.sigstore.CertificateVerifier".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.sigstore".to_string(),
                host_function: "certificateVerify".to_string(),
            },
        ],
    }
}

// ─── Runtime extension declarations ──────────────────────────────────────────

pub fn pub_key_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "pubKeyVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn keyless_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "keylessVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn keyless_prefix_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "keylessPrefixVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn github_actions_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "githubActionsVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn certificate_verify_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.sigstore".to_string()),
        function: "certificateVerify".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

/// `.digest()` -- receiver-style accessor that reads `digest` from the
/// `VerificationResponse` returned by any sigstore verify call. No host call.
pub fn digest_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: None,
        function: "digest".to_string(),
        global_style: false,
        receiver_style: true,
        num_args: 1,
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────
//
// All five verify variants are dispatched under the "oci"/"v2/verify" host
// capability (see `host_capabilities()` in `extensions.rs`), matching how the
// waPC/Wasi `host_callback` handles the internally-tagged
// `SigstoreVerificationInputV2` payload for the same operation.

pub(crate) fn pub_key_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        parse_pub_key_verify(builder_map)?,
    )
}

/// Fields of the builder map that `.pubKey(...).verify()` produces.
/// `#[serde(rename_all = "camelCase")]` matches the map's own key names
/// (`pubKeys`).
///
/// `pubKeys` defaults to empty when `.pubKey()` was never called. Every
/// element, and every value of `annotations`, must be a string: a
/// wrong-type element is rejected rather than dropped. Dropping a key
/// would silently require fewer keys than the policy author wrote;
/// dropping an annotation would silently remove a required annotation
/// from the check.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PubKeyVerifyArgs {
    image: String,
    #[serde(default)]
    pub_keys: Vec<String>,
    #[serde(default)]
    annotations: Option<BTreeMap<String, String>>,
}

fn parse_pub_key_verify(builder_map: &Value) -> Result<CallbackRequestType, String> {
    let args: PubKeyVerifyArgs = parse_builder_map(builder_map)?;

    Ok(CallbackRequestType::SigstorePubKeyVerify {
        image: args.image,
        pub_keys: args.pub_keys,
        annotations: args.annotations,
    })
}

pub(crate) fn keyless_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        parse_keyless_verify(builder_map)?,
    )
}

/// Fields of the builder map that `.keyless(issuer, subject).verify()`
/// produces. `keylessIssuers` and `keylessSubjects` are parallel arrays:
/// serde parses each one fully, by index, before [`zip_keyless`] pairs
/// them. This way a wrong-type issuer or subject is reported at the
/// position where it appears, rather than shifting every pair that
/// follows it.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeylessVerifyArgs {
    image: String,
    #[serde(default)]
    keyless_issuers: Vec<String>,
    #[serde(default)]
    keyless_subjects: Vec<String>,
    #[serde(default)]
    annotations: Option<BTreeMap<String, String>>,
}

fn parse_keyless_verify(builder_map: &Value) -> Result<CallbackRequestType, String> {
    let args: KeylessVerifyArgs = parse_builder_map(builder_map)?;
    let keyless = zip_keyless(args.keyless_issuers, args.keyless_subjects)?;

    Ok(CallbackRequestType::SigstoreKeylessVerify {
        image: args.image,
        keyless,
        annotations: args.annotations,
    })
}

pub(crate) fn keyless_prefix_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        parse_keyless_prefix_verify(builder_map)?,
    )
}

/// Fields of the builder map that
/// `.keylessPrefix(issuer, urlPrefix).verify()` produces. See
/// [`KeylessVerifyArgs`] for why the two parallel arrays are parsed in
/// full before [`zip_keyless_prefix`] pairs them.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeylessPrefixVerifyArgs {
    image: String,
    #[serde(default)]
    keyless_prefix_issuers: Vec<String>,
    #[serde(default)]
    keyless_prefix_urls: Vec<String>,
    #[serde(default)]
    annotations: Option<BTreeMap<String, String>>,
}

fn parse_keyless_prefix_verify(builder_map: &Value) -> Result<CallbackRequestType, String> {
    let args: KeylessPrefixVerifyArgs = parse_builder_map(builder_map)?;
    let keyless_prefix = zip_keyless_prefix(args.keyless_prefix_issuers, args.keyless_prefix_urls)?;

    Ok(CallbackRequestType::SigstoreKeylessPrefixVerify {
        image: args.image,
        keyless_prefix,
        annotations: args.annotations,
    })
}

pub(crate) fn github_actions_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        parse_github_actions_verify(builder_map)?,
    )
}

/// Fields of the builder map that `.githubAction(owner[, repo]).verify()`
/// produces. `repo` is only set by the 2-arg overload; when the 1-arg
/// overload was used, the key is entirely absent from the map and
/// `repo` is `None`. `repo` uses [`reject_null`]: when the 2-arg
/// overload was used, `repo` must be a string, and
/// `.githubAction("org", null)` is rejected rather than treated the same
/// as the 1-arg overload, so a `null` value from a CEL expression cannot
/// silently drop the repository restriction.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GithubActionsVerifyArgs {
    image: String,
    owner: String,
    #[serde(default, deserialize_with = "reject_null")]
    repo: Option<String>,
    #[serde(default)]
    annotations: Option<BTreeMap<String, String>>,
}

fn parse_github_actions_verify(builder_map: &Value) -> Result<CallbackRequestType, String> {
    let args: GithubActionsVerifyArgs = parse_builder_map(builder_map)?;

    Ok(CallbackRequestType::SigstoreGithubActionsVerify {
        image: args.image,
        owner: args.owner,
        repo: args.repo,
        annotations: args.annotations,
    })
}

pub(crate) fn certificate_verify_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    call_host(
        eval_ctx,
        "oci",
        "v2/verify",
        parse_certificate_verify(builder_map)?,
    )
}

/// Fields of the builder map that
/// `.certificate(...).certificateChain(...).requireRekorBundle(...).verify()`
/// produces.
///
/// `certificateChain` absent, or never called, means "no chain"; the
/// underlying Sigstore verifier then treats the certificate itself as
/// trusted. A present `certificateChain` element that is not a string is
/// rejected instead: silently dropping it, as an empty array, would have
/// the same "trust the certificate" effect for a policy author who meant
/// to require a chain.
///
/// `requireRekorBundle` absent means `false`, the same default the
/// `kw.crypto` and waPC/Wasi paths use. `requireRekorBundle` uses
/// [`reject_null`]: a present value must be a boolean, and a `null` or a
/// string like `"true"` is rejected instead of silently becoming
/// `false`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertificateVerifyArgs {
    image: String,
    certificate: String,
    #[serde(default)]
    certificate_chain: Option<Vec<String>>,
    #[serde(default, deserialize_with = "reject_null")]
    require_rekor_bundle: Option<bool>,
    #[serde(default)]
    annotations: Option<BTreeMap<String, String>>,
}

fn parse_certificate_verify(builder_map: &Value) -> Result<CallbackRequestType, String> {
    let args: CertificateVerifyArgs = parse_builder_map(builder_map)?;

    Ok(CallbackRequestType::SigstoreCertificateVerify {
        image: args.image,
        certificate: args.certificate.into_bytes(),
        certificate_chain: args
            .certificate_chain
            .map(|chain| chain.into_iter().map(String::into_bytes).collect()),
        require_rekor_bundle: args.require_rekor_bundle.unwrap_or(false),
        annotations: args.annotations,
    })
}

/// `.digest()` -- no host call. Returns the `digest` field from the
/// `VerificationResponse` map (`{"is_trusted": bool, "digest": string}`).
pub(crate) fn digest_handler(args: &[Value]) -> Result<Value, String> {
    args.first()
        .and_then(|v| v.get("digest"))
        .cloned()
        .ok_or_else(|| "digest: expected a response map with a 'digest' field".to_string())
}

// ─── Private helpers ──────────────────────────────────────────────────────────

/// Zip parallel `issuers` and `subjects` arrays into `Vec<KeylessInfo>`.
/// Both arrays are already fully parsed at this point (see
/// [`KeylessVerifyArgs`]), so this only pairs them up.
fn zip_keyless(issuers: Vec<String>, subjects: Vec<String>) -> Result<Vec<KeylessInfo>, String> {
    if issuers.len() != subjects.len() {
        return Err(format!(
            "issuer/subject arrays have different lengths ({} vs {})",
            issuers.len(),
            subjects.len()
        ));
    }

    Ok(issuers
        .into_iter()
        .zip(subjects)
        .map(|(issuer, subject)| KeylessInfo { issuer, subject })
        .collect())
}

/// Zip parallel `issuers` and `urlPrefixes` arrays into
/// `Vec<KeylessPrefixInfo>`. Both arrays are already fully parsed at this
/// point (see [`KeylessPrefixVerifyArgs`]), so this only pairs them up.
fn zip_keyless_prefix(
    issuers: Vec<String>,
    url_prefixes: Vec<String>,
) -> Result<Vec<KeylessPrefixInfo>, String> {
    if issuers.len() != url_prefixes.len() {
        return Err(format!(
            "issuer/urlPrefix arrays have different lengths ({} vs {})",
            issuers.len(),
            url_prefixes.len()
        ));
    }

    Ok(issuers
        .into_iter()
        .zip(url_prefixes)
        .map(|(issuer, url_prefix)| KeylessPrefixInfo { issuer, url_prefix })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use rstest::rstest;
    use serde_json::json;

    use super::*;

    /// The `image` every case below parses from `"img:latest"`.
    fn image() -> String {
        "img:latest".to_owned()
    }

    /// `items` as `Vec<String>`, for a case row that only needs to name
    /// the strings once.
    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// `items` as the `Vec<Vec<u8>>` a certificate chain parses into.
    fn byte_vecs(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    /// Every parse function accepts a well-formed builder map and
    /// returns the exact `CallbackRequestType` its fields describe.
    ///
    /// `github_action_owner_only` has no `repo` at all: the 1-arg
    /// overload never sets the key. `certificate_no_chain_and_no_rekor_bundle`
    /// has neither `certificateChain` nor `requireRekorBundle`: neither
    /// method was called, and both default to "no chain" / `false`, the
    /// same defaults `kw.crypto` and the waPC/Wasi paths use.
    #[rstest]
    #[case::pub_key(
        parse_pub_key_verify,
        json!({
            "image": "img:latest",
            "pubKeys": ["key1", "key2"],
            "annotations": {"env": "prod"}
        }),
        CallbackRequestType::SigstorePubKeyVerify {
            image: image(),
            pub_keys: strings(&["key1", "key2"]),
            annotations: Some(BTreeMap::from([("env".to_owned(), "prod".to_owned())])),
        }
    )]
    #[case::keyless(
        parse_keyless_verify,
        json!({
            "image": "img:latest",
            "keylessIssuers": ["issuer1", "issuer2"],
            "keylessSubjects": ["subject1", "subject2"]
        }),
        CallbackRequestType::SigstoreKeylessVerify {
            image: image(),
            keyless: vec![
                KeylessInfo { issuer: "issuer1".to_owned(), subject: "subject1".to_owned() },
                KeylessInfo { issuer: "issuer2".to_owned(), subject: "subject2".to_owned() },
            ],
            annotations: None,
        }
    )]
    #[case::keyless_prefix(
        parse_keyless_prefix_verify,
        json!({
            "image": "img:latest",
            "keylessPrefixIssuers": ["issuer1"],
            "keylessPrefixUrls": ["https://github.com/myorg/"]
        }),
        CallbackRequestType::SigstoreKeylessPrefixVerify {
            image: image(),
            keyless_prefix: vec![KeylessPrefixInfo {
                issuer: "issuer1".to_owned(),
                url_prefix: "https://github.com/myorg/".to_owned(),
            }],
            annotations: None,
        }
    )]
    #[case::github_action_owner_only(
        parse_github_actions_verify,
        json!({"image": "img:latest", "owner": "myorg"}),
        CallbackRequestType::SigstoreGithubActionsVerify {
            image: image(),
            owner: "myorg".to_owned(),
            repo: None,
            annotations: None,
        }
    )]
    #[case::github_action_owner_and_repo(
        parse_github_actions_verify,
        json!({"image": "img:latest", "owner": "myorg", "repo": "myrepo"}),
        CallbackRequestType::SigstoreGithubActionsVerify {
            image: image(),
            owner: "myorg".to_owned(),
            repo: Some("myrepo".to_owned()),
            annotations: None,
        }
    )]
    #[case::certificate_chain_and_rekor_bundle(
        parse_certificate_verify,
        json!({
            "image": "img:latest",
            "certificate": "cert-pem",
            "certificateChain": ["chain1", "chain2"],
            "requireRekorBundle": true
        }),
        CallbackRequestType::SigstoreCertificateVerify {
            image: image(),
            certificate: b"cert-pem".to_vec(),
            certificate_chain: Some(byte_vecs(&["chain1", "chain2"])),
            require_rekor_bundle: true,
            annotations: None,
        }
    )]
    #[case::certificate_no_chain_and_no_rekor_bundle(
        parse_certificate_verify,
        json!({"image": "img:latest", "certificate": "cert-pem"}),
        CallbackRequestType::SigstoreCertificateVerify {
            image: image(),
            certificate: b"cert-pem".to_vec(),
            certificate_chain: None,
            require_rekor_bundle: false,
            annotations: None,
        }
    )]
    fn parse_accepts_a_well_formed_builder_map(
        #[case] parse: fn(&Value) -> Result<CallbackRequestType, String>,
        #[case] builder_map: Value,
        #[case] expected: CallbackRequestType,
    ) {
        let result = parse(&builder_map).expect("expected a well-formed builder map to parse");
        assert_eq!(result, expected);
    }

    /// Every parse function must reject a wrong-type argument rather than
    /// drop it, whatever handler it belongs to: dropping it would fall
    /// back to a default that removes whatever restriction the argument
    /// controls. A `null` element inside an accumulated array (`pubKeys`,
    /// `keylessIssuers`, `keylessPrefixUrls`, `certificateChain`) is
    /// reported by index, so a bad element does not silently shift the
    /// pairing of a later one. A `null` scalar argument
    /// (`.githubAction("org", null)`) is rejected rather than treated the
    /// same as never calling the method at all.
    #[rstest]
    #[case::pub_key_null_element(
        parse_pub_key_verify,
        json!({"image": "img:latest", "pubKeys": ["key1", null]}),
        "pubKeys[1]"
    )]
    #[case::pub_key_non_string_annotation(
        parse_pub_key_verify,
        json!({"image": "img:latest", "pubKeys": ["key1"], "annotations": {"count": 5}}),
        "annotations.count"
    )]
    #[case::keyless_null_issuer_by_index(
        parse_keyless_verify,
        json!({
            "image": "img:latest",
            "keylessIssuers": [null, "issuer2"],
            "keylessSubjects": ["subject1", "subject2"]
        }),
        "keylessIssuers[0]"
    )]
    #[case::keyless_prefix_null_url(
        parse_keyless_prefix_verify,
        json!({
            "image": "img:latest",
            "keylessPrefixIssuers": ["issuer1"],
            "keylessPrefixUrls": [null]
        }),
        "keylessPrefixUrls[0]"
    )]
    #[case::github_action_null_repo(
        parse_github_actions_verify,
        json!({"image": "img:latest", "owner": "myorg", "repo": null}),
        "repo"
    )]
    #[case::github_action_non_string_repo(
        parse_github_actions_verify,
        json!({"image": "img:latest", "owner": "myorg", "repo": 1}),
        "repo"
    )]
    #[case::certificate_null_chain_element(
        parse_certificate_verify,
        json!({"image": "img:latest", "certificate": "cert-pem", "certificateChain": [null]}),
        "certificateChain[0]"
    )]
    #[case::certificate_non_boolean_require_rekor_bundle(
        parse_certificate_verify,
        json!({"image": "img:latest", "certificate": "cert-pem", "requireRekorBundle": "true"}),
        "requireRekorBundle"
    )]
    fn parse_rejects_a_wrong_type_argument(
        #[case] parse: fn(&Value) -> Result<CallbackRequestType, String>,
        #[case] builder_map: Value,
        #[case] needle: &str,
    ) {
        let err = parse(&builder_map).expect_err("expected an error");
        assert!(
            err.contains(needle),
            "expected {needle:?} in the error, got: {err:?}"
        );
    }
}
