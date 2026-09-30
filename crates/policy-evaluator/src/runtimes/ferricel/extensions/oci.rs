use std::sync::Arc;

use ferricel_types::extensions::{BuilderChainDecl, BuilderStep, ExtensionDecl};
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType,
    evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::{ExtensionSpec, builder_arg, call_host, str_field},
};

// ─── Host capabilities ────────────────────────────────────────────────────────

const MANIFEST_CAPABILITY: &str = "oci/v1/oci_manifest";
const MANIFEST_DIGEST_CAPABILITY: &str = "oci/v1/manifest_digest";
const MANIFEST_CONFIG_CAPABILITY: &str = "oci/v1/oci_manifest_config";

/// The `kw.oci` extensions, with the capability each one needs.
pub(super) fn specs() -> Vec<ExtensionSpec> {
    vec![
        ExtensionSpec {
            decl: manifest_extension(),
            capabilities: &[MANIFEST_CAPABILITY],
            handler: |ctx, args| manifest_handler(ctx, builder_arg(args, "kw.oci.manifest")?),
        },
        ExtensionSpec {
            decl: manifest_digest_extension(),
            capabilities: &[MANIFEST_DIGEST_CAPABILITY],
            handler: |ctx, args| {
                manifest_digest_handler(ctx, builder_arg(args, "kw.oci.manifestDigest")?)
            },
        },
        ExtensionSpec {
            decl: manifest_config_extension(),
            capabilities: &[MANIFEST_CONFIG_CAPABILITY],
            handler: |ctx, args| {
                manifest_config_handler(ctx, builder_arg(args, "kw.oci.manifestConfig")?)
            },
        },
    ]
}

/// `BuilderChainDecl` for the `kw.oci` library.
///
/// ```text
/// kw.oci.image(<string>)   → kw.oci.Client
///   .manifest()            → dyn  (host call: kw.oci.manifest)
///   .manifestDigest()      → dyn  (host call: kw.oci.manifestDigest)
///   .manifestConfig()      → dyn  (host call: kw.oci.manifestConfig)
/// ```
pub fn chain() -> BuilderChainDecl {
    BuilderChainDecl {
        steps: vec![
            BuilderStep::Entry {
                function: "kw.oci.image".to_string(),
                state_keys: vec!["image".to_string()],
                output_type: "kw.oci.Client".to_string(),
            },
            BuilderStep::Terminal {
                function: "manifest".to_string(),
                input_type: "kw.oci.Client".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.oci".to_string(),
                host_function: "manifest".to_string(),
            },
            BuilderStep::Terminal {
                function: "manifestDigest".to_string(),
                input_type: "kw.oci.Client".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.oci".to_string(),
                host_function: "manifestDigest".to_string(),
            },
            BuilderStep::Terminal {
                function: "manifestConfig".to_string(),
                input_type: "kw.oci.Client".to_string(),
                extra_arg_keys: vec![],
                host_namespace: "kw.oci".to_string(),
                host_function: "manifestConfig".to_string(),
            },
        ],
    }
}

// ─── Runtime extension declarations ──────────────────────────────────────────

pub fn manifest_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.oci".to_string()),
        function: "manifest".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn manifest_digest_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.oci".to_string()),
        function: "manifestDigest".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

pub fn manifest_config_extension() -> ExtensionDecl {
    ExtensionDecl {
        namespace: Some("kw.oci".to_string()),
        function: "manifestConfig".to_string(),
        global_style: false,
        receiver_style: false,
        num_args: 1,
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub(crate) fn manifest_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = str_field(builder_map, "image")?;
    call_host(
        eval_ctx,
        MANIFEST_CAPABILITY,
        CallbackRequestType::OciManifest { image },
    )
}

pub(crate) fn manifest_digest_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = str_field(builder_map, "image")?;
    call_host(
        eval_ctx,
        MANIFEST_DIGEST_CAPABILITY,
        CallbackRequestType::OciManifestDigest { image },
    )
}

pub(crate) fn manifest_config_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let image = str_field(builder_map, "image")?;
    call_host(
        eval_ctx,
        MANIFEST_CONFIG_CAPABILITY,
        CallbackRequestType::OciManifestAndConfig { image },
    )
}
