use std::{collections::BTreeSet, fs, path::Path};

use anyhow::{Result, anyhow};
use ferricel_core::compiler::Builder as CompilerBuilder;
use policy_evaluator::{
    ferricel_compiler_builder_chains, ferricel_compiler_extension_decls,
    ferricel_host_capabilities,
    policy_evaluator::PolicyExecutionMode,
    policy_metadata::{ContextAwareResource, Metadata, PolicyType},
};

use crate::scaffold::{
    kubewarden_crds::{ClusterAdmissionPolicy, ClusterAdmissionPolicySpec},
    vap::VapData,
};

/// Compiled path: compiles the VAP CEL expressions to Wasm, writes the module
/// to `wasm_path`, generates a `metadata.yml` alongside it, and builds a
/// [`ClusterAdmissionPolicy`] with only paramKind + paramRef in settings.
pub(crate) fn vap_compiled(vap_data: VapData, wasm_path: &Path) -> Result<ClusterAdmissionPolicy> {
    // Register all Kubewarden host-capability builder chains and extension
    // declarations so the compiler accepts CEL expressions that call kw.oci,
    // kw.net, kw.crypto, etc. in addition to kw.k8s (auto-registered by ferricel-core).
    let mut builder = CompilerBuilder::new();
    for chain in ferricel_compiler_builder_chains() {
        builder = builder.with_builder_chain(chain);
    }
    for decl in ferricel_compiler_extension_decls() {
        builder = builder.with_extension(decl);
    }
    let wasm_bytes = builder
        .build()
        .compile_vap_from_policy(&vap_data.vap)
        .map_err(|e| anyhow!("failed to compile VAP to Wasm: {e}"))?;

    fs::write(wasm_path, &wasm_bytes)
        .map_err(|e| anyhow!("cannot write Wasm module to {}: {e}", wasm_path.display()))?;

    // Canonicalize only after the file has been written, otherwise a relative
    // (and, until now, non-existing) output path would fall back to the
    // relative path, producing a `file://` URI that isn't absolute.
    let wasm_path_abs = wasm_path
        .canonicalize()
        .map_err(|e| anyhow!("cannot canonicalize {}: {e}", wasm_path.display()))?;

    // Derive host capabilities from the extensions section embedded in the
    // compiled wasm so metadata.yml accurately reflects what the policy uses.
    let used = ferricel_core::extensions_used(&wasm_bytes)
        .map_err(|e| anyhow!("failed to read host extensions from compiled module: {e}"))?;
    let caps = ferricel_host_capabilities(&used);
    let host_capabilities = if caps.is_empty() { None } else { Some(caps) };

    write_metadata_file(&vap_data, &wasm_path_abs, host_capabilities)?;

    let module = format!("file://{}", wasm_path_abs.display());

    Ok(ClusterAdmissionPolicy {
        api_version: "policies.kubewarden.io/v1".to_string(),
        kind: "ClusterAdmissionPolicy".to_string(),
        metadata: vap_data.metadata,
        spec: ClusterAdmissionPolicySpec {
            module,
            namespace_selector: vap_data.namespace_selector,
            match_policy: vap_data.match_policy,
            rules: vap_data.rules,
            object_selector: vap_data.object_selector,
            mutating: false,
            background_audit: true,
            context_aware_resources: BTreeSet::new(),
            failure_policy: None,
            mode: None,
            settings: vap_data.param_settings,
        },
    })
}

/// Write a `metadata.yml` file in the same directory as `wasm_path_abs`.
/// Returns an error if the file already exists.
fn write_metadata_file(
    vap_data: &VapData,
    wasm_path_abs: &Path,
    host_capabilities: Option<BTreeSet<String>>,
) -> Result<()> {
    let metadata_path = wasm_path_abs
        .parent()
        .ok_or_else(|| {
            anyhow!(
                "cannot determine parent directory of {}",
                wasm_path_abs.display()
            )
        })?
        .join("metadata.yml");

    if metadata_path.exists() {
        return Err(anyhow!(
            "metadata.yml already exists at {}",
            metadata_path.display()
        ));
    }

    let mut annotations = std::collections::BTreeMap::new();
    if let Some(name) = vap_data.metadata.name.as_deref() {
        annotations.insert("io.kubewarden.policy.title".to_string(), name.to_string());
    }

    // Safety: VapData::new() already validated that spec is present.
    let vap_spec = vap_data.vap.spec.as_ref().unwrap();

    let mut context_aware_resources = BTreeSet::new();
    if let Some(param_kind) = &vap_spec.param_kind
        && let (Some(api_version), Some(kind)) = (&param_kind.api_version, &param_kind.kind)
    {
        context_aware_resources.insert(ContextAwareResource {
            api_version: api_version.clone(),
            kind: kind.clone(),
        });
    }

    let policy_metadata = Metadata {
        protocol_version: None,
        rules: vap_data.rules.clone(),
        annotations: if annotations.is_empty() {
            None
        } else {
            Some(annotations)
        },
        mutating: false,
        background_audit: true,
        execution_mode: PolicyExecutionMode::Ferricel,
        policy_type: PolicyType::Kubernetes,
        context_aware_resources,
        host_capabilities,
        minimum_kubewarden_version: None,
    };

    let metadata_yaml = serde_yaml::to_string(&policy_metadata)
        .map_err(|e| anyhow!("cannot serialize metadata to YAML: {e}"))?;
    fs::write(&metadata_path, metadata_yaml).map_err(|e| {
        anyhow!(
            "cannot write metadata.yml to {}: {e}",
            metadata_path.display()
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{convert::TryFrom, fs::File};

    use k8s_openapi::api::admissionregistration::v1::{
        ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
    };
    use policy_evaluator::policy_metadata::Rule;
    use rstest::*;
    use tempfile::TempDir;

    use super::*;
    use crate::scaffold::vap::tests::test_data;

    fn open_vap_data(vap_yaml_path: &str, vap_binding_yaml_path: &str) -> VapData {
        let yaml_file = File::open(test_data(vap_yaml_path)).unwrap();
        let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(yaml_file).unwrap();

        let yaml_file = File::open(test_data(vap_binding_yaml_path)).unwrap();
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).unwrap();

        VapData::new(vap, vap_binding).unwrap()
    }

    #[rstest]
    #[case::vap_without_variables("vap/vap-without-variables.yml", "vap/vap-binding.yml", false)]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml", false)]
    #[case::vap_with_params("vap/vap-with-params.yml", "vap/vap-binding-params.yml", true)]
    fn compile_vap_to_wasm(
        #[case] vap_yaml_path: &str,
        #[case] vap_binding_yaml_path: &str,
        #[case] has_params: bool,
    ) {
        let yaml_file = File::open(test_data(vap_yaml_path)).unwrap();
        let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(yaml_file).unwrap();

        let yaml_file = File::open(test_data(vap_binding_yaml_path)).unwrap();
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).unwrap();

        let expected_rules = vap
            .clone()
            .spec
            .unwrap()
            .match_constraints
            .unwrap()
            .resource_rules
            .unwrap()
            .iter()
            .map(Rule::try_from)
            .collect::<Result<Vec<Rule>, &str>>()
            .unwrap();

        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");
        let expected_module = format!("file://{}", wasm_path.display());

        let vap_data = VapData::new(vap, vap_binding).unwrap();
        let cap = vap_compiled(vap_data, &wasm_path).unwrap();

        assert_eq!(expected_module, cap.spec.module);
        assert!(!cap.spec.mutating);
        assert!(cap.spec.background_audit);
        assert!(cap.spec.context_aware_resources.is_empty());
        assert!(cap.spec.failure_policy.is_none());
        assert!(cap.spec.mode.is_none());

        // validations, variables, failurePolicy must NOT be in settings
        assert!(!cap.spec.settings.contains_key("validations"));
        assert!(!cap.spec.settings.contains_key("variables"));
        assert!(!cap.spec.settings.contains_key("failurePolicy"));

        if has_params {
            assert!(cap.spec.settings.contains_key("paramKind"));
            assert!(cap.spec.settings.contains_key("paramRef"));
        } else {
            assert!(!cap.spec.settings.contains_key("paramKind"));
            assert!(!cap.spec.settings.contains_key("paramRef"));
        }

        assert_eq!(cap.spec.rules, expected_rules);
    }

    #[rstest]
    #[case::vap_without_variables("vap/vap-without-variables.yml", "vap/vap-binding.yml")]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml")]
    fn metadata_yml_is_generated(#[case] vap_yaml_path: &str, #[case] vap_binding_yaml_path: &str) {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data(vap_yaml_path, vap_binding_yaml_path);
        vap_compiled(vap_data, &wasm_path).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        assert!(metadata_path.exists(), "metadata.yml should be created");

        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();
        assert_eq!(metadata.execution_mode, PolicyExecutionMode::Ferricel);
        assert!(!metadata.mutating);
        assert!(metadata.background_audit);
        assert!(metadata.context_aware_resources.is_empty());
        assert!(metadata.protocol_version.is_none());
        assert!(!metadata.rules.is_empty());
    }

    #[test]
    fn metadata_yml_contains_context_aware_resources_for_params() {
        use policy_evaluator::policy_metadata::ContextAwareResource;

        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data("vap/vap-with-params.yml", "vap/vap-binding-params.yml");
        vap_compiled(vap_data, &wasm_path).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();

        assert!(
            metadata
                .context_aware_resources
                .contains(&ContextAwareResource {
                    api_version: "v1".to_string(),
                    kind: "ConfigMap".to_string(),
                }),
            "context_aware_resources should contain the param resource (v1/ConfigMap), got: {:?}",
            metadata.context_aware_resources
        );
    }

    #[test]
    fn metadata_yml_already_exists_returns_error() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        // pre-create metadata.yml to trigger the conflict
        let metadata_path = dir.path().join("metadata.yml");
        fs::write(&metadata_path, b"existing content").unwrap();

        let vap_data = open_vap_data("vap/vap-without-variables.yml", "vap/vap-binding.yml");
        let result = vap_compiled(vap_data, &wasm_path);

        match result {
            Ok(_) => panic!("expected an error but got Ok"),
            Err(e) => assert!(
                e.to_string().contains("metadata.yml already exists"),
                "unexpected error: {e}"
            ),
        }
    }

    /// VAPs that use no host-capability extensions (kw.oci / kw.net / etc.)
    /// must produce metadata.yml with `hostCapabilities: null` (field absent).
    #[rstest]
    #[case::vap_without_variables("vap/vap-without-variables.yml", "vap/vap-binding.yml")]
    #[case::vap_with_variables("vap/vap-with-variables.yml", "vap/vap-binding.yml")]
    fn metadata_yml_has_no_host_capabilities_when_none_used(
        #[case] vap_yaml_path: &str,
        #[case] vap_binding_yaml_path: &str,
    ) {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data(vap_yaml_path, vap_binding_yaml_path);
        vap_compiled(vap_data, &wasm_path).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();
        assert!(
            metadata.host_capabilities.is_none(),
            "expected no host_capabilities for a plain VAP, got: {:?}",
            metadata.host_capabilities
        );
    }

    /// A VAP that uses `kw.net.lookupHost` and `kw.oci.image(...).manifestDigest()`
    /// must produce metadata.yml with those capabilities populated.
    #[test]
    fn metadata_yml_contains_host_capabilities_when_used() {
        let dir = TempDir::new().unwrap();
        let wasm_path = dir.path().join("policy.wasm");

        let vap_data = open_vap_data("vap/vap-with-host-capabilities.yml", "vap/vap-binding.yml");
        vap_compiled(vap_data, &wasm_path).unwrap();

        let metadata_path = dir.path().join("metadata.yml");
        let metadata: Metadata =
            serde_yaml::from_str(&fs::read_to_string(&metadata_path).unwrap()).unwrap();

        let caps = metadata
            .host_capabilities
            .as_ref()
            .expect("host_capabilities should be Some for a policy using kw.net and kw.oci");

        assert!(
            caps.contains("net/v1/dns_lookup_host"),
            "expected net/v1/dns_lookup_host in host_capabilities, got: {caps:?}"
        );
        assert!(
            caps.contains("oci/v1/manifest_digest"),
            "expected oci/v1/manifest_digest in host_capabilities, got: {caps:?}"
        );
    }
}
