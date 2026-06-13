mod compiled;
mod interpreted;

use std::{convert::TryFrom, fs::File, path::Path};

use anyhow::{Result, anyhow};
use k8s_openapi::{
    api::admissionregistration::v1::{ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding},
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use policy_evaluator::policy_metadata::Rule;

pub(crate) fn vap(
    cel_policy_module: &str,
    vap_path: &Path,
    binding_path: &Path,
    compile_to_wasm: Option<&Path>,
) -> Result<()> {
    let vap_file = File::open(vap_path)
        .map_err(|e| anyhow!("cannot open {}: {e}", vap_path.to_str().unwrap()))?;
    let binding_file = File::open(binding_path)
        .map_err(|e| anyhow!("cannot open {}: {e}", binding_path.to_str().unwrap()))?;

    let vap: ValidatingAdmissionPolicy = serde_yaml::from_reader(vap_file)
        .map_err(|e| anyhow!("cannot convert given data into a ValidatingAdmissionPolicy: {e}"))?;
    let vap_binding: ValidatingAdmissionPolicyBinding = serde_yaml::from_reader(binding_file)
        .map_err(|e| {
            anyhow!("cannot convert given data into a ValidatingAdmissionPolicyBinding: {e}")
        })?;

    let vap_data = VapData::new(vap, vap_binding)?;

    let cluster_admission_policy = match compile_to_wasm {
        Some(wasm_path) => compiled::vap_compiled(vap_data, wasm_path)?,
        None => interpreted::vap_interpreted(cel_policy_module, vap_data)?,
    };

    serde_yaml::to_writer(std::io::stdout(), &cluster_admission_policy)?;

    Ok(())
}

/// Data extracted from a VAP + binding pair, shared by both output paths.
pub(crate) struct VapData {
    pub(crate) vap: ValidatingAdmissionPolicy,
    pub(crate) metadata: ObjectMeta,
    pub(crate) rules: Vec<Rule>,
    pub(crate) match_policy: Option<String>,
    pub(crate) namespace_selector: Option<LabelSelector>,
    pub(crate) object_selector: Option<LabelSelector>,
    /// paramKind + paramRef settings (when both are present).
    pub(crate) param_settings: serde_yaml::Mapping,
}

impl VapData {
    pub(crate) fn new(
        vap: ValidatingAdmissionPolicy,
        vap_binding: ValidatingAdmissionPolicyBinding,
    ) -> Result<Self> {
        let vap_spec = vap
            .spec
            .as_ref()
            .ok_or_else(|| anyhow!("ValidatingAdmissionPolicy has no spec"))?;
        let vap_binding_spec = vap_binding.spec.unwrap_or_default();

        // Params: both must be present together or both absent.
        let mut param_settings = serde_yaml::Mapping::new();
        match (&vap_spec.param_kind, vap_binding_spec.param_ref) {
            (Some(vap_param_kind), Some(vap_param_ref)) => {
                param_settings.insert("paramKind".into(), serde_yaml::to_value(vap_param_kind)?);
                param_settings.insert("paramRef".into(), serde_yaml::to_value(vap_param_ref)?);
            }
            (None, None) => {}
            _ => {
                return Err(anyhow!(
                    "Both paramKind and paramRef must be present together, or both absent"
                ));
            }
        }

        let namespace_selector = vap_binding_spec
            .match_resources
            .unwrap_or_default()
            .namespace_selector;

        let vap_match_constraints = vap_spec.match_constraints.clone().unwrap_or_default();
        let match_policy = vap_match_constraints.match_policy;
        let object_selector = vap_match_constraints.object_selector;
        let rules = vap_match_constraints
            .resource_rules
            .unwrap_or_default()
            .iter()
            .map(Rule::try_from)
            .collect::<Result<Vec<Rule>, &'static str>>()
            .map_err(|e| anyhow!("error converting VAP matchConstraints into rules: {e}"))?;

        Ok(VapData {
            vap,
            metadata: vap_binding.metadata,
            rules,
            match_policy,
            namespace_selector,
            object_selector,
            param_settings,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::Path;

    pub(crate) const CEL_POLICY_MODULE: &str = "ghcr.io/kubewarden/policies/cel-policy:latest";

    pub(crate) fn test_data(path: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(path)
            .to_string_lossy()
            .to_string()
    }
}
