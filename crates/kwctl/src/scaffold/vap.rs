mod compiled;
mod interpreted;
mod match_resources;

use std::{collections::BTreeSet, fs::File, path::Path};

use anyhow::{Result, anyhow};
use k8s_openapi::{
    api::admissionregistration::v1::{ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding},
    apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta},
};
use match_resources::merge_match_fields;
use policy_evaluator::policy_metadata::{ContextAwareResource, Rule};
use tracing::warn;

pub(crate) fn vap(
    cel_policy_module: &str,
    vap_path: &Path,
    binding_path: &Path,
    compile_to_wasm: Option<&Path>,
    force: bool,
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
        Some(wasm_path) => compiled::vap_compiled(vap_data, wasm_path, force)?,
        None => interpreted::vap_interpreted(cel_policy_module, vap_data)?,
    };

    serde_yaml::to_writer(std::io::stdout(), &cluster_admission_policy)?;

    Ok(())
}

/// Warn that this policy calls `kw.k8s`. This call reads Kubernetes
/// resources at evaluation time. The `granted` set holds the resources
/// allowed in `spec.contextAwareResources` and in `metadata.yml`. This set
/// comes only from `paramKind` and `namespaceObject`. It can miss
/// resources that the policy reads through an explicit `kw.k8s` call in
/// its own CEL.
///
/// The runtime denies a `kw.k8s` call when its apiVersion and kind are not
/// in `granted` (see `EvaluationContext::can_access_kubernetes_resource`).
/// Review the generated `contextAwareResources` list. Add each missing
/// apiVersion and kind by hand before you apply the policy.
pub(crate) fn warn_kw_k8s_requires_grants(granted: &BTreeSet<ContextAwareResource>) {
    if granted.is_empty() {
        warn!(
            "this policy calls kw.k8s.*. spec.contextAwareResources is empty. At evaluation time, the runtime will deny every kw.k8s get and list call. Add each apiVersion/kind that the policy reads through kw.k8s to spec.contextAwareResources in the generated ClusterAdmissionPolicy. If kwctl generated a metadata.yml file, add the same entries to contextAwareResources in that file."
        );
    } else {
        let granted_list = granted
            .iter()
            .map(|r| format!("{}/{}", r.api_version, r.kind))
            .collect::<Vec<_>>()
            .join(", ");
        warn!(
            "this policy calls kw.k8s.*. spec.contextAwareResources grants only {granted_list}, derived from paramKind and namespaceObject. Add every other apiVersion/kind that the policy reads through kw.k8s to spec.contextAwareResources by hand. If kwctl generated a metadata.yml file, add the same entries there. Without this step, the runtime denies the call at evaluation time."
        );
    }
}

/// Build the base `spec.contextAwareResources` allow list for a VAP: the
/// resource named by `paramKind` (from `vap_data.param_resource`), and
/// `v1/Namespace` when `uses_namespace_object` is true. Without these
/// grants, the compiled or interpreted policy is denied access when it
/// fetches the param resource via `paramRef`, or the Namespace via
/// `namespaceObject`, at evaluation time (see
/// `EvaluationContext::can_access_kubernetes_resource`).
///
/// Both output paths call this function with the same shape of input.
/// Only how `uses_namespace_object` is computed differs (see the field
/// docs on [`VapData::uses_namespace_object`]). A `warn!` call announces
/// every grant added, so the administrator can review it before they
/// apply the generated policy.
pub(crate) fn base_context_aware_resources(
    vap_data: &VapData,
    uses_namespace_object: bool,
) -> BTreeSet<ContextAwareResource> {
    let mut context_aware_resources = BTreeSet::new();

    if let Some(param_resource) = &vap_data.param_resource {
        warn!(
            "granting access to {}/{} via spec.contextAwareResources. paramKind requires this grant. Review it before you apply the policy",
            param_resource.api_version, param_resource.kind
        );
        context_aware_resources.insert(param_resource.clone());
    }

    if uses_namespace_object {
        warn!(
            "granting access to v1/Namespace via spec.contextAwareResources. namespaceObject requires this grant. Review it before you apply the policy"
        );
        context_aware_resources.insert(ContextAwareResource {
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
        });
    }

    context_aware_resources
}

/// Check whether any CEL expression in `vap` mentions `kw.k8s`.
///
/// The interpreted path uses this check because it has no compiled Wasm
/// module to inspect. The compiled path instead reads the exact list of
/// host extensions from the `ferricel.extensions` section of the module.
///
/// A text search can find `kw.k8s` inside a string literal and report a
/// false positive. It cannot miss a real use in valid CEL. So this check
/// never produces a false negative. A false positive only causes an
/// extra warning. It does not hide a real one.
fn vap_uses_kw_k8s(vap: &ValidatingAdmissionPolicy) -> bool {
    cel_expressions(vap).any(|expr| expr.contains("kw.k8s"))
}

/// Check whether any CEL expression in `vap` mentions `namespaceObject`.
///
/// Since ferricel 0.11, a compiled VAP that reads `namespaceObject`
/// resolves it on its own, through a `kw.k8s.get` call. The runtime gates
/// this call the same way it gates every other Kubernetes read: the
/// policy needs the `kubernetes/get_resource` host capability and a
/// `v1/Namespace` grant in `spec.contextAwareResources`.
/// `ferricel_core::vap_variables_used` gives the compiled path an exact
/// answer (see `compiled::vap_compiled`). The interpreted path has no
/// compiled module to inspect. So it falls back to the same text search
/// used for `kw.k8s` (see `vap_uses_kw_k8s`), with the same
/// false-positive-only guarantee.
fn vap_uses_namespace_object(vap: &ValidatingAdmissionPolicy) -> bool {
    cel_expressions(vap).any(|expr| expr.contains("namespaceObject"))
}

/// Every CEL expression in `vap`: the `validations`, `variables`, and
/// `matchConditions` expressions, in that order. Empty when `vap` has no
/// spec.
fn cel_expressions(vap: &ValidatingAdmissionPolicy) -> impl Iterator<Item = &str> {
    let spec = vap.spec.as_ref();
    let validations = spec
        .and_then(|s| s.validations.as_deref())
        .unwrap_or_default();
    let variables = spec
        .and_then(|s| s.variables.as_deref())
        .unwrap_or_default();
    let match_conditions = spec
        .and_then(|s| s.match_conditions.as_deref())
        .unwrap_or_default();

    validations
        .iter()
        .map(|v| v.expression.as_str())
        .chain(variables.iter().map(|v| v.expression.as_str()))
        .chain(match_conditions.iter().map(|m| m.expression.as_str()))
}

/// Data extracted from a VAP + binding pair, shared by both output paths.
pub(crate) struct VapData {
    pub(crate) vap: ValidatingAdmissionPolicy,
    pub(crate) metadata: ObjectMeta,
    pub(crate) rules: Vec<Rule>,
    pub(crate) match_policy: Option<String>,
    pub(crate) namespace_selector: Option<LabelSelector>,
    pub(crate) object_selector: Option<LabelSelector>,
    /// The settings that both output paths share: `paramKind` and
    /// `paramRef` (when both are present) and `failurePolicy` (when the
    /// VAP sets it). Each runtime reads these at evaluation time. The
    /// interpreted path adds the CEL expressions on top of them.
    pub(crate) settings: serde_yaml::Mapping,
    /// The Kubernetes resource (apiVersion/kind) named by `paramKind`, when
    /// present. This is the resource the compiled/interpreted policy fetches
    /// at evaluation time via `paramRef`, and must be granted access to via
    /// `spec.contextAwareResources` for the fetch to succeed.
    pub(crate) param_resource: Option<ContextAwareResource>,
    /// Whether any CEL expression in `vap` mentions `namespaceObject` (see
    /// `vap_uses_namespace_object`). The interpreted path reads this
    /// directly; the compiled path prefers the exact answer from
    /// `ferricel_core::vap_variables_used` on the compiled module, and only
    /// falls back to this text-search result when that section can't be
    /// read.
    pub(crate) uses_namespace_object: bool,
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

        // The binding only references its policy by name; make sure it
        // actually points at the VAP we were given. Without this check a
        // mismatched pair is silently combined, compiling one policy while
        // applying another policy's binding metadata (name, selectors,
        // paramRef, ...).
        let vap_name = vap
            .metadata
            .name
            .as_deref()
            .ok_or_else(|| anyhow!("ValidatingAdmissionPolicy has no metadata.name"))?;
        let policy_name = vap_binding_spec
            .policy_name
            .as_deref()
            .ok_or_else(|| anyhow!("ValidatingAdmissionPolicyBinding has no spec.policyName"))?;
        if policy_name != vap_name {
            return Err(anyhow!(
                "ValidatingAdmissionPolicyBinding spec.policyName '{policy_name}' does not match ValidatingAdmissionPolicy metadata.name '{vap_name}'"
            ));
        }

        let mut settings = serde_yaml::Mapping::new();

        // `failurePolicy` decides what the runtime does when a CEL
        // expression cannot be evaluated. It goes to the settings, not to
        // `spec.failurePolicy` of the ClusterAdmissionPolicy: that field
        // controls the webhook configuration, and the API server applies it
        // only when the call to the policy server fails. With the value in
        // the settings, the administrator can change it without a new build
        // of the policy.
        if let Some(failure_policy) = &vap_spec.failure_policy {
            settings.insert(
                "failurePolicy".into(),
                serde_yaml::to_value(failure_policy)?,
            );
        }

        // Params: both must be present together or both absent.
        let mut param_resource = None;
        match (&vap_spec.param_kind, vap_binding_spec.param_ref) {
            (Some(vap_param_kind), Some(mut vap_param_ref)) => {
                // The Kubernetes API marks `parameterNotFoundAction` as
                // required, but a hand-written binding may omit it. Default
                // to `Deny` (fail-closed) rather than silently forwarding an
                // incomplete paramRef, which the ferricel/cel-policy runtime
                // would reject at settings-validation time.
                if vap_param_ref.parameter_not_found_action.is_none() {
                    warn!(
                        "paramRef.parameterNotFoundAction not set in the binding; defaulting to Deny"
                    );
                    vap_param_ref.parameter_not_found_action = Some("Deny".to_string());
                }

                settings.insert("paramKind".into(), serde_yaml::to_value(vap_param_kind)?);
                settings.insert("paramRef".into(), serde_yaml::to_value(&vap_param_ref)?);

                if let (Some(api_version), Some(kind)) =
                    (&vap_param_kind.api_version, &vap_param_kind.kind)
                {
                    param_resource = Some(ContextAwareResource {
                        api_version: api_version.clone(),
                        kind: kind.clone(),
                    });
                }
            }
            (None, None) => {}
            _ => {
                return Err(anyhow!(
                    "Both paramKind and paramRef must be present together, or both absent"
                ));
            }
        }

        // Kubernetes runs the policy on a request only when the request
        // matches two match sets at the same time: `matchConstraints`
        // (set on the VAP) and `matchResources` (set on the binding). See
        // `match_resources::merge_match_fields` for how kwctl merges or
        // rejects each field of that match.
        let match_fields = merge_match_fields(
            vap_spec.match_constraints.clone().unwrap_or_default(),
            vap_binding_spec.match_resources.unwrap_or_default(),
        )?;

        let uses_namespace_object = vap_uses_namespace_object(&vap);

        Ok(VapData {
            vap,
            metadata: vap_binding.metadata,
            rules: match_fields.rules,
            match_policy: match_fields.match_policy,
            namespace_selector: match_fields.namespace_selector,
            object_selector: match_fields.object_selector,
            settings,
            param_resource,
            uses_namespace_object,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{collections::BTreeMap, fs::File, path::Path};

    use k8s_openapi::{
        api::admissionregistration::v1::{
            MatchResources, ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding,
        },
        apimachinery::pkg::apis::meta::v1::LabelSelector,
    };
    use rstest::*;

    use super::VapData;

    pub(crate) const CEL_POLICY_MODULE: &str = "ghcr.io/kubewarden/policies/cel-policy:latest";

    pub(crate) fn test_data(path: &str) -> String {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join(path)
            .to_string_lossy()
            .to_string()
    }

    fn open_vap_data(vap_yaml_path: &str, vap_binding_yaml_path: &str) -> VapData {
        let (vap, vap_binding) = open_raw(vap_yaml_path, vap_binding_yaml_path);
        VapData::new(vap, vap_binding).expect("cannot build VapData")
    }

    fn open_raw(
        vap_yaml_path: &str,
        vap_binding_yaml_path: &str,
    ) -> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
        let yaml_file = File::open(test_data(vap_yaml_path)).expect("cannot open VAP yaml file");
        let vap: ValidatingAdmissionPolicy =
            serde_yaml::from_reader(yaml_file).expect("cannot parse VAP yaml file");

        let yaml_file = File::open(test_data(vap_binding_yaml_path))
            .expect("cannot open VAP binding yaml file");
        let vap_binding: ValidatingAdmissionPolicyBinding =
            serde_yaml::from_reader(yaml_file).expect("cannot parse VAP binding yaml file");

        (vap, vap_binding)
    }

    fn open_vap(vap_yaml_path: &str) -> ValidatingAdmissionPolicy {
        let yaml_file = File::open(test_data(vap_yaml_path)).expect("cannot open VAP yaml file");
        serde_yaml::from_reader(yaml_file).expect("cannot parse VAP yaml file")
    }

    /// Build a VAP and binding pair. The match-field tests start from
    /// this pair and change it.
    #[fixture]
    fn vap_pair() -> (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding) {
        open_raw("vap/vap-without-variables.yml", "vap/vap-binding.yml")
    }

    /// Return a mutable reference to `vap.spec.matchConstraints`. When
    /// the field is absent, insert a default value first.
    fn vap_match_constraints(vap: &mut ValidatingAdmissionPolicy) -> &mut MatchResources {
        vap.spec
            .as_mut()
            .expect("vap has a spec")
            .match_constraints
            .get_or_insert_with(Default::default)
    }

    /// Return a mutable reference to `binding.spec.matchResources`. When
    /// the field is absent, insert a default value first.
    fn binding_match_resources(
        binding: &mut ValidatingAdmissionPolicyBinding,
    ) -> &mut MatchResources {
        binding
            .spec
            .as_mut()
            .expect("binding has a spec")
            .match_resources
            .get_or_insert_with(Default::default)
    }

    #[test]
    fn vap_uses_kw_k8s_detects_it_in_validations() {
        let vap = open_vap("vap/vap-with-k8s.yml");
        assert!(super::vap_uses_kw_k8s(&vap));
    }

    #[rstest]
    #[case::without_variables("vap/vap-without-variables.yml")]
    #[case::with_variables("vap/vap-with-variables.yml")]
    #[case::with_host_capabilities("vap/vap-with-host-capabilities.yml")]
    fn vap_uses_kw_k8s_is_false_when_not_used(#[case] vap_yaml_path: &str) {
        let vap = open_vap(vap_yaml_path);
        assert!(!super::vap_uses_kw_k8s(&vap));
    }

    #[test]
    fn vap_uses_namespace_object_detects_it_in_validations() {
        let vap = open_vap("vap/vap-with-namespace-object.yml");
        assert!(super::vap_uses_namespace_object(&vap));
    }

    #[rstest]
    #[case::without_variables("vap/vap-without-variables.yml")]
    #[case::with_variables("vap/vap-with-variables.yml")]
    #[case::with_k8s("vap/vap-with-k8s.yml")]
    fn vap_uses_namespace_object_is_false_when_not_used(#[case] vap_yaml_path: &str) {
        let vap = open_vap(vap_yaml_path);
        assert!(!super::vap_uses_namespace_object(&vap));
    }

    #[test]
    fn param_ref_parameter_not_found_action_defaults_to_deny_when_absent() {
        let vap_data = open_vap_data(
            "vap/vap-with-params.yml",
            "vap/vap-binding-params-no-action.yml",
        );

        assert_eq!(
            "Deny",
            vap_data.settings["paramRef"]["parameterNotFoundAction"]
                .as_str()
                .expect("parameterNotFoundAction should be a string")
        );
    }

    #[test]
    fn param_ref_parameter_not_found_action_is_preserved_when_present() {
        // The fixture explicitly sets parameterNotFoundAction to Deny; this
        // pins that an explicit value is forwarded as-is (not overwritten).
        let vap_data = open_vap_data("vap/vap-with-params.yml", "vap/vap-binding-params.yml");

        assert_eq!(
            "Deny",
            vap_data.settings["paramRef"]["parameterNotFoundAction"]
                .as_str()
                .expect("parameterNotFoundAction should be a string")
        );
    }

    // `failurePolicy` goes to the settings, not to `spec.failurePolicy` of
    // the ClusterAdmissionPolicy. That field controls the webhook, and the
    // API server applies it only when the call to the policy server fails.
    // The runtime reads `settings.failurePolicy` to decide what a CEL
    // runtime error does.
    #[rstest]
    #[case::fail("vap/vap-without-variables.yml", "Fail")]
    #[case::ignore("vap/vap-with-failure-policy-ignore.yml", "Ignore")]
    fn failure_policy_is_copied_to_settings(#[case] vap_yaml_path: &str, #[case] expected: &str) {
        let vap_data = open_vap_data(vap_yaml_path, "vap/vap-binding.yml");

        assert_eq!(
            Some(expected),
            vap_data.settings["failurePolicy"].as_str(),
            "settings.failurePolicy must match the VAP spec.failurePolicy"
        );
    }

    #[rstest]
    fn failure_policy_is_absent_from_settings_when_the_vap_does_not_set_it(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (mut vap, vap_binding) = vap_pair;
        vap.spec.as_mut().expect("vap has a spec").failure_policy = None;

        let vap_data = VapData::new(vap, vap_binding).expect("VapData::new should succeed");

        // The runtime treats a missing key as `Fail`. The scaffold must leave
        // the choice to the runtime, not write a default of its own.
        assert!(
            !vap_data.settings.contains_key("failurePolicy"),
            "settings must not contain failurePolicy, got: {:?}",
            vap_data.settings
        );
    }

    #[rstest]
    fn new_rejects_binding_whose_policy_name_does_not_match_the_vap(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (vap, mut vap_binding) = vap_pair;
        vap_binding
            .spec
            .as_mut()
            .expect("binding has a spec")
            .policy_name = Some("some-other-policy".to_string());

        let err = match VapData::new(vap, vap_binding) {
            Ok(_) => panic!("mismatched policyName/metadata.name should be rejected"),
            Err(e) => e,
        };

        let message = err.to_string();
        assert!(message.contains("some-other-policy"), "{message}");
        assert!(message.contains("vap-test"), "{message}");
    }

    #[rstest]
    fn new_rejects_vap_with_no_metadata_name(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (mut vap, vap_binding) = vap_pair;
        vap.metadata.name = None;

        let err = match VapData::new(vap, vap_binding) {
            Ok(_) => panic!("VAP with no metadata.name is rejected"),
            Err(e) => e,
        };

        assert!(err.to_string().contains("metadata.name"));
    }

    fn label_selector(labels: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            ),
            match_expressions: None,
        }
    }

    // The detailed match-field merge and rejection rules (namespaceSelector,
    // objectSelector, excludeResourceRules, resourceRules, matchPolicy) live
    // in `match_resources` and are tested there. These two tests only make
    // sure that `VapData::new` calls `match_resources::merge_match_fields`
    // and forwards its result.

    #[rstest]
    fn new_merges_namespace_selector_from_vap_and_binding(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (mut vap, vap_binding) = vap_pair;
        vap_match_constraints(&mut vap).namespace_selector =
            Some(label_selector(&[("team", "platform")]));
        // The fixture binding already sets `namespaceSelector` to
        // kubernetes.io/metadata.name=default.

        let vap_data = VapData::new(vap, vap_binding).expect("VapData::new should succeed");

        let namespace_selector = vap_data
            .namespace_selector
            .expect("namespace_selector should be present");
        assert_eq!(
            namespace_selector.match_labels,
            Some(BTreeMap::from([
                (
                    "kubernetes.io/metadata.name".to_string(),
                    "default".to_string()
                ),
                ("team".to_string(), "platform".to_string()),
            ]))
        );
    }

    #[rstest]
    fn new_rejects_a_vap_and_binding_that_both_set_object_selector(
        vap_pair: (ValidatingAdmissionPolicy, ValidatingAdmissionPolicyBinding),
    ) {
        let (mut vap, mut vap_binding) = vap_pair;
        vap_match_constraints(&mut vap).object_selector =
            Some(label_selector(&[("protected", "yes")]));
        binding_match_resources(&mut vap_binding).object_selector =
            Some(label_selector(&[("team", "security")]));

        let err = match VapData::new(vap, vap_binding) {
            Ok(_) => panic!("a VAP and binding that both set objectSelector should be rejected"),
            Err(e) => e,
        };

        assert!(err.to_string().contains("objectSelector"), "{err}");
    }
}
