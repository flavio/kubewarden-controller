//! Merge the VAP `matchConstraints` with the binding `matchResources` into
//! the match fields a `ClusterAdmissionPolicy` can hold, or reject the
//! pair when kwctl cannot represent it.
//!
//! Kubernetes runs the policy on a request only when the request matches
//! two match sets at the same time: `matchConstraints` (set on the VAP)
//! and `matchResources` (set on the binding). [`merge_match_fields`] must
//! merge or reject every field that can narrow that match. If it does
//! not, the generated `ClusterAdmissionPolicy` can run against resources
//! that the original VAP and binding pair excluded.

use anyhow::{Result, anyhow};
use k8s_openapi::{
    api::admissionregistration::v1::MatchResources,
    apimachinery::pkg::apis::meta::v1::LabelSelector,
};
use policy_evaluator::policy_metadata::Rule;

/// The match fields of a merged VAP and binding pair, in the shape a
/// `ClusterAdmissionPolicy` can hold.
pub(crate) struct MatchFields {
    pub(crate) rules: Vec<Rule>,
    pub(crate) match_policy: Option<String>,
    pub(crate) namespace_selector: Option<LabelSelector>,
    pub(crate) object_selector: Option<LabelSelector>,
}

/// Merge `vap_match_constraints` (from `spec.matchConstraints` on the
/// VAP) with `binding_match_resources` (from `spec.matchResources` on the
/// binding) into the match fields of a `ClusterAdmissionPolicy`.
///
/// This function rejects every field it cannot represent:
/// `excludeResourceRules` on either side, `resourceRules` on the binding,
/// `resourceNames` on a VAP `resourceRules` entry, and a binding
/// `matchPolicy` that differs from the VAP one. It merges
/// `namespaceSelector` with AND logic (see [`and_label_selectors`]) and
/// rejects a VAP and binding pair that both set `objectSelector` (see
/// [`combine_object_selectors`]).
pub(crate) fn merge_match_fields(
    vap_match_constraints: MatchResources,
    binding_match_resources: MatchResources,
) -> Result<MatchFields> {
    if vap_match_constraints
        .exclude_resource_rules
        .as_ref()
        .is_some_and(|rules| !rules.is_empty())
    {
        return Err(anyhow!(
            "ValidatingAdmissionPolicy spec.matchConstraints.excludeResourceRules is not supported. ClusterAdmissionPolicy has no matching field. Remove excludeResourceRules, and narrow spec.matchConstraints.resourceRules instead"
        ));
    }
    if binding_match_resources
        .exclude_resource_rules
        .as_ref()
        .is_some_and(|rules| !rules.is_empty())
    {
        return Err(anyhow!(
            "ValidatingAdmissionPolicyBinding spec.matchResources.excludeResourceRules is not supported. ClusterAdmissionPolicy has no matching field. Remove excludeResourceRules, and narrow spec.matchConstraints.resourceRules on the ValidatingAdmissionPolicy instead"
        ));
    }
    if binding_match_resources
        .resource_rules
        .as_ref()
        .is_some_and(|rules| !rules.is_empty())
    {
        return Err(anyhow!(
            "ValidatingAdmissionPolicyBinding spec.matchResources.resourceRules is not supported. kwctl only translates spec.matchConstraints.resourceRules from the ValidatingAdmissionPolicy. Move the narrowing into the ValidatingAdmissionPolicy, or remove it from the binding"
        ));
    }
    if vap_match_constraints
        .resource_rules
        .as_ref()
        .is_some_and(|rules| {
            rules
                .iter()
                .any(|rule| rule.resource_names.as_ref().is_some_and(|n| !n.is_empty()))
        })
    {
        return Err(anyhow!(
            "ValidatingAdmissionPolicy spec.matchConstraints.resourceRules[].resourceNames is not supported. ClusterAdmissionPolicy has no matching field. Remove resourceNames, and narrow the match with objectSelector instead"
        ));
    }
    if let Some(binding_match_policy) = binding_match_resources.match_policy.as_deref() {
        // This field defaults to "Equivalent" on both the VAP and the
        // binding. Kubernetes uses this default when a user leaves the
        // field unset.
        let vap_match_policy = vap_match_constraints
            .match_policy
            .as_deref()
            .unwrap_or("Equivalent");
        if binding_match_policy != vap_match_policy {
            return Err(anyhow!(
                "ValidatingAdmissionPolicyBinding spec.matchResources.matchPolicy is '{binding_match_policy}'. ValidatingAdmissionPolicy spec.matchConstraints.matchPolicy is '{vap_match_policy}'. The two values differ. Make the two values equal, or remove matchPolicy from the binding"
            ));
        }
    }

    let namespace_selector = and_label_selectors(
        "namespaceSelector",
        vap_match_constraints.namespace_selector.clone(),
        binding_match_resources.namespace_selector,
    )?;
    let object_selector = combine_object_selectors(
        vap_match_constraints.object_selector.clone(),
        binding_match_resources.object_selector,
    )?;
    let match_policy = vap_match_constraints.match_policy.clone();
    let rules = vap_match_constraints
        .resource_rules
        .unwrap_or_default()
        .iter()
        .map(Rule::try_from)
        .collect::<Result<Vec<Rule>, &'static str>>()
        .map_err(|e| anyhow!("error converting VAP matchConstraints into rules: {e}"))?;

    Ok(MatchFields {
        rules,
        match_policy,
        namespace_selector,
        object_selector,
    })
}

/// Combine a VAP selector and a binding selector into one selector with
/// AND logic.
///
/// Kubernetes runs the policy on an object only when the object matches
/// two selectors at the same time: the VAP `matchConstraints` selector
/// and the binding `matchResources` selector. A missing selector matches
/// every object. An absent side adds no condition.
///
/// A `LabelSelector` already combines `matchLabels` and `matchExpressions`
/// with AND logic. This function merges two selectors into one selector
/// that keeps that same AND logic. kwctl copies `matchExpressions` from
/// both selectors into the result, side by side. kwctl also merges
/// `matchLabels` from both selectors.
///
/// When a key has the same value on both sides, kwctl keeps one copy of
/// the key.
///
/// When a key has a different value on each side, the merged selector
/// can match no object: an object cannot have two different values for
/// the same label at the same time. kwctl returns an error instead of
/// building that selector. `field` names the selector in the error
/// message, for example `"namespaceSelector"`.
///
/// This AND merge gives the correct result only when both selectors read
/// the same set of labels on the same object at match time. That is true
/// for `namespaceSelector`: both sides read the labels of the one
/// Namespace object the request targets. It is not true for
/// `objectSelector`. On an UPDATE request, Kubernetes evaluates each
/// object selector on its own, against the old object or the new object
/// (`match(old) || match(new)`). ANDing the two merged predicates does
/// not give the same result as ANDing the two original ones. Do not use
/// this function for `objectSelector`. See [`combine_object_selectors`].
fn and_label_selectors(
    field: &str,
    a: Option<LabelSelector>,
    b: Option<LabelSelector>,
) -> Result<Option<LabelSelector>> {
    let (a, b) = match (a, b) {
        (None, None) => return Ok(None),
        (Some(a), None) => return Ok(Some(a)),
        (None, Some(b)) => return Ok(Some(b)),
        (Some(a), Some(b)) => (a, b),
    };

    let mut match_expressions = a.match_expressions.unwrap_or_default();
    match_expressions.extend(b.match_expressions.unwrap_or_default());

    let mut match_labels = a.match_labels.unwrap_or_default();
    for (key, b_value) in b.match_labels.unwrap_or_default() {
        match match_labels.get(&key) {
            Some(a_value) if a_value == &b_value => {
                // The two sides use the same value for this key. Keep
                // one copy.
            }
            Some(a_value) => {
                return Err(anyhow!(
                    "{field}: the ValidatingAdmissionPolicy sets the label '{key}' to '{a_value}'. The ValidatingAdmissionPolicyBinding sets it to '{b_value}'. A selector with both values matches no object. Set the same value on both sides, or remove the label from one side"
                ));
            }
            None => {
                match_labels.insert(key, b_value);
            }
        }
    }

    Ok(Some(LabelSelector {
        match_expressions: if match_expressions.is_empty() {
            None
        } else {
            Some(match_expressions)
        },
        match_labels: if match_labels.is_empty() {
            None
        } else {
            Some(match_labels)
        },
    }))
}

/// Whether `selector` sets no condition: both `matchLabels` and
/// `matchExpressions` are absent or empty. Such a selector matches every
/// object, the same as a missing selector. Callers treat the two cases
/// the same way.
fn label_selector_is_empty(selector: &LabelSelector) -> bool {
    selector
        .match_labels
        .as_ref()
        .is_none_or(|labels| labels.is_empty())
        && selector
            .match_expressions
            .as_ref()
            .is_none_or(|exprs| exprs.is_empty())
}

/// Combine a VAP `objectSelector` and a binding `objectSelector` into the
/// single selector a `ClusterAdmissionPolicy` can hold.
///
/// Unlike `namespaceSelector` (see [`and_label_selectors`]), an AND merge
/// of the two `objectSelector`s does not give the same result as what
/// Kubernetes runs. On an UPDATE request, Kubernetes evaluates each
/// selector on its own, against the old object or the new object:
/// `(A(old) || A(new)) && (B(old) || B(new))`. Merging first and then
/// applying old-or-new gives a different result:
/// `(A && B)(old) || (A && B)(new)`. The merged form can miss an UPDATE
/// that changes which object version satisfies which selector. It can
/// skip validation that the original VAP and binding pair would have
/// run.
///
/// kwctl has no target field that can hold two independent selectors. So
/// when both sides set a nonempty `objectSelector`, kwctl returns an
/// error instead of building a merge that gives the wrong result. An
/// empty selector (present but with no `matchLabels` and no
/// `matchExpressions`) matches every object. kwctl treats it as absent
/// and does not raise the error for it.
fn combine_object_selectors(
    vap_selector: Option<LabelSelector>,
    binding_selector: Option<LabelSelector>,
) -> Result<Option<LabelSelector>> {
    let vap_selector = vap_selector.filter(|s| !label_selector_is_empty(s));
    let binding_selector = binding_selector.filter(|s| !label_selector_is_empty(s));

    match (vap_selector, binding_selector) {
        (Some(_), Some(_)) => Err(anyhow!(
            "objectSelector: both the ValidatingAdmissionPolicy (spec.matchConstraints.objectSelector) and the ValidatingAdmissionPolicyBinding (spec.matchResources.objectSelector) set a selector. On an UPDATE request, Kubernetes matches each selector against the old object or the new object on its own. A single ClusterAdmissionPolicy.spec.objectSelector cannot express that pair. A merge of the two would skip UPDATE requests that the original VAP and binding validate. Remove objectSelector from one side. Keep it only on the VAP, or only on the binding"
        )),
        (Some(vap_selector), None) => Ok(Some(vap_selector)),
        (None, Some(binding_selector)) => Ok(Some(binding_selector)),
        (None, None) => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::{
        api::admissionregistration::v1::NamedRuleWithOperations,
        apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement,
    };
    use rstest::*;

    use super::*;

    fn label_selector(labels: &[(&str, &str)]) -> LabelSelector {
        LabelSelector {
            match_labels: Some(
                labels
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect::<BTreeMap<_, _>>(),
            ),
            match_expressions: None,
        }
    }

    fn in_requirement(key: &str, value: &str) -> LabelSelectorRequirement {
        LabelSelectorRequirement {
            key: key.to_string(),
            operator: "In".to_string(),
            values: Some(vec![value.to_string()]),
        }
    }

    fn expressions_selector(requirements: Vec<LabelSelectorRequirement>) -> LabelSelector {
        LabelSelector {
            match_labels: None,
            match_expressions: Some(requirements),
        }
    }

    #[rstest]
    #[case::both_absent(None, None, None)]
    #[case::only_vap(
        Some(label_selector(&[("env", "prod")])),
        None,
        Some(label_selector(&[("env", "prod")]))
    )]
    #[case::only_binding(
        None,
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("env", "prod")]))
    )]
    #[case::disjoint_labels_are_merged(
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("team", "platform")])),
        Some(label_selector(&[("env", "prod"), ("team", "platform")]))
    )]
    #[case::same_label_same_value_keeps_one_copy(
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("env", "prod")])),
        Some(label_selector(&[("env", "prod")]))
    )]
    #[case::match_expressions_are_concatenated(
        Some(expressions_selector(vec![in_requirement("env", "prod")])),
        Some(expressions_selector(vec![in_requirement("team", "platform")])),
        Some(expressions_selector(vec![
            in_requirement("env", "prod"),
            in_requirement("team", "platform"),
        ]))
    )]
    fn and_label_selectors_cases(
        #[case] vap: Option<LabelSelector>,
        #[case] binding: Option<LabelSelector>,
        #[case] expected: Option<LabelSelector>,
    ) {
        assert_eq!(
            and_label_selectors("namespaceSelector", vap, binding).expect("no label conflict"),
            expected
        );
    }

    #[test]
    fn and_label_selectors_rejects_a_label_with_different_values() {
        let vap = label_selector(&[("env", "prod")]);
        let binding = label_selector(&[("env", "staging")]);

        let err = match and_label_selectors("namespaceSelector", Some(vap), Some(binding)) {
            Ok(_) => panic!("a label with two different values should be rejected"),
            Err(e) => e,
        };

        let message = err.to_string();
        assert!(message.contains("namespaceSelector"), "{message}");
        assert!(message.contains("env"), "{message}");
        assert!(message.contains("prod"), "{message}");
        assert!(message.contains("staging"), "{message}");
    }

    #[rstest]
    #[case::empty_struct(LabelSelector { match_labels: None, match_expressions: None }, true)]
    #[case::empty_match_labels(
        LabelSelector { match_labels: Some(BTreeMap::new()), match_expressions: None },
        true
    )]
    #[case::empty_match_expressions(
        LabelSelector { match_labels: None, match_expressions: Some(Vec::new()) },
        true
    )]
    #[case::nonempty_match_labels(label_selector(&[("env", "prod")]), false)]
    #[case::nonempty_match_expressions(
        expressions_selector(vec![in_requirement("env", "prod")]),
        false
    )]
    fn label_selector_is_empty_cases(#[case] selector: LabelSelector, #[case] expected: bool) {
        assert_eq!(label_selector_is_empty(&selector), expected);
    }

    #[rstest]
    #[case::both_absent(None, None)]
    #[case::only_vap(Some(label_selector(&[("env", "prod")])), None)]
    #[case::only_binding(None, Some(label_selector(&[("env", "prod")])))]
    #[case::vap_selector_is_empty(
        Some(LabelSelector { match_labels: None, match_expressions: None }),
        Some(label_selector(&[("env", "prod")]))
    )]
    #[case::binding_selector_is_empty(
        Some(label_selector(&[("env", "prod")])),
        Some(LabelSelector { match_labels: None, match_expressions: None })
    )]
    fn combine_object_selectors_accepts_at_most_one_nonempty_selector(
        #[case] vap: Option<LabelSelector>,
        #[case] binding: Option<LabelSelector>,
    ) {
        combine_object_selectors(vap, binding).expect("at most one side sets a selector");
    }

    #[rstest]
    #[case::disjoint_selectors(
        label_selector(&[("protected", "yes")]),
        label_selector(&[("team", "security")])
    )]
    #[case::same_key_same_value(
        label_selector(&[("env", "prod")]),
        label_selector(&[("env", "prod")])
    )]
    fn combine_object_selectors_rejects_two_nonempty_selectors(
        #[case] vap: LabelSelector,
        #[case] binding: LabelSelector,
    ) {
        // Even when the two selectors agree (same key, same value), kwctl
        // still rejects the pair. On an UPDATE, Kubernetes matches the
        // two sides independently against the old and the new object
        // (see `combine_object_selectors`). So this rule stays simple,
        // rather than trying to prove the merge sound case by case.
        let err = match combine_object_selectors(Some(vap), Some(binding)) {
            Ok(_) => panic!("two nonempty objectSelectors should be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("objectSelector"), "{err}");
    }

    /// A minimal model of how Kubernetes matches `matchLabels` selectors,
    /// used only by the test below. It does not exercise any production
    /// code.
    fn matches_labels(selector: &LabelSelector, labels: &BTreeMap<String, String>) -> bool {
        selector
            .match_labels
            .as_ref()
            .unwrap_or(&BTreeMap::new())
            .iter()
            .all(|(k, v)| labels.get(k) == Some(v))
    }

    /// How Kubernetes matches an `objectSelector` on an UPDATE request:
    /// the selector matches when it matches the old object or the new
    /// object. See `admission.NewMatcher`, the VAP admission plugin in
    /// `k8s.io/apiserver`.
    fn k8s_object_selector_matches(
        selector: &LabelSelector,
        old: &BTreeMap<String, String>,
        new: &BTreeMap<String, String>,
    ) -> bool {
        matches_labels(selector, old) || matches_labels(selector, new)
    }

    /// Pins the report's counterexample. Merging the VAP and binding
    /// `objectSelector` with AND, then applying old-or-new matching to
    /// the merged selector, is not the same predicate as ANDing the two
    /// old-or-new matches that Kubernetes actually runs. This test builds
    /// no `MatchFields` and calls no scaffold code. It only documents,
    /// with a small label matcher, why `combine_object_selectors` rejects
    /// the pair instead of merging it.
    #[test]
    fn merging_object_selectors_would_change_which_update_requests_match() {
        let vap_selector = label_selector(&[("protected", "yes")]);
        let binding_selector = label_selector(&[("team", "security")]);

        let old = BTreeMap::from([
            ("protected".to_string(), "yes".to_string()),
            ("team".to_string(), "other".to_string()),
        ]);
        let new = BTreeMap::from([
            ("protected".to_string(), "no".to_string()),
            ("team".to_string(), "security".to_string()),
        ]);

        // The original VAP and binding pair: Kubernetes matches each
        // selector against old and new on its own, then ANDs the two
        // results.
        let original = k8s_object_selector_matches(&vap_selector, &old, &new)
            && k8s_object_selector_matches(&binding_selector, &old, &new);
        assert!(
            original,
            "the original VAP and binding pair should validate this UPDATE"
        );

        // The merged selector kwctl would build if it ANDed the two
        // sides first (what `and_label_selectors` does for
        // namespaceSelector).
        let merged =
            and_label_selectors("objectSelector", Some(vap_selector), Some(binding_selector))
                .expect("disjoint labels merge without conflict")
                .expect("both sides are present");
        let merged_matches = k8s_object_selector_matches(&merged, &old, &new);
        assert!(
            !merged_matches,
            "a merged objectSelector would (wrongly) skip this UPDATE, which is exactly why combine_object_selectors rejects the pair instead of merging it"
        );
    }

    fn match_resources_with(
        namespace_selector: Option<LabelSelector>,
        object_selector: Option<LabelSelector>,
    ) -> MatchResources {
        MatchResources {
            namespace_selector,
            object_selector,
            ..Default::default()
        }
    }

    #[rstest]
    #[case::vap_exclude_resource_rules(
        MatchResources {
            exclude_resource_rules: Some(vec![NamedRuleWithOperations::default()]),
            ..Default::default()
        },
        MatchResources::default(),
        Some("matchConstraints.excludeResourceRules")
    )]
    #[case::binding_exclude_resource_rules(
        MatchResources::default(),
        MatchResources {
            exclude_resource_rules: Some(vec![NamedRuleWithOperations::default()]),
            ..Default::default()
        },
        Some("matchResources.excludeResourceRules")
    )]
    #[case::binding_resource_rules(
        MatchResources::default(),
        MatchResources {
            resource_rules: Some(vec![NamedRuleWithOperations::default()]),
            ..Default::default()
        },
        Some("matchResources.resourceRules")
    )]
    #[case::vap_resource_rules_resource_names(
        MatchResources {
            resource_rules: Some(vec![NamedRuleWithOperations {
                resource_names: Some(vec!["cluster-config".to_string()]),
                ..Default::default()
            }]),
            ..Default::default()
        },
        MatchResources::default(),
        Some("resourceNames")
    )]
    #[case::binding_match_policy_differs_from_the_vap(
        // The VAP leaves `matchPolicy` unset. This field defaults to
        // "Equivalent". The binding sets `matchPolicy` to "Exact". The
        // two values differ.
        MatchResources::default(),
        MatchResources {
            match_policy: Some("Exact".to_string()),
            ..Default::default()
        },
        Some("matchPolicy")
    )]
    #[case::binding_match_policy_equals_the_vap_default(
        // The VAP leaves `matchPolicy` unset. This field defaults to
        // "Equivalent". The binding sets `matchPolicy` to the same
        // value. Kubernetes allows this.
        MatchResources::default(),
        MatchResources {
            match_policy: Some("Equivalent".to_string()),
            ..Default::default()
        },
        None
    )]
    #[case::vap_and_binding_namespace_selector_conflict(
        match_resources_with(
            Some(label_selector(&[("kubernetes.io/metadata.name", "other")])),
            None,
        ),
        match_resources_with(
            Some(label_selector(&[("kubernetes.io/metadata.name", "default")])),
            None,
        ),
        Some("namespaceSelector")
    )]
    #[case::vap_and_binding_object_selector_both_set(
        match_resources_with(None, Some(label_selector(&[("protected", "yes")]))),
        match_resources_with(None, Some(label_selector(&[("team", "security")]))),
        Some("objectSelector")
    )]
    #[case::vap_object_selector_and_empty_binding_object_selector_is_allowed(
        // An empty objectSelector on the binding matches every object,
        // the same as an absent one. It does not conflict with the VAP's
        // objectSelector.
        match_resources_with(None, Some(label_selector(&[("protected", "yes")]))),
        match_resources_with(
            None,
            Some(LabelSelector { match_labels: None, match_expressions: None }),
        ),
        None
    )]
    fn merge_match_fields_cases(
        #[case] vap_match_constraints: MatchResources,
        #[case] binding_match_resources: MatchResources,
        #[case] expected_error: Option<&str>,
    ) {
        let result = merge_match_fields(vap_match_constraints, binding_match_resources);
        match expected_error {
            None => {
                result.expect("merge_match_fields should succeed");
            }
            Some(needle) => {
                let err = match result {
                    Ok(_) => panic!("expected an error that mentions '{needle}'"),
                    Err(e) => e,
                };
                assert!(err.to_string().contains(needle), "{err}");
            }
        }
    }

    #[test]
    fn merge_match_fields_merges_namespace_selector_from_vap_and_binding() {
        let vap_match_constraints =
            match_resources_with(Some(label_selector(&[("team", "platform")])), None);
        let binding_match_resources = match_resources_with(
            Some(label_selector(&[(
                "kubernetes.io/metadata.name",
                "default",
            )])),
            None,
        );

        let match_fields = merge_match_fields(vap_match_constraints, binding_match_resources)
            .expect("merge_match_fields should succeed");

        let namespace_selector = match_fields
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

    #[test]
    fn merge_match_fields_keeps_binding_object_selector_that_the_vap_does_not_set() {
        let vap_match_constraints = MatchResources::default();
        let binding_match_resources =
            match_resources_with(None, Some(label_selector(&[("app", "web")])));

        let match_fields = merge_match_fields(vap_match_constraints, binding_match_resources)
            .expect("merge_match_fields should succeed");

        assert_eq!(
            match_fields
                .object_selector
                .expect("object_selector should be present")
                .match_labels,
            Some(BTreeMap::from([("app".to_string(), "web".to_string())]))
        );
    }

    #[test]
    fn merge_match_fields_keeps_vap_object_selector_that_the_binding_does_not_set() {
        let vap_match_constraints =
            match_resources_with(None, Some(label_selector(&[("app", "web")])));
        let binding_match_resources = MatchResources::default();

        let match_fields = merge_match_fields(vap_match_constraints, binding_match_resources)
            .expect("merge_match_fields should succeed");

        assert_eq!(
            match_fields
                .object_selector
                .expect("object_selector should be present")
                .match_labels,
            Some(BTreeMap::from([("app".to_string(), "web".to_string())]))
        );
    }

    #[test]
    fn merge_match_fields_keeps_the_scope_of_a_vap_resource_rule() {
        let vap_match_constraints = MatchResources {
            resource_rules: Some(vec![NamedRuleWithOperations {
                api_groups: Some(vec![String::new()]),
                api_versions: Some(vec!["v1".to_string()]),
                resources: Some(vec!["pods".to_string()]),
                operations: Some(vec!["CREATE".to_string()]),
                scope: Some("Namespaced".to_string()),
                resource_names: None,
            }]),
            ..Default::default()
        };
        let binding_match_resources = MatchResources::default();

        let match_fields = merge_match_fields(vap_match_constraints, binding_match_resources)
            .expect("merge_match_fields should succeed");

        assert_eq!(
            match_fields.rules[0].scope,
            Some(policy_evaluator::policy_metadata::Scope::Namespaced)
        );
    }
}
