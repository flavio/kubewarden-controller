use std::{collections::BTreeSet, sync::Arc};

use serde::Deserialize;
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType,
    evaluation_context::EvaluationContext,
    runtimes::ferricel::extensions::helpers::{
        call_host, empty_string_as_none, parse_builder_map, reject_null,
    },
};

pub(crate) fn get_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    call_host(
        eval_ctx,
        "kubernetes",
        "get_resource",
        parse_get(builder_map)?,
    )
}

/// Fields of the builder map that
/// `.apiVersion(...).kind(...).namespace(...).fieldMask(...).get(name)`
/// produces. `#[serde(rename_all = "camelCase")]` matches the map's own
/// key names (`apiVersion`, `fieldMasks`).
///
/// `namespace` uses [`empty_string_as_none`]: an absent key and `""` both
/// mean "no namespace" (see its own docs for why), but any other
/// non-string value, `null` included, is rejected. A `null` or
/// numeric namespace read from `object` must not silently widen the
/// search to a cluster-scoped lookup.
///
/// `fieldMasks` defaults to empty when `.fieldMask(...)` was never
/// called. A present element that is not a string is rejected rather
/// than dropped: a dropped element would silently widen the response
/// the policy reads back, past what the field mask was meant to limit
/// it to.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetArgs {
    api_version: String,
    kind: String,
    name: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    namespace: Option<String>,
    #[serde(default)]
    field_masks: Option<BTreeSet<String>>,
}

fn parse_get(builder_map: &Value) -> Result<CallbackRequestType, String> {
    let args: GetArgs = parse_builder_map(builder_map)?;

    Ok(CallbackRequestType::KubernetesGetResource {
        api_version: args.api_version,
        kind: args.kind,
        name: args.name,
        namespace: args.namespace,
        disable_cache: false,
        field_masks: args.field_masks,
    })
}

pub(crate) fn list_handler(
    eval_ctx: &Arc<EvaluationContext>,
    builder_map: &Value,
) -> Result<Value, String> {
    let (operation, request_type) = parse_list(builder_map)?;
    call_host(eval_ctx, "kubernetes", operation, request_type)
}

/// Fields of the builder map that
/// `.apiVersion(...).kind(...).namespace(...).labelSelector(...).fieldSelector(...).fieldMask(...).list()`
/// produces. See [`GetArgs`] for `namespace` and `fieldMasks`.
///
/// `labelSelector` and `fieldSelector` use [`reject_null`]: either key
/// is only ever present when the policy called the matching method, so
/// a present `null` (for example `object.spec.selector` evaluating to
/// `null`) is rejected instead of silently removing the filter and
/// widening the list to everything.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ListArgs {
    api_version: String,
    kind: String,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    namespace: Option<String>,
    #[serde(default, deserialize_with = "reject_null")]
    label_selector: Option<String>,
    #[serde(default, deserialize_with = "reject_null")]
    field_selector: Option<String>,
    #[serde(default)]
    field_masks: Option<BTreeSet<String>>,
}

fn parse_list(builder_map: &Value) -> Result<(&'static str, CallbackRequestType), String> {
    let args: ListArgs = parse_builder_map(builder_map)?;

    Ok(match args.namespace {
        Some(namespace) => (
            "list_resources_by_namespace",
            CallbackRequestType::KubernetesListResourceNamespace {
                api_version: args.api_version,
                kind: args.kind,
                namespace,
                label_selector: args.label_selector,
                field_selector: args.field_selector,
                field_masks: args.field_masks,
            },
        ),
        None => (
            "list_resources_all",
            CallbackRequestType::KubernetesListResourceAll {
                api_version: args.api_version,
                kind: args.kind,
                label_selector: args.label_selector,
                field_selector: args.field_selector,
                field_masks: args.field_masks,
            },
        ),
    })
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    #[test]
    fn parse_get_with_namespace() {
        let result = parse_get(&json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "name": "my-cm",
            "namespace": "team-a"
        }))
        .expect("expected a well-formed builder map to parse");

        assert_eq!(
            result,
            CallbackRequestType::KubernetesGetResource {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                name: "my-cm".to_string(),
                namespace: Some("team-a".to_string()),
                disable_cache: false,
                field_masks: None,
            }
        );
    }

    #[rstest]
    #[case::absent(json!({"apiVersion": "v1", "kind": "ConfigMap", "name": "my-cm"}))]
    #[case::empty(
        json!({"apiVersion": "v1", "kind": "ConfigMap", "name": "my-cm", "namespace": ""})
    )]
    fn parse_get_without_a_namespace(#[case] builder_map: Value) {
        let result = parse_get(&builder_map).expect("expected a well-formed builder map to parse");

        assert_eq!(
            result,
            CallbackRequestType::KubernetesGetResource {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                name: "my-cm".to_string(),
                namespace: None,
                disable_cache: false,
                field_masks: None,
            }
        );
    }

    #[test]
    fn parse_get_with_field_masks() {
        let result = parse_get(&json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "name": "my-cm",
            "fieldMasks": ["data", "metadata.name"]
        }))
        .expect("expected a well-formed builder map to parse");

        assert_eq!(
            result,
            CallbackRequestType::KubernetesGetResource {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                name: "my-cm".to_string(),
                namespace: None,
                disable_cache: false,
                field_masks: Some(BTreeSet::from([
                    "data".to_string(),
                    "metadata.name".to_string()
                ])),
            }
        );
    }

    #[test]
    fn parse_list_with_namespace_and_selectors_targets_the_namespace() {
        let (operation, result) = parse_list(&json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "namespace": "team-a",
            "labelSelector": "app=demo",
            "fieldSelector": "metadata.name=my-cm"
        }))
        .expect("expected a well-formed builder map to parse");

        assert_eq!(operation, "list_resources_by_namespace");
        assert_eq!(
            result,
            CallbackRequestType::KubernetesListResourceNamespace {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                namespace: "team-a".to_string(),
                label_selector: Some("app=demo".to_string()),
                field_selector: Some("metadata.name=my-cm".to_string()),
                field_masks: None,
            }
        );
    }

    /// The compiled module's own `params` lookup always sends the
    /// `namespace` key, and uses `""` for a cluster-scoped param
    /// resource: this must still list across all namespaces.
    #[test]
    fn parse_list_with_an_empty_namespace_targets_all_namespaces() {
        let (operation, result) = parse_list(&json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "namespace": ""
        }))
        .expect("expected a well-formed builder map to parse");

        assert_eq!(operation, "list_resources_all");
        assert_eq!(
            result,
            CallbackRequestType::KubernetesListResourceAll {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                label_selector: None,
                field_selector: None,
                field_masks: None,
            }
        );
    }

    #[test]
    fn parse_list_without_a_namespace_targets_all_namespaces() {
        let (operation, result) = parse_list(&json!({"apiVersion": "v1", "kind": "ConfigMap"}))
            .expect("expected a well-formed builder map to parse");

        assert_eq!(operation, "list_resources_all");
        assert_eq!(
            result,
            CallbackRequestType::KubernetesListResourceAll {
                api_version: "v1".to_string(),
                kind: "ConfigMap".to_string(),
                label_selector: None,
                field_selector: None,
                field_masks: None,
            }
        );
    }

    /// Every wrong-type argument must be rejected rather than dropped,
    /// whatever field or handler it belongs to: dropping it would widen
    /// the query past what the policy author wrote. A `null` or
    /// non-string `namespace` must not fall back to "no namespace" (a
    /// broader, not narrower, search). A `null` `labelSelector` or
    /// `fieldSelector` must not fall back to "no filter". A `null`
    /// `fieldMasks` element is reported by index.
    #[rstest]
    #[case::get_null_namespace(
        parse_get,
        json!({"apiVersion": "v1", "kind": "ConfigMap", "name": "my-cm", "namespace": null}),
        "namespace"
    )]
    #[case::get_non_string_namespace(
        parse_get,
        json!({"apiVersion": "v1", "kind": "ConfigMap", "name": "my-cm", "namespace": 1}),
        "namespace"
    )]
    #[case::get_null_field_mask_element(
        parse_get,
        json!({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "name": "my-cm",
            "fieldMasks": ["data", null]
        }),
        "fieldMasks[1]"
    )]
    #[case::list_null_namespace(
        list_wrapper,
        json!({"apiVersion": "v1", "kind": "ConfigMap", "namespace": null}),
        "namespace"
    )]
    #[case::list_null_label_selector(
        list_wrapper,
        json!({"apiVersion": "v1", "kind": "ConfigMap", "labelSelector": null}),
        "labelSelector"
    )]
    #[case::list_non_string_field_selector(
        list_wrapper,
        json!({"apiVersion": "v1", "kind": "ConfigMap", "fieldSelector": 1}),
        "fieldSelector"
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

    /// Adapts [`parse_list`]'s `(operation, CallbackRequestType)` return
    /// to the `fn(&Value) -> Result<CallbackRequestType, String>` shape
    /// [`parse_rejects_a_wrong_type_argument`] shares with [`parse_get`].
    fn list_wrapper(builder_map: &Value) -> Result<CallbackRequestType, String> {
        parse_list(builder_map).map(|(_, request_type)| request_type)
    }
}
