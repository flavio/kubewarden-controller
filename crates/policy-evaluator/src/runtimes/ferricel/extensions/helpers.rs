use std::sync::Arc;

use serde::{Deserialize, Deserializer, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    callback_requests::CallbackRequestType, evaluation_context::EvaluationContext,
    runtimes::callback::host_callback_typed,
};

// ─── Handler helpers ──────────────────────────────────────────────────────────

/// Extract a required string field from a builder map.
pub(crate) fn str_field(map: &Value, key: &str) -> Result<String, String> {
    map[key]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("missing or non-string field '{key}' in builder map"))
}

/// Deserialize a ferricel builder map into `T`, with a field path (for
/// example `pubKeys[1]` or `annotations.count`) on every error.
///
/// A handler declares `T` as a `#[derive(Deserialize)]` struct with one
/// field per builder-map key (`#[serde(rename_all = "camelCase")]` on the
/// struct matches the key names the compiler writes). This gives every
/// field serde's own rules for free: a missing required field is an
/// error, a present value of the wrong type is an error naming the type
/// it got, and `#[serde(default)]` turns an absent key into an empty
/// `Vec` or `None` without turning a *present* wrong-type value into the
/// same default. The one gap serde leaves is a present `null` for an
/// `Option<T>` field, which normally also means `None`; use
/// [`reject_null`] as that field's `deserialize_with` when a `null`
/// argument must be rejected instead (see its own docs for why).
///
/// The map itself may carry extra keys (`__type__`, or fields another
/// overload of the same builder chain sets): serde ignores a key that
/// `T` does not declare, so `T` only needs the fields it reads.
pub(crate) fn parse_builder_map<T: DeserializeOwned>(map: &Value) -> Result<T, String> {
    serde_path_to_error::deserialize(map).map_err(|e| e.to_string())
}

/// A `deserialize_with` function for an `Option<T>` field that must
/// reject a present `null`, not treat it the same as an absent key.
///
/// Plain serde maps both "the key is absent" and "the key is present
/// with a `null` value" to `None`. That default is wrong for a builder
/// chain step that overwrites a single key from one CEL argument (unlike
/// an accumulating step): the two cases are "the policy author never
/// called this method" and "the policy author called it with a `null`
/// argument" (for example `.githubAction("org", object.spec.repo)` where
/// `repo` is `null`), and only the compiled module can tell them apart.
/// Silently treating a `null` argument as "not called" would fall back
/// to a default that removes whatever restriction the argument
/// controls.
///
/// Pair this with `#[serde(default)]` on the field: `default` supplies
/// `None` when the key is absent, so this function only ever runs on a
/// value that is actually present, and a `null` there fails like any
/// other wrong type.
pub(crate) fn reject_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// A `deserialize_with` function for the `namespace` field of a `kw.k8s`
/// builder map: an absent key or an empty string both mean "no
/// namespace".
///
/// A `kw.k8s` chain written in CEL sets the `namespace` key only when
/// the policy calls `.namespace(...)`. The `params` lookup that a
/// compiled VAP module runs on its own always sets the key, and uses
/// `""` when neither `paramRef.namespace` nor `request.namespace` is
/// set (for example, a cluster-scoped param resource). Treating `""` as
/// a real namespace would build a broken API path, or reject a
/// cluster-scoped resource with "cannot search for it inside of a
/// namespace", so `""` must keep meaning "no namespace" here -- unlike
/// [`reject_null`], which this function otherwise matches: pair it with
/// `#[serde(default)]`, and any present value that is not a string,
/// `null` included, is still an error.
pub(crate) fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(reject_null::<D, String>(deserializer)?.filter(|s| !s.is_empty()))
}

/// Authorize and dispatch a `CallbackRequestType` built from a ferricel
/// extension handler, synchronously waiting for the response.
///
/// This routes through [`host_callback_typed`] -- the single authorization
/// gate (host-capability + Kubernetes-resource checks) for the callback
/// channel, which waPC/Wasi policies also reach via their `host_callback`
/// adapter -- so no gating logic lives in the ferricel handlers themselves.
///
/// Returns an error if the callback channel is not set; the channel handling
/// is part of the shared dispatch path, so the error is the very same one
/// waPC/Wasi guests get when no callback channel is available.
pub(crate) fn call_host(
    eval_ctx: &Arc<EvaluationContext>,
    namespace: &str,
    operation: &str,
    request_type: CallbackRequestType,
) -> Result<Value, String> {
    let payload = host_callback_typed(namespace, operation, request_type, eval_ctx)
        .map_err(|e| e.to_string())?;

    serde_json::from_slice(&payload).map_err(|e| format!("failed to deserialize response: {e}"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    /// A single `namespace` field using [`empty_string_as_none`], the
    /// same way `GetArgs`/`ListArgs` in `extensions/kubernetes.rs` do.
    #[derive(Deserialize, Debug, PartialEq)]
    struct NamespaceExample {
        #[serde(default, deserialize_with = "empty_string_as_none")]
        namespace: Option<String>,
    }

    #[rstest]
    #[case::absent(json!({"kind": "ConfigMap"}), None)]
    #[case::empty(json!({"namespace": ""}), None)]
    #[case::set(json!({"namespace": "team-a"}), Some("team-a".to_string()))]
    fn empty_string_as_none_treats_empty_as_absent(
        #[case] map: Value,
        #[case] expected: Option<String>,
    ) {
        let result: NamespaceExample =
            parse_builder_map(&map).expect("expected a well-formed map to parse");
        assert_eq!(result.namespace, expected);
    }

    /// Unlike [`reject_null`], [`empty_string_as_none`] treats `""` as
    /// absent. It still rejects every other wrong type, `null` included:
    /// see its own docs for why `""` is the one exception.
    #[rstest]
    #[case::null(json!({"namespace": null}))]
    #[case::not_a_string(json!({"namespace": 1}))]
    fn empty_string_as_none_rejects_every_other_wrong_type(#[case] map: Value) {
        let err = parse_builder_map::<NamespaceExample>(&map)
            .expect_err("a null or wrong-type namespace must be rejected");
        assert!(
            err.contains("namespace"),
            "expected the field name in the error, got: {err:?}"
        );
    }

    /// A struct with one field per rule that [`parse_builder_map`] and
    /// [`reject_null`] must enforce together: `required` has no default,
    /// `items` is a required-but-defaults-to-empty array, `optional` is
    /// a plain `Option` (serde's own "absent or null both mean `None`"
    /// rule), and `strict_optional` uses [`reject_null`] to turn a
    /// present `null` into an error instead.
    #[derive(Deserialize, Debug, PartialEq)]
    struct Example {
        required: String,
        #[serde(default)]
        items: Vec<String>,
        #[serde(default)]
        optional: Option<String>,
        #[serde(default, deserialize_with = "reject_null")]
        strict_optional: Option<String>,
    }

    /// An `Example` with `required: "value"` and the given `optional`
    /// and `strict_optional`, for a table that only varies those two
    /// fields.
    fn example(optional: Option<&str>, strict_optional: Option<&str>) -> Example {
        Example {
            required: "value".to_string(),
            items: vec![],
            optional: optional.map(str::to_string),
            strict_optional: strict_optional.map(str::to_string),
        }
    }

    #[rstest]
    #[case::all_fields_set(
        json!({"required": "value", "optional": "a", "strict_optional": "b"}),
        example(Some("a"), Some("b"))
    )]
    #[case::only_the_required_field(json!({"required": "value"}), example(None, None))]
    // The map may carry extra keys (`__type__`, or fields another
    // overload of the same builder chain sets): serde ignores a key that
    // `Example` does not declare.
    #[case::extra_key_is_ignored(
        json!({"__type__": "kw.sigstore.VerifierBuilder", "required": "value"}),
        example(None, None)
    )]
    // A plain `Option` field (`optional`) treats a present `null` the
    // same as an absent key: only a `reject_null` field (`strict_optional`)
    // tells the two apart.
    #[case::plain_option_null_is_none(
        json!({"required": "value", "optional": null}),
        example(None, None)
    )]
    fn parse_builder_map_accepts_a_well_formed_map(#[case] map: Value, #[case] expected: Example) {
        let result: Example = parse_builder_map(&map).expect("expected a well-formed map to parse");
        assert_eq!(result, expected);
    }

    /// Every error [`parse_builder_map`] can produce names the field it
    /// came from: a missing required field, a wrong-type array element
    /// (by index, so a bad element does not silently shift the ones
    /// after it), and a present `null` on a [`reject_null`] field (which
    /// a plain `Option` field would have accepted as `None`).
    #[rstest]
    #[case::missing_required_field(json!({}), "required")]
    #[case::wrong_type_array_element(
        json!({"required": "value", "items": ["a", 1]}),
        "items[1]"
    )]
    #[case::reject_null_rejects_a_present_null(
        json!({"required": "value", "strict_optional": null}),
        "strict_optional"
    )]
    fn parse_builder_map_names_the_field_in_the_error(#[case] map: Value, #[case] needle: &str) {
        let err = parse_builder_map::<Example>(&map).expect_err("expected an error");
        assert!(
            err.contains(needle),
            "expected {needle:?} in the error, got: {err:?}"
        );
    }
}
