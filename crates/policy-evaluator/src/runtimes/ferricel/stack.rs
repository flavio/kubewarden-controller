use std::{collections::BTreeSet, sync::Arc};

use wasmtime_provider::wasmtime;

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::ferricel::{errors::FerricelRuntimeError, stack_pre::StackPre},
};

/// Per-evaluation state for the ferricel runtime.
pub(crate) struct Stack {
    engine: Arc<ferricel_core::runtime::Engine>,
    eval_ctx: Arc<EvaluationContext>,

    /// See [`StackPre`]'s `vap_variables` field docs for `None` semantics.
    vap_variables: Option<Arc<BTreeSet<String>>>,
}

impl Stack {
    pub fn new_from_pre(stack_pre: &StackPre, eval_ctx: &EvaluationContext) -> Self {
        Self {
            engine: Arc::new(stack_pre.rehydrate(eval_ctx)),
            eval_ctx: Arc::new(eval_ctx.clone()),
            vap_variables: stack_pre.vap_variables(),
        }
    }

    pub(crate) fn eval_ctx(&self) -> &EvaluationContext {
        &self.eval_ctx
    }

    /// Whether the compiled policy may reference the well-known VAP variable
    /// `name` (e.g. `"namespaceObject"`).
    ///
    /// Used at settings-validation time to warn when a Kubernetes resource
    /// that the compiled wasm may need is not granted (see
    /// `validate_settings_json`'s `references_namespace_object` parameter).
    ///
    /// Returns `true` conservatively when this information isn't available
    /// (see [`StackPre`]'s `vap_variables` field docs), so that callers
    /// default to warning rather than silently missing a real gap.
    pub(crate) fn references_vap_variable(&self, name: &str) -> bool {
        self.vap_variables
            .as_deref()
            .is_none_or(|vars| vars.contains(name))
    }

    /// Evaluate the compiled Wasm module with the given JSON-encoded
    /// bindings.
    ///
    /// The error tells the caller what went wrong:
    ///   - [`FerricelRuntimeError::ExecutionDeadlineExceeded`] when the
    ///     evaluation ran past the epoch deadline. See
    ///     [`EvaluationContext::epoch_deadline`].
    ///   - [`FerricelRuntimeError::CelRuntimeError`] when the module trapped
    ///     on a CEL runtime error. A `matchConditions` or `validations`
    ///     expression that evaluates to an error does not trap. The module
    ///     applies the `failurePolicy` binding to it on its own. Under
    ///     `Ignore`, it records a warning in the response instead. As a
    ///     result, this variant now happens only when the module cannot
    ///     fetch `params` or `namespaceObject`. Only this error goes
    ///     through the host's own handling of the VAP `failurePolicy`.
    ///   - [`FerricelRuntimeError::EvalFailed`] for every other failure.
    ///     This covers a Wasm trap, a memory limit, a missing export, or a
    ///     bug in the host.
    pub fn eval(&self, bindings_json: Option<&str>) -> Result<String, FerricelRuntimeError> {
        self.engine.eval(bindings_json).map_err(|e| {
            if matches!(
                e.downcast_ref::<wasmtime::Trap>(),
                Some(wasmtime::Trap::Interrupt)
            ) {
                return FerricelRuntimeError::ExecutionDeadlineExceeded;
            }
            if let Some(cel_err) = e.downcast_ref::<ferricel_core::CelRuntimeError>() {
                return FerricelRuntimeError::CelRuntimeError(cel_err.clone());
            }
            FerricelRuntimeError::EvalFailed(e)
        })
    }
}
