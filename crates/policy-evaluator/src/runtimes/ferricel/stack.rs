use std::sync::Arc;

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::ferricel::{errors::FerricelRuntimeError, stack_pre::StackPre},
};

/// Per-evaluation state for the ferricel runtime.
pub(crate) struct Stack {
    engine: Arc<ferricel_core::runtime::Engine>,
    eval_ctx: Arc<EvaluationContext>,
}

impl Stack {
    pub fn new_from_pre(stack_pre: &StackPre, eval_ctx: &EvaluationContext) -> Self {
        Self {
            engine: Arc::new(stack_pre.rehydrate(eval_ctx)),
            eval_ctx: Arc::new(eval_ctx.clone()),
        }
    }

    pub(crate) fn eval_ctx(&self) -> &EvaluationContext {
        &self.eval_ctx
    }

    /// Evaluate the compiled Wasm module with the given JSON-encoded bindings.
    pub fn eval(&self, bindings_json: Option<&str>) -> Result<String, FerricelRuntimeError> {
        self.engine
            .eval(bindings_json)
            .map_err(FerricelRuntimeError::EvalFailed)
    }
}
