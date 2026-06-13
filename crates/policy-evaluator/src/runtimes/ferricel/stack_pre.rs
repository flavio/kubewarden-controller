use ferricel_core::EnginePre;
use ferricel_types::LogLevel;
use wasmtime_provider::wasmtime;

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::ferricel::{errors::FerricelRuntimeError, extensions, logging},
};

/// Pre-initialized ferricel engine.
///
/// Stores a [`ferricel_core::EnginePre`] -- the pre-compiled, pre-linked
/// [`wasmtime::InstancePre`] without any extension function implementations.
/// Extension functions are injected at rehydration time in
/// [`rehydrate`](StackPre::rehydrate), where the per-evaluation
/// [`EvaluationContext`] (including the callback channel) is available.
///
/// [`Clone`] is cheap: [`EnginePre`] is internally `Arc`-backed.
#[derive(Clone)]
pub(crate) struct StackPre {
    engine_pre: EnginePre,
}

impl StackPre {
    /// Create a new `StackPre` from the already-compiled `wasmtime::Module`.
    ///
    /// The `engine` must be the same engine used to compile the module.
    /// This runs the linker setup and `instantiate_pre` once; per-request
    /// cost is then limited to [`rehydrate`](Self::rehydrate).
    pub fn new(
        wasm_engine: wasmtime::Engine,
        module: wasmtime::Module,
    ) -> Result<Self, FerricelRuntimeError> {
        let engine_pre = ferricel_core::runtime::Builder::new()
            .with_engine(wasm_engine)
            .with_module(module)
            // Forward all guest log levels to the host tracing subscriber;
            // the subscriber's own filter decides what is actually recorded.
            .with_log_level(LogLevel::Debug)
            .build_pre()
            .map_err(FerricelRuntimeError::EngineBuild)?;
        Ok(Self { engine_pre })
    }

    /// Create a ready-to-use [`ferricel_core::runtime::Engine`] by injecting
    /// all Kubewarden host-capability extension functions and a per-evaluation
    /// logger that routes guest `cel_log` events to the `policy_log` tracing
    /// target with `policy_id` attached.
    ///
    /// Every extension is always registered. Extensions that require a callback
    /// channel return a clear error if `eval_ctx.callback_channel` is `None`.
    pub(crate) fn rehydrate(&self, eval_ctx: &EvaluationContext) -> ferricel_core::runtime::Engine {
        self.engine_pre.rehydrate(
            extensions::build_extensions(eval_ctx),
            logging::policy_logger(eval_ctx.policy_id.clone()),
        )
    }
}
