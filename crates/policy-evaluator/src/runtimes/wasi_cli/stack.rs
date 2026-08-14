use std::sync::Arc;

use tracing::debug;
use wasmtime_wasi::{I32Exit, WasiCtxBuilder, p1::WasiP1Ctx, p2::pipe::MemoryOutputPipe};

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::wasi_cli::{errors::WasiRuntimeError, stack_pre::StackPre, wasi_pipe::WasiPipe},
};

const EXIT_SUCCESS: i32 = 0;

/// Maximum bytes a policy may write to stdout or stderr.
/// Protects the host from memory exhaustion caused by a runaway or
/// malicious policy.
/// 4 MiB is well above any realistic output: stdout carries the JSON
/// AdmissionResponse (typically a few KB, tens of KB with large mutation
/// patches; Kubernetes objects themselves are capped at ~1.5 MiB by etcd),
/// and stderr carries policy logs. Expected steady-state usage is well
/// under 1 MiB per evaluation; the cap only bounds the worst case, at
/// most 8 MiB (stdout + stderr) per in-flight evaluation.
const MAX_OUTPUT_PIPE_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

pub(crate) struct Context {
    pub(crate) wasi_ctx: WasiP1Ctx,
    pub(crate) stdin_pipe: WasiPipe,
    pub(crate) eval_ctx: Arc<EvaluationContext>,
}

pub(crate) struct Stack {
    stack_pre: StackPre,
    eval_ctx: Arc<EvaluationContext>,
}

pub(crate) struct RunResult {
    pub stdout: String,
    pub stderr: String,
}

impl Stack {
    pub(crate) fn new_from_pre(stack_pre: &StackPre, eval_ctx: &EvaluationContext) -> Self {
        Self {
            stack_pre: stack_pre.to_owned(),
            eval_ctx: Arc::new(eval_ctx.to_owned()),
        }
    }

    /// Run a WASI program with the given input and args
    pub(crate) fn run(
        &self,
        input: &[u8],
        args: &[&str],
    ) -> std::result::Result<RunResult, WasiRuntimeError> {
        if tokio::runtime::Handle::try_current().is_ok() {
            // The synchronous WASI support provided by wasmtime-wasi is
            // implemented on top of its async support: each WASI call invokes
            // `tokio::runtime::Handle::block_on`, which panics when executed
            // on a thread that is driving async tasks (e.g. a tokio worker
            // thread).
            // To be safe regardless of the calling context, run the evaluation
            // on a dedicated thread. This thread has no tokio context, causing
            // wasmtime-wasi to drive the WASI calls using its own internal
            // tokio runtime.
            std::thread::scope(|scope| {
                scope
                    .spawn(|| self.run_internal(input, args))
                    .join()
                    .unwrap_or_else(|err| std::panic::resume_unwind(err))
            })
        } else {
            self.run_internal(input, args)
        }
    }

    fn run_internal(
        &self,
        input: &[u8],
        args: &[&str],
    ) -> std::result::Result<RunResult, WasiRuntimeError> {
        let stdout_pipe = MemoryOutputPipe::new(MAX_OUTPUT_PIPE_BYTES);
        let stderr_pipe = MemoryOutputPipe::new(MAX_OUTPUT_PIPE_BYTES);
        let stdin_pipe = WasiPipe::new(input);

        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();

        let wasi_ctx = WasiCtxBuilder::new()
            .args(&args)
            .stdin(stdin_pipe.clone())
            .stdout(stdout_pipe.clone())
            .stderr(stderr_pipe.clone())
            .build_p1();
        let ctx = Context {
            wasi_ctx,
            stdin_pipe,
            eval_ctx: self.eval_ctx.clone(),
        };

        let mut store = self
            .stack_pre
            .build_store(ctx, self.eval_ctx.epoch_deadline);
        let instance = self.stack_pre.rehydrate(&mut store)?;
        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(WasiRuntimeError::WasmMissingStartFn)?;
        let evaluation_result = start_fn.call(&mut store, ());

        // Dropping the store, this is no longer needed and we want to make
        // sure the guest is done writing to the output pipes.
        drop(store);

        let stderr = pipe_to_string("stderr", &stderr_pipe)?.trim().to_string();

        if let Err(err) = evaluation_result {
            if let Some(exit_error) = err.downcast_ref::<I32Exit>() {
                if exit_error.0 == EXIT_SUCCESS {
                    let stdout = pipe_to_string("stdout", &stdout_pipe)?;
                    return Ok(RunResult { stdout, stderr });
                } else {
                    debug!(
                        "WASI program exited with error code: {}, error: {}",
                        exit_error.0, stderr
                    );

                    return Err(WasiRuntimeError::WasiEvaluation { stderr, error: err });
                }
            }

            debug!("WASI program exited with error: {}", stderr);
            return Err(WasiRuntimeError::WasiEvaluation { stderr, error: err });
        }

        let stdout = pipe_to_string("stdout", &stdout_pipe)?;
        Ok(RunResult { stdout, stderr })
    }
}

fn pipe_to_string(
    name: &str,
    pipe: &MemoryOutputPipe,
) -> std::result::Result<String, WasiRuntimeError> {
    let buf = pipe.contents();
    String::from_utf8(buf.to_vec()).map_err(|e| WasiRuntimeError::PipeConversion {
        name: name.to_string(),
        error: format!("Cannot convert buffer to UTF8 string: {e}"),
    })
}
