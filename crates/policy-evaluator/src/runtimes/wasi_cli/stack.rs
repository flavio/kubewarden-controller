use std::sync::Arc;

use tracing::debug;
use wasmtime_wasi::{I32Exit, WasiCtxBuilder, p1::WasiP1Ctx};

use crate::{
    evaluation_context::EvaluationContext,
    runtimes::wasi_cli::{
        bounded_output_pipe::BoundedOutputPipe, errors::WasiRuntimeError, stack_pre::StackPre,
        wasi_pipe::WasiPipe,
    },
};

const EXIT_SUCCESS: i32 = 0;

/// Maximum bytes a policy may write to stdout.
///
/// Stdout carries the JSON `AdmissionResponse`, which for mutating
/// policies includes the *entire* `mutated_object`, not just a patch (see
/// `AdmissionResponse::from_policy_validation_response`). This is not
/// bounded by etcd's ~1.5 MiB object size limit: policies can validate and
/// mutate objects served by aggregated API servers, which are not stored
/// in etcd and are not subject to that limit. 64 MiB is well above any
/// realistic legitimate output, while still bounding the worst case of a
/// runaway or malicious policy.
///
/// Exceeding this cap traps the guest immediately (see
/// `BoundedOutputPipe`), surfacing as a `WasiRuntimeError::WasiEvaluation`
/// with a clear message, rather than a silently truncated stdout that
/// later fails to deserialize.
const MAX_STDOUT_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Maximum bytes a policy may write to stderr.
///
/// Stderr does not carry structured policy logs: the Kubewarden SDKs send
/// those to the host via the `kubewarden/tracing.log` host capability
/// (see `host_callback`'s `"tracing" => "log"` branch), which does not go
/// through this pipe at all. What ends up on stderr is only diagnostic
/// output that originates below the SDK layer: language runtime panics,
/// crash traces, or ad-hoc `eprintln!`/`console.error` debugging output.
/// This is expected to be tiny (a stack trace at most), so a much smaller
/// cap than stdout's is appropriate.
const MAX_STDERR_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

pub(crate) struct Context {
    pub(crate) wasi_ctx: WasiP1Ctx,
    pub(crate) stdin_pipe: WasiPipe,
    pub(crate) eval_ctx: Arc<EvaluationContext>,
    pub(crate) limits: wasmtime::StoreLimits,
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
        let stdout_pipe = BoundedOutputPipe::new("stdout", MAX_STDOUT_BYTES);
        let stderr_pipe = BoundedOutputPipe::new("stderr", MAX_STDERR_BYTES);
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
            limits: self.stack_pre.store_limits(),
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
    pipe: &BoundedOutputPipe,
) -> std::result::Result<String, WasiRuntimeError> {
    let buf = pipe.contents();
    String::from_utf8(buf.to_vec()).map_err(|e| WasiRuntimeError::PipeConversion {
        name: name.to_string(),
        error: format!("Cannot convert buffer to UTF8 string: {e}"),
    })
}
