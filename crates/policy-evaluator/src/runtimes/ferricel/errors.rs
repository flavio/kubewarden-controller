use thiserror::Error;

#[derive(Error, Debug)]
pub enum FerricelRuntimeError {
    #[error("failed to build ferricel engine: {0}")]
    EngineBuild(#[source] anyhow::Error),

    #[error("ferricel evaluation failed: {0}")]
    EvalFailed(#[source] anyhow::Error),

    #[error("policy execution interrupted: execution deadline exceeded")]
    ExecutionDeadlineExceeded,

    #[error("cannot serialize ferricel bindings: {0}")]
    BindingsSerialization(#[source] serde_json::Error),

    #[error("cannot deserialize ferricel response: {0}")]
    ResponseDeserialization(#[source] serde_json::Error),
}
