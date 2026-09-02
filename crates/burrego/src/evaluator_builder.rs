use std::path::{Path, PathBuf};

use wasmtime::{Engine, Module};

use crate::{
    Evaluator, ResourceLimits,
    errors::{BurregoError, Result},
    host_callbacks::HostCallbacks,
};

#[derive(Default)]
pub struct EvaluatorBuilder {
    policy_path: Option<PathBuf>,
    module: Option<Module>,
    engine: Option<Engine>,
    epoch_deadline: Option<u64>,
    resource_limits: Option<ResourceLimits>,
    host_callbacks: Option<HostCallbacks>,
}

impl EvaluatorBuilder {
    #[must_use]
    pub fn policy_path(mut self, path: &Path) -> Self {
        self.policy_path = Some(path.into());
        self
    }

    #[must_use]
    pub fn module(mut self, module: Module) -> Self {
        self.module = Some(module);
        self
    }

    #[must_use]
    pub fn engine(mut self, engine: &Engine) -> Self {
        self.engine = Some(engine.clone());
        self
    }

    #[must_use]
    pub fn enable_epoch_interruptions(mut self, deadline: u64) -> Self {
        self.epoch_deadline = Some(deadline);
        self
    }

    /// Enable enforcement of resource limits on the instantiated Rego
    /// WebAssembly module, leveraging wasmtime's
    /// [`ResourceLimiter`](wasmtime::ResourceLimiter) facility.
    ///
    /// This can be used to prevent a malicious, or misbehaving, Rego
    /// policy from exhausting the host's memory. See [`ResourceLimits`]
    /// for details.
    #[must_use]
    pub fn enable_resource_limits(mut self, resource_limits: ResourceLimits) -> Self {
        self.resource_limits = Some(resource_limits);
        self
    }

    #[must_use]
    pub fn host_callbacks(mut self, host_callbacks: HostCallbacks) -> Self {
        self.host_callbacks = Some(host_callbacks);
        self
    }

    fn validate(&self) -> Result<()> {
        if self.policy_path.is_some() && self.module.is_some() {
            return Err(BurregoError::EvaluatorBuilderError(
                "policy_path and module cannot be set at the same time".to_string(),
            ));
        }
        if self.policy_path.is_none() && self.module.is_none() {
            return Err(BurregoError::EvaluatorBuilderError(
                "Either policy_path or module must be set".to_string(),
            ));
        }

        if self.host_callbacks.is_none() {
            return Err(BurregoError::EvaluatorBuilderError(
                "host_callbacks must be set".to_string(),
            ));
        }

        Ok(())
    }

    pub fn build(&self) -> Result<Evaluator> {
        self.validate()?;

        let engine = match &self.engine {
            Some(e) => e.clone(),
            None => {
                let mut config = wasmtime::Config::default();
                if self.epoch_deadline.is_some() {
                    config.epoch_interruption(true);
                }
                Engine::new(&config).map_err(|e| {
                    BurregoError::WasmEngineError(format!("cannot create wasmtime Engine: {e:?}"))
                })?
            }
        };

        let module = match &self.module {
            Some(m) => m.clone(),
            None => Module::from_file(
                &engine,
                self.policy_path.clone().expect("policy_path should be set"),
            )
            .map_err(|e| {
                BurregoError::WasmEngineError(format!("cannot create wasmtime Module: {e:?}"))
            })?,
        };

        let host_callbacks = self
            .host_callbacks
            .clone()
            .expect("host callbacks should be set");

        Evaluator::from_engine_and_module(
            engine,
            module,
            host_callbacks,
            self.epoch_deadline,
            self.resource_limits,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    // Per the WebAssembly specification, linear memory is grown in units of
    // pages, and a page is fixed at 64KiB.
    const WASM_PAGE_SIZE: usize = 65536;

    // Reuse a gatekeeper policy already compiled to Wasm and committed to
    // the repository by the `policy-evaluator` crate. `test_data/gatekeeper`
    // is gitignored and only produced by the `opa build` step of the e2e
    // tests, so it's not guaranteed to exist when running `cargo test`
    // (e.g. in the unit-tests CI job, or on a fresh checkout).
    fn gatekeeper_policy_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../policy-evaluator/tests/data/gatekeeper_always_happy_policy.wasm")
    }

    // Verifies that `ResourceLimits` is correctly enforced by leveraging
    // wasmtime's `ResourceLimiter` facility.
    //
    // `Evaluator` always allocates a 5-page (320KiB) linear memory upfront
    // and hands it over to the Rego module (see `Evaluator::setup`).
    // Configuring a `max_memory_size` smaller than that must cause the
    // evaluator creation to fail, while a generous limit must not affect a
    // normal evaluation.

    #[test]
    fn evaluation_succeeds_with_generous_resource_limits() {
        let resource_limits = ResourceLimits {
            max_memory_size: Some(32 * WASM_PAGE_SIZE),
            max_table_elements: Some(10_000),
        };

        let evaluator = EvaluatorBuilder::default()
            .policy_path(&gatekeeper_policy_path())
            .host_callbacks(HostCallbacks::default())
            .enable_resource_limits(resource_limits)
            .build();

        assert!(
            evaluator.is_ok(),
            "evaluator creation should succeed: {:?}",
            evaluator.err()
        );
    }

    #[test]
    fn build_fails_when_initial_memory_is_above_the_limit() {
        // The evaluator always allocates a 5-page linear memory upfront,
        // which is already above the configured limit.
        let resource_limits = ResourceLimits {
            max_memory_size: Some(WASM_PAGE_SIZE),
            ..Default::default()
        };

        let evaluator = EvaluatorBuilder::default()
            .policy_path(&gatekeeper_policy_path())
            .host_callbacks(HostCallbacks::default())
            .enable_resource_limits(resource_limits)
            .build();

        assert!(
            evaluator.is_err(),
            "evaluator creation should fail because the initial memory exceeds the limit"
        );
    }

    #[test]
    fn evaluation_without_resource_limits_still_works() {
        let evaluator = EvaluatorBuilder::default()
            .policy_path(&gatekeeper_policy_path())
            .host_callbacks(HostCallbacks::default())
            .build();

        assert!(
            evaluator.is_ok(),
            "evaluator creation should succeed: {:?}",
            evaluator.err()
        );
    }
}
