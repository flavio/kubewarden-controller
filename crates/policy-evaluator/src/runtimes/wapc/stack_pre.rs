use wasmtime_provider::wasmtime;

use crate::policy_evaluator::policy_evaluator_builder::ResourceLimits;
use crate::runtimes::wapc::errors::{Result, WapcRuntimeError};

/// Reduce allocation time of new `WasmtimeProviderEngine`, see the `rehydrate` method
#[derive(Clone)]
pub(crate) struct StackPre {
    engine_provider_pre: wasmtime_provider::WasmtimeEngineProviderPre,
}

impl StackPre {
    pub(crate) fn new(
        engine: wasmtime::Engine,
        module: wasmtime::Module,
        resource_limits: Option<ResourceLimits>,
    ) -> Result<Self> {
        let mut builder = wasmtime_provider::WasmtimeEngineProviderBuilder::new()
            .engine(engine)
            .module(module);

        if let Some(resource_limits) = resource_limits {
            builder = builder.enable_resource_limits(resource_limits.into());
        }

        let engine_provider_pre = builder
            .build_pre()
            .map_err(WapcRuntimeError::WasmtimeEngineBuilder)?;
        Ok(Self {
            engine_provider_pre,
        })
    }

    /// Allocate a new `WasmtimeEngineProvider` instance by using a pre-allocated instance
    pub(crate) fn rehydrate(
        &self,
        epoch_deadline: Option<u64>,
    ) -> Result<wasmtime_provider::WasmtimeEngineProvider> {
        let wapc_epoch_deadlines =
            epoch_deadline.map(|deadline| wasmtime_provider::EpochDeadlines {
                wapc_init: deadline,
                wapc_func: deadline,
            });

        let engine = self
            .engine_provider_pre
            .rehydrate(wapc_epoch_deadlines)
            .map_err(WapcRuntimeError::WasmtimeEngineBuilder)?;
        Ok(engine)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use wasmtime_provider::wasmtime::{Engine, Module};

    use super::*;

    // Per the WebAssembly specification, linear memory is grown in units of
    // pages, and a page is fixed at 64KiB.
    const WASM_PAGE_SIZE: usize = 65536;

    /// A minimal waPC guest module that, on every `__guest_call`, keeps
    /// growing its linear memory by one page at a time until `memory.grow`
    /// fails. It then reports back (as its response) the final memory size,
    /// expressed in pages.
    ///
    /// The module itself declares a maximum of 16 pages, so that even when
    /// no host-side resource limit is configured, the test terminates
    /// quickly.
    const GROW_MEMORY_WAT: &str = r#"
    (module
      (import "wapc" "__guest_response" (func $guest_response (param i32 i32)))
      (memory (export "memory") 1 16)

      (func (export "wapc_init"))

      (func (export "__guest_call") (param i32 i32) (result i32)
        (local $pages i32)
        (block $done
          (loop $loop
            (local.set $pages (memory.grow (i32.const 1)))
            (br_if $done (i32.lt_s (local.get $pages) (i32.const 0)))
            (br $loop)
          )
        )
        (i32.store (i32.const 0) (memory.size))
        (call $guest_response (i32.const 0) (i32.const 4))
        (i32.const 1)
      )
    )
    "#;

    fn noop_callback(
        _id: u64,
        _binding: &str,
        _namespace: &str,
        _operation: &str,
        _payload: &[u8],
    ) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![])
    }

    fn call_and_read_u32_pages(stack_pre: &StackPre) -> u32 {
        let engine_provider = stack_pre.rehydrate(None).expect("cannot rehydrate engine");
        let host = wapc::WapcHost::new(Box::new(engine_provider), Some(Box::new(noop_callback)))
            .expect("cannot create waPC host");

        let response = host.call("grow", &[]).expect("call should succeed");
        u32::from_le_bytes(
            response
                .try_into()
                .expect("response should be made of 4 bytes"),
        )
    }

    #[rstest]
    // Without any resource limit configured, the guest can grow memory up
    // to the module's own declared maximum (16 pages).
    #[case::unbounded(None, 16)]
    // The host-enforced limit (4 pages) is lower than the module's own
    // maximum (16 pages), so it must be the one that stops the growth.
    #[case::capped_by_resource_limits(
        Some(ResourceLimits {
            max_memory_size: Some(4 * WASM_PAGE_SIZE),
            ..Default::default()
        }),
        4
    )]
    fn memory_growth(#[case] resource_limits: Option<ResourceLimits>, #[case] expected_pages: u32) {
        let engine = Engine::default();
        let module = Module::new(&engine, GROW_MEMORY_WAT).expect("cannot compile WAT to wasm");
        let stack_pre =
            StackPre::new(engine, module, resource_limits).expect("cannot build StackPre");

        assert_eq!(call_and_read_u32_pages(&stack_pre), expected_pages);
    }
}
