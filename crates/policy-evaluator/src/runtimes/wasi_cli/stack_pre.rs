use wasmtime::{AsContext, Engine, InstancePre, Linker, Memory, Module, StoreContext};

use crate::{
    policy_evaluator::policy_evaluator_builder::ResourceLimits,
    runtimes::{
        callback::host_callback,
        wasi_cli::{
            errors::{Result, WasiRuntimeError},
            stack::Context,
        },
    },
};

/// Reduce the allocation time of a Wasi Stack. This is done by leveraging `wasmtime::InstancePre`.
#[derive(Clone)]
pub(crate) struct StackPre {
    engine: Engine,
    instance_pre: InstancePre<Context>,
    resource_limits: Option<ResourceLimits>,
}

impl StackPre {
    pub(crate) fn new(
        engine: Engine,
        module: Module,
        resource_limits: Option<ResourceLimits>,
    ) -> Result<Self> {
        let mut linker = Linker::<Context>::new(&engine);
        wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |c: &mut Context| &mut c.wasi_ctx)
            .map_err(WasiRuntimeError::WasmLinkerError)?;
        add_host_call_to_linker(&mut linker)?;

        let instance_pre = linker
            .instantiate_pre(&module)
            .map_err(WasiRuntimeError::WasmInstantiate)?;
        Ok(Self {
            engine,
            instance_pre,
            resource_limits,
        })
    }

    /// Create a brand new `wasmtime::Store` to be used during an evaluation
    pub(crate) fn build_store(
        &self,
        ctx: Context,
        epoch_deadline: Option<u64>,
    ) -> wasmtime::Store<Context> {
        let mut store = wasmtime::Store::new(&self.engine, ctx);
        if let Some(deadline) = epoch_deadline {
            store.set_epoch_deadline(deadline);
        }
        store.limiter(|ctx| &mut ctx.limits);

        store
    }

    /// Allocate a new `wasmtime::Instance` that is bound to the given `wasmtime::Store`.
    /// It's recommended to provide a brand new `wasmtime::Store` created by the
    /// `build_store` method
    pub(crate) fn rehydrate(
        &self,
        store: &mut wasmtime::Store<Context>,
    ) -> Result<wasmtime::Instance> {
        self.instance_pre
            .instantiate(store)
            .map_err(WasiRuntimeError::WasmInstantiate)
    }

    /// Build the `wasmtime::StoreLimits` to be enforced on the `wasmtime::Store`
    /// created by `build_store`, based on the `ResourceLimits` configured for
    /// this `StackPre`.
    pub(crate) fn store_limits(&self) -> wasmtime::StoreLimits {
        let mut builder = wasmtime::StoreLimitsBuilder::new();
        if let Some(limits) = self.resource_limits {
            if let Some(max_memory_size) = limits.max_memory_size {
                builder = builder.memory_size(max_memory_size);
            }
            if let Some(max_table_elements) = limits.max_table_elements {
                builder = builder.table_elements(max_table_elements);
            }
        }
        builder.build()
    }
}

fn add_host_call_to_linker(linker: &mut wasmtime::Linker<Context>) -> Result<()> {
    let host_call_impl = |mut caller: wasmtime::Caller<'_, Context>,
                          bd_ptr: i32,
                          bd_len: i32,
                          ns_ptr: i32,
                          ns_len: i32,
                          op_ptr: i32,
                          op_len: i32,
                          ptr: i32,
                          len: i32| {
        let memory_export = caller
            .get_export("memory")
            .ok_or_else(|| WasiRuntimeError::WasiMemExport)?;
        let memory = memory_export
            .into_memory()
            .ok_or_else(|| WasiRuntimeError::WasiMemExportCannotConvert)?;

        let stdin = &caller.data().stdin_pipe;

        let vec = get_vec_from_memory(caller.as_context(), memory, ptr, len);
        let bd_vec = get_vec_from_memory(caller.as_context(), memory, bd_ptr, bd_len);
        let bd = std::str::from_utf8(&bd_vec).map_err(WasiRuntimeError::WasiMemOpToUtF8)?;
        let ns_vec = get_vec_from_memory(caller.as_context(), memory, ns_ptr, ns_len);
        let ns = std::str::from_utf8(&ns_vec).map_err(WasiRuntimeError::WasiMemOpToUtF8)?;
        let op_vec = get_vec_from_memory(caller.as_context(), memory, op_ptr, op_len);
        let op = std::str::from_utf8(&op_vec).map_err(WasiRuntimeError::WasiMemOpToUtF8)?;

        let host_callback_response = host_callback(bd, ns, op, &vec, &caller.data().eval_ctx);

        // return 1 if the host callback failed, 0 otherwise
        let func_return_value = host_callback_response.is_err() as i32;

        let response_msg = match host_callback_response {
            Ok(r) => r,
            Err(e) => e.to_string().as_bytes().to_owned(),
        };

        stdin.send(&response_msg)?;
        Ok(func_return_value)
    };

    linker
        .func_wrap("host", "call", host_call_impl)
        .map_err(|e| WasiRuntimeError::WasmHostFuncDefinitionError {
            name: "host.call".to_string(),
            error: e.to_string(),
        })?;

    // used by the JS policies
    linker
        .func_wrap("kubewarden:javy/host", "call", host_call_impl)
        .map_err(|e| WasiRuntimeError::WasmHostFuncDefinitionError {
            name: "kubewarden:javy/host:call".to_string(),
            error: e.to_string(),
        })?;

    Ok(())
}

fn get_vec_from_memory<'a, T: 'static>(
    store: impl Into<StoreContext<'a, T>>,
    mem: Memory,
    ptr: i32,
    len: i32,
) -> Vec<u8> {
    let data = mem.data(store);
    data[ptr as usize..(ptr + len) as usize].to_vec()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rstest::rstest;
    use wasmtime_wasi::WasiCtxBuilder;

    use super::*;
    use crate::{evaluation_context::EvaluationContext, runtimes::wasi_cli::wasi_pipe::WasiPipe};

    // Per the WebAssembly specification, linear memory is grown in units of
    // pages, and a page is fixed at 64KiB.
    const WASM_PAGE_SIZE: usize = 65536;

    /// A minimal WASI module that, on `_start`, keeps growing its linear
    /// memory by one page at a time until `memory.grow` fails.
    ///
    /// The module itself declares a maximum of 16 pages, so that even when
    /// no host-side resource limit is configured, the test terminates
    /// quickly.
    const GROW_MEMORY_WAT: &str = r#"
    (module
      (memory (export "memory") 1 16)
      (func (export "_start")
        (block $done
          (loop $loop
            (br_if $done (i32.lt_s (memory.grow (i32.const 1)) (i32.const 0)))
            (br $loop)
          )
        )
      )
    )
    "#;

    fn build_stack_pre(resource_limits: Option<ResourceLimits>) -> Result<StackPre> {
        let engine = Engine::default();
        let module = Module::new(&engine, GROW_MEMORY_WAT).expect("cannot compile WAT to wasm");
        StackPre::new(engine, module, resource_limits)
    }

    fn build_context(stack_pre: &StackPre) -> Context {
        Context {
            wasi_ctx: WasiCtxBuilder::new().build_p1(),
            stdin_pipe: WasiPipe::new(&[]),
            eval_ctx: Arc::new(EvaluationContext::default()),
            limits: stack_pre.store_limits(),
        }
    }

    /// Instantiates the module, calls `_start`, and returns the final
    /// number of pages the module's memory grew to.
    fn run_and_get_memory_pages(stack_pre: &StackPre) -> u64 {
        let ctx = build_context(stack_pre);
        let mut store = stack_pre.build_store(ctx, None);
        let instance = stack_pre
            .rehydrate(&mut store)
            .expect("instantiation should succeed");
        let start_fn = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .expect("cannot find _start function");
        start_fn
            .call(&mut store, ())
            .expect("_start call should succeed");

        instance
            .get_memory(&mut store, "memory")
            .expect("cannot find memory export")
            .size(&store)
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
    fn memory_growth(#[case] resource_limits: Option<ResourceLimits>, #[case] expected_pages: u64) {
        let stack_pre = build_stack_pre(resource_limits).expect("cannot build StackPre");
        assert_eq!(run_and_get_memory_pages(&stack_pre), expected_pages);
    }

    #[test]
    fn initial_memory_above_limit_fails_at_instantiation() {
        // The module requests 1 page (64KiB) of initial memory, which is
        // already above the configured limit.
        let resource_limits = ResourceLimits {
            max_memory_size: Some(WASM_PAGE_SIZE / 2),
            ..Default::default()
        };
        let stack_pre = build_stack_pre(Some(resource_limits)).expect("cannot build StackPre");

        let ctx = build_context(&stack_pre);
        let mut store = stack_pre.build_store(ctx, None);
        let result = stack_pre.rehydrate(&mut store);

        assert!(
            result.is_err(),
            "instantiation should fail because initial memory exceeds the limit"
        );
    }
}
