/// Configure limits on the resources a single Rego WebAssembly instance is
/// allowed to consume, leveraging wasmtime's
/// [`ResourceLimiter`](https://docs.rs/wasmtime/latest/wasmtime/trait.ResourceLimiter.html)
/// facility (via [`wasmtime::StoreLimits`]).
///
/// This can be used to prevent a malicious, or misbehaving, Rego policy
/// from exhausting the host's memory, for example by growing its linear
/// memory in an unbounded loop.
///
/// When a limit is exceeded, the corresponding `memory.grow`/`table.grow`
/// wasm instruction fails and returns `-1` to the guest, following the
/// WebAssembly specification. The OPA-compiled Wasm modules treat a failed
/// growth (via `opa_malloc`) as a fatal allocation failure, which is
/// reported back to the host as a trap. The memory/table cap itself is
/// always enforced by the host regardless of how the guest reacts to the
/// failed growth.
///
/// Note: burrego always allocates a 5-page (320KiB) linear memory upfront
/// (see [`crate::Evaluator`]) and hands it to the Rego module. Setting
/// [`ResourceLimits::max_memory_size`] below that size will cause the
/// evaluator creation to fail.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResourceLimits {
    /// Maximum size, in bytes, that the module's linear memory is allowed to
    /// grow to.
    ///
    /// `None` (the default) means no limit is enforced.
    pub max_memory_size: Option<usize>,

    /// Maximum number of elements the module's table is allowed to grow to.
    ///
    /// `None` (the default) means no limit is enforced.
    pub max_table_elements: Option<usize>,
}

// Builds a `wasmtime::StoreLimits` out of the (optional) `ResourceLimits`
// configuration. When `None` is provided, the resulting limits are
// effectively unlimited (i.e. wasmtime's defaults).
pub(crate) fn store_limits(resource_limits: Option<ResourceLimits>) -> wasmtime::StoreLimits {
    let mut builder = wasmtime::StoreLimitsBuilder::new();
    if let Some(limits) = resource_limits {
        if let Some(max_memory_size) = limits.max_memory_size {
            builder = builder.memory_size(max_memory_size);
        }
        if let Some(max_table_elements) = limits.max_table_elements {
            builder = builder.table_elements(max_table_elements);
        }
    }
    builder.build()
}
