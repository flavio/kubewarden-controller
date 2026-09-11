use std::{
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use wasmtime_wasi::{
    cli::{IsTerminal, StdoutStream},
    p2::{OutputStream, Pollable, StreamError, StreamResult},
};

/// An in-memory pipe that can be used as the STDOUT/STDERR of a WASI guest,
/// bounded to a maximum capacity.
///
/// This plays the same role as `wasmtime_wasi::p2::pipe::MemoryOutputPipe`,
/// but with different overflow semantics. `MemoryOutputPipe` also has a
/// capacity, but writes that would exceed it are only rejected through
/// `check_write` returning `StreamError::Closed`. Under the p1 CLI adapter
/// (used by this runtime, see `wasmtime_wasi::p1`), `Closed` is surfaced to
/// the guest as a plain `errno` from `fd_write`: a soft, recoverable I/O
/// error. A guest that doesn't check this return value (as observed with
/// some language runtimes) keeps running with silently truncated output,
/// which later fails at a completely different layer (e.g. the host
/// failing to deserialize a truncated `AdmissionResponse`), with an error
/// message that gives no hint about the actual cause.
///
/// `BoundedOutputPipe` instead reports capacity overflow as
/// `StreamError::Trap`, which the p1 adapter turns into a real Wasm trap
/// that terminates the guest immediately (see `wasmtime_wasi::p1::write`
/// and its handling of `StreamError::Trap` vs `StreamError::Closed`). This
/// surfaces as a clear, actionable error through the existing
/// `WasiRuntimeError::WasiEvaluation` path, regardless of whether the guest
/// checks its own write return values.
#[derive(Clone)]
pub(crate) struct BoundedOutputPipe {
    name: &'static str,
    capacity: usize,
    buffer: Arc<Mutex<BytesMut>>,
}

impl BoundedOutputPipe {
    /// Create a new pipe that traps once more than `capacity` bytes are
    /// written to it. `name` is used only to build a descriptive trap
    /// message (e.g. "stdout", "stderr").
    pub(crate) fn new(name: &'static str, capacity: usize) -> Self {
        Self {
            name,
            capacity,
            buffer: Arc::new(Mutex::new(BytesMut::new())),
        }
    }

    /// Returns the bytes written to the pipe so far.
    pub(crate) fn contents(&self) -> Bytes {
        self.buffer.lock().unwrap().clone().freeze()
    }

    /// The name given at construction time (e.g. "stdout", "stderr").
    pub(crate) fn name(&self) -> &'static str {
        self.name
    }

    fn overflow_message(&self) -> String {
        format!(
            "policy exceeded the maximum allowed size of {} bytes for {}",
            self.capacity, self.name
        )
    }

    fn overflow_trap(&self) -> StreamError {
        StreamError::Trap(wasmtime::Error::msg(self.overflow_message()))
    }
}

impl IsTerminal for BoundedOutputPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdoutStream for BoundedOutputPipe {
    fn p2_stream(&self) -> Box<dyn OutputStream> {
        Box::new(self.clone())
    }

    fn async_stream(&self) -> Box<dyn tokio::io::AsyncWrite + Send + Sync> {
        Box::new(self.clone())
    }
}

impl OutputStream for BoundedOutputPipe {
    fn write(&mut self, bytes: Bytes) -> StreamResult<()> {
        let mut buffer = self.buffer.lock().unwrap();
        if bytes.len() > self.capacity - buffer.len() {
            return Err(self.overflow_trap());
        }
        buffer.extend_from_slice(bytes.as_ref());
        Ok(())
    }

    fn flush(&mut self) -> StreamResult<()> {
        // This stream is always flushed.
        Ok(())
    }

    fn check_write(&mut self) -> StreamResult<usize> {
        let consumed = self.buffer.lock().unwrap().len();
        if consumed < self.capacity {
            Ok(self.capacity - consumed)
        } else {
            // The buffer is full: no more bytes will ever be written. Note
            // this deliberately traps rather than reporting
            // `StreamError::Closed`: see the type-level documentation for
            // why a soft, recoverable error is not appropriate here.
            Err(self.overflow_trap())
        }
    }
}

#[async_trait::async_trait]
impl Pollable for BoundedOutputPipe {
    async fn ready(&mut self) {}
}

/// Only consumed by the (potential, future) WASIp3 host bindings (see
/// `wasmtime_wasi::p3::cli`); not exercised by this codebase today, which
/// resolves stdout/stderr through `p2_stream` (see the `OutputStream` impl
/// above) both for the p1 CLI adapter and for WASIp2 components.
///
/// Unlike `OutputStream::write`, this can't report a Wasm trap: the
/// `AsyncWrite` trait has no error variant for it, only a plain
/// `std::io::Error`. Rather than silently accepting only what fits (as
/// `wasmtime_wasi`'s own `MemoryOutputPipe` does on this same path, and as
/// this implementation used to), an overflowing write is rejected in full
/// with an `io::Error` describing the cap that was hit. This still isn't a
/// guest-terminating trap — a WASIp3 guest would see it as a recoverable
/// stream error rather than being killed outright — but it avoids two
/// problems with silent truncation: the failure would otherwise surface
/// much later, at a completely different layer, with no indication of the
/// real cause; and returning `Ok(0)` for an already-full buffer (the
/// truncation behavior when the buffer has zero bytes left) is a
/// recognized hazard for `AsyncWrite` callers, which may busy-loop on it.
impl tokio::io::AsyncWrite for BoundedOutputPipe {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut buffer = self.buffer.lock().unwrap();
        if buf.len() > self.capacity - buffer.len() {
            return Poll::Ready(Err(std::io::Error::other(self.overflow_message())));
        }
        buffer.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_within_capacity_is_accepted() {
        let mut pipe = BoundedOutputPipe::new("stdout", 10);

        pipe.write(Bytes::from_static(b"hello")).unwrap();
        pipe.write(Bytes::from_static(b"world")).unwrap();

        assert_eq!(pipe.contents(), Bytes::from_static(b"helloworld"));
    }

    #[test]
    fn write_beyond_capacity_traps() {
        let mut pipe = BoundedOutputPipe::new("stdout", 10);

        pipe.write(Bytes::from_static(b"0123456789")).unwrap();

        let err = pipe.write(Bytes::from_static(b"x")).unwrap_err();
        assert!(matches!(err, StreamError::Trap(_)));
        assert!(err.to_string().contains("stdout"));

        // The already-written bytes are preserved; the overflowing write is
        // rejected in full, not partially applied.
        assert_eq!(pipe.contents(), Bytes::from_static(b"0123456789"));
    }

    #[test]
    fn check_write_traps_once_full() {
        let mut pipe = BoundedOutputPipe::new("stderr", 5);

        assert_eq!(pipe.check_write().unwrap(), 5);

        pipe.write(Bytes::from_static(b"12345")).unwrap();

        let err = pipe.check_write().unwrap_err();
        assert!(matches!(err, StreamError::Trap(_)));
        assert!(err.to_string().contains("stderr"));
    }

    #[tokio::test]
    async fn async_write_errors_at_capacity() {
        use tokio::io::AsyncWriteExt;

        let mut pipe = BoundedOutputPipe::new("stdout", 5);

        // A write that fits within capacity succeeds in full.
        let n = AsyncWriteExt::write(&mut pipe, b"01234").await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(pipe.contents(), Bytes::from_static(b"01234"));

        // A further write, now that the pipe is full, is rejected in full
        // (not silently truncated) with an `io::Error` naming the pipe.
        let err = AsyncWriteExt::write(&mut pipe, b"x").await.unwrap_err();
        assert!(err.to_string().contains("stdout"));
        assert_eq!(pipe.contents(), Bytes::from_static(b"01234"));
    }
}
