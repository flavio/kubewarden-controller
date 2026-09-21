use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::Bytes;
use tracing::warn;
use wasmtime_wasi::{
    cli::{IsTerminal, StdinStream},
    p2::{InputStream, Pollable, StreamError, StreamResult},
};

use crate::runtimes::wasi_cli::errors::WasiRuntimeError;

/// A read/write pipe that can be used as the STDIN of a WASI guest.
///
/// The pipe is internally shared: cloning it returns a new handle that
/// operates on the same buffer. It's safe to write to the `WasiPipe`
/// instance multiple times, even while the WASI guest is running. The
/// guest will find the data on its STDIN.
///
/// When the buffer is empty, the guest sees EOF. Writing more data to the
/// pipe makes it readable again. This is used by the host_call
/// implementation to provide the host callback response to the guest.
///
/// The host_call protocol requires the guest to fully drain the pipe (down
/// to a transient EOF, see below) before invoking another `host.call`: the
/// initial payload must be read to EOF before the guest can even parse it,
/// and each callback response must be read to EOF before the guest knows
/// it's complete. As a consequence, at the point `send` is called the
/// buffer is always expected to be empty for a well-behaved guest. `send`
/// takes advantage of this invariant to protect the host from a guest that
/// violates the protocol (e.g. by looping on `host.call` without ever
/// reading the responses): it wipes any unread bytes before appending the
/// new payload, rather than letting them accumulate without bound. This
/// keeps the pipe's memory usage bounded by the size of the largest single
/// payload (initial input or one callback response), with no need for an
/// explicit capacity limit.
#[derive(Clone, Default)]
pub(crate) struct WasiPipe {
    // A plain `std::sync::Mutex` is used on purpose, instead of an async
    // (e.g. `tokio::sync::Mutex`) one:
    //
    // * The `InputStream::read` and `AsyncRead::poll_read` methods we have
    //   to implement below are synchronous by contract (the former is
    //   documented by wasmtime-wasi-io as "a non-blocking read", the latter
    //   is a `poll_*` function). There's no `.await` point available inside
    //   them to use an async mutex with.
    // * The critical sections here (`VecDeque::extend`/`drain`) are
    //   in-memory only and complete in well under a microsecond: they can
    //   never block the async reactor for a meaningful amount of time.
    // * The guest is single-threaded and `host_call` (which calls `send`)
    //   only runs on the guest's own call stack while it invokes a WASI
    //   host function. The guest cannot simultaneously be reading stdin
    //   and calling `host.call`, so reader and writer are serialized by
    //   construction and contention is not expected in practice.
    // * This matches upstream: wasmtime-wasi's own `MemoryInputPipe` /
    //   `MemoryOutputPipe` (used here for stdout/stderr) are implemented
    //   with `Arc<std::sync::Mutex<..>>` too.
    buffer: Arc<Mutex<VecDeque<u8>>>,
}

impl WasiPipe {
    pub fn new(data: &[u8]) -> Self {
        let mut buffer: VecDeque<u8> = VecDeque::new();
        buffer.extend(data);

        Self {
            buffer: Arc::new(Mutex::new(buffer)),
        }
    }

    /// Append data to the pipe, making it available to the WASI guest.
    ///
    /// Any data left unread from a previous payload is discarded first: a
    /// well-behaved guest always drains the pipe to (transient) EOF before
    /// the host has a chance to `send` again, so leftover bytes can only be
    /// the result of a guest violating the host_call protocol. See the
    /// type-level documentation for details.
    pub fn send(&self, data: &[u8]) -> Result<(), WasiRuntimeError> {
        let mut buffer = self
            .buffer
            .lock()
            .map_err(|_| WasiRuntimeError::WasiPipePoisonedLock)?;
        if !buffer.is_empty() {
            warn!(
                discarded_bytes = buffer.len(),
                "WASI guest did not drain stdin before the host wrote more data to it; \
                 discarding unread bytes. This indicates the guest is violating the \
                 host_call protocol (a host.call response, or the initial input, was \
                 not fully read before another host.call was issued)."
            );
            buffer.clear();
        }
        buffer.extend(data);
        Ok(())
    }

    /// Read up to `size` bytes from the pipe. Returns `None` when the
    /// buffer is empty (EOF).
    fn read_bytes(&self, size: usize) -> Result<Option<Bytes>, WasiRuntimeError> {
        let mut buffer = self
            .buffer
            .lock()
            .map_err(|_| WasiRuntimeError::WasiPipePoisonedLock)?;
        if buffer.is_empty() {
            return Ok(None);
        }
        let amt = std::cmp::min(size, buffer.len());
        let data: Vec<u8> = buffer.drain(..amt).collect();
        Ok(Some(data.into()))
    }
}

impl IsTerminal for WasiPipe {
    fn is_terminal(&self) -> bool {
        false
    }
}

impl StdinStream for WasiPipe {
    // Only consumed by WASIp3 (see `p3/cli/host.rs` in wasmtime-wasi), which
    // is not exercised by this codebase today (we use the synchronous
    // WASIp1 support, via `add_to_linker_sync`, which resolves stdin through
    // `p2_stream` below). Kept for trait-completeness (`async_stream` is a
    // required method of `StdinStream`) and to be ready in case WASIp3
    // support is added in the future.
    //
    // Note: the transient-EOF trick this pipe relies on (see `p2_stream`
    // below) cannot be faithfully expressed as a `tokio::io::AsyncRead`:
    // EOF is conventionally a terminal state for that trait, and any
    // adapter built on top of it (including wasmtime-wasi's own
    // `AsyncReadStream`, used by the default `p2_stream` implementation)
    // will latch it permanently. Should the host_call protocol ever need to
    // run over this path, it will need to be redesigned; this method's
    // `AsyncRead` impl mirrors the same "ready with zero bytes = EOF, then
    // readable again" semantics as `read_bytes`, but consumers built on top
    // of it are not required to honor the "readable again" part.
    fn async_stream(&self) -> Box<dyn tokio::io::AsyncRead + Send + Sync> {
        Box::new(self.clone())
    }

    // Overridden because the default implementation wraps `async_stream()`
    // in a `wasmtime_wasi::p2::pipe::AsyncReadStream`, which spawns a
    // background task to eagerly pull from the `AsyncRead` and forwards
    // data through a channel. That adapter treats EOF as a terminal state:
    // once it observes a zero-byte read it marks the stream closed forever,
    // and it also introduces a scheduling race between that background task
    // and `send()`.
    //
    // Our host_call implementation relies on EOF being transient: the guest
    // drains stdin (sees EOF), invokes the `host.call` import, we `send()`
    // the callback response into the buffer, and the guest reads again.
    // This method returns `self` directly as the `InputStream`, so reads
    // happen synchronously against the shared buffer at the exact moment
    // the guest calls `fd_read`, with no extra task or channel involved.
    //
    // This is the path used both by the synchronous and the (potential,
    // future) asynchronous WASIp1 linker (`add_to_linker_sync` /
    // `add_to_linker_async`), and by WASIp2 components: see
    // `wasmtime_wasi::p2::stdio`, which resolves stdin via `p2_stream()`.
    fn p2_stream(&self) -> Box<dyn InputStream> {
        Box::new(self.clone())
    }
}

impl InputStream for WasiPipe {
    fn read(&mut self, size: usize) -> StreamResult<Bytes> {
        match self.read_bytes(size) {
            Ok(Some(data)) => Ok(data),
            // An empty buffer is reported as EOF. The stream is not
            // permanently closed: writing more data to the pipe makes it
            // readable again.
            Ok(None) => Err(StreamError::Closed),
            Err(e) => Err(StreamError::Trap(wasmtime::Error::msg(e.to_string()))),
        }
    }
}

#[async_trait::async_trait]
impl Pollable for WasiPipe {
    // A `WasiPipe` read never has to wait for data to become available: it
    // always has an immediate answer, either some bytes or a (transient)
    // EOF. Reporting "always ready" is deliberate, not a shortcut: the
    // host_call protocol requires the guest to observe EOF as soon as the
    // buffer is drained (so it knows the request payload is complete) and
    // to be able to read again once `send()` provides more data. If this
    // method instead waited for data to be available before resolving, an
    // empty buffer would never resolve as "ready to read EOF" and the guest
    // would hang forever instead of observing EOF.
    async fn ready(&mut self) {}
}

impl tokio::io::AsyncRead for WasiPipe {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.read_bytes(buf.remaining()) {
            // Filling zero bytes while resolving `Ready` is the `AsyncRead`
            // convention for EOF. Note there's no waker stored anywhere:
            // this implementation never returns `Poll::Pending`, since (like
            // `Pollable::ready` above) a read never has to wait.
            Ok(None) => Poll::Ready(Ok(())),
            Ok(Some(data)) => {
                buf.put_slice(&data);
                Poll::Ready(Ok(()))
            }
            Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;

    // Exercises the `InputStream` path, which is what's used today by both
    // the synchronous and (potential future) asynchronous WASIp1 linker, as
    // well as by WASIp2 components (see the comment on `p2_stream` above).

    #[test]
    fn input_stream_read_drains_initial_data() {
        let pipe = WasiPipe::new(b"hello world");
        let mut stream = pipe.p2_stream();

        assert_eq!(stream.read(5).unwrap(), Bytes::from_static(b"hello"));
        assert_eq!(stream.read(100).unwrap(), Bytes::from_static(b" world"));
    }

    #[test]
    fn input_stream_empty_buffer_reports_closed() {
        let pipe = WasiPipe::new(b"data");
        let mut stream = pipe.p2_stream();

        stream.read(100).unwrap();

        assert!(matches!(stream.read(10), Err(StreamError::Closed)));
    }

    // This is the behavior the host_call implementation relies on: the
    // guest drains stdin (observes EOF), invokes the `host.call` import
    // (which internally calls `WasiPipe::send`), and reads again to find
    // the host callback response on stdin. EOF must therefore be
    // transient, not a permanently closed stream. This is also exactly the
    // behavior that the default `p2_stream` implementation (going through
    // `wasmtime_wasi::p2::pipe::AsyncReadStream`) would NOT provide, which
    // is why `p2_stream` is overridden in this file.
    #[test]
    fn input_stream_readable_again_after_send() {
        let pipe = WasiPipe::new(b"request");
        let mut stream = pipe.p2_stream();

        assert_eq!(stream.read(100).unwrap(), Bytes::from_static(b"request"));
        assert!(matches!(stream.read(10), Err(StreamError::Closed)));

        pipe.send(b"host response").unwrap();

        assert_eq!(
            stream.read(100).unwrap(),
            Bytes::from_static(b"host response")
        );
        assert!(matches!(stream.read(10), Err(StreamError::Closed)));
    }

    // `send` protects the host from a guest that violates the host_call
    // protocol by never draining a previous payload: instead of letting
    // unread bytes accumulate without bound, it wipes them before
    // appending the new payload. A well-behaved guest never observes this
    // (it always drains to EOF first), but this guards against a
    // misbehaving/malicious one holding the host hostage via unbounded
    // memory growth.
    #[test]
    fn send_discards_unread_data() {
        let pipe = WasiPipe::new(b"");
        let mut stream = pipe.p2_stream();

        // Guest never reads this first payload.
        pipe.send(b"first payload, never read").unwrap();

        // A second `send` (as would happen on a second `host.call` without
        // the guest draining stdin in between) discards the first payload
        // entirely rather than concatenating with it.
        pipe.send(b"second payload").unwrap();

        assert_eq!(
            stream.read(100).unwrap(),
            Bytes::from_static(b"second payload")
        );
        assert!(matches!(stream.read(10), Err(StreamError::Closed)));
    }

    // The `StdinStream` documentation requires that "the returned stream
    // must share state with all other streams previously created", since
    // guests may create multiple handles to the same stdin. Cloning a
    // `WasiPipe` (as `Context.stdin_pipe`, held by `host_call`, and the one
    // handed to `WasiCtxBuilder::stdin` do) must observe the same buffer.
    #[test]
    fn stream_handles_share_state() {
        let pipe = WasiPipe::new(b"");
        let mut stream_a = pipe.p2_stream();
        let mut stream_b = pipe.p2_stream();

        pipe.send(b"data").unwrap();

        assert_eq!(stream_a.read(100).unwrap(), Bytes::from_static(b"data"));
        assert!(matches!(stream_b.read(10), Err(StreamError::Closed)));
    }

    // Exercises the `AsyncRead` path, only consumed today by WASIp3, not
    // used by this codebase (see the comment on `async_stream` above).

    #[tokio::test]
    async fn async_read_returns_data_then_eof() {
        let pipe = WasiPipe::new(b"hello");
        let mut reader = std::pin::Pin::from(pipe.async_stream());

        let mut buf = [0u8; 5];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Ready with zero bytes filled is the `AsyncRead` convention for
        // EOF.
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    // Same transient-EOF contract as `input_stream_readable_again_after_send`,
    // this time over the `AsyncRead` implementation itself. Note that this
    // only demonstrates that `WasiPipe`'s own `AsyncRead` impl doesn't latch
    // EOF; wrappers built on top of an `AsyncRead` (such as wasmtime-wasi's
    // `AsyncReadStream`, used by the default `p2_stream` implementation) are
    // not guaranteed to preserve this behavior, since EOF is conventionally
    // a terminal state for that trait. See the comment on `async_stream`
    // above for why this matters if WASIp3 support is ever added.
    #[tokio::test]
    async fn async_read_readable_again_after_send() {
        let pipe = WasiPipe::new(b"request");
        let mut reader = std::pin::Pin::from(pipe.async_stream());

        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"request");

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        pipe.send(b"host response").unwrap();

        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"host response");
    }

    // A `WasiPipe` read never has to wait for data: it always resolves
    // immediately, whether the buffer holds data or is empty (transient
    // EOF). See the comment on the `Pollable` impl above for why this
    // matters for the host_call protocol.
    #[tokio::test]
    async fn pollable_always_ready() {
        let pipe = WasiPipe::new(b"");
        let mut stream = pipe.p2_stream();

        stream.ready().await;

        pipe.send(b"data").unwrap();
        stream.ready().await;
    }
}
