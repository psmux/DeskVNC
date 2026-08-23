//! The dedicated writer task and its outbound queue (PRDRDP/00 R10,
//! PRDRDP/06 §2.4, PRDRDP/12 §3.8).
//!
//! `AsyncWriteExt::write_all` is not cancellation safe and no wrapper makes
//! it so. A `write_all` dropped part way has already put some of its bytes on
//! the wire, the peer holds half a PDU, and RDP offers no resynchronisation
//! point inside a TPKT unit, so there is no recovery short of dropping the
//! connection. The rule that follows is absolute: **no write appears inside a
//! `select!` arm anywhere in this crate**, and this module is what makes that
//! structural rather than a convention. The run loop task never holds a
//! writer, so it cannot misuse one.
//!
//! The queue is bounded at [`WRITER_QUEUE`]. An unbounded queue turns a slow
//! link into unbounded memory growth, which is the failure mode a viewer must
//! not have. A full queue parks the run loop, which stops it reading, which
//! closes the TCP receive window, which throttles the server. That is the
//! backpressure we want and it costs nothing.
//!
//! This task does no protocol work at all: an [`Outbound::Frame`] is a
//! `Bytes` and nothing else, encoded on the run loop's task before it was
//! queued. That is what keeps ordering trivially correct, because one ordered
//! channel with one consumer cannot interleave two encoders.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

/// Slots in the outbound queue.
///
/// Bounded, for the reason in this module's documentation. 64 is the same
/// order as the 256 slot command channel, far more than any single dispatch
/// produces, and small enough that a stalled socket parks the run loop within
/// a frame or two (PRDRDP/06 §2.4, PRDRDP/12 §5.1).
pub const WRITER_QUEUE: usize = 64;

/// How long the writer waits for the TLS layer to shut down cleanly.
///
/// A server that never answers must not hold the session open. PRDRDP/06 §6.4
/// budgets 500 ms for this step inside a three second whole teardown budget.
const CLOSE_BUDGET: Duration = Duration::from_millis(500);

/// One thing to put on the wire.
#[derive(Debug)]
pub enum Outbound {
    /// One whole encoded PDU. Must go out in order.
    Frame(Bytes),
    /// Drain what is already queued, then flush and shut the TLS layer down.
    ///
    /// The MCS Disconnect Provider Ultimatum (MS-RDPBCGR 2.2.2.3) is queued
    /// as a `Frame` ahead of this by whoever is tearing down, so the ordering
    /// stays in one place. This variant is only the close.
    Shutdown,
}

/// Drain `rx` onto `writer` until the channel closes or a write fails.
///
/// Returns when there is nothing more to write. The caller joins it as part
/// of the teardown budget (PRDRDP/06 §6.4).
///
/// Errors are logged rather than returned: by the time a write fails the run
/// loop has already seen, or is about to see, the same failure on the read
/// half, and that is the one the user is told about. A writer task that
/// returned an error would need a channel to return it on, which is exactly
/// the shared state this split exists to avoid.
pub async fn writer_task<W>(mut writer: W, mut rx: mpsc::Receiver<Outbound>, sent: Arc<AtomicU64>)
where
    W: AsyncWrite + Unpin,
{
    while let Some(item) = rx.recv().await {
        match item {
            Outbound::Frame(bytes) => {
                if let Err(e) = writer.write_all(&bytes).await {
                    tracing::debug!(error = %e, "rdp write failed");
                    break;
                }
                sent.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                // Flush per PDU. RDP is request and response through the whole
                // connection sequence, so a buffered Connect Initial that has
                // not reached the socket is a thirty second timeout waiting to
                // happen. The stream underneath is TCP_NODELAY already
                // (`crates/vnc-transport/src/tcp.rs` sets it), so this costs a
                // syscall, not a round trip.
                if let Err(e) = writer.flush().await {
                    tracing::debug!(error = %e, "rdp flush failed");
                    break;
                }
            }
            Outbound::Shutdown => {
                // `poll_shutdown` on a TLS stream sends close_notify. Budgeted,
                // because a server that never answers must not hold the session
                // open (PRDRDP/06 §6.4).
                match tokio::time::timeout(CLOSE_BUDGET, writer.shutdown()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => tracing::debug!(error = %e, "rdp shutdown failed"),
                    Err(_) => tracing::debug!("rdp shutdown timed out"),
                }
                break;
            }
        }
    }
    // Whatever is still queued is queued for a socket that is going away.
    // Closing rather than dropping means a sender learns about it as a closed
    // channel, which the run loop reports as `ConnectionClosed`.
    rx.close();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A writer that records what reached it, and how many times it was
    /// flushed and shut down.
    #[derive(Default, Clone)]
    struct Recorder(Arc<Mutex<RecorderInner>>);

    #[derive(Default)]
    struct RecorderInner {
        written: Vec<u8>,
        flushes: usize,
        shutdowns: usize,
    }

    impl AsyncWrite for Recorder {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.0
                .lock()
                .expect("not poisoned")
                .written
                .extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.0.lock().expect("not poisoned").flushes += 1;
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            self.0.lock().expect("not poisoned").shutdowns += 1;
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// Ordering is the property the whole split exists to guarantee, so it is
    /// the property that gets a test.
    #[tokio::test]
    async fn frames_reach_the_wire_in_the_order_they_were_queued() {
        let recorder = Recorder::default();
        let sent = Arc::new(AtomicU64::new(0));
        let (tx, rx) = mpsc::channel(WRITER_QUEUE);
        let task = tokio::spawn(writer_task(recorder.clone(), rx, sent.clone()));

        for i in 0u8..8 {
            tx.send(Outbound::Frame(Bytes::from(vec![i; 4])))
                .await
                .expect("the writer is running");
        }
        drop(tx);
        task.await.expect("the writer task does not panic");

        let inner = recorder.0.lock().expect("not poisoned");
        let expected: Vec<u8> = (0u8..8).flat_map(|i| [i; 4]).collect();
        assert_eq!(inner.written, expected);
        assert_eq!(inner.flushes, 8, "one flush per PDU");
        assert_eq!(sent.load(Ordering::Relaxed), 32, "every byte counted");
    }

    /// `Shutdown` drains what is already queued before it closes, which is
    /// what makes the MCS Disconnect Provider Ultimatum arrive rather than
    /// being thrown away with the queue.
    #[tokio::test]
    async fn shutdown_drains_what_is_already_queued_first() {
        let recorder = Recorder::default();
        let (tx, rx) = mpsc::channel(WRITER_QUEUE);
        let task = tokio::spawn(writer_task(
            recorder.clone(),
            rx,
            Arc::new(AtomicU64::new(0)),
        ));

        tx.send(Outbound::Frame(Bytes::from_static(b"ultimatum")))
            .await
            .expect("running");
        tx.send(Outbound::Shutdown).await.expect("running");
        // Anything queued after the shutdown is for a socket that is gone.
        let _ = tx.send(Outbound::Frame(Bytes::from_static(b"late"))).await;
        drop(tx);
        task.await.expect("no panic");

        let inner = recorder.0.lock().expect("not poisoned");
        assert_eq!(inner.written, b"ultimatum");
        assert_eq!(inner.shutdowns, 1);
    }

    /// A dead writer closes the channel, so the run loop's next `send`
    /// fails and it reports `ConnectionClosed` rather than queueing into a
    /// void.
    #[tokio::test]
    async fn a_finished_writer_closes_the_queue() {
        let (tx, rx) = mpsc::channel(WRITER_QUEUE);
        let task = tokio::spawn(writer_task(
            Recorder::default(),
            rx,
            Arc::new(AtomicU64::new(0)),
        ));
        tx.send(Outbound::Shutdown).await.expect("running");
        task.await.expect("no panic");
        assert!(tx.send(Outbound::Frame(Bytes::new())).await.is_err());
    }
}
