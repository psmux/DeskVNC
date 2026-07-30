//! The transfer queue (PRD/08 §3.3): "queue, don't parallelize wildly".
//!
//! Two or three transfers run at once; every file inside one queue item (a
//! folder tree) runs sequentially so ordering is predictable. Each item owns a
//! [`CancellationToken`] so the UI's per-row `[x]` can stop exactly one
//! transfer, and closing the panel/session can stop all of them.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

/// Concurrent transfers. Three keeps a fast link busy without turning a
/// folder of small files into a thundering herd of SFTP handles.
pub const MAX_CONCURRENT_TRANSFERS: usize = 3;

/// Tracks the in-flight queue items and enforces the concurrency limit.
#[derive(Debug)]
pub struct TransferQueue {
    permits: Arc<Semaphore>,
    limit: usize,
    live: Mutex<HashMap<String, CancellationToken>>,
}

impl TransferQueue {
    /// `limit` is clamped to 1..=3, the PRD is explicit that this is not a
    /// knob users get to turn into a denial of service.
    pub fn new(limit: usize) -> Self {
        let limit = limit.clamp(1, MAX_CONCURRENT_TRANSFERS);
        Self {
            permits: Arc::new(Semaphore::new(limit)),
            limit,
            live: Mutex::new(HashMap::new()),
        }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Register a queue item and hand back its cancellation token. Registering
    /// an id that is already live returns the existing token rather than
    /// orphaning the running transfer.
    pub fn register(&self, id: &str) -> CancellationToken {
        let mut live = self.live.lock();
        live.entry(id.to_string()).or_default().clone()
    }

    /// Wait for a slot. Held for the whole of one queue item, so a folder tree
    /// occupies exactly one slot however many files it contains.
    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        // The semaphore is never closed, so this cannot fail; if it somehow
        // did, falling back to an unbounded run beats panicking.
        self.permits
            .clone()
            .acquire_owned()
            .await
            .expect("transfer semaphore is never closed")
    }

    /// Cancel one item. Returns false when the id is unknown (already
    /// finished, or never existed).
    pub fn cancel(&self, id: &str) -> bool {
        match self.live.lock().get(id) {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    /// Cancel everything, panel closed, session ended, app exiting.
    pub fn cancel_all(&self) {
        for token in self.live.lock().values() {
            token.cancel();
        }
    }

    /// Drop an item's bookkeeping once its task has emitted a terminal event.
    pub fn finish(&self, id: &str) {
        self.live.lock().remove(id);
    }

    /// Queue items that have not finished yet (queued *and* running).
    pub fn live(&self) -> usize {
        self.live.lock().len()
    }

    /// Free slots right now.
    pub fn available(&self) -> usize {
        self.permits.available_permits()
    }

    pub fn is_cancelled(&self, id: &str) -> bool {
        self.live
            .lock()
            .get(id)
            .map(|t| t.is_cancelled())
            .unwrap_or(false)
    }
}

impl Default for TransferQueue {
    fn default() -> Self {
        Self::new(MAX_CONCURRENT_TRANSFERS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[test]
    fn the_limit_is_clamped() {
        assert_eq!(TransferQueue::new(0).limit(), 1);
        assert_eq!(TransferQueue::new(2).limit(), 2);
        assert_eq!(TransferQueue::new(99).limit(), MAX_CONCURRENT_TRANSFERS);
        assert_eq!(TransferQueue::default().limit(), MAX_CONCURRENT_TRANSFERS);
    }

    #[tokio::test]
    async fn never_runs_more_than_the_limit_at_once() {
        let queue = Arc::new(TransferQueue::new(3));
        let running = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));

        let mut tasks = Vec::new();
        for _ in 0..12 {
            let queue = queue.clone();
            let running = running.clone();
            let peak = peak.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = queue.acquire().await;
                let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(5)).await;
                running.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert!(peak.load(Ordering::SeqCst) <= 3, "concurrency exceeded");
        assert_eq!(queue.available(), 3, "permits leaked");
    }

    #[test]
    fn cancel_targets_exactly_one_item() {
        let queue = TransferQueue::new(3);
        let a = queue.register("a");
        let b = queue.register("b");
        assert_eq!(queue.live(), 2);

        assert!(queue.cancel("a"));
        assert!(a.is_cancelled());
        assert!(!b.is_cancelled());
        assert!(queue.is_cancelled("a"));
        assert!(!queue.is_cancelled("b"));

        assert!(!queue.cancel("nope"));
        queue.finish("a");
        assert_eq!(queue.live(), 1);
        assert!(!queue.cancel("a"));
        assert!(!queue.is_cancelled("a"));
    }

    #[test]
    fn registering_twice_keeps_the_same_token() {
        let queue = TransferQueue::new(1);
        let first = queue.register("x");
        let second = queue.register("x");
        queue.cancel("x");
        assert!(first.is_cancelled() && second.is_cancelled());
        assert_eq!(queue.live(), 1);
    }

    #[test]
    fn cancel_all_stops_everything() {
        let queue = TransferQueue::new(3);
        let tokens: Vec<_> = ["a", "b", "c"]
            .iter()
            .map(|id| queue.register(id))
            .collect();
        queue.cancel_all();
        assert!(tokens.iter().all(|t| t.is_cancelled()));
    }
}
