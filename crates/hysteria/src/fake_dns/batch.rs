//! Cooperative group commit on existing DNS workers; no background thread or timer.
use super::{CliError, FakeDns, Result, canonical};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock},
    time::{Duration, Instant},
};
// Match the TUN DNS worker bound; reservations include names currently being written.
const MAX_PENDING: usize = 128;
const MAX_BATCH: usize = 64;
const WINDOW: Duration = Duration::from_millis(1);
type Outcome = std::result::Result<u32, Arc<str>>;
struct Request {
    name: String,
    result: OnceLock<Outcome>,
}
#[derive(Default)]
struct State {
    running: bool,
    closing: bool,
    queue: VecDeque<Arc<Request>>,
    pending: HashMap<String, Arc<Request>>,
}
// If both locks are needed, acquire batch state before the name map.
// Disk I/O holds neither lock; `running` keeps exactly one writer active.
#[derive(Default)]
pub(super) struct Batches {
    state: Mutex<State>,
    changed: Condvar,
}
struct Leader<'a> {
    dns: &'a FakeDns,
    finished: bool,
    failure: Arc<str>,
}
impl Drop for Leader<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.dns.fail_batch(&self.failure);
        }
    }
}
fn lock_error() -> CliError {
    CliError::new("Fake-IP batch lock failed")
}
impl FakeDns {
    pub(super) fn allocate_with(
        &self,
        name: &str,
        mut persist: impl FnMut(&[String], &[String]) -> Result<()>,
    ) -> Result<u32> {
        let name = canonical(name)?;
        {
            let map = self.map.lock().map_err(|_| lock_error())?;
            if let Some(id) = map.existing(&name, self.capacity)? {
                return Ok(id);
            }
        }
        let mut state = self.batches.state.lock().map_err(|_| lock_error())?;
        if state.closing {
            return Err(CliError::new("Fake-IP resolver is stopping"));
        }
        let count = {
            let map = self.map.lock().map_err(|_| lock_error())?;
            if let Some(id) = map.existing(&name, self.capacity)? {
                return Ok(id);
            }
            map.names.len()
        };
        let request = if let Some(request) = state.pending.get(&name) {
            Arc::clone(request)
        } else {
            if state.pending.len() >= MAX_PENDING {
                return Err(CliError::new(
                    "Fake-IP pending allocation limit reached; retry later",
                ));
            }
            if count + state.pending.len() >= self.capacity {
                return Err(CliError::new(
                    "Fake-IP cache capacity is full or reserved; no address was reused",
                ));
            }
            let request = Arc::new(Request {
                name: name.clone(),
                result: OnceLock::new(),
            });
            state.pending.insert(name, Arc::clone(&request));
            state.queue.push_back(Arc::clone(&request));
            self.batches.changed.notify_all();
            request
        };
        loop {
            if let Some(result) = request.result.get() {
                return result
                    .clone()
                    .map_err(|message| CliError::new(message.as_ref()));
            }
            if state.running {
                state = self.batches.changed.wait(state).map_err(|_| lock_error())?;
            } else {
                state.running = true;
                self.lead_batch(state, &mut persist)?;
                state = self.batches.state.lock().map_err(|_| lock_error())?;
            }
        }
    }
    fn lead_batch(
        &self,
        state: MutexGuard<'_, State>,
        persist: &mut impl FnMut(&[String], &[String]) -> Result<()>,
    ) -> Result<()> {
        let mut leader = Leader {
            dns: self,
            finished: false,
            failure: Arc::from("Fake-IP batch writer failed; inspect storage and restart"),
        };
        // Declare the owned guard after Leader so it is released before failure cleanup.
        let mut state = state;
        let deadline = Instant::now() + WINDOW;
        while state.queue.len() < MAX_BATCH && !state.closing {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            state = self
                .batches
                .changed
                .wait_timeout(state, remaining)
                .map_err(|_| lock_error())?
                .0;
        }
        let size = state.queue.len().min(MAX_BATCH);
        let requests: Vec<_> = state.queue.drain(..size).collect();
        if requests.is_empty() {
            state.running = false;
            leader.finished = true;
            self.batches.changed.notify_all();
            return Ok(());
        }
        let snapshot = Arc::clone(&self.map.lock().map_err(|_| lock_error())?.names);
        drop(state);
        let names: Vec<_> = requests
            .iter()
            .map(|request| request.name.clone())
            .collect();
        if let Err(error) = persist(&snapshot, &names) {
            leader.failure = Arc::from(error.to_string());
            return Err(error);
        }
        drop(snapshot);
        // Publication and reservation release are atomic relative to new admissions.
        let mut state = self.batches.state.lock().map_err(|_| lock_error())?;
        let mut map = self.map.lock().map_err(|_| lock_error())?;
        for request in requests {
            let id = u32::try_from(map.names.len() + 1)
                .map_err(|_| CliError::new("Fake-IP index overflow"))?;
            Arc::make_mut(&mut map.names).push(request.name.clone());
            map.ids.insert(request.name.clone(), id);
            state.pending.remove(&request.name);
            let _ = request.result.set(Ok(id));
        }
        let count = map.names.len();
        drop(map);
        state.running = false;
        leader.finished = true;
        self.batches.changed.notify_all();
        drop(state);
        self.warn_capacity(count);
        Ok(())
    }
    fn fail_batch(&self, message: &Arc<str>) {
        let mut state = self
            .batches
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allocation_failed = true;
        for (_, request) in state.pending.drain() {
            let _ = request.result.set(Err(Arc::clone(message)));
        }
        state.queue.clear();
        state.running = false;
        self.batches.state.clear_poison();
        self.batches.changed.notify_all();
    }
    pub(super) fn close_batches(&self) -> Result<()> {
        let mut state = self.batches.state.lock().map_err(|_| lock_error())?;
        state.closing = true;
        while let Some(request) = state.queue.pop_front() {
            state.pending.remove(&request.name);
            let _ = request
                .result
                .set(Err(Arc::from("Fake-IP resolver is stopping")));
        }
        self.batches.changed.notify_all();
        while state.running {
            state = self.batches.changed.wait(state).map_err(|_| lock_error())?;
        }
        let mut map = self.map.lock().map_err(|_| lock_error())?;
        if !map.closed {
            map.closed = true;
            self.cache_lock.unlock()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake_dns::FakeDnsConfig;

    fn queued(dns: &FakeDns, count: usize) -> Vec<Arc<Request>> {
        let mut state = dns.batches.state.lock().unwrap();
        (0..count)
            .map(|i| {
                let request = Arc::new(Request {
                    name: format!("batch{i}.example"),
                    result: OnceLock::new(),
                });
                state
                    .pending
                    .insert(request.name.clone(), Arc::clone(&request));
                state.queue.push_back(Arc::clone(&request));
                request
            })
            .collect()
    }
    fn run(
        dns: &FakeDns,
        mut persist: impl FnMut(&[String], &[String]) -> Result<()>,
    ) -> Result<()> {
        let mut state = dns.batches.state.lock().unwrap();
        state.running = true;
        dns.lead_batch(state, &mut persist)
    }
    #[test]
    fn batches_are_bounded_and_publish_only_after_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            ..Default::default()
        };
        let dns = FakeDns::open(&config).unwrap();
        let requests = queued(&dns, MAX_BATCH + 1);
        run(&dns, |old, new| {
            assert_eq!(new.len(), MAX_BATCH);
            assert!(requests.iter().all(|r| r.result.get().is_none()));
            assert!(dns.map.lock().unwrap().names.is_empty());
            dns.persist(old, new)
        })
        .unwrap();
        assert!(requests[MAX_BATCH].result.get().is_none());
        run(&dns, |old, new| {
            assert_eq!(new.len(), 1);
            dns.persist(old, new)
        })
        .unwrap();
        for (i, request) in requests.iter().enumerate() {
            assert_eq!(
                request.result.get().unwrap().as_ref().unwrap(),
                &(u32::try_from(i).unwrap() + 1)
            );
        }
        dns.close().unwrap();
        let reopened = FakeDns::open(&config).unwrap();
        for (i, request) in requests.iter().enumerate() {
            assert_eq!(
                reopened.allocate(&request.name).unwrap(),
                u32::try_from(i).unwrap() + 1
            );
        }
    }
    #[test]
    fn uncertain_batch_fails_all_waiters_and_preserves_persisted_ids() {
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            ..Default::default()
        };
        let dns = FakeDns::open(&config).unwrap();
        let requests = queued(&dns, MAX_BATCH + 1);
        assert!(
            run(&dns, |old, new| {
                dns.persist(old, new)?;
                Err(CliError::new("injected directory sync failure"))
            })
            .is_err()
        );
        assert!(requests.iter().all(|r| r.result.get().unwrap().is_err()));
        assert!(dns.allocate("other.example").is_err());
        dns.close().unwrap();
        let reopened = FakeDns::open(&config).unwrap();
        assert_eq!(reopened.map.lock().unwrap().names.len(), MAX_BATCH);
        assert_eq!(
            reopened.allocate("other.example").unwrap(),
            u32::try_from(MAX_BATCH).unwrap() + 1
        );
    }
    #[test]
    fn panicking_writer_releases_waiters_and_close() {
        let dir = tempfile::tempdir().unwrap();
        let dns = FakeDns::open(&FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            ..Default::default()
        })
        .unwrap();
        let requests = queued(&dns, MAX_BATCH + 1);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = run(&dns, |_, _| panic!("injected writer panic"));
        }));
        assert!(result.is_err());
        assert!(requests.iter().all(|r| r.result.get().unwrap().is_err()));
        assert!(!dns.batches.state.lock().unwrap().running);
        dns.close().unwrap();
    }
    #[test]
    fn pending_limit_is_recoverable_and_close_waits_for_inflight_only() {
        use std::sync::mpsc;
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            ..Default::default()
        };
        let dns = Arc::new(FakeDns::open(&config).unwrap());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let writer_dns = Arc::clone(&dns);
        let writer = std::thread::spawn(move || {
            writer_dns.allocate_with("inflight.example", |old, new| {
                started_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                writer_dns.persist(old, new)
            })
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let requests = queued(&dns, MAX_PENDING - 1);
        assert!(dns.allocate("overflow.example").is_err());
        assert!(!dns.map.lock().unwrap().allocation_failed);
        let closing_dns = Arc::clone(&dns);
        let (closed_tx, closed_rx) = mpsc::channel();
        let closer = std::thread::spawn(move || {
            closing_dns.close().unwrap();
            closed_tx.send(()).unwrap();
        });
        let deadline = Instant::now() + Duration::from_secs(5);
        while !dns.batches.state.lock().unwrap().closing && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let closing = dns.batches.state.lock().unwrap().closing;
        let prematurely_closed = closed_rx.try_recv().is_ok();
        let cache_locked = FakeDns::open(&config).is_err();
        release_tx.send(()).unwrap();
        assert_eq!(writer.join().unwrap().unwrap(), 1);
        closer.join().unwrap();
        assert!(closing && !prematurely_closed && cache_locked);
        assert!(requests.iter().all(|r| r.result.get().unwrap().is_err()));
        let reopened = FakeDns::open(&config).unwrap();
        assert_eq!(reopened.map.lock().unwrap().names.len(), 1);
        assert_eq!(reopened.allocate("next.example").unwrap(), 2);
    }
}
