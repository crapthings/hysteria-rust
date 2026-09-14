use std::{
    thread,
    time::{Duration, Instant},
};

pub fn join_until<T>(task: thread::JoinHandle<T>) -> T {
    assert!(
        wait_finished(&task, Duration::from_secs(35)),
        "fixture thread did not finish before deadline"
    );
    task.join().unwrap()
}

fn wait_finished<T>(task: &thread::JoinHandle<T>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !task.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
    true
}

#[test]
fn unresponsive_thread_wait_is_bounded() {
    let (release, blocked) = std::sync::mpsc::channel::<()>();
    let task = thread::spawn(move || {
        let _ = blocked.recv();
    });
    let finished = wait_finished(&task, Duration::from_millis(40));
    // Release and join even if the assertion fails, so this regression leaks no worker.
    drop(release);
    task.join().unwrap();
    assert!(!finished);
}
