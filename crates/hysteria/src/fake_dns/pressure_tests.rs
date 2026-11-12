//! Opt-in Linux release measurements. Only private temporary files and child processes are used.
use super::*;
use hickory_resolver::proto::{op::Query, rr::Name};
use std::{
    process::Command,
    time::{Duration, Instant},
};

fn request(name: &str) -> Vec<u8> {
    let mut query = Message::query();
    query
        .queries
        .push(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    query.to_vec().unwrap()
}
fn response(dns: &FakeDns, name: &str, packet: &[u8]) -> ResponseCode {
    let reply = Message::from_vec(&dns.answer(packet).unwrap().unwrap()).unwrap();
    if reply.metadata.response_code == ResponseCode::NoError {
        let RData::A(address) = reply.answers[0].data else {
            panic!("missing address")
        };
        assert_eq!(
            dns.reverse(address.0.into()).unwrap().as_deref(),
            Some(name)
        );
    }
    reply.metadata.response_code
}
fn directory() -> tempfile::TempDir {
    if let Some(path) = std::env::var_os("HYSTERIA_FAKE_IP_BENCH_DIR") {
        fs::create_dir_all(&path).unwrap();
        tempfile::tempdir_in(path).unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}
fn child(test: &str, mode: &str, path: &std::path::Path) -> Command {
    // Ignore SIGXFSZ only in the dedicated child so the limited write returns EFBIG.
    // Positional arguments are passed separately, never interpolated into shell code.
    let mut command = if mode == "file-size-limit" {
        let mut shell = Command::new("/bin/sh");
        shell.args(["-c", "trap '' XFSZ; exec \"$@\"", "fake-ip-test"]);
        shell.arg(std::env::current_exe().unwrap());
        shell
    } else {
        Command::new(std::env::current_exe().unwrap())
    };
    command
        .args([test, "--exact", "--ignored", "--nocapture"])
        .env("HYSTERIA_FAKE_IP_CHILD_MODE", mode)
        .env("HYSTERIA_FAKE_IP_CHILD_DIR", path);
    command
}
fn run_child(command: &mut Command, marker: &str) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|line| line.starts_with(marker))
        .expect("missing child result");
    println!("{line}");
}

#[test]
#[ignore = "explicit bounded Linux release DNS-handler pressure measurement"]
fn measure_linux_release_dns_pressure() {
    assert!(
        !cfg!(debug_assertions),
        "use --release for this measurement"
    );
    for count in [4096, 16_384, 64_000] {
        let directory = directory();
        run_child(
            &mut child(
                "fake_dns::pressure_tests::cold_dns_child",
                &count.to_string(),
                directory.path(),
            ),
            "FAKE_IP_PRESSURE ",
        );
    }
    for mode in ["file-size-limit", "permission-denied"] {
        let directory = directory();
        let mut command = child(
            "fake_dns::pressure_tests::storage_failure_child",
            mode,
            directory.path(),
        );
        if mode == "permission-denied" {
            use std::os::unix::{fs::MetadataExt, process::CommandExt};
            if fs::metadata(directory.path()).unwrap().uid() == 0 {
                // Drop privilege only in this test child. Change only its private directory.
                std::os::unix::fs::chown(directory.path(), Some(65_534), Some(65_534)).unwrap();
                command.uid(65_534).gid(65_534);
            }
        }
        run_child(&mut command, "STORAGE_RECOVERY ");
    }
}

fn percentile(samples: &[f64], percent: usize) -> f64 {
    samples[(samples.len() * percent).div_ceil(100).saturating_sub(1)]
}
fn usage() -> (Duration, u64) {
    static TICKS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let frequency = *TICKS.get_or_init(|| {
        let result = Command::new("getconf").arg("CLK_TCK").output().unwrap();
        assert!(result.status.success());
        let frequency: u64 = String::from_utf8(result.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!((1..=1_000_000).contains(&frequency));
        frequency
    });
    let stat = fs::read_to_string("/proc/self/stat").unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let ticks = fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap();
    let cpu = Duration::from_secs(ticks / frequency)
        + Duration::from_nanos((ticks % frequency) * 1_000_000_000 / frequency);
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    (cpu, rss)
}

fn measured_answer(dns: &FakeDns, name: &str) -> f64 {
    let packet = request(name);
    let start = Instant::now();
    let bytes = dns.answer(&packet).unwrap().unwrap();
    let elapsed = start.elapsed().as_secs_f64() * 1_000_000.0;
    let reply = Message::from_vec(&bytes).unwrap();
    assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
    let RData::A(address) = reply.answers[0].data else {
        panic!("missing A")
    };
    assert_eq!(
        dns.reverse(address.0.into()).unwrap().as_deref(),
        Some(name)
    );
    elapsed
}
fn phase(
    dns: &Arc<FakeDns>,
    prefix: &str,
    threads: usize,
    each: usize,
    cached: bool,
) -> serde_json::Value {
    let before = fs::metadata(&dns.path).unwrap().len();
    let before_stats = *dns.persist_stats.lock().unwrap();
    let cpu = usage().0;
    let start = Instant::now();
    let mut samples = if threads == 1 {
        (0..each)
            .map(|i| {
                measured_answer(
                    dns,
                    &if cached {
                        "seed-00000.measurement.invalid".to_owned()
                    } else {
                        format!("{prefix}-{i:04}.measurement.invalid")
                    },
                )
            })
            .collect::<Vec<_>>()
    } else {
        let tasks: Vec<_> = (0..threads)
            .map(|thread| {
                let dns = Arc::clone(dns);
                let prefix = prefix.to_owned();
                std::thread::spawn(move || {
                    (0..each)
                        .map(|i| {
                            measured_answer(
                                &dns,
                                &format!("{prefix}-{:04}.measurement.invalid", thread * each + i),
                            )
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        tasks
            .into_iter()
            .flat_map(|task| task.join().unwrap())
            .collect()
    };
    let wall = start.elapsed();
    let (after_cpu, rss) = usage();
    samples.sort_by(f64::total_cmp);
    let queries = u64::try_from(threads * each).unwrap();
    let after = fs::metadata(&dns.path).unwrap().len();
    let after_stats = *dns.persist_stats.lock().unwrap();
    let commits = after_stats.0 - before_stats.0;
    let logical_bytes = after_stats.1 - before_stats.1;
    if cached {
        assert_eq!(before, after);
        assert_eq!(commits, 0);
    } else {
        let increase =
            u64::try_from(format!("{prefix}-0000.measurement.invalid").len() + 3).unwrap();
        assert_eq!(after, before + queries * increase);
        assert!(commits > 0 && commits <= queries);
    }
    serde_json::json!({"name":prefix,"queries":queries,"threads":threads,"p50_us":percentile(&samples,50),"p95_us":percentile(&samples,95),"p99_us":percentile(&samples,99),
        "wall_ms":wall.as_secs_f64()*1000.0,"driver_and_handler_cpu_ms":(after_cpu-cpu).as_secs_f64()*1000.0,"process_peak_rss_kib":rss,
        "snapshot_commits":commits,"logical_snapshot_bytes":logical_bytes,"final_cache_bytes":after})
}
#[test]
#[ignore = "child helper for the Linux pressure measurement"]
fn cold_dns_child() {
    let Ok(mode) = std::env::var("HYSTERIA_FAKE_IP_CHILD_MODE") else {
        return;
    };
    if mode == "mixed" || mode == "sustained" {
        mixed_pressure(mode == "sustained");
        return;
    }
    let count: usize = mode.parse().unwrap();
    let root = PathBuf::from(std::env::var_os("HYSTERIA_FAKE_IP_CHILD_DIR").unwrap());
    let config = FakeDnsConfig {
        cache: root.join("cache.json"),
        max_entries: MAX_CAPACITY,
    };
    let names = (0..count)
        .map(|i| format!("seed-{i:05}.measurement.invalid"))
        .collect();
    fs::write(
        &config.cache,
        serde_json::to_vec(&Stored { version: 1, names }).unwrap(),
    )
    .unwrap();
    let dns = Arc::new(FakeDns::open(&config).unwrap());
    let serial = phase(&dns, "serial", 1, 64, false);
    let burst = phase(&dns, "burst", 16, 8, false);
    let warm = phase(&dns, "warm", 1, 2048, true);
    assert_eq!(inspect_cache(&config.cache).unwrap(), count + 192);
    dns.close().unwrap();
    let reopened = FakeDns::open(&config).unwrap();
    assert_eq!(
        reopened.allocate("seed-00000.measurement.invalid").unwrap(),
        1
    );
    assert_eq!(inspect_cache(&config.cache).unwrap(), count + 192);
    println!(
        "FAKE_IP_PRESSURE {}",
        serde_json::json!({"seed_entries":count,"final_entries":count+192,"capacity":MAX_CAPACITY,"debug_assertions":cfg!(debug_assertions),"serial":serial,"burst":burst,"warm":warm,"reopen_passed":true})
    );
}

enum Restriction {
    FileSize {
        saved: String,
    },
    Directory {
        path: PathBuf,
        permissions: fs::Permissions,
    },
}
fn file_limit(value: Option<&str>) -> String {
    let mut command = Command::new("prlimit");
    command.args(["--pid", &std::process::id().to_string()]);
    if let Some(value) = value {
        command.arg(format!("--fsize={value}:"));
    } else {
        command.args(["--fsize", "--output=SOFT", "--noheadings", "--raw"]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
impl Restriction {
    fn new(mode: &str, directory: &std::path::Path) -> Self {
        if mode == "permission-denied" {
            use std::os::unix::fs::PermissionsExt;
            let permissions = fs::metadata(directory).unwrap().permissions();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o500)).unwrap();
            return Self::Directory {
                path: directory.to_path_buf(),
                permissions,
            };
        }
        assert_eq!(mode, "file-size-limit");
        let saved = file_limit(None);
        file_limit(Some("16"));
        Self::FileSize { saved }
    }
}
impl Drop for Restriction {
    fn drop(&mut self) {
        match self {
            Self::Directory { path, permissions } => {
                fs::set_permissions(path, permissions.clone()).unwrap();
            }
            Self::FileSize { saved } => {
                file_limit(Some(saved));
            }
        }
    }
}
#[test]
#[ignore = "isolated child helper; never alter the parent test process limits"]
fn storage_failure_child() {
    let Ok(mode) = std::env::var("HYSTERIA_FAKE_IP_CHILD_MODE") else {
        return;
    };
    let root = PathBuf::from(std::env::var_os("HYSTERIA_FAKE_IP_CHILD_DIR").unwrap());
    let config = FakeDnsConfig {
        cache: root.join("cache.json"),
        ..Default::default()
    };
    let dns = FakeDns::open(&config).unwrap();
    assert_eq!(dns.allocate("known.example").unwrap(), 1);
    let before = fs::read(&config.cache).unwrap();
    let restriction = Restriction::new(&mode, &root);
    assert_eq!(
        response(&dns, "blocked.example", &request("blocked.example")),
        ResponseCode::ServFail
    );
    assert_eq!(
        response(&dns, "known.example", &request("known.example")),
        ResponseCode::NoError
    );
    assert_eq!(fs::read(&config.cache).unwrap(), before);
    drop(restriction);
    assert!(
        dns.allocate("fresh.example").is_err(),
        "new allocations remain stopped even after restoring access"
    );
    dns.close().unwrap();
    let dns = FakeDns::open(&config).unwrap();
    assert_eq!(dns.allocate("known.example").unwrap(), 1);
    assert_eq!(dns.allocate("fresh.example").unwrap(), 2);
    println!(
        "STORAGE_RECOVERY {}",
        serde_json::json!({"mode":mode,"old_file_unchanged":true,"known_mapping_available":true,"new_allocation_stopped_until_restart":true,"restart_preserves_ids":true})
    );
}

#[test]
#[ignore = "explicit bounded Linux release mixed DNS measurement"]
fn measure_linux_release_mixed_dns() {
    assert!(
        !cfg!(debug_assertions),
        "use --release for this measurement"
    );
    let directory = directory();
    run_child(
        &mut child(
            "fake_dns::pressure_tests::cold_dns_child",
            "mixed",
            directory.path(),
        ),
        "FAKE_IP_MIXED ",
    );
}

#[test]
#[ignore = "explicit approximately one-minute Linux release mixed DNS measurement"]
fn measure_linux_release_sustained_dns() {
    assert!(
        !cfg!(debug_assertions),
        "use --release for this measurement"
    );
    let directory = directory();
    run_child(
        &mut child(
            "fake_dns::pressure_tests::cold_dns_child",
            "sustained",
            directory.path(),
        ),
        "FAKE_IP_MIXED ",
    );
}

fn mixed_pressure(sustained: bool) {
    use std::sync::{Barrier, atomic::AtomicUsize};
    let root = PathBuf::from(std::env::var_os("HYSTERIA_FAKE_IP_CHILD_DIR").unwrap());
    let config = FakeDnsConfig {
        cache: root.join("cache.json"),
        max_entries: MAX_CAPACITY,
    };
    let names = (0..64_000)
        .map(|i| format!("seed-{i:05}.measurement.invalid"))
        .collect();
    fs::write(
        &config.cache,
        serde_json::to_vec(&Stored { version: 1, names }).unwrap(),
    )
    .unwrap();
    let dns = Arc::new(FakeDns::open(&config).unwrap());
    let before = *dns.persist_stats.lock().unwrap();
    let barrier = Arc::new(Barrier::new(16));
    let active = Arc::new(AtomicUsize::new(8));
    let cpu = usage().0;
    let start = Instant::now();
    let tasks: Vec<_> = (0..16)
        .map(|thread| {
            let dns = Arc::clone(&dns);
            let barrier = Arc::clone(&barrier);
            let active = Arc::clone(&active);
            std::thread::spawn(move || mixed_worker(&dns, &barrier, &active, thread, sustained))
        })
        .collect();
    let mut cold = Vec::new();
    let mut warm = Vec::new();
    let mut overlap = Vec::new();
    for task in tasks {
        let (is_cold, samples, overlapping) = task.join().unwrap();
        if is_cold {
            cold.extend(samples);
        } else {
            warm.extend(samples);
        }
        overlap.extend(overlapping);
    }
    let wall = start.elapsed();
    let (after_cpu, rss) = usage();
    let after = *dns.persist_stats.lock().unwrap();
    assert!(!overlap.is_empty());
    assert_eq!(inspect_cache(&config.cache).unwrap(), 64_512);
    dns.close().unwrap();
    let reopened = FakeDns::open(&config).unwrap();
    assert_eq!(
        dns.map.lock().unwrap().ids,
        reopened.map.lock().unwrap().ids
    );
    assert!((1..=512).contains(&(after.0 - before.0)));
    let summary = |mut samples: Vec<f64>| {
        samples.sort_by(f64::total_cmp);
        serde_json::json!({"queries":samples.len(),"p50_us":percentile(&samples,50),"p95_us":percentile(&samples,95),"p99_us":percentile(&samples,99)})
    };
    println!(
        "FAKE_IP_MIXED {}",
        serde_json::json!({"seed_entries":64000,"final_entries":64512,"sustained":sustained,
        "cold":summary(cold),"warm":summary(warm),"warm_while_cold_workers_active":summary(overlap),
        "snapshot_commits":after.0-before.0,"logical_snapshot_bytes":after.1-before.1,
        "wall_ms":wall.as_secs_f64()*1000.0,"driver_and_handler_cpu_ms":(after_cpu-cpu).as_secs_f64()*1000.0,
        "process_peak_rss_kib":rss,"all_new_ids_preserved_on_reopen":true,"all_seed_ids_preserved_on_reopen":true})
    );
}

fn mixed_worker(
    dns: &FakeDns,
    barrier: &std::sync::Barrier,
    active: &std::sync::atomic::AtomicUsize,
    thread: usize,
    sustained: bool,
) -> (bool, Vec<f64>, Vec<f64>) {
    use std::sync::atomic::Ordering;
    barrier.wait();
    let mut samples = Vec::new();
    let mut overlapping = Vec::new();
    let cold = thread < 8;
    let queries = if cold {
        64
    } else if sustained {
        64_000
    } else {
        4096
    };
    for i in 0..queries {
        let name = if cold {
            format!("mixed-{thread}-{i}.measurement.invalid")
        } else {
            format!(
                "seed-{:05}.measurement.invalid",
                (thread * 4096 + i) % 64_000
            )
        };
        let concurrent = active.load(Ordering::Acquire) > 0;
        let elapsed = measured_answer(dns, &name);
        samples.push(elapsed);
        if !cold && concurrent {
            overlapping.push(elapsed);
        }
        if cold && sustained {
            std::thread::sleep(Duration::from_secs(1));
        } else if !cold {
            std::thread::sleep(Duration::from_micros(if sustained { 1000 } else { 100 }));
        }
    }
    if cold {
        active.fetch_sub(1, Ordering::Release);
    }
    (cold, samples, overlapping)
}
