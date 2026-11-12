//! Persistent synthetic DNS addresses. Never recycle an address to a different name.
use crate::{CliError, Result};
use hickory_resolver::proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    sync::{Arc, Mutex},
};
mod batch;

pub(crate) const DEFAULT_CAPACITY: usize = 4096;
pub(crate) const MAX_CAPACITY: usize = 65_536;
const MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
fn default_capacity() -> usize {
    DEFAULT_CAPACITY
}
const V4: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const V6: u128 = 0xfd00_0198_0018_0000_0000_0000_0000_0000;
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FakeDnsConfig {
    pub cache: PathBuf,
    #[serde(default = "default_capacity")]
    pub max_entries: usize,
}
impl Default for FakeDnsConfig {
    fn default() -> Self {
        Self {
            cache: PathBuf::new(),
            max_entries: DEFAULT_CAPACITY,
        }
    }
}
impl FakeDnsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.cache.as_os_str().is_empty() {
            return Err(CliError::new("tun.dns.cache is required"));
        }
        if !(1..=MAX_CAPACITY).contains(&self.max_entries) {
            return Err(CliError::new(
                "tun.dns.maxEntries must be between 1 and 65536",
            ));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    names: Vec<String>,
}
struct Map {
    closed: bool,
    names: Arc<Vec<String>>,
    ids: HashMap<String, u32>,
    allocation_failed: bool,
}
impl Map {
    fn existing(&self, name: &str, capacity: usize) -> Result<Option<u32>> {
        if self.closed {
            return Err(CliError::new("Fake-IP resolver is stopped"));
        }
        if let Some(id) = self.ids.get(name) {
            return Ok(Some(*id));
        }
        if self.allocation_failed {
            return Err(CliError::new(
                "Fake-IP allocation stopped after a persistence failure; inspect storage and restart",
            ));
        }
        if self.names.len() >= capacity {
            return Err(CliError::new("Fake-IP cache full; no address was reused"));
        }
        Ok(None)
    }
}
#[derive(Serialize)]
struct StoredView<'a> {
    version: u8,
    names: NamesView<'a>,
}
struct NamesView<'a> {
    existing: &'a [String],
    additional: &'a [String],
}
impl Serialize for NamesView<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut sequence =
            serializer.serialize_seq(Some(self.existing.len() + self.additional.len()))?;
        for name in self.existing {
            sequence.serialize_element(name)?;
        }
        for name in self.additional {
            sequence.serialize_element(name)?;
        }
        sequence.end()
    }
}
pub(crate) struct FakeDns {
    capacity: usize,
    batches: batch::Batches,
    #[cfg(test)]
    persist_stats: Mutex<(u64, u64)>,
    capacity_warned: std::sync::atomic::AtomicBool,
    cache_lock: fs::File,
    reported: std::sync::atomic::AtomicBool,
    path: PathBuf,
    map: Mutex<Map>,
}
/// Whether an address belongs to the reserved synthetic pools (not proof of an allocated mapping).
#[must_use]
pub fn is_fake_address(ip: IpAddr) -> bool {
    is_fake(ip)
}
pub(crate) fn pool_addresses() -> [IpAddr; 2] {
    [Ipv4Addr::from(V4 + 1).into(), Ipv6Addr::from(V6 + 1).into()]
}
pub(crate) fn is_fake(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => u32::from(ip) & 0xfffe_0000 == V4,
        IpAddr::V6(ip) => u128::from(ip) & !0xffff_ffff == V6,
    }
}
fn index(ip: IpAddr) -> Option<usize> {
    if !is_fake(ip) {
        return None;
    }
    let id = match ip {
        IpAddr::V4(ip) => u32::from(ip) - V4,
        IpAddr::V6(ip) => u32::try_from(u128::from(ip) - V6).ok()?,
    };
    usize::try_from(id).ok()?.checked_sub(1)
}
impl FakeDns {
    pub(crate) fn open(config: &FakeDnsConfig) -> Result<Self> {
        config.validate()?;
        let mut lock_path = config.cache.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        if fs::symlink_metadata(&lock_path).is_ok_and(|meta| !meta.is_file()) {
            return Err(CliError::new("Fake-IP lock must be a regular file"));
        }
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(lock_path)?;
        lock.try_lock()
            .map_err(|_| CliError::new("Fake-IP cache is already in use or cannot be locked"))?;
        let map = load_map(&config.cache)?;
        if map.names.len() > config.max_entries {
            return Err(CliError::new(
                "Fake-IP cache exceeds tun.dns.maxEntries; raise the limit instead of truncating mappings",
            ));
        }
        let count = map.names.len();
        let dns = Self {
            capacity: config.max_entries,
            batches: batch::Batches::default(),
            #[cfg(test)]
            persist_stats: Mutex::new((0, 0)),
            capacity_warned: std::sync::atomic::AtomicBool::new(false),
            cache_lock: lock,
            reported: std::sync::atomic::AtomicBool::new(false),
            path: config.cache.clone(),
            map: Mutex::new(map),
        };
        // Verify persistence before changing interfaces/routes; never announce unpersisted IPs.
        dns.persist(
            &dns.map
                .lock()
                .map_err(|_| CliError::new("Fake-IP cache lock failed"))?
                .names,
            &[],
        )?;
        dns.warn_capacity(count);
        Ok(dns)
    }
    pub(crate) fn close(&self) -> Result<()> {
        self.close_batches()
    }
    fn persist(&self, names: &[String], additional: &[String]) -> Result<()> {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        {
            let mut buffered = std::io::BufWriter::with_capacity(64 * 1024, file.as_file_mut());
            serde_json::to_writer(
                &mut buffered,
                &StoredView {
                    version: 1,
                    names: NamesView {
                        existing: names,
                        additional,
                    },
                },
            )
            .map_err(|_| {
                CliError::new(
                    "cannot write Fake-IP cache snapshot; check storage space and permissions",
                )
            })?;
            buffered.flush()?;
        }
        file.as_file().sync_all()?;
        #[cfg(test)]
        let written_bytes = file.as_file().metadata()?.len();
        file.persist(&self.path)
            .map_err(|_| CliError::new("cannot persist Fake-IP cache"))?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        #[cfg(test)]
        {
            let mut stats = self.persist_stats.lock().unwrap();
            stats.0 += 1;
            stats.1 += written_bytes;
        }
        Ok(())
    }
    pub(crate) fn reverse(&self, ip: IpAddr) -> Result<Option<String>> {
        let Some(index) = index(ip) else {
            if is_fake(ip) {
                return Err(CliError::new("unknown synthetic address"));
            }
            return Ok(None);
        };
        self.map
            .lock()
            .map_err(|_| CliError::new("Fake-IP cache lock failed"))?
            .names
            .get(index)
            .cloned()
            .map(Some)
            .ok_or_else(|| CliError::new("unknown synthetic address; refusing to forward it"))
    }
    fn allocate(&self, name: &str) -> Result<u32> {
        self.allocate_with(name, |names, additional| self.persist(names, additional))
    }
    fn warn_capacity(&self, count: usize) {
        if count * 10 >= self.capacity * 9
            && !self
                .capacity_warned
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            eprintln!(
                "Fake-IP capacity warning: {count}/{} mappings; review tun.dns.maxEntries and storage before adding domains. Addresses are never recycled.",
                self.capacity
            );
        }
    }
    /// None means a non-address query should go through the configured proxy DNS path.
    pub(crate) fn answer(&self, bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let query = Message::from_vec(bytes).map_err(|_| CliError::new("invalid DNS query"))?;
        if query.metadata.message_type != MessageType::Query
            || query.metadata.op_code != OpCode::Query
            || query.queries.len() != 1
        {
            return Err(CliError::new("expected one standard DNS question"));
        }
        let question = &query.queries[0];
        let mut reply = Message::response(query.metadata.id, OpCode::Query);
        reply.queries.clone_from(&query.queries);
        reply.metadata.recursion_desired = query.metadata.recursion_desired;
        reply.metadata.recursion_available = true;
        if question.query_class() != DNSClass::IN {
            reply.metadata.response_code = ResponseCode::Refused;
            return reply
                .to_vec()
                .map(Some)
                .map_err(|_| CliError::new("cannot encode DNS reply"));
        }
        match question.query_type() {
            RecordType::A | RecordType::AAAA => match self.allocate(&question.name().to_ascii()) {
                Ok(id) => {
                    let data = if question.query_type() == RecordType::A {
                        RData::A(A(Ipv4Addr::from(V4 + id)))
                    } else {
                        RData::AAAA(AAAA(Ipv6Addr::from(V6 + u128::from(id))))
                    };
                    reply
                        .answers
                        .push(Record::from_rdata(question.name().clone(), 60, data));
                }
                Err(error) => {
                    if !self
                        .reported
                        .swap(true, std::sync::atomic::Ordering::Relaxed)
                    {
                        eprintln!("Fake-IP allocation failed: {error}");
                    }
                    reply.metadata.response_code = ResponseCode::ServFail;
                }
            },
            // Address hints in HTTPS/SVCB/ANY responses would bypass reverse mapping.
            RecordType::HTTPS | RecordType::SVCB | RecordType::ANY => {}
            _ => return Ok(None),
        }
        reply
            .to_vec()
            .map(Some)
            .map_err(|_| CliError::new("cannot encode DNS reply"))
    }
}
/// Read-only validation shared with runtime loading; never acquire a lock or persist.
pub(crate) fn inspect_cache(path: &std::path::Path) -> Result<usize> {
    Ok(load_map(path)?.names.len())
}
/// A read-only snapshot for one diagnostic name; never expose unrelated domain history.
pub(crate) struct MappingSnapshot {
    pub entries: usize,
    pub addresses: Option<[IpAddr; 2]>,
}
pub(crate) fn inspect_mapping(path: &std::path::Path, name: &str) -> Result<MappingSnapshot> {
    // Unlike pre-start inspection, a live probe requires an existing cache.
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(CliError::new(
            "Fake-IP cache must be an existing regular file",
        ));
    }
    let map = load_map(path)?;
    let addresses = map.ids.get(&canonical(name)?).map(|id| {
        [
            IpAddr::V4(Ipv4Addr::from(V4 + id)),
            IpAddr::V6(Ipv6Addr::from(V6 + u128::from(*id))),
        ]
    });
    Ok(MappingSnapshot {
        entries: map.names.len(),
        addresses,
    })
}

fn load_map(path: &std::path::Path) -> Result<Map> {
    let names = match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(CliError::new(
                    "Fake-IP cache must be a regular file, not a symlink",
                ));
            }
            let mut bytes = Vec::new();
            fs::File::open(path)?
                .take(MAX_FILE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_FILE_BYTES {
                return Err(CliError::new("Fake-IP cache exceeds 32 MiB"));
            }
            let stored: Stored = serde_json::from_slice(&bytes)
                .map_err(|_| CliError::new("invalid Fake-IP cache; refusing to reset mappings"))?;
            if stored.version != 1 || stored.names.len() > MAX_CAPACITY {
                return Err(CliError::new("unsupported Fake-IP cache"));
            }
            stored.names
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(error) => return Err(error.into()),
    };
    let mut ids = HashMap::new();
    for (i, name) in names.iter().enumerate() {
        if canonical(name)? != *name
            || ids
                .insert(name.clone(), u32::try_from(i + 1).unwrap_or(0))
                .is_some()
        {
            return Err(CliError::new("invalid or duplicate Fake-IP cache name"));
        }
    }
    Ok(Map {
        closed: false,
        names: Arc::new(names),
        ids,
        allocation_failed: false,
    })
}
fn canonical(name: &str) -> Result<String> {
    let name = idna::domain_to_ascii(name.trim_end_matches('.'))
        .map_err(|_| CliError::new("invalid DNS name"))?
        .to_ascii_lowercase();
    rustls::pki_types::ServerName::try_from(name.as_str())
        .map_err(|_| CliError::new("invalid DNS name"))?;
    if name.parse::<IpAddr>().is_ok() {
        return Err(CliError::new("DNS name must not be an IP literal"));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{op::Query, rr::Name};
    fn query(name: &str, kind: RecordType) -> Vec<u8> {
        let mut q = Message::query();
        q.queries
            .push(Query::query(Name::from_ascii(name).unwrap(), kind));
        q.to_vec().unwrap()
    }
    fn answer(dns: &FakeDns, name: &str, kind: RecordType) -> IpAddr {
        let reply = Message::from_vec(&dns.answer(&query(name, kind)).unwrap().unwrap()).unwrap();
        match reply.answers[0].data {
            RData::A(A(ip)) => ip.into(),
            RData::AAAA(AAAA(ip)) => ip.into(),
            _ => panic!("expected address"),
        }
    }
    #[test]
    #[ignore = "explicit temporary-file persistence measurement; not a throughput benchmark"]
    fn measure_persistence_cost() {
        let directory = tempfile::tempdir().unwrap();
        let dns = FakeDns::open(&FakeDnsConfig {
            cache: directory.path().join("cache.json"),
            ..Default::default()
        })
        .unwrap();
        for count in [4096, 16_384, 65_536] {
            let names: Vec<_> = (0..count)
                .map(|i| format!("host{i}.measurement.invalid"))
                .collect();
            dns.persist(&names, &[]).unwrap();
            let mut elapsed = Vec::new();
            for _ in 0..16 {
                let start = std::time::Instant::now();
                dns.persist(&names, &[]).unwrap();
                elapsed.push(start.elapsed().as_micros());
            }
            elapsed.sort_unstable();
            eprintln!(
                "PERSIST_MEASUREMENT {}",
                serde_json::json!({
                    "entries":count,"writes":16,"bytes_per_write":fs::metadata(&dns.path).unwrap().len(),
                    "median_us":elapsed[8],"p95_us":elapsed[15],"debug_assertions":cfg!(debug_assertions)
                })
            );
        }
    }
    #[test]
    fn expansion_preserves_v1_ids_and_lowering_capacity_never_truncates() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            max_entries: 2,
        };
        let default: FakeDnsConfig =
            serde_json::from_value(serde_json::json!({"cache":config.cache})).unwrap();
        assert_eq!(default.max_entries, DEFAULT_CAPACITY);

        let dns = FakeDns::open(&config).unwrap();
        assert_eq!(dns.allocate("first.example").unwrap(), 1);
        assert_eq!(dns.allocate("second.example").unwrap(), 2);
        assert!(dns.allocate("third.example").is_err());
        assert_eq!(dns.allocate("first.example").unwrap(), 1);
        dns.close().unwrap();
        config.max_entries = 10;
        let dns = FakeDns::open(&config).unwrap();
        assert_eq!(dns.allocate("first.example").unwrap(), 1);
        assert_eq!(dns.allocate("third.example").unwrap(), 3);
        dns.close().unwrap();
        let before = fs::read(&config.cache).unwrap();
        assert_eq!(
            before,
            serde_json::to_vec(&Stored {
                version: 1,
                names: vec![
                    "first.example".into(),
                    "second.example".into(),
                    "third.example".into()
                ]
            })
            .unwrap()
        );
        config.max_entries = 2;
        assert!(FakeDns::open(&config).is_err());
        assert_eq!(fs::read(&config.cache).unwrap(), before);
        for limit in [0, MAX_CAPACITY + 1] {
            config.max_entries = limit;
            assert!(config.validate().is_err());
        }
    }
    #[test]
    fn maximum_capacity_stays_within_both_pools_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            max_entries: MAX_CAPACITY,
        };
        let names: Vec<_> = (0..MAX_CAPACITY - 1)
            .map(|i| format!("host{i}.example"))
            .collect();
        fs::write(
            &config.cache,
            serde_json::to_vec(&Stored { version: 1, names }).unwrap(),
        )
        .unwrap();
        let dns = FakeDns::open(&config).unwrap();
        let ip4 = answer(&dns, "last.example", RecordType::A);
        let ip6 = answer(&dns, "last.example", RecordType::AAAA);
        assert!(is_fake(ip4) && is_fake(ip6));
        assert_eq!(index(ip4), Some(MAX_CAPACITY - 1));
        assert_eq!(index(ip6), Some(MAX_CAPACITY - 1));
        assert!(dns.allocate("overflow.example").is_err());
        dns.close().unwrap();
        let dns = FakeDns::open(&config).unwrap();
        assert_eq!(answer(&dns, "last.example", RecordType::A), ip4);
    }
    #[test]
    fn uncertain_persistence_blocks_new_ids_but_preserves_known_mappings() {
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            ..Default::default()
        };
        let dns = FakeDns::open(&config).unwrap();
        assert_eq!(dns.allocate("known.example").unwrap(), 1);
        // Simulate successful rename followed by a directory synchronization failure.
        assert!(
            dns.allocate_with("uncertain.example", |names, new| {
                dns.persist(names, new)?;
                Err(CliError::new("injected post-rename failure"))
            })
            .is_err()
        );
        assert_eq!(dns.allocate("known.example").unwrap(), 1);
        assert!(dns.allocate("different.example").is_err());
        assert!(dns.reverse(Ipv4Addr::from(V4 + 2).into()).is_err());
        dns.close().unwrap();
        let dns = FakeDns::open(&config).unwrap();
        assert_eq!(dns.allocate("uncertain.example").unwrap(), 2);
        assert_eq!(dns.allocate("different.example").unwrap(), 3);
    }
    #[test]
    fn pending_persistence_does_not_block_existing_lookups_or_publish_new_mapping() {
        let dir = tempfile::tempdir().unwrap();
        let dns = Arc::new(
            FakeDns::open(&FakeDnsConfig {
                cache: dir.path().join("cache.json"),
                ..Default::default()
            })
            .unwrap(),
        );
        dns.allocate("known.example").unwrap();
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let writer = Arc::clone(&dns);
        let task = std::thread::spawn(move || {
            writer.allocate_with("pending.example", |names, new| {
                entered.send(()).unwrap();
                wait.recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                writer.persist(names, new)
            })
        });
        ready
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let reader = Arc::clone(&dns);
        let (observed, result) = std::sync::mpsc::channel();
        let read = std::thread::spawn(move || {
            let known = reader.allocate("known.example").unwrap();
            let reverse = reader.reverse(Ipv4Addr::from(V4 + 1).into()).unwrap();
            let unpublished = reader.reverse(Ipv4Addr::from(V4 + 2).into()).is_err();
            observed.send((known, reverse, unpublished)).unwrap();
        });
        let snapshot = result.recv_timeout(std::time::Duration::from_millis(500));
        release.send(()).unwrap();
        assert_eq!(task.join().unwrap().unwrap(), 2);
        read.join().unwrap();
        assert_eq!(snapshot.unwrap(), (1, Some("known.example".into()), true));
        assert_eq!(
            dns.reverse(Ipv4Addr::from(V4 + 2).into()).unwrap(),
            Some("pending.example".into())
        );
    }
    #[test]
    fn concurrent_allocations_never_duplicate_ids_and_capacity_warning_is_sticky() {
        let dir = tempfile::tempdir().unwrap();
        let dns = Arc::new(
            FakeDns::open(&FakeDnsConfig {
                cache: dir.path().join("cache.json"),
                max_entries: 10,
            })
            .unwrap(),
        );
        let tasks: Vec<_> = (0..18)
            .map(|i| {
                let dns = Arc::clone(&dns);
                std::thread::spawn(move || dns.allocate(&format!("host{}.example", i % 9)).unwrap())
            })
            .collect();
        let ids: std::collections::HashSet<_> =
            tasks.into_iter().map(|task| task.join().unwrap()).collect();
        assert_eq!(ids.len(), 9);
        assert!(
            dns.capacity_warned
                .load(std::sync::atomic::Ordering::Relaxed)
        );
        assert_eq!(inspect_cache(&dns.path).unwrap(), 9);
    }
    #[test]
    fn dual_stack_persists_and_never_recycles() {
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            ..Default::default()
        };
        let dns = FakeDns::open(&config).unwrap();
        assert!(FakeDns::open(&config).is_err());
        let v4 = answer(&dns, "Example.COM.", RecordType::A);
        let v6 = answer(&dns, "example.com", RecordType::AAAA);
        assert_eq!(dns.reverse(v4).unwrap().as_deref(), Some("example.com"));
        assert_eq!(dns.reverse(v6).unwrap().as_deref(), Some("example.com"));
        assert!(dns.reverse("198.19.255.254".parse().unwrap()).is_err());
        assert_eq!(dns.reverse("192.168.1.1".parse().unwrap()).unwrap(), None);
        dns.close().unwrap();
        let replacement = FakeDns::open(&config).unwrap();
        let stopped = dns
            .answer(&query("later.example", RecordType::A))
            .unwrap()
            .unwrap();
        assert_eq!(
            Message::from_vec(&stopped).unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
        drop(dns);
        let dns = replacement;
        assert_eq!(answer(&dns, "example.com", RecordType::A), v4);
        assert_ne!(answer(&dns, "another.example", RecordType::A), v4);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&config.cache).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn exhaustion_and_corruption_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
            ..Default::default()
        };
        let names = (0..DEFAULT_CAPACITY)
            .map(|i| format!("host{i}.example"))
            .collect();
        fs::write(
            &config.cache,
            serde_json::to_vec(&Stored { version: 1, names }).unwrap(),
        )
        .unwrap();
        let dns = FakeDns::open(&config).unwrap();
        let reply = dns
            .answer(&query("extra.example", RecordType::A))
            .unwrap()
            .unwrap();
        assert_eq!(
            Message::from_vec(&reply).unwrap().metadata.response_code,
            ResponseCode::ServFail
        );
        assert_eq!(
            dns.reverse(Ipv4Addr::from(V4 + 1).into())
                .unwrap()
                .as_deref(),
            Some("host0.example")
        );
        drop(dns);
        fs::write(&config.cache, "invalid").unwrap();
        assert!(FakeDns::open(&config).is_err());
        assert_eq!(fs::read_to_string(&config.cache).unwrap(), "invalid");
    }
    #[test]
    fn no_address_hints_or_false_dnssec_claim() {
        let dir = tempfile::tempdir().unwrap();
        let dns = FakeDns::open(&FakeDnsConfig {
            cache: dir.path().join("cache"),
            ..Default::default()
        })
        .unwrap();
        for kind in [RecordType::HTTPS, RecordType::SVCB, RecordType::ANY] {
            let reply =
                Message::from_vec(&dns.answer(&query("example.com", kind)).unwrap().unwrap())
                    .unwrap();
            assert!(reply.answers.is_empty());
            assert!(!reply.metadata.authentic_data);
        }
        assert!(
            dns.answer(&query("example.com", RecordType::TXT))
                .unwrap()
                .is_none()
        );
        assert!(dns.answer(&[0; 3]).is_err());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod pressure_tests;
