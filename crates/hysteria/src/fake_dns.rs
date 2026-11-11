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
    sync::Mutex,
};
pub(crate) const LIMIT: usize = 4096;
const V4: u32 = u32::from_be_bytes([198, 18, 0, 0]);
const V6: u128 = 0xfd00_0198_0018_0000_0000_0000_0000_0000;
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FakeDnsConfig {
    pub cache: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    version: u8,
    names: Vec<String>,
}
struct Map {
    closed: bool,
    names: Vec<String>,
    ids: HashMap<String, u32>,
}
pub(crate) struct FakeDns {
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
        if config.cache.as_os_str().is_empty() {
            return Err(CliError::new("tun.dns.cache is required"));
        }
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
        let dns = Self {
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
        )?;
        Ok(dns)
    }
    pub(crate) fn close(&self) -> Result<()> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| CliError::new("Fake-IP cache lock failed"))?;
        if !map.closed {
            map.closed = true;
            self.cache_lock.unlock()?;
        }
        Ok(())
    }
    fn persist(&self, names: &[String]) -> Result<()> {
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
        serde_json::to_writer(
            &mut file,
            &Stored {
                version: 1,
                names: names.to_vec(),
            },
        )
        .map_err(|_| CliError::new("cannot serialize Fake-IP cache"))?;
        file.flush()?;
        file.as_file().sync_all()?;
        file.persist(&self.path)
            .map_err(|_| CliError::new("cannot persist Fake-IP cache"))?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
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
        let name = canonical(name)?;
        let mut map = self
            .map
            .lock()
            .map_err(|_| CliError::new("Fake-IP cache lock failed"))?;
        if map.closed {
            return Err(CliError::new("Fake-IP resolver is stopped"));
        }
        if let Some(id) = map.ids.get(&name) {
            return Ok(*id);
        }
        if map.names.len() >= LIMIT {
            return Err(CliError::new("Fake-IP cache full; no address was reused"));
        }
        let mut names = map.names.clone();
        names.push(name.clone());
        self.persist(&names)?;
        let id = u32::try_from(names.len()).map_err(|_| CliError::new("Fake-IP index overflow"))?;
        map.names = names;
        map.ids.insert(name, id);
        Ok(id)
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
                .take(2 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 2 * 1024 * 1024 {
                return Err(CliError::new("Fake-IP cache exceeds 2 MiB"));
            }
            let stored: Stored = serde_json::from_slice(&bytes)
                .map_err(|_| CliError::new("invalid Fake-IP cache; refusing to reset mappings"))?;
            if stored.version != 1 || stored.names.len() > LIMIT {
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
        names,
        ids,
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
    fn dual_stack_persists_and_never_recycles() {
        let dir = tempfile::tempdir().unwrap();
        let config = FakeDnsConfig {
            cache: dir.path().join("cache.json"),
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
        };
        let names = (0..LIMIT).map(|i| format!("host{i}.example")).collect();
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
