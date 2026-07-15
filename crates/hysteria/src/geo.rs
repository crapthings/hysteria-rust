use crate::{CliError, Result, config::AclConfig};
use prost::Message;
use regex::Regex;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const GEOIP_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat";
const GEOSITE_URL: &str =
    "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat";
const DEFAULT_UPDATE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

#[derive(Clone, PartialEq, Message)]
struct Cidr {
    #[prost(bytes, tag = "1")]
    ip: Vec<u8>,
    #[prost(uint32, tag = "2")]
    prefix: u32,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIp {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    cidr: Vec<Cidr>,
    #[prost(bool, tag = "3")]
    inverse_match: bool,
}

#[derive(Clone, PartialEq, Message)]
struct GeoIpList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoIp>,
}

#[derive(Clone, PartialEq, Message)]
struct Attribute {
    #[prost(string, tag = "1")]
    key: String,
}

#[derive(Clone, PartialEq, Message)]
struct Domain {
    #[prost(int32, tag = "1")]
    kind: i32,
    #[prost(string, tag = "2")]
    value: String,
    #[prost(message, repeated, tag = "3")]
    attribute: Vec<Attribute>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSite {
    #[prost(string, tag = "1")]
    country_code: String,
    #[prost(message, repeated, tag = "2")]
    domain: Vec<Domain>,
}

#[derive(Clone, PartialEq, Message)]
struct GeoSiteList {
    #[prost(message, repeated, tag = "1")]
    entry: Vec<GeoSite>,
}

pub(crate) struct GeoDatabases {
    ip: Option<HashMap<String, GeoIp>>,
    site: Option<HashMap<String, GeoSite>>,
}

impl GeoDatabases {
    pub(crate) fn load(config: &AclConfig, rules: &str) -> Result<Self> {
        let update = if config.geo_update_interval.is_empty() {
            DEFAULT_UPDATE
        } else {
            humantime::parse_duration(&config.geo_update_interval)
                .map_err(|error| CliError::new(format!("invalid acl.geoUpdateInterval: {error}")))?
        };
        let ip = rules
            .to_ascii_lowercase()
            .contains("geoip:")
            .then(|| load_geoip(config.geoip.as_str(), update))
            .transpose()?;
        let site = rules
            .to_ascii_lowercase()
            .contains("geosite:")
            .then(|| load_geosite(config.geosite.as_str(), update))
            .transpose()?;
        Ok(Self { ip, site })
    }

    pub(crate) fn ip_matcher(&self, name: &str) -> Result<GeoIpMatcher> {
        let entry = self
            .ip
            .as_ref()
            .and_then(|entries| entries.get(&name.to_ascii_lowercase()))
            .ok_or_else(|| CliError::new(format!("GeoIP country code {name:?} not found")))?;
        let mut networks = Vec::with_capacity(entry.cidr.len());
        for cidr in &entry.cidr {
            let ip = match cidr.ip.as_slice() {
                bytes if bytes.len() == 4 => IpAddr::from(<[u8; 4]>::try_from(bytes).unwrap()),
                bytes if bytes.len() == 16 => IpAddr::from(<[u8; 16]>::try_from(bytes).unwrap()),
                _ => return Err(CliError::new("invalid GeoIP address length")),
            };
            let prefix =
                u8::try_from(cidr.prefix).map_err(|_| CliError::new("invalid GeoIP prefix"))?;
            networks.push((ip, prefix));
        }
        Ok(GeoIpMatcher {
            networks,
            inverse: entry.inverse_match,
        })
    }

    pub(crate) fn site_matcher(&self, value: &str) -> Result<GeoSiteMatcher> {
        let mut parts = value.split('@');
        let name = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
        let required = parts
            .map(|part| part.trim().to_ascii_lowercase())
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();
        let entry = self
            .site
            .as_ref()
            .and_then(|entries| entries.get(&name))
            .ok_or_else(|| CliError::new(format!("GeoSite name {name:?} not found")))?;
        let domains = entry
            .domain
            .iter()
            .map(|domain| {
                Ok(GeoDomain {
                    kind: domain.kind,
                    value: domain.value.to_ascii_lowercase(),
                    regex: (domain.kind == 1)
                        .then(|| Regex::new(&domain.value))
                        .transpose()
                        .map_err(|error| {
                            CliError::new(format!("invalid GeoSite regex: {error}"))
                        })?,
                    attributes: domain
                        .attribute
                        .iter()
                        .map(|attribute| attribute.key.to_ascii_lowercase())
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(GeoSiteMatcher { domains, required })
    }
}

#[derive(Clone)]
pub(crate) struct GeoIpMatcher {
    networks: Vec<(IpAddr, u8)>,
    inverse: bool,
}

impl GeoIpMatcher {
    pub(crate) fn matches(&self, ips: &[IpAddr]) -> bool {
        let matched = ips.iter().any(|candidate| {
            self.networks
                .iter()
                .any(|(network, prefix)| cidr_contains(*network, *prefix, *candidate))
        });
        matched != self.inverse
    }
}

#[derive(Clone)]
pub(crate) struct GeoSiteMatcher {
    domains: Vec<GeoDomain>,
    required: Vec<String>,
}

#[derive(Clone)]
struct GeoDomain {
    kind: i32,
    value: String,
    regex: Option<Regex>,
    attributes: HashSet<String>,
}

impl GeoSiteMatcher {
    pub(crate) fn matches(&self, host: &str) -> bool {
        self.domains.iter().any(|domain| {
            self.required
                .iter()
                .all(|attr| domain.attributes.contains(attr))
                && match domain.kind {
                    0 => host.contains(&domain.value),
                    1 => domain
                        .regex
                        .as_ref()
                        .is_some_and(|regex| regex.is_match(host)),
                    2 => host == domain.value || host.ends_with(&format!(".{}", domain.value)),
                    3 => host == domain.value,
                    _ => false,
                }
        })
    }
}

fn load_geoip(configured: &str, update: Duration) -> Result<HashMap<String, GeoIp>> {
    let path = prepare_file(configured, "geoip.dat", GEOIP_URL, update, |bytes| {
        GeoIpList::decode(bytes).is_ok()
    })?;
    let list = GeoIpList::decode(fs::read(&path)?.as_slice())
        .map_err(|error| CliError::new(format!("failed to decode {}: {error}", path.display())))?;
    Ok(list
        .entry
        .into_iter()
        .map(|entry| (entry.country_code.to_ascii_lowercase(), entry))
        .collect())
}

fn load_geosite(configured: &str, update: Duration) -> Result<HashMap<String, GeoSite>> {
    let path = prepare_file(configured, "geosite.dat", GEOSITE_URL, update, |bytes| {
        GeoSiteList::decode(bytes).is_ok()
    })?;
    let list = GeoSiteList::decode(fs::read(&path)?.as_slice())
        .map_err(|error| CliError::new(format!("failed to decode {}: {error}", path.display())))?;
    Ok(list
        .entry
        .into_iter()
        .map(|entry| (entry.country_code.to_ascii_lowercase(), entry))
        .collect())
}

fn prepare_file(
    configured: &str,
    default: &str,
    url: &str,
    update: Duration,
    validate: impl Fn(&[u8]) -> bool + Send + 'static,
) -> Result<PathBuf> {
    if !configured.is_empty() {
        return Ok(PathBuf::from(configured));
    }
    let path = PathBuf::from(default);
    let metadata = fs::metadata(&path).ok();
    let stale = metadata.as_ref().is_none_or(|metadata| metadata.len() == 0)
        || metadata
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| SystemTime::now().duration_since(modified).ok())
            .is_none_or(|age| age > update);
    if stale {
        let existed = path.exists();
        if let Err(error) = download(url, &path, validate) {
            if !existed {
                return Err(error);
            }
        }
    }
    Ok(path)
}

fn download(
    url: &str,
    path: &Path,
    validate: impl Fn(&[u8]) -> bool + Send + 'static,
) -> Result<()> {
    crate::tls::ensure_crypto_provider();
    let url = url.to_owned();
    let path = path.to_owned();
    std::thread::spawn(move || {
        let response = reqwest::blocking::get(&url)
            .map_err(|error| CliError::new(format!("failed to download {url}: {error}")))?
            .error_for_status()
            .map_err(|error| CliError::new(format!("failed to download {url}: {error}")))?;
        let bytes = response
            .bytes()
            .map_err(|error| CliError::new(format!("failed to download {url}: {error}")))?;
        if !validate(&bytes) {
            return Err(CliError::new(format!(
                "downloaded Geo database from {url} failed its integrity check"
            )));
        }
        let temporary = path.with_extension(format!("dat.{}.tmp", std::process::id()));
        fs::write(&temporary, bytes)?;
        fs::rename(&temporary, path)?;
        Ok(())
    })
    .join()
    .map_err(|_| CliError::new("Geo database download thread panicked"))?
}

#[cfg(test)]
pub(crate) fn write_test_databases(directory: &Path) -> (PathBuf, PathBuf) {
    let geoip = directory.join("geoip.dat");
    let geosite = directory.join("geosite.dat");
    fs::write(
        &geoip,
        GeoIpList {
            entry: vec![GeoIp {
                country_code: "PRIVATE".to_owned(),
                cidr: vec![Cidr {
                    ip: vec![192, 168, 0, 0],
                    prefix: 16,
                }],
                inverse_match: false,
            }],
        }
        .encode_to_vec(),
    )
    .unwrap();
    fs::write(
        &geosite,
        GeoSiteList {
            entry: vec![
                GeoSite {
                    country_code: "GOOGLE".to_owned(),
                    domain: vec![
                        Domain {
                            kind: 2,
                            value: "google.com".to_owned(),
                            attribute: Vec::new(),
                        },
                        Domain {
                            kind: 2,
                            value: "ggpht.cn".to_owned(),
                            attribute: vec![Attribute {
                                key: "cn".to_owned(),
                            }],
                        },
                    ],
                },
                GeoSite {
                    country_code: "NETFLIX".to_owned(),
                    domain: vec![Domain {
                        kind: 2,
                        value: "fast.com".to_owned(),
                        attribute: Vec::new(),
                    }],
                },
            ],
        }
        .encode_to_vec(),
    )
    .unwrap();
    (geoip, geosite)
}

fn cidr_contains(network: IpAddr, prefix: u8, candidate: IpAddr) -> bool {
    match (network, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) if prefix <= 32 => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            u32::from(network) & mask == u32::from(candidate) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) if prefix <= 128 => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            u128::from(network) & mask == u128::from(candidate) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn databases() -> GeoDatabases {
        let directory = tempfile::tempdir().unwrap();
        let (geoip, geosite) = write_test_databases(directory.path());
        GeoDatabases::load(
            &AclConfig {
                geoip: geoip.display().to_string(),
                geosite: geosite.display().to_string(),
                ..Default::default()
            },
            "reject(geoip:private)\nreject(geosite:google@cn)",
        )
        .unwrap()
    }

    #[test]
    fn loads_v2ray_geoip_cidrs() {
        let matcher = databases().ip_matcher("PRIVATE").unwrap();
        assert!(matcher.matches(&["192.168.1.1".parse().unwrap()]));
        assert!(!matcher.matches(&["8.8.8.8".parse().unwrap()]));
    }

    #[test]
    fn loads_geosite_types_and_attributes() {
        let databases = databases();
        let netflix = databases.site_matcher("netflix").unwrap();
        assert!(netflix.matches("fast.com"));
        assert!(netflix.matches("www.fast.com"));
        let google_cn = databases.site_matcher("google@cn").unwrap();
        assert!(google_cn.matches("ggpht.cn"));
        assert!(!google_cn.matches("waymo.com"));
    }
}
