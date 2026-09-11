use crate::{CliError, Result, config::ServerAcmeDns};
use hickory_resolver::{
    TokioResolver,
    proto::rr::{RData, RecordType},
};
use reqwest::{Client, RequestBuilder, StatusCode};
use rustls_acme::Dns01Solver as AcmeDns01Solver;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DNS_TTL: u32 = 300;
const PROPAGATION_TIMEOUT: Duration = Duration::from_secs(120);

pub(crate) fn solver(config: &ServerAcmeDns) -> Result<Arc<dyn AcmeDns01Solver>> {
    let resolver = TokioResolver::builder_tokio()
        .map_err(|error| CliError::new(format!("failed to configure DNS resolver: {error}")))?
        .build()
        .map_err(|error| CliError::new(format!("failed to configure DNS resolver: {error}")))?;
    Ok(Arc::new(DnsSolver {
        client: Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| {
                CliError::new(format!("failed to configure ACME DNS client: {error}"))
            })?,
        resolver,
        provider: Provider::from_config(config)?,
        records: Mutex::new(HashMap::new()),
    }))
}

#[derive(Clone)]
enum Provider {
    Njalla {
        token: String,
    },
    Porkbun {
        key: String,
        secret: String,
    },
    Cloudflare {
        token: String,
    },
    DuckDns {
        token: String,
        domain: String,
    },
    Gandi {
        token: String,
    },
    GoDaddy {
        token: String,
    },
    NameDotCom {
        token: String,
        user: String,
        server: String,
    },
    Vultr {
        token: String,
    },
}

impl Provider {
    fn from_config(dns: &ServerAcmeDns) -> Result<Self> {
        let get = |key: &str| dns.config.get(key).cloned().unwrap_or_default();
        Ok(match dns.name.trim().to_ascii_lowercase().as_str() {
            "njalla" => Self::Njalla {
                token: get("njalla_api_token"),
            },
            "porkbun" => Self::Porkbun {
                key: get("porkbun_api_key"),
                secret: get("porkbun_api_secret_key"),
            },
            "cloudflare" => Self::Cloudflare {
                token: get("cloudflare_api_token"),
            },
            "duckdns" => Self::DuckDns {
                token: get("duckdns_api_token"),
                domain: get("duckdns_override_domain"),
            },
            "gandi" => Self::Gandi {
                token: get("gandi_api_token"),
            },
            "godaddy" => Self::GoDaddy {
                token: get("godaddy_api_token"),
            },
            "namedotcom" => Self::NameDotCom {
                token: get("namedotcom_token"),
                user: get("namedotcom_user"),
                server: {
                    let server = get("namedotcom_server");
                    if server.is_empty() {
                        "https://api.name.com".to_owned()
                    } else {
                        server
                    }
                },
            },
            "vultr" => Self::Vultr {
                token: get("vultr_api_token"),
            },
            _ => return Err(CliError::new("unsupported ACME DNS provider")),
        })
    }
}

#[derive(Clone)]
struct RecordHandle {
    zone: String,
    name: String,
    id: String,
}

struct DnsSolver {
    client: Client,
    resolver: TokioResolver,
    provider: Provider,
    records: Mutex<HashMap<(String, String), RecordHandle>>,
}

#[async_trait::async_trait]
impl AcmeDns01Solver for DnsSolver {
    async fn present(&self, domain: &str, value: &str) -> std::result::Result<(), String> {
        let domain = domain.trim_start_matches("*.").trim_end_matches('.');
        let fqdn = format!("_acme-challenge.{domain}");
        let zone = self.find_zone(&fqdn).await?;
        let name = relative_name(&fqdn, &zone)?;
        let handle = self.create(&fqdn, &zone, &name, value).await?;
        self.records
            .lock()
            .map_err(|_| "ACME DNS record store is poisoned".to_owned())?
            .insert((domain.to_owned(), value.to_owned()), handle.clone());
        if let Err(error) = self.wait_for_txt(&fqdn, value).await {
            let cleanup = self.remove(&handle, value).await;
            self.records
                .lock()
                .map_err(|_| "ACME DNS record store is poisoned".to_owned())?
                .remove(&(domain.to_owned(), value.to_owned()));
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; cleanup also failed: {cleanup}"),
            });
        }
        Ok(())
    }

    async fn cleanup(&self, domain: &str, value: &str) -> std::result::Result<(), String> {
        let domain = domain.trim_start_matches("*.").trim_end_matches('.');
        let handle = self
            .records
            .lock()
            .map_err(|_| "ACME DNS record store is poisoned".to_owned())?
            .remove(&(domain.to_owned(), value.to_owned()));
        match handle {
            Some(handle) => self.remove(&handle, value).await,
            None => Ok(()),
        }
    }
}

impl DnsSolver {
    async fn find_zone(&self, fqdn: &str) -> std::result::Result<String, String> {
        let labels: Vec<_> = fqdn.split('.').collect();
        for offset in 0..labels.len().saturating_sub(1) {
            let candidate = labels[offset..].join(".");
            if self
                .resolver
                .lookup(&candidate, RecordType::SOA)
                .await
                .is_ok()
            {
                return Ok(candidate);
            }
        }
        Err(format!(
            "could not discover authoritative DNS zone for {fqdn}"
        ))
    }

    async fn wait_for_txt(&self, fqdn: &str, value: &str) -> std::result::Result<(), String> {
        let deadline = Instant::now() + PROPAGATION_TIMEOUT;
        loop {
            // A negative TXT response may otherwise remain cached for the whole
            // propagation window after the record has just been created.
            self.resolver.clear_cache();
            if let Ok(lookup) = self.resolver.txt_lookup(fqdn).await
                && lookup.answers().iter().any(|record| {
                    let RData::TXT(txt) = &record.data else {
                        return false;
                    };
                    txt.txt_data
                        .iter()
                        .flat_map(|part| part.iter())
                        .copied()
                        .eq(value.bytes())
                })
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "DNS TXT record for {fqdn} did not propagate within 120s"
                ));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn create(
        &self,
        fqdn: &str,
        zone: &str,
        name: &str,
        value: &str,
    ) -> std::result::Result<RecordHandle, String> {
        let id = match &self.provider {
            Provider::Cloudflare { token } => {
                let zones: CfEnvelope<Vec<CfZone>> = json(
                    self.client
                        .get("https://api.cloudflare.com/client/v4/zones")
                        .bearer_auth(token)
                        .query(&[("name", zone)]),
                    "Cloudflare zone lookup",
                )
                .await?;
                let zone_id = zones
                    .result
                    .into_iter()
                    .find(|item| item.name.trim_end_matches('.') == zone)
                    .ok_or_else(|| format!("Cloudflare zone {zone} was not found"))?
                    .id;
                let created: CfEnvelope<CfRecord> = json(
                    self.client.post(format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"))
                        .bearer_auth(token).json(&serde_json::json!({"type":"TXT", "name":fqdn, "content":value, "ttl":DNS_TTL})),
                    "Cloudflare record creation",
                ).await?;
                format!("{zone_id}:{}", created.result.id)
            }
            Provider::DuckDns { token, domain } => {
                let domain = if domain.is_empty() {
                    duckdns_domain(fqdn)?
                } else {
                    domain.trim_end_matches('.').to_owned()
                };
                let body = text(
                    self.client.get("https://www.duckdns.org/update").query(&[
                        ("domains", domain.as_str()),
                        ("token", token.as_str()),
                        ("txt", value),
                        ("verbose", "true"),
                    ]),
                    "DuckDNS record creation",
                )
                .await?;
                if body.lines().next() != Some("OK") {
                    return Err(format!(
                        "DuckDNS record creation failed: {}",
                        bounded(&body)
                    ));
                }
                String::new()
            }
            Provider::Gandi { token } => {
                let url =
                    format!("https://api.gandi.net/v5/livedns/domains/{zone}/records/{name}/TXT");
                let mut values = match json_allow_not_found::<GandiRecord>(
                    self.client.get(&url).bearer_auth(token),
                    "Gandi record lookup",
                )
                .await?
                {
                    Some(record) => record.rrset_values,
                    None => Vec::new(),
                };
                if !values.iter().any(|item| item == value) {
                    values.push(value.to_owned());
                }
                empty(
                    self.client
                        .put(url)
                        .bearer_auth(token)
                        .json(&serde_json::json!({"rrset_values":values,"rrset_ttl":DNS_TTL})),
                    "Gandi record creation",
                )
                .await?;
                String::new()
            }
            Provider::GoDaddy { token } => {
                let url = format!("https://api.godaddy.com/v1/domains/{zone}/records/TXT/{name}");
                let mut records = json_allow_not_found::<Vec<GoDaddyRecord>>(
                    self.client
                        .get(&url)
                        .header("Authorization", format!("sso-key {token}")),
                    "GoDaddy record lookup",
                )
                .await?
                .unwrap_or_default();
                if !records.iter().any(|record| record.data == value) {
                    records.push(GoDaddyRecord {
                        data: value.to_owned(),
                        ttl: 600,
                    });
                }
                empty(
                    self.client
                        .put(url)
                        .header("Authorization", format!("sso-key {token}"))
                        .json(&records),
                    "GoDaddy record creation",
                )
                .await?;
                String::new()
            }
            Provider::Njalla { token } => {
                let result = njalla_call(&self.client, "https://njal.la/api/1/", token, "add-record",
                    serde_json::json!({"domain":zone,"name":name,"type":"TXT","content":value,"ttl":DNS_TTL})).await?;
                let id = result
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .filter(|id| !id.is_empty())
                    .ok_or_else(|| "Njalla returned an invalid record ID".to_owned())?;
                id.to_owned()
            }
            Provider::Porkbun { key, secret } => {
                let response: PorkbunResponse = json(
                    self.client.post(format!("https://api.porkbun.com/api/json/v3/dns/create/{zone}"))
                        .json(&serde_json::json!({"apikey":key,"secretapikey":secret,"name":name,"type":"TXT","content":value,"ttl":DNS_TTL.to_string()})),
                    "Porkbun record creation",
                ).await?;
                response.record_id()?
            }
            Provider::NameDotCom {
                token,
                user,
                server,
            } => {
                let created: NameRecord = json(
                    self.client.post(format!("{}/v4/domains/{zone}/records", server.trim_end_matches('/')))
                        .basic_auth(user, Some(token)).json(&serde_json::json!({"host":name,"type":"TXT","answer":value,"ttl":DNS_TTL})),
                    "name.com record creation",
                ).await?;
                created.id.to_string()
            }
            Provider::Vultr { token } => {
                let created: VultrRecordEnvelope = json(
                    self.client.post(format!("https://api.vultr.com/v2/domains/{zone}/records"))
                        .bearer_auth(token).json(&serde_json::json!({"name":name,"type":"TXT","data":format!("\"{value}\""),"ttl":DNS_TTL})),
                    "Vultr record creation",
                ).await?;
                created.record.id
            }
        };
        Ok(RecordHandle {
            zone: zone.to_owned(),
            name: name.to_owned(),
            id,
        })
    }

    #[allow(clippy::too_many_lines)]
    async fn remove(&self, handle: &RecordHandle, value: &str) -> std::result::Result<(), String> {
        match &self.provider {
            Provider::Njalla { token } => {
                njalla_call(
                    &self.client,
                    "https://njal.la/api/1/",
                    token,
                    "remove-record",
                    serde_json::json!({"domain":handle.zone,"id":handle.id}),
                )
                .await?;
                Ok(())
            }
            Provider::Porkbun { key, secret } => {
                let response: PorkbunResponse = json(
                    self.client
                        .post(format!(
                            "https://api.porkbun.com/api/json/v3/dns/delete/{}/{}",
                            handle.zone, handle.id
                        ))
                        .json(&serde_json::json!({"apikey":key,"secretapikey":secret})),
                    "Porkbun record cleanup",
                )
                .await?;
                response.check()
            }
            Provider::Cloudflare { token } => {
                let (zone_id, record_id) = handle
                    .id
                    .split_once(':')
                    .ok_or_else(|| "invalid Cloudflare record handle".to_owned())?;
                empty(self.client.delete(format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}")).bearer_auth(token), "Cloudflare record cleanup").await
            }
            Provider::DuckDns { token, domain } => {
                let domain = if domain.is_empty() {
                    duckdns_domain(&format!("{}.{}", handle.name, handle.zone))?
                } else {
                    domain.trim_end_matches('.').to_owned()
                };
                let body = text(
                    self.client.get("https://www.duckdns.org/update").query(&[
                        ("domains", domain.as_str()),
                        ("token", token.as_str()),
                        ("txt", ""),
                        ("clear", "true"),
                        ("verbose", "true"),
                    ]),
                    "DuckDNS record cleanup",
                )
                .await?;
                if body.lines().next() == Some("OK") {
                    Ok(())
                } else {
                    Err(format!("DuckDNS record cleanup failed: {}", bounded(&body)))
                }
            }
            Provider::Gandi { token } => {
                let url = format!(
                    "https://api.gandi.net/v5/livedns/domains/{}/records/{}/TXT",
                    handle.zone, handle.name
                );
                let Some(mut record) = json_allow_not_found::<GandiRecord>(
                    self.client.get(&url).bearer_auth(token),
                    "Gandi record cleanup lookup",
                )
                .await?
                else {
                    return Ok(());
                };
                record
                    .rrset_values
                    .retain(|item| item != value && item.trim_matches('"') != value);
                if record.rrset_values.is_empty() {
                    empty(
                        self.client.delete(url).bearer_auth(token),
                        "Gandi record cleanup",
                    )
                    .await
                } else {
                    empty(self.client.put(url).bearer_auth(token).json(&serde_json::json!({"rrset_values":record.rrset_values,"rrset_ttl":record.rrset_ttl.max(DNS_TTL)})), "Gandi record cleanup").await
                }
            }
            Provider::GoDaddy { token } => {
                let url = format!(
                    "https://api.godaddy.com/v1/domains/{}/records/TXT/{}",
                    handle.zone, handle.name
                );
                let auth = format!("sso-key {token}");
                let Some(mut records) = json_allow_not_found::<Vec<GoDaddyRecord>>(
                    self.client.get(&url).header("Authorization", &auth),
                    "GoDaddy record cleanup lookup",
                )
                .await?
                else {
                    return Ok(());
                };
                records.retain(|record| record.data != value);
                if records.is_empty() {
                    empty(
                        self.client.delete(url).header("Authorization", auth),
                        "GoDaddy record cleanup",
                    )
                    .await
                } else {
                    empty(
                        self.client
                            .put(url)
                            .header("Authorization", auth)
                            .json(&records),
                        "GoDaddy record cleanup",
                    )
                    .await
                }
            }
            Provider::NameDotCom {
                token,
                user,
                server,
            } => {
                empty(
                    self.client
                        .delete(format!(
                            "{}/v4/domains/{}/records/{}",
                            server.trim_end_matches('/'),
                            handle.zone,
                            handle.id
                        ))
                        .basic_auth(user, Some(token)),
                    "name.com record cleanup",
                )
                .await
            }
            Provider::Vultr { token } => {
                empty(
                    self.client
                        .delete(format!(
                            "https://api.vultr.com/v2/domains/{}/records/{}",
                            handle.zone, handle.id
                        ))
                        .bearer_auth(token),
                    "Vultr record cleanup",
                )
                .await
            }
        }
    }
}

async fn njalla_call(
    client: &Client,
    endpoint: &str,
    token: &str,
    method: &str,
    params: serde_json::Value,
) -> std::result::Result<serde_json::Value, String> {
    let response: serde_json::Value = json(
        client
            .post(endpoint)
            .header("Authorization", format!("Njalla {token}"))
            .json(&serde_json::json!({"jsonrpc":"2.0","id":"1","method":method,"params":params})),
        "Njalla DNS request",
    )
    .await?;
    if response.get("error").is_some_and(|error| !error.is_null()) {
        return Err("Njalla API rejected the request".to_owned());
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| "Njalla API response is missing result".to_owned())
}

fn relative_name(fqdn: &str, zone: &str) -> std::result::Result<String, String> {
    if fqdn == zone {
        return Ok("@".to_owned());
    }
    fqdn.strip_suffix(&format!(".{zone}"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("DNS name {fqdn} is outside zone {zone}"))
}

fn duckdns_domain(fqdn: &str) -> std::result::Result<String, String> {
    let fqdn = fqdn.trim_end_matches('.');
    let labels: Vec<_> = fqdn.split('.').collect();
    if fqdn.to_ascii_lowercase().ends_with(".duckdns.org") {
        if labels.len() < 3 {
            return Err(format!("invalid DuckDNS name {fqdn}"));
        }
        Ok(labels[labels.len() - 3..].join("."))
    } else {
        labels
            .last()
            .map(|label| (*label).to_owned())
            .ok_or_else(|| format!("invalid DuckDNS name {fqdn}"))
    }
}

async fn response(
    request: RequestBuilder,
    operation: &str,
) -> std::result::Result<reqwest::Response, String> {
    request
        .send()
        .await
        .map_err(|error| format!("{operation} failed: {error}"))
}

async fn json<T: DeserializeOwned>(
    request: RequestBuilder,
    operation: &str,
) -> std::result::Result<T, String> {
    let response = response(request, operation).await?;
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("{operation} response failed: {error}"))?;
    if !status.is_success() {
        return Err(format!(
            "{operation} returned HTTP {status}: {}",
            bounded(&String::from_utf8_lossy(&bytes))
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("{operation} returned invalid JSON: {error}"))
}

async fn json_allow_not_found<T: DeserializeOwned>(
    request: RequestBuilder,
    operation: &str,
) -> std::result::Result<Option<T>, String> {
    let response = response(request, operation).await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let status = response.status();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| format!("{operation} response failed: {error}"))?;
    if !status.is_success() {
        return Err(format!(
            "{operation} returned HTTP {status}: {}",
            bounded(&String::from_utf8_lossy(&bytes))
        ));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("{operation} returned invalid JSON: {error}"))
}

async fn text(request: RequestBuilder, operation: &str) -> std::result::Result<String, String> {
    let response = response(request, operation).await?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| format!("{operation} response failed: {error}"))?;
    if status.is_success() {
        Ok(body)
    } else {
        Err(format!(
            "{operation} returned HTTP {status}: {}",
            bounded(&body)
        ))
    }
}

async fn empty(request: RequestBuilder, operation: &str) -> std::result::Result<(), String> {
    let response = response(request, operation).await?;
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    let body = response.text().await.unwrap_or_default();
    Err(format!(
        "{operation} returned HTTP {status}: {}",
        bounded(&body)
    ))
}

fn bounded(value: &str) -> String {
    value.chars().take(512).collect()
}

#[derive(Deserialize)]
struct CfEnvelope<T> {
    result: T,
}

#[derive(Deserialize)]
struct PorkbunResponse {
    status: String,
    #[serde(default)]
    id: serde_json::Value,
}

impl PorkbunResponse {
    fn check(&self) -> std::result::Result<(), String> {
        if self.status == "SUCCESS" {
            Ok(())
        } else {
            Err("Porkbun API rejected the request".to_owned())
        }
    }

    fn record_id(&self) -> std::result::Result<String, String> {
        self.check()?;
        let id = match &self.id {
            serde_json::Value::String(id) => id.clone(),
            serde_json::Value::Number(id) if id.is_u64() => id.to_string(),
            _ => String::new(),
        };
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("Porkbun returned an invalid record ID".to_owned());
        }
        Ok(id)
    }
}
#[derive(Deserialize)]
struct CfZone {
    id: String,
    name: String,
}
#[derive(Deserialize)]
struct CfRecord {
    id: String,
}
#[derive(Deserialize)]
struct GandiRecord {
    #[serde(default)]
    rrset_values: Vec<String>,
    #[serde(default)]
    rrset_ttl: u32,
}
#[derive(Clone, Deserialize, Serialize)]
struct GoDaddyRecord {
    data: String,
    ttl: u32,
}
#[derive(Deserialize)]
struct NameRecord {
    id: i64,
}
#[derive(Deserialize)]
struct VultrRecordEnvelope {
    record: VultrRecord,
}
#[derive(Deserialize)]
struct VultrRecord {
    id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn njalla_rpc_authenticates_and_checks_api_errors() {
        use axum::{Json, Router, http::HeaderMap, routing::post};
        let app = Router::new().route(
            "/",
            post(
                |headers: HeaderMap, Json(body): Json<serde_json::Value>| async move {
                    assert_eq!(headers["authorization"], "Njalla test-token");
                    assert_eq!(body["jsonrpc"], "2.0");
                    assert_eq!(body["params"]["domain"], "example.com");
                    Json(match body["method"].as_str().unwrap() {
                        "add-record" => {
                            assert_eq!(body["params"]["type"], "TXT");
                            assert_eq!(body["params"]["name"], "_acme-challenge");
                            assert_eq!(body["params"]["content"], "challenge");
                            serde_json::json!({"result":{"id":"42"}})
                        }
                        "remove-record" => {
                            assert_eq!(body["params"]["id"], "42");
                            serde_json::json!({"result":{}})
                        }
                        "denied" => {
                            serde_json::json!({"error":{"code":403,"message":"private detail"}})
                        }
                        _ => serde_json::json!({}),
                    })
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = Client::builder().no_proxy().build().unwrap();
        let result = njalla_call(&client, &endpoint, "test-token", "add-record", serde_json::json!({"domain":"example.com","name":"_acme-challenge","type":"TXT","content":"challenge","ttl":300})).await.unwrap();
        assert_eq!(result["id"], "42");
        njalla_call(
            &client,
            &endpoint,
            "test-token",
            "remove-record",
            serde_json::json!({"domain":"example.com","id":result["id"]}),
        )
        .await
        .unwrap();
        for method in ["denied", "malformed"] {
            assert!(
                njalla_call(
                    &client,
                    &endpoint,
                    "test-token",
                    method,
                    serde_json::json!({"domain":"example.com"})
                )
                .await
                .is_err()
            );
        }
        server.abort();
    }

    #[test]
    fn validates_porkbun_responses() {
        for id in [serde_json::json!(123), serde_json::json!("123")] {
            let response: PorkbunResponse =
                serde_json::from_value(serde_json::json!({"status":"SUCCESS","id":id})).unwrap();
            assert_eq!(response.record_id().unwrap(), "123");
        }
        for body in [
            r#"{"status":"ERROR","id":123}"#,
            r#"{"status":"SUCCESS"}"#,
            r#"{"status":"SUCCESS","id":"../all"}"#,
        ] {
            let response: PorkbunResponse = serde_json::from_str(body).unwrap();
            assert!(response.record_id().is_err());
        }
        let response: PorkbunResponse = serde_json::from_str(r#"{"status":"SUCCESS"}"#).unwrap();
        assert!(response.check().is_ok());
    }

    #[test]
    fn computes_relative_record_names() {
        assert_eq!(
            relative_name("_acme-challenge.edge.example.com", "example.com").unwrap(),
            "_acme-challenge.edge"
        );
        assert!(relative_name("elsewhere.test", "example.com").is_err());
    }

    #[test]
    fn matches_go_duckdns_domain_selection() {
        assert_eq!(
            duckdns_domain("_acme-challenge.foo.duckdns.org").unwrap(),
            "foo.duckdns.org"
        );
        assert_eq!(duckdns_domain("foo.example.com").unwrap(), "com");
    }
}
