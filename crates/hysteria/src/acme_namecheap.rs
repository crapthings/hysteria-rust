use crate::{CliError, config::ServerAcmeDns};
use std::sync::Arc;
use xmltree::{Element, XMLNode};

#[derive(Clone)]
pub(crate) struct Provider {
    key: String,
    user: String,
    ip: String,
    endpoint: String,
    lock: Arc<tokio::sync::Mutex<()>>,
}

impl Provider {
    pub(crate) fn new(config: &ServerAcmeDns) -> Result<Self, CliError> {
        let get = |key: &str| config.config.get(key).cloned().unwrap_or_default();
        let endpoint = get("namecheap_api_endpoint");
        let endpoint = if endpoint.is_empty() {
            "https://api.namecheap.com/xml.response".to_owned()
        } else {
            endpoint
        };
        let url = reqwest::Url::parse(&endpoint)
            .map_err(|_| CliError::new("invalid Namecheap API endpoint"))?;
        if url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(CliError::new(
                "Namecheap API endpoint must be an HTTPS URL without credentials, query or fragment",
            ));
        }
        let ip = get("namecheap_client_ip");
        if ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(CliError::new(
                "namecheap_client_ip must be a whitelisted IPv4 address",
            ));
        }
        Ok(Self {
            key: get("namecheap_api_key"),
            user: get("namecheap_api_user"),
            ip,
            endpoint,
            lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    async fn call(
        &self,
        client: &reqwest::Client,
        zone: &str,
        command: &str,
        mut fields: Vec<(String, String)>,
    ) -> Result<Element, String> {
        let (sld, tld) = zone
            .split_once('.')
            .ok_or_else(|| "invalid Namecheap zone".to_owned())?;
        for (key, value) in [
            ("ApiUser", self.user.as_str()),
            ("UserName", self.user.as_str()),
            ("ApiKey", self.key.as_str()),
            ("ClientIp", self.ip.as_str()),
            ("SLD", sld),
            ("TLD", tld),
            ("Command", command),
        ] {
            fields.push((key.to_owned(), value.to_owned()));
        }
        let response = client
            .post(&self.endpoint)
            .form(&fields)
            .send()
            .await
            .map_err(|_| "Namecheap API request failed".to_owned())?;
        if !response.status().is_success() {
            return Err("Namecheap API HTTP error".to_owned());
        }
        let body = response
            .bytes()
            .await
            .map_err(|_| "Namecheap response read failed".to_owned())?;
        let root = Element::parse(body.as_ref())
            .map_err(|_| "invalid Namecheap XML response".to_owned())?;
        if root.name != "ApiResponse"
            || root.attributes.get("Status").map(String::as_str) != Some("OK")
        {
            return Err("Namecheap API rejected the request".to_owned());
        }
        root.get_child("CommandResponse")
            .cloned()
            .ok_or_else(|| "missing Namecheap command response".to_owned())
    }

    // Returns whether this call added a record, so cleanup never removes a pre-existing value.
    pub(crate) async fn update(
        &self,
        client: &reqwest::Client,
        zone: &str,
        name: &str,
        value: &str,
        add: bool,
    ) -> Result<bool, String> {
        let _guard = self.lock.lock().await;
        let response = self
            .call(client, zone, "namecheap.domains.dns.getHosts", vec![])
            .await?;
        let result = response
            .get_child("DomainDNSGetHostsResult")
            .ok_or_else(|| "missing Namecheap host list".to_owned())?;
        if result.attributes.get("IsUsingOurDNS").map(String::as_str) != Some("true") {
            return Err("domain is not using Namecheap DNS".to_owned());
        }
        let mut records: Vec<Element> = result
            .children
            .iter()
            .filter_map(|node| match node {
                XMLNode::Element(host) if host.name == "Host" => Some(host.clone()),
                _ => None,
            })
            .collect();
        let matches = |record: &Element| {
            record.attributes.get("Name").map(String::as_str) == Some(name)
                && record.attributes.get("Type").map(String::as_str) == Some("TXT")
                && record.attributes.get("Address").map(String::as_str) == Some(value)
        };
        let existing = records.iter().position(matches);
        if add {
            if existing.is_some() {
                return Ok(false);
            }
            let mut record = Element::new("Host");
            for (key, value) in [
                ("Name", name),
                ("Type", "TXT"),
                ("Address", value),
                ("TTL", "300"),
            ] {
                record.attributes.insert(key.to_owned(), value.to_owned());
            }
            records.push(record);
        } else if let Some(index) = existing {
            records.remove(index);
        } else {
            return Ok(false);
        }
        let mut fields = host_fields(&records)?;
        if let Some(email) = result.attributes.get("EmailType") {
            fields.push(("EmailType".to_owned(), email.clone()));
        }
        let response = self
            .call(client, zone, "namecheap.domains.dns.setHosts", fields)
            .await?;
        if response
            .get_child("DomainDNSSetHostsResult")
            .and_then(|r| r.attributes.get("IsSuccess"))
            .map(String::as_str)
            != Some("true")
        {
            return Err("Namecheap failed to update DNS records".to_owned());
        }
        Ok(add)
    }
}

fn host_fields(records: &[Element]) -> Result<Vec<(String, String)>, String> {
    let mut fields = Vec::new();
    for (index, record) in records.iter().enumerate() {
        for (source, target) in [
            ("Name", "HostName"),
            ("Type", "RecordType"),
            ("Address", "Address"),
            ("TTL", "TTL"),
            ("MXPref", "MXPref"),
        ] {
            if let Some(value) = record.attributes.get(source) {
                fields.push((format!("{target}{}", index + 1), value.clone()));
            } else if source != "MXPref" {
                return Err(format!(
                    "Namecheap host is missing {source}; refusing to overwrite records"
                ));
            }
        }
    }
    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Form, Router, routing::post};
    use std::collections::HashMap;

    #[tokio::test]
    async fn preserves_existing_records_when_adding_and_removing_challenge() {
        crate::tls::ensure_crypto_provider();
        let calls = Arc::new(std::sync::Mutex::new(0));
        let observed = calls.clone();
        let app = Router::new().route("/", post(move |Form(fields): Form<HashMap<String, String>>| {
            let calls = calls.clone();
            async move {
                let mut count = calls.lock().unwrap();
                assert_eq!(fields["ApiKey"], "test-key");
                assert_eq!(fields["SLD"], "example");
                assert_eq!(fields["TLD"], "co.uk");
                let result = if fields["Command"].ends_with("getHosts") {
                    let txt = if *count >= 2 { r#"<Host Name="_acme-challenge" Type="TXT" Address="challenge" TTL="300"/>"# } else { "" };
                    format!(r#"<DomainDNSGetHostsResult IsUsingOurDNS="true" EmailType="MX"><Host Name="@" Type="A" Address="192.0.2.1" TTL="1800"/><Host Name="@" Type="MX" Address="mail.example.co.uk" TTL="1800" MXPref="10"/><Host Name="_acme-challenge" Type="TXT" Address="other-token" TTL="600"/>{txt}</DomainDNSGetHostsResult>"#)
                } else {
                    assert_eq!(fields["Address1"], "192.0.2.1");
                    assert_eq!(fields["MXPref2"], "10");
                    assert_eq!(fields["Address3"], "other-token");
                    assert_eq!(fields["EmailType"], "MX");
                    if *count == 1 { assert_eq!(fields["Address4"], "challenge"); }
                    else { assert!(!fields.contains_key("Address4")); }
                    r#"<DomainDNSSetHostsResult IsSuccess="true"/>"#.to_owned()
                };
                *count += 1;
                format!(r#"<ApiResponse Status="OK"><CommandResponse>{result}</CommandResponse></ApiResponse>"#)
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let provider = Provider {
            key: "test-key".to_owned(),
            user: "user".to_owned(),
            ip: "192.0.2.2".to_owned(),
            endpoint,
            lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        assert!(
            provider
                .update(
                    &client,
                    "example.co.uk",
                    "_acme-challenge",
                    "challenge",
                    true
                )
                .await
                .unwrap()
        );
        provider
            .update(
                &client,
                "example.co.uk",
                "_acme-challenge",
                "challenge",
                false,
            )
            .await
            .unwrap();
        assert_eq!(*observed.lock().unwrap(), 4);
        server.abort();
    }

    #[test]
    fn refuses_incomplete_host_records() {
        let record = Element::parse(r#"<Host Name="@" Type="A"/>"#.as_bytes()).unwrap();
        assert!(host_fields(&[record]).is_err());
    }
}
