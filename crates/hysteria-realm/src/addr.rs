use percent_encoding::percent_decode_str;
use std::{collections::HashMap, fmt};
use thiserror::Error;
use url::Url;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RealmAddrError {
    #[error("invalid realm address scheme")]
    InvalidScheme,
    #[error("invalid realm address: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmAddr {
    pub scheme: String,
    pub rendezvous_scheme: String,
    pub token: String,
    pub host: String,
    pub port: u16,
    pub realm_id: String,
    pub local_port: Option<u16>,
    pub params: HashMap<String, Vec<String>>,
}

impl RealmAddr {
    /// Parses a `realm://` or `realm+http://` rendezvous address.
    ///
    /// # Errors
    ///
    /// Returns an error when the scheme, token, authority, realm ID, port, or
    /// local-port query parameter is invalid.
    pub fn parse(input: &str) -> Result<Self, RealmAddrError> {
        let url = Url::parse(input).map_err(|error| RealmAddrError::Invalid(error.to_string()))?;
        let (rendezvous_scheme, default_port) = match url.scheme() {
            "realm" => ("https", 443),
            "realm+http" => ("http", 80),
            _ => return Err(RealmAddrError::InvalidScheme),
        };
        if url.cannot_be_a_base() || url.fragment().is_some() || input.ends_with('?') {
            return Err(RealmAddrError::Invalid(
                "opaque addresses, fragments, and empty query markers are not supported".to_owned(),
            ));
        }
        let host = url
            .host_str()
            .filter(|host| !host.is_empty())
            .ok_or_else(|| RealmAddrError::Invalid("rendezvous host is required".to_owned()))?;
        let token = decoded_userinfo(&url)?;
        let realm_id = decoded_realm_id(&url)?;
        let port = url.port().unwrap_or(default_port);
        let mut params: HashMap<String, Vec<String>> = HashMap::new();
        for (name, value) in url.query_pairs() {
            params
                .entry(name.into_owned())
                .or_default()
                .push(value.into_owned());
        }
        let local_port = match params.get("lport") {
            None => None,
            Some(values) if values.len() == 1 => Some(values[0].parse::<u16>().map_err(|_| {
                RealmAddrError::Invalid("lport must be an integer in 1-65535".to_owned())
            })?),
            Some(_) => {
                return Err(RealmAddrError::Invalid(
                    "lport must be specified at most once".to_owned(),
                ));
            }
        };
        if local_port == Some(0) {
            return Err(RealmAddrError::Invalid(
                "lport must be an integer in 1-65535".to_owned(),
            ));
        }
        Ok(Self {
            scheme: url.scheme().to_owned(),
            rendezvous_scheme: rendezvous_scheme.to_owned(),
            token,
            host: host.to_owned(),
            port,
            realm_id,
            local_port,
            params,
        })
    }

    #[must_use]
    pub fn host_port(&self) -> String {
        match self.host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(_)) => format!("[{}]:{}", self.host, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
    }

    #[must_use]
    pub fn base_url(&self) -> String {
        format!("{}://{}", self.rendezvous_scheme, self.host_port())
    }

    #[must_use]
    pub fn query_values(&self, name: &str) -> &[String] {
        self.params.get(name).map_or(&[], Vec::as_slice)
    }
}

impl fmt::Display for RealmAddr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.base_url())
    }
}

fn decoded_userinfo(url: &Url) -> Result<String, RealmAddrError> {
    if url.username().is_empty() {
        return Err(RealmAddrError::Invalid(
            "realm token is required".to_owned(),
        ));
    }
    let encoded = url.password().map_or_else(
        || url.username().to_owned(),
        |password| format!("{}:{password}", url.username()),
    );
    let token = percent_decode_str(&encoded)
        .decode_utf8()
        .map_err(|_| RealmAddrError::Invalid("realm token is invalid UTF-8".to_owned()))?;
    if token.is_empty() {
        return Err(RealmAddrError::Invalid(
            "realm token is required".to_owned(),
        ));
    }
    Ok(token.into_owned())
}

fn decoded_realm_id(url: &Url) -> Result<String, RealmAddrError> {
    let encoded = url.path().strip_prefix('/').unwrap_or(url.path());
    if encoded.is_empty() || encoded.contains('/') {
        return Err(RealmAddrError::Invalid(
            "realm id must be a single path segment".to_owned(),
        ));
    }
    let decoded = percent_decode_str(encoded)
        .decode_utf8()
        .map_err(|_| RealmAddrError::Invalid("realm id is invalid UTF-8".to_owned()))?;
    if decoded.is_empty() || decoded.contains('/') {
        return Err(RealmAddrError::Invalid(
            "realm id must be a single path segment".to_owned(),
        ));
    }
    Ok(decoded.into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_address_forms() {
        let address = RealmAddr::parse(
            "realm://token%3Avalue@[2001:db8::1]:8443/realm%20id?stun=a:3478&stun=b&lport=4433",
        )
        .unwrap();
        assert_eq!(address.rendezvous_scheme, "https");
        assert_eq!(address.host, "[2001:db8::1]");
        assert_eq!(address.host_port(), "[2001:db8::1]:8443");
        assert_eq!(address.token, "token:value");
        assert_eq!(address.realm_id, "realm id");
        assert_eq!(address.local_port, Some(4433));
        assert_eq!(address.query_values("stun"), ["a:3478", "b"]);

        let address = RealmAddr::parse("realm+http://secret@example.com/realm").unwrap();
        assert_eq!(address.base_url(), "http://example.com:80");
    }

    #[test]
    fn rejects_go_invalid_address_forms() {
        for input in [
            "hysteria2://secret@example.com/realm",
            "realm://example.com/realm",
            "realm://secret@/realm",
            "realm://secret@example.com",
            "realm://secret@example.com/realm/extra",
            "realm://secret@example.com/realm%2Fextra",
            "realm://secret@example.com:70000/realm",
            "realm://secret@example.com/realm#fragment",
            "realm://secret@example.com/realm?lport=0",
            "realm://secret@example.com/realm?lport=1&lport=2",
        ] {
            assert!(RealmAddr::parse(input).is_err(), "accepted {input}");
        }
    }
}
