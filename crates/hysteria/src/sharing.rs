//! Standard Hysteria sharing links; exports contain selected credentials and public TLS material, never private keys.
use crate::{
    CliError, Result,
    config::{ClientConfig, ServerConfig},
};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Normalize a direct server address, including IPv6 and port hopping.
/// # Errors
/// Rejects malformed addresses, schemes and invalid port values.
pub fn normalize_address(value: &str) -> Result<String> {
    if value.starts_with("realm:") || value.starts_with("realm+http:") {
        return Err(CliError::new(
            "a Realm address is not a direct server address; use the Realm sharing scheme",
        ));
    }
    let ipv6;
    let value = if value.parse::<std::net::Ipv6Addr>().is_ok() {
        ipv6 = format!("[{value}]");
        ipv6.as_str()
    } else {
        value
    };
    if value.is_empty()
        || value.chars().any(char::is_whitespace)
        || value.contains(['/', '?', '#', '@', '\\', '%'])
    {
        return Err(CliError::new(
            "invalid server address; expected hostname or bracketed IPv6 with optional port(s)",
        ));
    }
    let (host, ports) = if value.starts_with('[') {
        let end = value
            .find(']')
            .ok_or_else(|| CliError::new("invalid IPv6 server address"))?;
        let host = &value[..=end];
        let rest = &value[end + 1..];
        (
            host,
            if rest.is_empty() {
                "443"
            } else {
                rest.strip_prefix(':')
                    .ok_or_else(|| CliError::new("invalid server port"))?
            },
        )
    } else {
        value.split_once(':').unwrap_or((value, "443"))
    };
    // URL parsing validates/normalizes the host without trying to interpret multi-port syntax.
    let url = url::Url::parse(&format!("https://{host}/"))
        .map_err(|_| CliError::new("invalid server hostname"))?;
    let host = url
        .host_str()
        .ok_or_else(|| CliError::new("server hostname is required"))?;
    for entry in ports.split(',') {
        let pair: Vec<_> = entry.split('-').collect();
        if pair.len() > 2
            || pair.iter().any(|port| {
                port.is_empty()
                    || !port.bytes().all(|b| b.is_ascii_digit())
                    || port.parse::<u16>().map_or(true, |port| port == 0)
            })
        {
            return Err(CliError::new(
                "server ports must be 1-65535, with optional comma-separated ranges",
            ));
        }
    }
    Ok(format!("{host}:{ports}"))
}

/// Explicit choices needed to turn a server configuration into one client link.
#[derive(Default)]
pub struct ServerShareOptions {
    pub address: String,
    pub user: Option<String>,
    pub external_auth: Option<String>,
    pub sni: String,
    pub insecure: bool,
    pub pin_cert: bool,
    pub name: Option<String>,
}

/// Generate one standard direct-mode URI without contacting the server or CA.
/// # Errors
/// Rejects unsupported authentication, ambiguous users, mTLS configurations,
/// invalid connection settings and unreadable requested public key material.
pub fn server_uri(config: &ServerConfig, options: &ServerShareOptions) -> Result<String> {
    config.validate()?;
    let is_realm = config.listen.starts_with("realm:") || config.listen.starts_with("realm+http:");
    if is_realm && !options.address.is_empty() {
        return Err(CliError::new("Realm export uses listen; omit --address"));
    }
    if !config.tls.client_ca.is_empty() {
        return Err(CliError::new(
            "this server requires client certificates; a sharing link cannot carry the required client identity, use a client configuration instead",
        ));
    }
    let address = if is_realm {
        config.listen.clone()
    } else {
        normalize_address(&options.address)?
    };
    if address.rsplit_once(':').is_some_and(|(host, _)| {
        host.trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_unspecified())
    }) {
        return Err(CliError::new(
            "--address must be a client-reachable address, not an unspecified listening address",
        ));
    }
    if !options.sni.is_empty() {
        rustls::pki_types::ServerName::try_from(options.sni.clone())
            .map_err(|_| CliError::new("invalid --sni hostname or IP address"))?;
    }
    let kind = config.auth.kind.trim().to_ascii_lowercase();
    let auth = match kind.as_str() {
        "password" if options.user.is_none() && options.external_auth.is_none() => config.auth.password.clone(),
        "userpass" if options.external_auth.is_none() => {
            let user = options.user.as_ref().ok_or_else(|| CliError::new("select one account with --user for userpass authentication"))?;
            if user.contains(':') { return Err(CliError::new("userpass usernames containing ':' cannot be shared")); }
            let password = config.auth.userpass.get(user).ok_or_else(|| CliError::new("selected user does not exist"))?;
            format!("{user}:{password}")
        }
        "http" | "https" | "command" | "cmd" if options.user.is_none() => options.external_auth.clone().filter(|auth| !auth.is_empty()).ok_or_else(|| CliError::new("external authentication requires --auth-stdin; backend credentials cannot be inferred"))?,
        _ => return Err(CliError::new("credential selection does not match the configured authentication type")),
    };
    let pin = if options.pin_cert {
        if config.tls.cert.is_empty() {
            return Err(CliError::new(
                "--pin-cert requires a configured static tls.cert file; ACME certificate pinning is not supported by this command",
            ));
        }
        let certificates = crate::tls::read_certificates(Path::new(&config.tls.cert))?;
        let leaf = certificates
            .first()
            .ok_or_else(|| CliError::new("certificate file contains no certificate"))?;
        format!("{:x}", Sha256::digest(leaf.as_ref()))
    } else {
        String::new()
    };
    let ech = config
        .ech
        .as_ref()
        .map(|ech| {
            crate::server_ech::load(Path::new(&ech.key_path))
                .map(|material| material.encoded_config_list())
        })
        .transpose()?
        .unwrap_or_default();
    let mut client: ClientConfig = serde_json::from_value(serde_json::json!({
        "server":address,"auth":auth,"tls":{"sni":options.sni,"insecure":options.insecure,"pinSHA256":pin,"ech":ech}
    })).map_err(|_| CliError::new("failed to build sharing configuration"))?;
    client.obfs = config.obfs.clone();
    if is_realm {
        // Server-local bind ports must not be imposed on clients (including same-host clients).
        let mut realm = url::Url::parse(&client.server)
            .map_err(|_| CliError::new("invalid Realm listen address"))?;
        let params: Vec<_> = realm
            .query_pairs()
            .filter(|(key, _)| key != "lport")
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        realm.set_query(None);
        if !params.is_empty() {
            realm.query_pairs_mut().extend_pairs(params);
        }
        client.server = realm.into();
        client
            .realm
            .stun_servers
            .clone_from(&config.realm.stun_servers);
        client.realm.insecure = config.realm.insecure;
    }
    client.validate_connection()?;
    let mut uri = client.share_uri()?;
    if let Some(name) = &options.name {
        uri.push('#');
        uri.push_str(
            &percent_encoding::utf8_percent_encode(name, percent_encoding::NON_ALPHANUMERIC)
                .to_string(),
        );
    }
    Ok(uri)
}

/// Export the standard combined Realm sharing scheme.
/// # Errors
/// Rejects invalid Realm settings or options that cannot be represented faithfully.
pub fn realm_uri(config: &ClientConfig) -> Result<String> {
    let realm = hysteria_realm::RealmAddr::parse(&config.server)
        .map_err(|_| CliError::new("invalid Realm address"))?;
    if config.realm.insecure {
        return Err(CliError::new(
            "realm.insecure cannot be represented by the standard sharing URI; use a full client configuration",
        ));
    }
    if realm
        .params
        .keys()
        .any(|key| !matches!(key.as_str(), "stun" | "lport"))
    {
        return Err(CliError::new("unsupported Realm address parameter"));
    }
    if config.auth.is_empty() {
        return Err(CliError::new(
            "Hysteria authentication is required separately from the Realm token",
        ));
    }
    let mut direct = config.clone();
    direct.server = "placeholder.invalid:443".into();
    let common = direct.share_uri()?;
    let mut output =
        url::Url::parse(&config.server).map_err(|_| CliError::new("invalid Realm address"))?;
    output
        .set_scheme(if realm.scheme == "realm" {
            "hysteria2+realm"
        } else {
            "hysteria2+realm+http"
        })
        .map_err(|()| CliError::new("invalid Realm sharing scheme"))?;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("auth", &config.auth);
    if let Some((_, params)) = common.split_once('?') {
        for (key, value) in url::form_urlencoded::parse(params.as_bytes()) {
            query.append_pair(&key, &value);
        }
    }
    let stun = if realm.query_values("stun").is_empty() {
        &config.realm.stun_servers
    } else {
        realm.query_values("stun")
    };
    for value in stun {
        query.append_pair("stun", value);
    }
    if let Some(port) = realm.local_port {
        query.append_pair("lport", &port.to_string());
    }
    output.set_query(Some(&query.finish()));
    Ok(output.into())
}
