//! Offline client setup; imported links never control local listeners or system settings.
use base64::Engine as _;
use hysteria_cli::{CliError, Result, config::ClientConfig};
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    io::{BufRead, Write},
};

pub(crate) fn generate(
    interactive: bool,
    uri: Option<&str>,
    allow_insecure: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<String> {
    let mut value = if let Some(uri) = uri {
        import(uri)?
    } else if interactive {
        writeln!(
            output,
            "Client setup — paste a sharing link, or press Enter for manual setup.\nInput may be visible in your terminal; credentials are saved only in the configuration."
        )?;
        let uri = crate::init::ask(input, output, "Sharing link", "")?;
        if uri.is_empty() {
            manual_client(input, output)?
        } else {
            import(&uri)?
        }
    } else {
        json!({"server":"vpn.example.com:443","auth":"REPLACE_WITH_SERVER_PASSWORD","tls":{"insecure":false}})
    };
    if value["tls"]["insecure"] == true && !allow_insecure {
        if !interactive {
            return Err(CliError::new(
                "sharing link disables certificate verification; inspect it and explicitly use --allow-insecure to retain this setting",
            ));
        }
        let answer = crate::init::ask(
            input,
            output,
            "Link disables certificate verification. Keep this setting? yes/no",
            "no",
        )?;
        if answer != "yes" {
            return Err(CliError::new(
                "insecure import cancelled; no configuration written",
            ));
        }
    }
    let mut port = 1080;
    if interactive {
        loop {
            let answer =
                crate::init::ask(input, output, "Local SOCKS5 port (127.0.0.1 only)", "1080")?;
            if let Ok(parsed) = answer.parse::<u16>()
                && parsed != 0
            {
                port = parsed;
                break;
            }
            writeln!(output, "Enter a port between 1 and 65535.")?;
        }
    }
    value["socks5"] = json!({"listen":format!("127.0.0.1:{port}")});
    let config: ClientConfig = serde_json::from_value(value.clone())
        .map_err(|_| CliError::new("invalid imported configuration"))?;
    config.validate().map_err(|_| CliError::new("invalid connection settings in client configuration; check TLS, authentication and obfuscation parameters"))?;
    let yaml = serde_yaml_ng::to_string(&value)
        .map_err(|_| CliError::new("could not serialize client configuration"))?;
    Ok(format!(
        "# Hysteria client configuration. Keep this file private.\n# Set server/auth before use. SOCKS5 listens only on this machine.\n# This does not change system proxy, routes or DNS.\n{yaml}"
    ))
}

fn manual_client(input: &mut impl BufRead, output: &mut impl Write) -> Result<Value> {
    let address = crate::init::ask(input, output, "Server address or realm:// URI", "")?;
    let realm = address.starts_with("realm:") || address.starts_with("realm+http:");
    let server = if realm {
        hysteria_realm::RealmAddr::parse(&address)
            .map_err(|_| CliError::new("invalid Realm address"))?;
        address
    } else {
        hysteria_cli::sharing::normalize_address(&address)?
    };
    let auth = crate::init::ask(
        input,
        output,
        if realm {
            "Hysteria authentication (not the Realm token)"
        } else {
            "Authentication"
        },
        "",
    )?;
    if auth.is_empty() {
        return Err(CliError::new(
            "authentication is required; no configuration written",
        ));
    }
    let sni = if realm {
        let name = crate::init::ask(input, output, "Proxy certificate name (TLS SNI)", "")?;
        rustls::pki_types::ServerName::try_from(name.clone()).map_err(|_| CliError::new("a valid certificate name is required; use a pinned sharing link for self-signed certificates"))?;
        name
    } else {
        String::new()
    };
    Ok(json!({"server":server,"auth":auth,"tls":{"insecure":false,"sni":sni}}))
}

fn decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit())
        {
            return Err(CliError::new("invalid percent encoding in sharing link"));
        }
    }
    percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| CliError::new("sharing link must decode to UTF-8"))
}

fn import(uri: &str) -> Result<Value> {
    if uri.len() > 64 * 1024 || uri.chars().any(char::is_whitespace) {
        return Err(CliError::new(
            "sharing link is too large or contains unescaped whitespace",
        ));
    }
    if uri.starts_with("hysteria2+realm://") || uri.starts_with("hysteria2+realm+http://") {
        return import_realm(uri);
    }
    let rest = uri
        .strip_prefix("hysteria2://")
        .or_else(|| uri.strip_prefix("hy2://"))
        .ok_or_else(|| {
            CliError::new("expected a hysteria2://, hy2:// or hysteria2+realm:// sharing link")
        })?;
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    let (auth, server) = authority
        .rsplit_once('@')
        .ok_or_else(|| CliError::new("sharing link must include authentication"))?;
    if auth.contains('@') {
        return Err(CliError::new(
            "special characters in authentication must be percent-encoded",
        ));
    }
    let mut value = json!({"server":hysteria_cli::sharing::normalize_address(server)?,"auth":decode(auth)?,"tls":{"insecure":false}});
    let mut seen = HashSet::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, raw) = pair
            .split_once('=')
            .ok_or_else(|| CliError::new("sharing link parameters must use key=value"))?;
        let key = decode(key)?;
        let parameter = decode(&raw.replace('+', " "))?;
        if !seen.insert(key.clone()) {
            return Err(CliError::new("duplicate sharing link parameter"));
        }
        match key.as_str() {
            "sni" | "pinSHA256" => value["tls"][&key] = parameter.into(),
            "ech" => {
                if parameter.is_empty() {
                    return Err(CliError::new("ECH config list must not be empty"));
                }
                base64::engine::general_purpose::STANDARD
                    .decode(&parameter)
                    .map_err(|_| {
                        CliError::new(
                            "ECH in a sharing link must be inline base64, not a local file path",
                        )
                    })?;
                value["tls"]["ech"] = parameter.into();
            }
            "insecure" => {
                value["tls"]["insecure"] = match parameter.as_str() {
                    "0" => false.into(),
                    "1" => true.into(),
                    _ => return Err(CliError::new("insecure must be 0 or 1")),
                }
            }
            "obfs" => value["obfs"]["type"] = parameter.into(),
            "obfs-password" => value["obfs"]["salamander"]["password"] = parameter.into(),
            _ => {
                return Err(CliError::new(
                    "unsupported sharing link parameter; nothing was imported",
                ));
            }
        }
    }
    let kind = value["obfs"]["type"].as_str().unwrap_or("").to_owned();
    if !matches!(kind.as_str(), "" | "salamander" | "gecko") {
        return Err(CliError::new("unsupported sharing link obfuscation type"));
    }
    if value["obfs"]["salamander"].is_object() {
        if kind.is_empty() {
            return Err(CliError::new("obfs-password requires an obfs type"));
        }
        if kind == "gecko" {
            let password = value["obfs"]
                .as_object_mut()
                .unwrap()
                .remove("salamander")
                .unwrap();
            value["obfs"]["gecko"] = password;
        }
    }
    Ok(value)
}

fn import_realm(uri: &str) -> Result<Value> {
    // Validate escapes before URL query parsing can replace malformed input.
    decode(uri)?;
    let mut url = url::Url::parse(uri).map_err(|_| CliError::new("invalid Realm sharing URI"))?;
    let scheme = match url.scheme() {
        "hysteria2+realm" => "realm",
        "hysteria2+realm+http" => "realm+http",
        _ => return Err(CliError::new("invalid Realm sharing scheme")),
    };
    let mut auth = None;
    let mut common = url::form_urlencoded::Serializer::new(String::new());
    let mut realm = url::form_urlencoded::Serializer::new(String::new());
    let mut local_port = false;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "auth" => {
                if auth.replace(value.into_owned()).is_some() {
                    return Err(CliError::new("duplicate Realm auth parameter"));
                }
            }
            "stun" => {
                if value.is_empty() {
                    return Err(CliError::new("empty STUN server"));
                }
                realm.append_pair("stun", &value);
            }
            "lport" => {
                if local_port {
                    return Err(CliError::new("duplicate Realm lport parameter"));
                }
                local_port = true;
                realm.append_pair("lport", &value);
            }
            _ => {
                common.append_pair(&key, &value);
            }
        }
    }
    let auth = auth.filter(|auth| !auth.is_empty()).ok_or_else(|| {
        CliError::new("Realm link requires auth separately from the rendezvous token")
    })?;
    let encoded = percent_encoding::utf8_percent_encode(&auth, percent_encoding::NON_ALPHANUMERIC);
    let mut value = import(&format!(
        "hysteria2://{encoded}@placeholder.invalid/?{}",
        common.finish()
    ))?;
    url.set_scheme(scheme)
        .map_err(|()| CliError::new("invalid Realm scheme"))?;
    url.set_fragment(None);
    let params = realm.finish();
    url.set_query((!params.is_empty()).then_some(params.as_str()));
    hysteria_realm::RealmAddr::parse(url.as_str())
        .map_err(|_| CliError::new("invalid Realm address or local port"))?;
    value["server"] = url.to_string().into();
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn imports_hopping_ipv6_and_roundtrips_auth() {
        for server in ["example.com:443,5000-5002", "[::1]:8443"] {
            let uri = format!(
                "hy2://user:p%40ss%2Bword@{server}/?sni=edge.example.com&obfs=salamander&obfs-password=some+secret"
            );
            let text = generate(false, Some(&uri), false, &mut &b""[..], &mut Vec::new()).unwrap();
            let config: ClientConfig = serde_yaml_ng::from_str(&text).unwrap();
            assert_eq!(config.server, server);
            assert_eq!(config.auth, "user:p@ss+word");
            assert_eq!(config.socks5.as_ref().unwrap().listen, "127.0.0.1:1080");
            let exported = config.share_uri().unwrap();
            assert_eq!(import(&exported).unwrap(), import(&uri).unwrap());
        }
    }
    #[test]
    fn rejects_ambiguous_or_insecure_links_without_echoing_secrets() {
        for uri in [
            "hy2://secret@host/?insecure=1",
            "hy2://secret@host/?sni=x&sni=y",
            "hy2://secret@host/?unknown=x",
            "hy2://sec%ZZret@host/",
            "hy2://secret@host:0/",
            "hy2://secret@host/path",
        ] {
            let error =
                generate(false, Some(uri), false, &mut &b""[..], &mut Vec::new()).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        assert!(
            generate(
                false,
                Some("hy2://secret@host/?insecure=1"),
                true,
                &mut &b""[..],
                &mut Vec::new()
            )
            .is_ok()
        );
    }
}
