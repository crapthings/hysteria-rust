use crate::{CliError, Result, acme_dns, config::ServerAcme};
use axum::{
    Router,
    extract::{Path, State},
    http::StatusCode,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose};
use futures::StreamExt as _;
use rustls_acme::{AcmeConfig, EventOk, ResolvesServerCertAcme, UseChallenge, caches::DirCache};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::{io::AsyncWriteExt as _, net::TcpListener, task::JoinHandle};
use tokio_rustls::TlsAcceptor;

pub(crate) struct AcmeRuntime {
    state_task: JoinHandle<()>,
    challenge_tasks: Vec<JoinHandle<()>>,
}

impl Drop for AcmeRuntime {
    fn drop(&mut self) {
        self.state_task.abort();
        for task in &self.challenge_tasks {
            task.abort();
        }
    }
}

struct PreparedChallenges {
    kind: UseChallenge,
    http: Option<TcpListener>,
    tls: Option<TcpListener>,
}

pub(crate) async fn acquire(config: &ServerAcme) -> Result<(rustls::ServerConfig, AcmeRuntime)> {
    crate::tls::ensure_crypto_provider();
    let prepared = prepare_challenges(config).await?;
    let directory = if config.dir.is_empty() {
        std::env::var_os("HYSTERIA_ACME_DIR").map_or_else(|| PathBuf::from("acme"), PathBuf::from)
    } else {
        PathBuf::from(&config.dir)
    };
    let mut builder = AcmeConfig::new_with_provider(
        &config.domains,
        Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
    );
    if is_zerossl(config) {
        let eab = zerossl_eab(&directory, config.email.trim()).await?;
        let mac_key = eab.mac_key()?;
        builder = builder
            .directory("https://acme.zerossl.com/v2/DV90")
            .external_account(eab.key_id, mac_key);
    } else {
        builder = builder.directory_lets_encrypt(true);
    }
    let mut builder = builder.cache(DirCache::new(directory));
    if !config.email.trim().is_empty() {
        builder = builder.contact_push(format!("mailto:{}", config.email.trim()));
    }
    builder = if matches!(prepared.kind, UseChallenge::Dns01) {
        builder.dns01_solver(acme_dns::solver(&config.dns)?)
    } else {
        builder.challenge_type(prepared.kind)
    };
    let mut state = builder.state();
    let resolver = state.resolver();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| CliError::new(format!("failed to configure ACME TLS: {error}")))?
    .with_no_client_auth()
    .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn rustls::server::ResolvesServerCert>);

    let mut challenge_tasks = Vec::new();
    if let Some(listener) = prepared.http {
        challenge_tasks.push(spawn_http_challenge(listener, Arc::clone(&resolver))?);
    }
    if let Some(listener) = prepared.tls {
        let challenge_tls = state.challenge_rustls_config_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ));
        challenge_tasks.push(spawn_tls_challenge(listener, challenge_tls)?);
    }

    loop {
        let event = state
            .next()
            .await
            .ok_or_else(|| CliError::new("ACME state ended before issuing a certificate"))?;
        match event {
            Ok(EventOk::DeployedCachedCert | EventOk::DeployedNewCert) => break,
            Ok(event) => eprintln!("ACME: {event:?}"),
            Err(error) => {
                for task in &challenge_tasks {
                    task.abort();
                }
                return Err(CliError::new(format!(
                    "ACME certificate acquisition failed: {error}"
                )));
            }
        }
    }

    let state_task = tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(event) => eprintln!("ACME: {event:?}"),
                Err(error) => eprintln!("ACME renewal error: {error}"),
            }
        }
    });
    Ok((
        tls,
        AcmeRuntime {
            state_task,
            challenge_tasks,
        },
    ))
}

fn is_zerossl(config: &ServerAcme) -> bool {
    matches!(
        config.ca.trim().to_ascii_lowercase().as_str(),
        "zerossl" | "zero"
    )
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ZeroSslEab {
    #[serde(rename = "eab_kid", default)]
    key_id: String,
    #[serde(rename = "eab_hmac_key", default)]
    mac_key_base64: String,
}

impl ZeroSslEab {
    fn mac_key(&self) -> Result<Vec<u8>> {
        for engine in [
            &general_purpose::URL_SAFE_NO_PAD,
            &general_purpose::URL_SAFE,
            &general_purpose::STANDARD,
        ] {
            if let Ok(key) = engine.decode(self.mac_key_base64.as_bytes())
                && !key.is_empty()
            {
                return Ok(key);
            }
        }
        Err(CliError::new("ZeroSSL returned an invalid EAB HMAC key"))
    }
}

#[derive(Debug, Deserialize)]
struct ZeroSslEabApiResponse {
    #[serde(default)]
    success: bool,
    #[serde(flatten)]
    credentials: ZeroSslEab,
    #[serde(default)]
    error: ZeroSslApiError,
}

#[derive(Debug, Default, Deserialize)]
struct ZeroSslApiError {
    #[serde(default)]
    code: i64,
    #[serde(rename = "type", default)]
    kind: String,
}

async fn zerossl_eab(directory: &FsPath, email: &str) -> Result<ZeroSslEab> {
    let path = directory.join("zerossl-eab.json");
    if let Ok(contents) = fs::read(&path) {
        let credentials: ZeroSslEab = serde_json::from_slice(&contents)
            .map_err(|error| CliError::new(format!("invalid cached ZeroSSL EAB: {error}")))?;
        credentials.mac_key()?;
        if credentials.key_id.is_empty() {
            return Err(CliError::new("cached ZeroSSL EAB key ID is empty"));
        }
        return Ok(credentials);
    }
    let response = reqwest::Client::new()
        .post("https://api.zerossl.com/acme/eab-credentials-email")
        .header("user-agent", "hysteria-rust")
        .form(&[("email", email)])
        .send()
        .await
        .map_err(|error| CliError::new(format!("failed to request ZeroSSL EAB: {error}")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|error| CliError::new(format!("failed to read ZeroSSL EAB response: {error}")))?;
    let parsed: ZeroSslEabApiResponse = serde_json::from_slice(&body)
        .map_err(|error| CliError::new(format!("invalid ZeroSSL EAB response: {error}")))?;
    if !status.is_success() || !parsed.success || parsed.error.code != 0 {
        return Err(CliError::new(format!(
            "ZeroSSL EAB request failed with HTTP {status}: {} (code {})",
            parsed.error.kind, parsed.error.code
        )));
    }
    if parsed.credentials.key_id.is_empty() {
        return Err(CliError::new("ZeroSSL returned an empty EAB key ID"));
    }
    parsed.credentials.mac_key()?;
    fs::create_dir_all(directory)?;
    let serialized = serde_json::to_vec(&parsed.credentials)
        .map_err(|error| CliError::new(format!("failed to encode ZeroSSL EAB cache: {error}")))?;
    fs::write(&path, serialized)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(parsed.credentials)
}

fn challenge(config: &ServerAcme) -> UseChallenge {
    match config.kind.trim().to_ascii_lowercase().as_str() {
        "http" => UseChallenge::Http01,
        "tls" => UseChallenge::TlsAlpn01,
        "dns" => UseChallenge::Dns01,
        _ if config.disable_tls_alpn => UseChallenge::Http01,
        _ if config.disable_http => UseChallenge::TlsAlpn01,
        _ => UseChallenge::Http01AndTlsAlpn01,
    }
}

async fn prepare_challenges(config: &ServerAcme) -> Result<PreparedChallenges> {
    let requested = challenge(config);
    let mut prepared = PreparedChallenges {
        kind: requested,
        http: None,
        tls: None,
    };
    match requested {
        UseChallenge::Http01 => {
            let port = nonzero_or(config.http.alt_port, config.alt_http_port, 80);
            prepared.http = Some(bind_challenge(&config.listen_host, port, "HTTP-01").await?);
        }
        UseChallenge::TlsAlpn01 => {
            let port = nonzero_or(config.tls.alt_port, config.alt_tls_alpn_port, 443);
            prepared.tls = Some(bind_challenge(&config.listen_host, port, "TLS-ALPN-01").await?);
        }
        UseChallenge::Dns01 => {}
        UseChallenge::Http01AndTlsAlpn01 => {
            let http_port = nonzero_or(config.http.alt_port, config.alt_http_port, 80);
            let tls_port = nonzero_or(config.tls.alt_port, config.alt_tls_alpn_port, 443);
            let (http, tls) = tokio::join!(
                bind_challenge(&config.listen_host, http_port, "HTTP-01"),
                bind_challenge(&config.listen_host, tls_port, "TLS-ALPN-01"),
            );
            match (http, tls) {
                (Ok(http), Ok(tls)) => {
                    prepared.http = Some(http);
                    prepared.tls = Some(tls);
                }
                (Ok(http), Err(error)) => {
                    eprintln!("ACME legacy mode: {error}; continuing with HTTP-01 only");
                    prepared.kind = UseChallenge::Http01;
                    prepared.http = Some(http);
                }
                (Err(error), Ok(tls)) => {
                    eprintln!("ACME legacy mode: {error}; continuing with TLS-ALPN-01 only");
                    prepared.kind = UseChallenge::TlsAlpn01;
                    prepared.tls = Some(tls);
                }
                (Err(http), Err(tls)) => {
                    return Err(CliError::new(format!(
                        "failed to bind both legacy ACME challenge listeners: {http}; {tls}"
                    )));
                }
            }
        }
    }
    Ok(prepared)
}

fn spawn_http_challenge(
    listener: TcpListener,
    resolver: Arc<ResolvesServerCertAcme>,
) -> Result<JoinHandle<()>> {
    let app = Router::new()
        .route("/.well-known/acme-challenge/{token}", get(http_challenge))
        .with_state(resolver);
    eprintln!(
        "ACME HTTP-01 challenge listener on {}",
        listener.local_addr()?
    );
    Ok(tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, app).await {
            eprintln!("ACME HTTP-01 listener failed: {error}");
        }
    }))
}

async fn http_challenge(
    Path(token): Path<String>,
    State(resolver): State<Arc<ResolvesServerCertAcme>>,
) -> (StatusCode, String) {
    resolver.get_http_01_key_auth(&token).map_or_else(
        || (StatusCode::NOT_FOUND, String::new()),
        |body| (StatusCode::OK, body),
    )
}

fn spawn_tls_challenge(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
) -> Result<JoinHandle<()>> {
    eprintln!(
        "ACME TLS-ALPN-01 challenge listener on {}",
        listener.local_addr()?
    );
    Ok(tokio::spawn(async move {
        let acceptor = TlsAcceptor::from(tls);
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(stream).await {
                    let _ = stream.shutdown().await;
                }
            });
        }
    }))
}

async fn bind_challenge(host: &str, port: u16, kind: &str) -> Result<TcpListener> {
    let host = if host.trim().is_empty() {
        "0.0.0.0"
    } else {
        host.trim()
    };
    TcpListener::bind((host, port)).await.map_err(|error| {
        CliError::new(format!(
            "failed to bind ACME {kind} challenge listener on {host}:{port}: {error}"
        ))
    })
}

const fn nonzero_or(primary: u16, legacy: u16, default: u16) -> u16 {
    if primary != 0 {
        primary
    } else if legacy != 0 {
        legacy
    } else {
        default
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_explicit_and_legacy_challenges_and_ports() {
        let mut config = ServerAcme::default();
        assert!(matches!(
            challenge(&config),
            UseChallenge::Http01AndTlsAlpn01
        ));
        config.disable_tls_alpn = true;
        assert!(matches!(challenge(&config), UseChallenge::Http01));
        config.disable_tls_alpn = false;
        config.disable_http = true;
        assert!(matches!(challenge(&config), UseChallenge::TlsAlpn01));
        config.kind = "tls".to_owned();
        assert!(matches!(challenge(&config), UseChallenge::TlsAlpn01));
        assert_eq!(nonzero_or(8443, 9443, 443), 8443);
        assert_eq!(nonzero_or(0, 9443, 443), 9443);
        assert_eq!(nonzero_or(0, 0, 443), 443);
    }

    #[tokio::test]
    async fn legacy_mode_prepares_both_listeners_and_degrades_to_the_available_one() {
        async fn free_port() -> u16 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            listener.local_addr().unwrap().port()
        }

        async fn prepare_free_pair(config: &mut ServerAcme) -> PreparedChallenges {
            for _ in 0..16 {
                config.alt_http_port = free_port().await;
                config.alt_tls_alpn_port = free_port().await;
                if config.alt_http_port == config.alt_tls_alpn_port {
                    continue;
                }
                if let Ok(prepared) = prepare_challenges(config).await {
                    return prepared;
                }
            }
            panic!("failed to reserve two ACME test ports after 16 attempts");
        }

        let mut config = ServerAcme {
            listen_host: "127.0.0.1".to_owned(),
            ..ServerAcme::default()
        };
        let prepared = prepare_free_pair(&mut config).await;
        assert_eq!(prepared.kind, UseChallenge::Http01AndTlsAlpn01);
        assert!(prepared.http.is_some());
        assert!(prepared.tls.is_some());
        drop(prepared);

        let occupied = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        config.alt_http_port = occupied.local_addr().unwrap().port();
        let mut prepared = None;
        for _ in 0..16 {
            config.alt_tls_alpn_port = free_port().await;
            if let Ok(candidate) = prepare_challenges(&config).await {
                prepared = Some(candidate);
                break;
            }
        }
        let prepared = prepared.expect("failed to reserve an ACME TLS test port after 16 attempts");
        assert_eq!(prepared.kind, UseChallenge::TlsAlpn01);
        assert!(prepared.http.is_none());
        assert!(prepared.tls.is_some());
    }

    #[test]
    fn parses_zerossl_eab_and_decodes_url_safe_key() {
        let response: ZeroSslEabApiResponse = serde_json::from_str(
            r#"{"success":true,"eab_kid":"kid","eab_hmac_key":"AQID-_8","error":{"code":0,"type":""}}"#,
        )
        .unwrap();
        assert!(response.success);
        assert_eq!(response.credentials.key_id, "kid");
        assert_eq!(response.credentials.mac_key().unwrap(), [1, 2, 3, 251, 255]);
    }

    #[tokio::test]
    async fn loads_and_validates_cached_zerossl_eab() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("zerossl-eab.json"),
            br#"{"eab_kid":"cached","eab_hmac_key":"AQID"}"#,
        )
        .unwrap();
        let credentials = zerossl_eab(directory.path(), "ignored@example.com")
            .await
            .unwrap();
        assert_eq!(credentials.key_id, "cached");
        assert_eq!(credentials.mac_key().unwrap(), [1, 2, 3]);
    }
}
