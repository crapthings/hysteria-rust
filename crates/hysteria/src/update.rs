use crate::{CliError, Result};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty, Limited};
use hyper::{Request, StatusCode, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use std::{future::Future, sync::Arc, time::Duration};
use tokio_rustls::TlsConnector;

const UPDATE_ENDPOINT: &str =
    "https://api.github.com/repos/crapthings/hysteria-rust/releases?per_page=100";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const RELEASE_PAGE: &str = "https://github.com/crapthings/hysteria-rust/releases";
const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const UPDATE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateResponse {
    pub has_update: bool,
    pub latest_version: String,
    pub url: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    draft: bool,
    prerelease: bool,
}

// Compare semantic versions, not API ordering or lexicographic tag names.
fn release_response(bytes: &[u8], current: &str) -> Result<UpdateResponse> {
    let releases: Vec<Release> = serde_json::from_slice(bytes)
        .map_err(|_| CliError::new("invalid GitHub releases response"))?;
    let current = semver::Version::parse(current)
        .map_err(|_| CliError::new("invalid application version"))?;
    let latest = releases
        .into_iter()
        .filter_map(|release| {
            if release.draft {
                return None;
            }
            let version = semver::Version::parse(release.tag_name.strip_prefix('v')?).ok()?;
            if current.pre.is_empty() && (release.prerelease || !version.pre.is_empty()) {
                return None;
            }
            Some(version)
        })
        .max_by(semver::Version::cmp_precedence)
        .ok_or_else(|| CliError::new("no compatible versioned release in GitHub response"))?;
    Ok(UpdateResponse {
        has_update: latest.cmp_precedence(&current).is_gt(),
        url: format!("{RELEASE_PAGE}/tag/v{latest}"),
        latest_version: latest.to_string(),
    })
}

/// Checks this Rust project's published releases without changing installed binaries.
///
/// # Errors
/// Returns an error for request, status, size, decoding or version failures.
pub async fn check_update() -> Result<UpdateResponse> {
    check_update_at(UPDATE_ENDPOINT).await
}

async fn check_update_at(endpoint: &str) -> Result<UpdateResponse> {
    crate::tls::ensure_crypto_provider();
    let client = reqwest::Client::builder()
        .timeout(UPDATE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("hysteria-rust/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|_| CliError::new("failed to create update client"))?;
    // Include body consumption in the deadline, even for a slow streaming peer.
    tokio::time::timeout(UPDATE_TIMEOUT, async {
        let mut response = client
            .get(endpoint)
            .header("accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|_| CliError::new("failed to query GitHub releases"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(CliError::new(format!(
                "GitHub releases returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| CliError::new("failed to read GitHub releases response"))?
        {
            if chunk.len() > MAX_RESPONSE_BYTES - body.len() {
                return Err(CliError::new("GitHub releases response exceeds 4 MiB"));
            }
            body.extend_from_slice(&chunk);
        }
        release_response(&body, env!("CARGO_PKG_VERSION"))
    })
    .await
    .map_err(|_| CliError::new("update check timed out"))?
}

/// Checks directly at startup and every 24 hours.
pub(crate) async fn background_server() {
    background(check_update).await;
}

/// Runs client update checks through the authenticated Hysteria TCP connection.
pub(crate) async fn background_client(client: Arc<hysteria_transport::ProxyClient>) {
    background(|| check_update_through_client(UPDATE_ENDPOINT, &client)).await;
}

async fn background<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<UpdateResponse>>,
{
    loop {
        if let Ok(response) = check().await
            && response.has_update
        {
            eprintln!(
                "update available: {} ({})",
                response.latest_version, response.url
            );
        }
        tokio::time::sleep(UPDATE_INTERVAL).await;
    }
}

async fn check_update_through_client(
    endpoint: &str,
    client: &hysteria_transport::ProxyClient,
) -> Result<UpdateResponse> {
    tokio::time::timeout(UPDATE_TIMEOUT, async {
        let url =
            url::Url::parse(endpoint).map_err(|_| CliError::new("invalid update endpoint"))?;
        let host = url
            .host_str()
            .ok_or_else(|| CliError::new("update endpoint has no host"))?;
        if url.scheme() != "https" {
            return Err(CliError::new("tunneled update endpoint must use HTTPS"));
        }
        let port = url.port_or_known_default().unwrap_or(443);
        let tunnel = client.tcp(&format!("{host}:{port}")).await?;
        let tls = crate::tls::client_config(None, false, None, None, None)?;
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|error| CliError::new(format!("invalid update endpoint host: {error}")))?;
        let stream = TlsConnector::from(Arc::new(tls))
            .connect(server_name, tunnel)
            .await
            .map_err(|error| CliError::new(format!("update TLS handshake failed: {error}")))?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|error| CliError::new(format!("update HTTP handshake failed: {error}")))?;
        // Dropping the request (including on timeout) must stop its HTTP driver.
        let mut connection_tasks = tokio::task::JoinSet::new();
        connection_tasks.spawn(async move {
            let _ = connection.await;
        });
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let request = Request::get(path)
            .header("host", host)
            .header("accept", "application/vnd.github+json")
            .header(
                "user-agent",
                concat!("hysteria-rust/", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::<Bytes>::new())
            .map_err(|error| CliError::new(format!("invalid update request: {error}")))?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| CliError::new(format!("failed to check for updates: {error}")))?;
        if response.status() != StatusCode::OK {
            return Err(CliError::new(format!(
                "update service returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let body = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
            .collect()
            .await
            .map_err(|error| CliError::new(format!("invalid update response body: {error}")))?
            .to_bytes();
        release_response(&body, env!("CARGO_PKG_VERSION"))
    })
    .await
    .map_err(|_| CliError::new("update check timed out"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn selects_versions_without_downgrades_or_stable_to_prerelease_promotions() {
        let body = br#"[
          {"tag_name":"v0.1.0-rc.9","draft":false,"prerelease":true},
          {"tag_name":"v0.1.0-rc.10","draft":false,"prerelease":true},
          {"tag_name":"v9.0.0","draft":true,"prerelease":false},
          {"tag_name":"nightly","draft":false,"prerelease":true},
          {"tag_name":"v0.0.9","draft":false,"prerelease":false}
        ]"#;
        let response = release_response(body, "0.1.0-rc.6").unwrap();
        assert!(response.has_update);
        assert_eq!(response.latest_version, "0.1.0-rc.10");
        assert_eq!(response.url, format!("{RELEASE_PAGE}/tag/v0.1.0-rc.10"));
        assert!(!release_response(body, "0.1.0").unwrap().has_update);
        assert!(!release_response(body, "0.1.0-rc.10").unwrap().has_update);
        assert!(release_response(b"[]", "0.1.0").is_err());
        assert!(release_response(b"not JSON", "0.1.0").is_err());
        let release = br#"[{"tag_name":"v0.1.0","draft":false,"prerelease":false}]"#;
        assert!(release_response(release, "0.1.0-rc.6").unwrap().has_update);
        let metadata = br#"[{"tag_name":"v0.1.0+build2","draft":false,"prerelease":false}]"#;
        assert!(
            !release_response(metadata, "0.1.0+build1")
                .unwrap()
                .has_update
        );
    }

    async fn fixture(status: &str, body: Vec<u8>) -> Result<UpdateResponse> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 4096];
            let size = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.starts_with("GET /releases?per_page=100 "));
            assert!(request.contains("application/vnd.github+json"));
            assert!(request.contains("hysteria-rust/"));
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.write_all(&body).await;
        });
        let result = check_update_at(&format!("http://{address}/releases?per_page=100")).await;
        server.await.unwrap();
        result
    }

    #[tokio::test]
    async fn checks_rust_releases_and_rejects_bad_status_schema_and_oversized_body() {
        let body = br#"[{"tag_name":"v9.0.0","draft":false,"prerelease":false}]"#;
        assert!(fixture("200 OK", body.to_vec()).await.unwrap().has_update);
        assert!(fixture("403 Forbidden", b"{}".to_vec()).await.is_err());
        assert!(fixture("200 OK", b"{}".to_vec()).await.is_err());
        assert!(
            fixture("200 OK", vec![b' '; MAX_RESPONSE_BYTES + 1])
                .await
                .is_err()
        );
    }
}
