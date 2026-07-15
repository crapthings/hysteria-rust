use crate::{CliError, Result};
use bytes::Bytes;
use http_body_util::{BodyExt as _, Empty};
use hyper::{Request, StatusCode, client::conn::http1};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use std::{future::Future, sync::Arc, time::Duration};
use tokio_rustls::TlsConnector;

const UPDATE_ENDPOINT: &str = "https://api.hy2.io/v1/update";
const UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
const UPDATE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UpdateResponse {
    #[serde(rename = "update")]
    pub has_update: bool,
    #[serde(rename = "lver")]
    pub latest_version: String,
    pub url: String,
    pub urgent: bool,
}

/// Checks the official Hysteria update service for a server-side release.
///
/// # Errors
///
/// Returns an error for request, HTTP status, or response decoding failures.
pub async fn check_update() -> Result<UpdateResponse> {
    check_update_at(UPDATE_ENDPOINT, "server").await
}

async fn check_update_at(endpoint: &str, side: &str) -> Result<UpdateResponse> {
    crate::tls::ensure_crypto_provider();
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        platform => platform,
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        architecture => architecture,
    };
    let client = reqwest::Client::builder()
        .timeout(UPDATE_TIMEOUT)
        .build()
        .map_err(|error| CliError::new(format!("failed to create update client: {error}")))?;
    let response = client
        .get(endpoint)
        .query(&[
            ("cver", env!("CARGO_PKG_VERSION")),
            ("plat", platform),
            ("arch", architecture),
            ("chan", "release"),
            ("side", side),
        ])
        .send()
        .await
        .map_err(|error| CliError::new(format!("failed to check for updates: {error}")))?;
    let status = response.status();
    if status != reqwest::StatusCode::OK {
        return Err(CliError::new(format!(
            "update service returned HTTP {}",
            status.as_u16()
        )));
    }
    response
        .json()
        .await
        .map_err(|error| CliError::new(format!("invalid update response: {error}")))
}

/// Runs the Go-compatible direct server update check immediately and every 24 hours.
pub(crate) async fn background_server() {
    background(|| check_update_at(UPDATE_ENDPOINT, "server")).await;
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
                "update available: {} ({}){}",
                response.latest_version,
                response.url,
                if response.urgent { " [urgent]" } else { "" }
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
        let url = update_url(endpoint, "client")?;
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
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let path = match url.query() {
            Some(query) => format!("{}?{query}", url.path()),
            None => url.path().to_owned(),
        };
        let request = Request::get(path)
            .header("host", host)
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
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| CliError::new(format!("invalid update response body: {error}")))?
            .to_bytes();
        serde_json::from_slice(&body)
            .map_err(|error| CliError::new(format!("invalid update response: {error}")))
    })
    .await
    .map_err(|_| CliError::new("update check timed out"))?
}

fn update_url(endpoint: &str, side: &str) -> Result<url::Url> {
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        platform => platform,
    };
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        architecture => architecture,
    };
    let mut url = url::Url::parse(endpoint)
        .map_err(|error| CliError::new(format!("invalid update endpoint: {error}")))?;
    url.query_pairs_mut()
        .append_pair("cver", env!("CARGO_PKG_VERSION"))
        .append_pair("plat", platform)
        .append_pair("arch", architecture)
        .append_pair("chan", "release")
        .append_pair("side", side);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn sends_go_query_fields_and_decodes_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let size = stream.read(&mut request).await.unwrap();
            let request = String::from_utf8_lossy(&request[..size]);
            assert!(request.starts_with("GET /v1/update?"));
            for field in ["cver=", "plat=", "arch=", "chan=release", "side=server"] {
                assert!(request.contains(field), "missing {field} in {request}");
            }
            let body = r#"{"update":true,"lver":"9.9.9","url":"https://example.test/release","urgent":true}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        });
        let response = check_update_at(&format!("http://{address}/v1/update"), "server")
            .await
            .unwrap();
        assert_eq!(
            response,
            UpdateResponse {
                has_update: true,
                latest_version: "9.9.9".to_owned(),
                url: "https://example.test/release".to_owned(),
                urgent: true,
            }
        );
        server.await.unwrap();
    }

    #[test]
    fn client_update_url_uses_tunneled_side_field() {
        let url = update_url(UPDATE_ENDPOINT, "client").unwrap();
        let query = url.query().unwrap();
        for field in ["cver=", "plat=", "arch=", "chan=release", "side=client"] {
            assert!(query.contains(field), "missing {field} in {query}");
        }
        assert_eq!(url.host_str(), Some("api.hy2.io"));
        assert_eq!(url.scheme(), "https");
    }
}
