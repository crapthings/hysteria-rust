use crate::{CliError, Result, config::ServerAuth};
use hysteria_protocol::AuthRequest;
use hysteria_transport::Authenticator;
use serde::{Deserialize, Serialize};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

const HTTP_AUTH_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn build(config: &ServerAuth) -> Result<Arc<dyn Authenticator>> {
    let authenticator: Arc<dyn Authenticator> =
        match config.kind.trim().to_ascii_lowercase().as_str() {
            "password" => {
                let password = config.password.clone();
                Arc::new(move |_remote: SocketAddr, request: &AuthRequest| {
                    (request.auth == password).then(|| "password".to_owned())
                })
            }
            "userpass" => {
                let users = config
                    .userpass
                    .iter()
                    .map(|(username, password)| (username.to_ascii_lowercase(), password.clone()))
                    .collect::<std::collections::HashMap<_, _>>();
                Arc::new(move |_remote: SocketAddr, request: &AuthRequest| {
                    request
                        .auth
                        .split_once(':')
                        .and_then(|(username, password)| {
                            let username = username.to_ascii_lowercase();
                            users
                                .get(&username)
                                .is_some_and(|expected| expected == password)
                                .then_some(username)
                        })
                })
            }
            "http" | "https" => Arc::new(HttpAuthenticator::new(
                config.http.url.clone(),
                config.http.insecure,
            )?),
            "command" | "cmd" => Arc::new(CommandAuthenticator {
                command: config.command.clone(),
            }),
            kind => {
                return Err(CliError::new(format!(
                    "unsupported server auth type {kind:?}"
                )));
            }
        };
    Ok(authenticator)
}

#[derive(Debug)]
struct HttpAuthenticator {
    client: reqwest::Client,
    url: String,
}

impl HttpAuthenticator {
    fn new(url: String, insecure: bool) -> Result<Self> {
        crate::tls::ensure_crypto_provider();
        let client = reqwest::Client::builder()
            .timeout(HTTP_AUTH_TIMEOUT)
            .danger_accept_invalid_certs(insecure)
            .build()
            .map_err(|error| CliError::new(format!("invalid HTTP authenticator: {error}")))?;
        Ok(Self { client, url })
    }
}

#[derive(Debug, Serialize)]
struct HttpAuthRequest<'a> {
    addr: String,
    auth: &'a str,
    tx: u64,
}

#[derive(Debug, Deserialize)]
struct HttpAuthResponse {
    ok: bool,
    id: String,
}

impl Authenticator for HttpAuthenticator {
    fn authenticate_async<'a>(
        &'a self,
        remote: SocketAddr,
        request: &'a AuthRequest,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            let response = self
                .client
                .post(&self.url)
                .json(&HttpAuthRequest {
                    addr: remote.to_string(),
                    auth: &request.auth,
                    tx: request.rx,
                })
                .send()
                .await
                .ok()?;
            if response.status() != reqwest::StatusCode::OK {
                return None;
            }
            let response = response.json::<HttpAuthResponse>().await.ok()?;
            response.ok.then_some(response.id)
        })
    }
}

#[derive(Debug)]
struct CommandAuthenticator {
    command: String,
}

impl Authenticator for CommandAuthenticator {
    fn authenticate_async<'a>(
        &'a self,
        remote: SocketAddr,
        request: &'a AuthRequest,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(async move {
            let output = tokio::process::Command::new(&self.command)
                .arg(remote.to_string())
                .arg(&request.auth)
                .arg(request.rx.to_string())
                .output()
                .await
                .ok()?;
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn http_authenticator_matches_go_json_contract() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (expected_auth, status, response) in [
                ("deny", "200 OK", r#"{"ok":false,"id":"ignored"}"#),
                (
                    "bad-status",
                    "403 Forbidden",
                    r#"{"ok":true,"id":"ignored"}"#,
                ),
                ("bad-json", "200 OK", "{"),
                ("allow", "200 OK", r#"{"ok":true,"id":"http-user"}"#),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let body = read_http_body(&mut stream).await;
                let request: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(request["addr"], "127.0.0.1:3456");
                assert_eq!(request["auth"], expected_auth);
                assert_eq!(request["tx"], 12345);
                stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                            response.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            }
        });
        let authenticator =
            HttpAuthenticator::new(format!("http://{address}/auth"), false).unwrap();
        let remote = "127.0.0.1:3456".parse().unwrap();
        assert_eq!(
            authenticator
                .authenticate_async(
                    remote,
                    &AuthRequest {
                        auth: "deny".to_owned(),
                        rx: 12345,
                    },
                )
                .await,
            None
        );
        for auth in ["bad-status", "bad-json"] {
            assert_eq!(
                authenticator
                    .authenticate_async(
                        remote,
                        &AuthRequest {
                            auth: auth.to_owned(),
                            rx: 12345,
                        },
                    )
                    .await,
                None
            );
        }
        assert_eq!(
            authenticator
                .authenticate_async(
                    remote,
                    &AuthRequest {
                        auth: "allow".to_owned(),
                        rx: 12345,
                    },
                )
                .await,
            Some("http-user".to_owned())
        );
        server.await.unwrap();
    }

    async fn read_http_body(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let header_end = loop {
            if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
            let mut chunk = [0; 1024];
            let size = stream.read(&mut chunk).await.unwrap();
            assert_ne!(size, 0);
            request.extend_from_slice(&chunk[..size]);
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.strip_prefix("content-length: ")
                    .or_else(|| line.strip_prefix("Content-Length: "))
            })
            .unwrap()
            .trim()
            .parse::<usize>()
            .unwrap();
        while request.len() < header_end + content_length {
            let mut chunk = [0; 1024];
            let size = stream.read(&mut chunk).await.unwrap();
            assert_ne!(size, 0);
            request.extend_from_slice(&chunk[..size]);
        }
        request[header_end..header_end + content_length].to_vec()
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn command_authenticator_passes_exact_arguments_and_trims_id() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("authenticate.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\n[ \"$1\" = \"127.0.0.1:3456\" ] && [ \"$2\" = \"allow\" ] && [ \"$3\" = \"12345\" ] || exit 1\nprintf ' command-user \\n'\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        let authenticator = CommandAuthenticator {
            command: script.display().to_string(),
        };
        let remote = "127.0.0.1:3456".parse().unwrap();
        assert_eq!(
            authenticator
                .authenticate_async(
                    remote,
                    &AuthRequest {
                        auth: "allow".to_owned(),
                        rx: 12345,
                    },
                )
                .await,
            Some("command-user".to_owned())
        );
        assert_eq!(
            authenticator
                .authenticate_async(
                    remote,
                    &AuthRequest {
                        auth: "deny".to_owned(),
                        rx: 12345,
                    },
                )
                .await,
            None
        );
    }
}
