use crate::{PunchMetadata, RealmAddr};
use bytes::Bytes;
use futures::{Stream, StreamExt as _};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{fmt, pin::Pin};
use thiserror::Error;
use url::Url;

const MAX_ERROR_BODY_SIZE: usize = 64 * 1024;
const MAX_EVENT_BUFFER_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub session_id: String,
    pub ttl: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    pub ttl: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub punch: PunchMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectResponse {
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub punch: PunchMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PunchEvent {
    pub addresses: Vec<String>,
    #[serde(flatten)]
    pub punch: PunchMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ErrorResponse {
    #[serde(default)]
    pub error: String,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusError {
    pub status: StatusCode,
    pub response: ErrorResponse,
}

impl fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.response.error.is_empty() && self.response.message.is_empty() {
            write!(formatter, "realm server returned {}", self.status.as_u16())
        } else {
            write!(
                formatter,
                "realm server returned {}: {}: {}",
                self.status.as_u16(),
                self.response.error,
                self.response.message
            )
        }
    }
}

impl std::error::Error for StatusError {}

#[derive(Debug, Error)]
pub enum RealmClientError {
    #[error("invalid realm client configuration: {0}")]
    InvalidConfig(String),
    #[error("invalid realm request: {0}")]
    InvalidRequest(String),
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Status(#[from] StatusError),
    #[error("invalid realm response: {0}")]
    Response(String),
}

#[derive(Debug, Clone)]
pub struct RealmClient {
    base_url: Url,
    token: String,
    http: reqwest::Client,
}

impl RealmClient {
    /// Creates a rendezvous client from a parsed Realm address.
    ///
    /// # Errors
    ///
    /// Returns an error if the base URL or HTTP client configuration is invalid.
    pub fn from_addr(address: &RealmAddr, insecure: bool) -> Result<Self, RealmClientError> {
        let base_url = Url::parse(&address.base_url())
            .map_err(|error| RealmClientError::InvalidConfig(error.to_string()))?;
        let http = default_http_client(insecure)?;
        Self::new(base_url, address.token.clone(), http)
    }

    /// Creates a rendezvous client with a caller-provided HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error unless the URL is HTTP(S), has an authority, and the token is non-empty.
    pub fn new(
        mut base_url: Url,
        token: String,
        http: reqwest::Client,
    ) -> Result<Self, RealmClientError> {
        if !matches!(base_url.scheme(), "http" | "https") {
            return Err(RealmClientError::InvalidConfig(
                "base URL scheme must be http or https".to_owned(),
            ));
        }
        if base_url.host_str().is_none() {
            return Err(RealmClientError::InvalidConfig(
                "base URL host is required".to_owned(),
            ));
        }
        if token.is_empty() {
            return Err(RealmClientError::InvalidConfig(
                "token is required".to_owned(),
            ));
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        Ok(Self {
            base_url,
            token,
            http,
        })
    }

    /// Registers a Realm server and its candidate addresses.
    ///
    /// # Errors
    ///
    /// Returns an error for request, HTTP status, or response-decoding failures.
    pub async fn register(
        &self,
        realm_id: &str,
        addresses: Vec<String>,
    ) -> Result<RegisterResponse, RealmClientError> {
        self.json(
            Method::POST,
            realm_id,
            &[],
            &self.token,
            Some(&AddressRequest { addresses }),
            StatusCode::OK,
        )
        .await
    }

    /// Removes a registered Realm session.
    ///
    /// # Errors
    ///
    /// Returns an error for request or unexpected HTTP status failures.
    pub async fn deregister(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<(), RealmClientError> {
        self.empty(
            Method::DELETE,
            realm_id,
            &[],
            session_id,
            Option::<&()>::None,
            StatusCode::NO_CONTENT,
        )
        .await
    }

    /// Refreshes a registered Realm session.
    ///
    /// # Errors
    ///
    /// Returns an error for request, HTTP status, or response-decoding failures.
    pub async fn heartbeat(
        &self,
        realm_id: &str,
        session_id: &str,
        request: &HeartbeatRequest,
    ) -> Result<HeartbeatResponse, RealmClientError> {
        self.json(
            Method::POST,
            realm_id,
            &["heartbeat"],
            session_id,
            Some(request),
            StatusCode::OK,
        )
        .await
    }

    /// Starts a client-to-server Realm connection attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for request, HTTP status, or response-decoding failures.
    pub async fn connect(
        &self,
        realm_id: &str,
        request: &ConnectRequest,
    ) -> Result<ConnectResponse, RealmClientError> {
        self.json(
            Method::POST,
            realm_id,
            &["connect"],
            &self.token,
            Some(request),
            StatusCode::OK,
        )
        .await
    }

    /// Posts fresh server candidates for an incoming connection attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for request or unexpected HTTP status failures.
    pub async fn connect_response(
        &self,
        realm_id: &str,
        session_id: &str,
        nonce: &str,
        addresses: Vec<String>,
    ) -> Result<(), RealmClientError> {
        self.empty(
            Method::POST,
            realm_id,
            &["connects", nonce],
            session_id,
            Some(&AddressRequest { addresses }),
            StatusCode::NO_CONTENT,
        )
        .await
    }

    /// Opens the server-sent event stream for incoming punch attempts.
    ///
    /// # Errors
    ///
    /// Returns an error for request or unexpected HTTP status failures.
    pub async fn events(
        &self,
        realm_id: &str,
        session_id: &str,
    ) -> Result<EventStream, RealmClientError> {
        let response = self
            .request(Method::GET, realm_id, &["events"], session_id)?
            .send()
            .await?;
        if response.status() != StatusCode::OK {
            return Err(status_error(response).await.into());
        }
        Ok(EventStream {
            stream: Box::pin(response.bytes_stream()),
            input: Vec::new(),
            event_name: String::new(),
            data: String::new(),
            ended: false,
        })
    }

    async fn json<I: Serialize + ?Sized, O: DeserializeOwned>(
        &self,
        method: Method,
        realm_id: &str,
        path: &[&str],
        token: &str,
        input: Option<&I>,
        expected: StatusCode,
    ) -> Result<O, RealmClientError> {
        let response = send(self.request(method, realm_id, path, token)?, input).await?;
        if response.status() != expected {
            return Err(status_error(response).await.into());
        }
        response.json().await.map_err(Into::into)
    }

    async fn empty<I: Serialize + ?Sized>(
        &self,
        method: Method,
        realm_id: &str,
        path: &[&str],
        token: &str,
        input: Option<&I>,
        expected: StatusCode,
    ) -> Result<(), RealmClientError> {
        let response = send(self.request(method, realm_id, path, token)?, input).await?;
        if response.status() != expected {
            return Err(status_error(response).await.into());
        }
        Ok(())
    }

    fn request(
        &self,
        method: Method,
        realm_id: &str,
        path: &[&str],
        token: &str,
    ) -> Result<reqwest::RequestBuilder, RealmClientError> {
        if realm_id.is_empty() || realm_id.contains('/') {
            return Err(RealmClientError::InvalidRequest(
                "realm id must be a single path segment".to_owned(),
            ));
        }
        let mut url = self.base_url.clone();
        url.set_query(None);
        {
            let mut segments = url.path_segments_mut().map_err(|()| {
                RealmClientError::InvalidConfig("base URL cannot contain path segments".to_owned())
            })?;
            segments.pop_if_empty();
            segments.push("v1").push(realm_id);
            for segment in path {
                segments.push(segment);
            }
        }
        let mut request = self.http.request(method, url);
        if !token.is_empty() {
            request = request.bearer_auth(token);
        }
        Ok(request)
    }
}

#[derive(Serialize)]
struct AddressRequest {
    addresses: Vec<String>,
}

async fn send<I: Serialize + ?Sized>(
    request: reqwest::RequestBuilder,
    input: Option<&I>,
) -> Result<reqwest::Response, reqwest::Error> {
    match input {
        Some(input) => request.json(input),
        None => request,
    }
    .send()
    .await
}

fn default_http_client(insecure: bool) -> Result<reqwest::Client, RealmClientError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()
        .map_err(Into::into)
}

async fn status_error(response: reqwest::Response) -> StatusError {
    let status = response.status();
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while bytes.len() < MAX_ERROR_BODY_SIZE {
        let Some(Ok(chunk)) = stream.next().await else {
            break;
        };
        let remaining = MAX_ERROR_BODY_SIZE - bytes.len();
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
    }
    let response = serde_json::from_slice(&bytes).unwrap_or_default();
    StatusError { status, response }
}

type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send>>;

pub struct EventStream {
    stream: ByteStream,
    input: Vec<u8>,
    event_name: String,
    data: String,
    ended: bool,
}

impl fmt::Debug for EventStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventStream")
            .field("buffered_bytes", &self.input.len())
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl EventStream {
    /// Reads the next `punch` server-sent event, ignoring comments and other event kinds.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failures, oversized events, invalid UTF-8, or invalid JSON.
    pub async fn next(&mut self) -> Result<Option<PunchEvent>, RealmClientError> {
        loop {
            while let Some(position) = self.input.iter().position(|byte| *byte == b'\n') {
                let mut line = self.input.drain(..=position).collect::<Vec<_>>();
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                let line = std::str::from_utf8(&line)
                    .map_err(|error| RealmClientError::Response(error.to_string()))?;
                if let Some(event) = self.process_line(line)? {
                    return Ok(Some(event));
                }
            }
            if self.ended {
                return Ok(None);
            }
            match self.stream.next().await {
                Some(Ok(chunk)) => {
                    if self.input.len() + chunk.len() > MAX_EVENT_BUFFER_SIZE {
                        return Err(RealmClientError::Response(
                            "realm event exceeds 1 MiB".to_owned(),
                        ));
                    }
                    self.input.extend_from_slice(&chunk);
                }
                Some(Err(error)) => return Err(error.into()),
                None => self.ended = true,
            }
        }
    }

    fn process_line(&mut self, line: &str) -> Result<Option<PunchEvent>, RealmClientError> {
        if line.is_empty() {
            if self.event_name == "punch" {
                let event = serde_json::from_str(&self.data)
                    .map_err(|error| RealmClientError::Response(error.to_string()))?;
                self.event_name.clear();
                self.data.clear();
                return Ok(Some(event));
            }
            self.event_name.clear();
            self.data.clear();
            return Ok(None);
        }
        if line.starts_with(':') {
            return Ok(None);
        }
        let Some((field, mut value)) = line.split_once(':') else {
            return Ok(None);
        };
        value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => value.clone_into(&mut self.event_name),
            "data" => {
                if !self.data.is_empty() {
                    self.data.push('\n');
                }
                self.data.push_str(value);
            }
            _ => {}
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, extract::Request, http::header, response::Response, routing::any};
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn matches_go_http_and_sse_contract() {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let handler_seen = Arc::clone(&seen);
        let app = Router::new().fallback(any(move |request: Request| {
            let seen = Arc::clone(&handler_seen);
            async move {
                let method = request.method().clone();
                let path = request.uri().path().to_owned();
                let authorization = request
                    .headers()
                    .get(header::AUTHORIZATION)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                seen.lock()
                    .unwrap()
                    .push(format!("{method} {path} {authorization}"));
                match (method, path.as_str()) {
                    (Method::POST, "/v1/realm") => Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(r#"{"session_id":"session","ttl":60}"#))
                        .unwrap(),
                    (Method::POST, "/v1/realm/connect") => Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(axum::body::Body::from(r#"{"addresses":["203.0.113.1:443"],"nonce":"00112233445566778899aabbccddeeff","obfs":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"}"#))
                        .unwrap(),
                    (Method::GET, "/v1/realm/events") => Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(axum::body::Body::from(": comment\n\nevent: ignored\ndata: {}\n\nevent: punch\ndata: {\"addresses\":[\"198.51.100.1:443\"],\"nonce\":\"00112233445566778899aabbccddeeff\",\"obfs\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"}\n\n"))
                        .unwrap(),
                    _ => Response::builder()
                        .status(StatusCode::NO_CONTENT)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = RealmClient::new(
            format!("http://{address}").parse().unwrap(),
            "realm-token".to_owned(),
            reqwest::Client::new(),
        )
        .unwrap();
        let registered = client
            .register("realm", vec!["203.0.113.1:443".to_owned()])
            .await
            .unwrap();
        assert_eq!(registered.session_id, "session");
        let punch = PunchMetadata {
            nonce: "00112233445566778899aabbccddeeff".to_owned(),
            obfs: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        };
        let connected = client
            .connect(
                "realm",
                &ConnectRequest {
                    addresses: vec!["198.51.100.1:443".to_owned()],
                    punch: punch.clone(),
                },
            )
            .await
            .unwrap();
        assert_eq!(connected.punch, punch);
        let mut events = client.events("realm", "session").await.unwrap();
        assert_eq!(events.next().await.unwrap().unwrap().punch, punch);
        assert!(events.next().await.unwrap().is_none());
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "POST /v1/realm Bearer realm-token",
                "POST /v1/realm/connect Bearer realm-token",
                "GET /v1/realm/events Bearer session",
            ]
        );
        server.abort();
    }
}
