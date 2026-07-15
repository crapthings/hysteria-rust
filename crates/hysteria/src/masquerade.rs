use crate::{CliError, Result, config::MasqueradeConfig};
use axum::{
    Extension, Router,
    body::{Body, HttpBody},
    extract::{ConnectInfo, State},
    http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, Uri, header},
    middleware::{self, Next},
    response::IntoResponse,
};
use hysteria_transport::{
    MasqueradeBodyStream, MasqueradeHandler, MasqueradeRequest, MasqueradeResponse,
};
use std::{future::Future, net::SocketAddr, path::PathBuf, pin::Pin, sync::Arc};
use tokio::{net::TcpListener, task::JoinHandle};
use tokio_rustls::TlsAcceptor;
use tokio_stream::{StreamExt, wrappers::ReceiverStream};
use tower::ServiceExt;
use tower_http::services::ServeDir;

const HOP_HEADERS: &[&str] = &[
    "connection",
    "proxy-connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];
const HTML_SIGNATURES: &[&[u8]] = &[
    b"<!DOCTYPE HTML",
    b"<HTML",
    b"<HEAD",
    b"<SCRIPT",
    b"<IFRAME",
    b"<H1",
    b"<DIV",
    b"<FONT",
    b"<TABLE",
    b"<A",
    b"<STYLE",
    b"<TITLE",
    b"<B",
    b"<BODY",
    b"<BR",
    b"<P",
    b"<!--",
];

#[derive(Clone)]
pub(crate) struct Masquerade {
    router: Router,
}

impl Masquerade {
    pub(crate) fn build(config: &MasqueradeConfig) -> Result<Self> {
        let router = match config.kind.trim().to_ascii_lowercase().as_str() {
            "" | "404" => Router::new().fallback(not_found),
            "string" => string_router(config)?,
            "file" => {
                Router::new().fallback_service(ServeDir::new(PathBuf::from(&config.file.dir)))
            }
            "proxy" => proxy_router(config)?,
            kind => {
                return Err(CliError::new(format!(
                    "unsupported masquerade type {kind:?}"
                )));
            }
        };
        Ok(Self { router })
    }

    pub(crate) fn router(&self) -> Router {
        self.router.clone()
    }

    pub(crate) async fn start_tcp(
        &self,
        config: &MasqueradeConfig,
        mut tls: rustls::ServerConfig,
        quic_port: u16,
    ) -> Result<Option<MasqueradeTcpServers>> {
        if config.listen_http.is_empty() && config.listen_https.is_empty() {
            return Ok(None);
        }
        let cleartext_listener = if config.listen_http.is_empty() {
            None
        } else {
            Some(bind_frontend(&config.listen_http, "HTTP").await?)
        };
        let tls_listener = if config.listen_https.is_empty() {
            None
        } else {
            Some(bind_frontend(&config.listen_https, "HTTPS").await?)
        };
        let https_port = parse_listen_port(&config.listen_https);
        let mut tasks = Vec::with_capacity(2);
        let cleartext_address = cleartext_listener
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()?;
        if let Some(listener) = cleartext_listener {
            let router = frontend_router(
                self.router(),
                FrontendConfig {
                    quic_port,
                    https_port,
                    force_https: config.force_https,
                    scheme: "http",
                },
            );
            tasks.push(tokio::spawn(async move {
                let _ = axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await;
            }));
        }

        let tls_address = tls_listener
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()?;
        if let Some(listener) = tls_listener {
            tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            let acceptor = TlsAcceptor::from(Arc::new(tls));
            let router = frontend_router(
                self.router(),
                FrontendConfig {
                    quic_port,
                    https_port,
                    force_https: false,
                    scheme: "https",
                },
            );
            tasks.push(tokio::spawn(serve_https(listener, acceptor, router)));
        }
        Ok(Some(MasqueradeTcpServers {
            http_address: cleartext_address,
            https_address: tls_address,
            tasks,
        }))
    }
}

pub(crate) struct MasqueradeTcpServers {
    pub(crate) http_address: Option<SocketAddr>,
    pub(crate) https_address: Option<SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for MasqueradeTcpServers {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FrontendConfig {
    quic_port: u16,
    https_port: u16,
    force_https: bool,
    scheme: &'static str,
}

#[derive(Debug, Clone, Copy)]
struct RequestScheme(&'static str);

#[derive(Debug, Clone, Copy)]
struct Http3Request;

fn frontend_router(router: Router, config: FrontendConfig) -> Router {
    router.layer(middleware::from_fn_with_state(config, frontend_response))
}

async fn frontend_response(
    State(config): State<FrontendConfig>,
    mut request: Request<Body>,
    next: Next,
) -> Response<Body> {
    if config.force_https {
        return redirect_to_https(&request, config.https_port);
    }
    request
        .extensions_mut()
        .insert(RequestScheme(config.scheme));
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::ALT_SVC,
        HeaderValue::from_str(&format!("h3=\":{}\"; ma=2592000", config.quic_port))
            .expect("an Alt-Svc port is a valid header value"),
    );
    response
}

fn redirect_to_https(request: &Request<Body>, https_port: u16) -> Response<Body> {
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let authority = if https_port == 0 || https_port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{https_port}")
    };
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", axum::http::uri::PathAndQuery::as_str);
    let location = format!("https://{authority}{path}");
    let body = if request.method() == axum::http::Method::HEAD {
        Body::empty()
    } else {
        let escaped = html_escape(&location);
        Body::from(format!("<a href=\"{escaped}\">Moved Permanently</a>.\n\n"))
    };
    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::MOVED_PERMANENTLY;
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&location).expect("a request-derived redirect is a valid header"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('\'', "&#39;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
}

async fn bind_frontend(listen: &str, label: &str) -> Result<TcpListener> {
    let listen = normalize_listen(listen);
    TcpListener::bind(&listen).await.map_err(|error| {
        CliError::new(format!(
            "failed to bind masquerade {label} listener {listen}: {error}"
        ))
    })
}

fn normalize_listen(listen: &str) -> String {
    if listen.starts_with(':') {
        format!("0.0.0.0{listen}")
    } else {
        listen.to_owned()
    }
}

fn parse_listen_port(listen: &str) -> u16 {
    normalize_listen(listen)
        .parse::<SocketAddr>()
        .map_or(0, |address| address.port())
}

async fn serve_https(listener: TcpListener, acceptor: TlsAcceptor, router: Router) {
    loop {
        let Ok((stream, remote)) = listener.accept().await else {
            break;
        };
        let acceptor = acceptor.clone();
        let router = router.clone().layer(Extension(ConnectInfo(remote)));
        tokio::spawn(async move {
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(error) => {
                    eprintln!("masquerade HTTPS handshake failed: {error}");
                    return;
                }
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            let service = hyper_util::service::TowerToHyperService::new(router);
            let builder =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            let _ = builder.serve_connection_with_upgrades(io, service).await;
        });
    }
}

impl MasqueradeHandler for Masquerade {
    fn handle<'a>(
        &'a self,
        request: MasqueradeRequest,
    ) -> Pin<Box<dyn Future<Output = MasqueradeResponse> + Send + 'a>> {
        Box::pin(async move {
            let scheme = if request.uri.scheme_str() == Some("http") {
                "http"
            } else {
                "https"
            };
            let mut incoming = Request::builder()
                .method(request.method)
                .uri(request.uri)
                .body(match request.body_stream {
                    Some(stream) => Body::from_stream(
                        ReceiverStream::new(stream.into_receiver())
                            .map(|chunk| chunk.map_err(std::io::Error::other)),
                    ),
                    None => Body::from(request.body),
                })
                .expect("validated HTTP/3 request parts form an HTTP request");
            *incoming.headers_mut() = request.headers;
            incoming
                .extensions_mut()
                .insert(ConnectInfo(request.remote_address));
            incoming.extensions_mut().insert(RequestScheme(scheme));
            incoming.extensions_mut().insert(Http3Request);
            let response = match self.router.clone().oneshot(incoming).await {
                Ok(response) => response,
                Err(error) => match error {},
            };
            into_transport_response(response)
        })
    }
}

fn into_transport_response(response: Response<Body>) -> MasqueradeResponse {
    let (parts, body) = response.into_parts();
    let (sender, receiver) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut body = body.into_data_stream();
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|error| error.to_string());
            if sender.send(chunk).await.is_err() {
                break;
            }
        }
    });
    MasqueradeResponse {
        status: parts.status,
        headers: parts.headers,
        body: bytes::Bytes::new(),
        body_stream: Some(MasqueradeBodyStream::from_receiver(receiver)),
    }
}

async fn not_found() -> Response<Body> {
    let mut response = Response::new(Body::from("404 page not found\n"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn string_router(config: &MasqueradeConfig) -> Result<Router> {
    let status = if config.string.status_code == 0 {
        StatusCode::OK
    } else {
        StatusCode::from_u16(config.string.status_code)
            .map_err(|error| CliError::new(format!("invalid masquerade status: {error}")))?
    };
    let mut headers = HeaderMap::new();
    for (name, value) in &config.string.headers {
        let name = name.parse::<HeaderName>().map_err(|error| {
            CliError::new(format!("invalid masquerade header {name:?}: {error}"))
        })?;
        let value = value
            .parse::<HeaderValue>()
            .map_err(|error| CliError::new(format!("invalid masquerade header value: {error}")))?;
        headers.insert(name, value);
    }
    let body = config.string.content.clone();
    if !headers.contains_key(header::CONTENT_TYPE) {
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(detect_string_content_type(body.as_bytes())),
        );
    }
    Ok(Router::new().fallback(move || {
        let headers = headers.clone();
        let body = body.clone();
        async move { (status, headers, body) }
    }))
}

fn detect_string_content_type(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(512)];
    let trimmed = data
        .iter()
        .position(|byte| !matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' '))
        .map_or(&[][..], |start| &data[start..]);
    if HTML_SIGNATURES.iter().any(|signature| {
        trimmed.len() > signature.len()
            && trimmed[..signature.len()].eq_ignore_ascii_case(signature)
            && matches!(trimmed[signature.len()], b' ' | b'>')
    }) {
        return "text/html; charset=utf-8";
    }
    if trimmed.len() >= 5 && trimmed[..5].eq_ignore_ascii_case(b"<?xml") {
        return "text/xml; charset=utf-8";
    }
    if data.starts_with(b"%PDF-") {
        return "application/pdf";
    }
    if data.starts_with(&[0xef, 0xbb, 0xbf]) {
        return "text/plain; charset=utf-8";
    }
    if data
        .iter()
        .all(|byte| !matches!(byte, 0x00..=0x08 | 0x0b | 0x0e..=0x1a | 0x1c..=0x1f))
    {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

#[derive(Clone)]
struct ProxyBackend {
    client: reqwest::Client,
    target: reqwest::Url,
    rewrite_host: bool,
    x_forwarded: bool,
}

fn proxy_router(config: &MasqueradeConfig) -> Result<Router> {
    crate::tls::ensure_crypto_provider();
    let target = reqwest::Url::parse(&config.proxy.url)
        .map_err(|error| CliError::new(format!("invalid masquerade proxy URL: {error}")))?;
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.proxy.insecure)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| CliError::new(format!("invalid masquerade proxy: {error}")))?;
    let backend = ProxyBackend {
        client,
        target,
        rewrite_host: config.proxy.rewrite_host,
        x_forwarded: config.proxy.x_forwarded,
    };
    Ok(Router::new().fallback(proxy_request).with_state(backend))
}

async fn proxy_request(
    State(backend): State<ProxyBackend>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    match proxy_request_inner(&backend, remote, request).await {
        Ok(response) => response,
        Err(_error) => StatusCode::BAD_GATEWAY.into_response(),
    }
}

async fn proxy_request_inner(
    backend: &ProxyBackend,
    remote: SocketAddr,
    mut request: Request<Body>,
) -> std::result::Result<Response<Body>, ()> {
    let upgrading = is_upgrade_request(request.headers());
    if upgrading && request.extensions().get::<Http3Request>().is_some() {
        return Ok(StatusCode::NOT_IMPLEMENTED.into_response());
    }
    let incoming_upgrade = upgrading.then(|| hyper::upgrade::on(&mut request));
    let (parts, body) = request.into_parts();
    let scheme = parts
        .extensions
        .get::<RequestScheme>()
        .map_or("https", |scheme| scheme.0);
    let original_host = request_host(&parts.uri, &parts.headers);
    let target = rewrite_url(&backend.target, &parts.uri);
    let body_length = body.size_hint().exact();
    let mut headers = parts.headers;
    if !upgrading {
        remove_hop_headers(&mut headers);
    }
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    ] {
        headers.remove(name);
    }
    if backend.rewrite_host {
        headers.remove(header::HOST);
    } else if let Some(host) = &original_host
        && let Ok(host) = HeaderValue::from_str(host)
    {
        headers.insert(header::HOST, host);
    }
    if backend.x_forwarded {
        if let Ok(value) = HeaderValue::from_str(&remote.ip().to_string()) {
            headers.insert("x-forwarded-for", value);
        }
        if let Some(host) = original_host
            && let Ok(value) = HeaderValue::from_str(&host)
        {
            headers.insert("x-forwarded-host", value);
        }
        headers.insert("x-forwarded-proto", HeaderValue::from_static(scheme));
    }
    if !headers.contains_key(header::CONTENT_LENGTH)
        && let Some(length) = body_length
        && let Ok(value) = HeaderValue::from_str(&length.to_string())
    {
        headers.insert(header::CONTENT_LENGTH, value);
    }
    let upstream = backend
        .client
        .request(parts.method, target)
        .version(if upgrading {
            axum::http::Version::HTTP_11
        } else {
            parts.version
        })
        .headers(headers)
        .body(reqwest::Body::wrap_stream(body.into_data_stream()))
        .send()
        .await
        .map_err(|_error| ())?;
    let status = upstream.status();
    let mut headers = upstream.headers().clone();
    if status == StatusCode::SWITCHING_PROTOCOLS
        && let Some(incoming_upgrade) = incoming_upgrade
    {
        let upstream_upgrade = upstream.upgrade();
        tokio::spawn(async move {
            let (incoming, upstream) = tokio::join!(incoming_upgrade, upstream_upgrade);
            let (Ok(incoming), Ok(mut upstream)) = (incoming, upstream) else {
                return;
            };
            let mut incoming = hyper_util::rt::TokioIo::new(incoming);
            let _ = tokio::io::copy_bidirectional(&mut incoming, &mut upstream).await;
        });
        let mut response = Response::new(Body::empty());
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        return Ok(response);
    }
    remove_hop_headers(&mut headers);
    let mut response = Response::new(Body::from_stream(upstream.bytes_stream()));
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn is_upgrade_request(headers: &HeaderMap) -> bool {
    headers.contains_key(header::UPGRADE)
        && headers
            .get(header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

fn rewrite_url(base: &reqwest::Url, incoming: &Uri) -> reqwest::Url {
    let mut target = base.clone();
    let base_path = base.path();
    let incoming_path = incoming.path();
    let path = match (base_path.ends_with('/'), incoming_path.starts_with('/')) {
        (true, true) => format!("{}{}", base_path, &incoming_path[1..]),
        (false, false) => format!("{base_path}/{incoming_path}"),
        _ => format!("{base_path}{incoming_path}"),
    };
    target.set_path(&path);
    let query = match (base.query(), incoming.query()) {
        (Some(base), Some(incoming)) => Some(format!("{base}&{incoming}")),
        (Some(base), None) => Some(base.to_owned()),
        (None, Some(incoming)) => Some(incoming.to_owned()),
        (None, None) => None,
    };
    target.set_query(query.as_deref());
    target
}

fn request_host(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority()
        .map(ToString::to_string)
        .or_else(|| headers.get(header::HOST)?.to_str().ok().map(str::to_owned))
}

fn remove_hop_headers(headers: &mut HeaderMap) {
    if let Some(connection) = headers.get(header::CONNECTION).cloned()
        && let Ok(connection) = connection.to_str()
    {
        for name in connection.split(',').map(str::trim) {
            headers.remove(name);
        }
    }
    for name in HOP_HEADERS {
        headers.remove(*name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hysteria_transport::MasqueradeHandler;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn parse_config(yaml: &str) -> MasqueradeConfig {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    fn request(uri: &str, body: &'static [u8]) -> MasqueradeRequest {
        MasqueradeRequest {
            remote_address: "127.0.0.1:3456".parse().unwrap(),
            method: axum::http::Method::POST,
            uri: uri.parse().unwrap(),
            headers: HeaderMap::new(),
            body: bytes::Bytes::from_static(body),
            body_stream: None,
        }
    }

    #[tokio::test]
    async fn string_and_file_backends_serve_http3_requests() {
        let string = Masquerade::build(&parse_config(
            "type: string\nstring:\n  content: ordinary site\n  statusCode: 418\n  headers: { x-site: rust }\n",
        ))
        .unwrap();
        let mut response = string
            .handle(request("https://example.test/path", b"ignored"))
            .await;
        assert_eq!(response.status, StatusCode::IM_A_TEAPOT);
        assert_eq!(response.headers["x-site"], "rust");
        assert_eq!(
            response.headers[header::CONTENT_TYPE],
            "text/plain; charset=utf-8"
        );
        assert_eq!(response.collect_body().await.unwrap(), "ordinary site");

        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("hello.txt"), "static content").unwrap();
        let file = Masquerade::build(&parse_config(&format!(
            "type: file\nfile:\n  dir: '{}'\n",
            directory.path().display()
        )))
        .unwrap();
        let mut file_request = request("https://example.test/hello.txt", b"");
        file_request.method = axum::http::Method::GET;
        let mut response = file.handle(file_request).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.collect_body().await.unwrap(), "static content");
        assert_eq!(response.headers[header::CONTENT_TYPE], "text/plain");
    }

    #[test]
    fn string_content_sniffing_matches_go_text_cases() {
        assert_eq!(
            detect_string_content_type(b"  <!doctype html><title>site</title>"),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            detect_string_content_type(b"<?xml version=\"1.0\"?>"),
            "text/xml; charset=utf-8"
        );
        assert_eq!(
            detect_string_content_type(b"plain text"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            detect_string_content_type(b"binary\0data"),
            "application/octet-stream"
        );
    }

    #[tokio::test]
    async fn proxy_backend_rewrites_url_host_and_forwarding_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut stream).await;
            assert!(request.starts_with("POST /base/path?fixed=1&incoming=2 HTTP/1.1\r\n"));
            let lowercase = request.to_ascii_lowercase();
            assert!(lowercase.contains("host: original.test\r\n"));
            assert!(lowercase.contains("x-forwarded-for: 127.0.0.1\r\n"));
            assert!(lowercase.contains("x-forwarded-host: original.test\r\n"));
            assert!(lowercase.contains("x-forwarded-proto: https\r\n"));
            assert!(request.ends_with("proxy body"));
            stream
                .write_all(
                    b"HTTP/1.1 201 Created\r\nContent-Length: 8\r\nX-Upstream: yes\r\nConnection: close\r\n\r\nupstream",
                )
                .await
                .unwrap();
        });
        let backend = Masquerade::build(&parse_config(&format!(
            "type: proxy\nproxy:\n  url: 'http://{address}/base?fixed=1'\n  rewriteHost: false\n  xForwarded: true\n"
        )))
        .unwrap();
        let mut response = backend
            .handle(request(
                "https://original.test/path?incoming=2",
                b"proxy body",
            ))
            .await;
        assert_eq!(response.status, StatusCode::CREATED);
        assert_eq!(response.headers["x-upstream"], "yes");
        assert!(!response.headers.contains_key(header::CONNECTION));
        assert_eq!(response.collect_body().await.unwrap(), "upstream");
        upstream.await.unwrap();
    }

    #[tokio::test]
    async fn proxy_backend_tunnels_http_upgrades_bidirectionally() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let request = read_headers(&mut stream).await;
            assert!(request.starts_with("GET /socket HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("connection: upgrade\r\n")
            );
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("upgrade: websocket\r\n")
            );
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
                )
                .await
                .unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let backend = Masquerade::build(&parse_config(&format!(
            "type: proxy\nproxy:\n  url: 'http://{upstream_address}'\n"
        )))
        .unwrap();
        let frontend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend_address = frontend.local_addr().unwrap();
        let frontend_task = tokio::spawn(async move {
            axum::serve(
                frontend,
                backend
                    .router()
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(frontend_address)
            .await
            .unwrap();
        client
            .write_all(
                b"GET /socket HTTP/1.1\r\nHost: cover.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
        let response = read_headers(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        client.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        client.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        upstream.await.unwrap();
        frontend_task.abort();
    }

    #[tokio::test]
    async fn http3_proxy_rejects_connection_upgrades() {
        let backend = Masquerade::build(&parse_config(
            "type: proxy\nproxy:\n  url: 'http://127.0.0.1:9'\n",
        ))
        .unwrap();
        let mut request = request("https://cover.test/socket", b"");
        request.method = axum::http::Method::GET;
        request
            .headers
            .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
        request
            .headers
            .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        let mut response = backend.handle(request).await;
        assert_eq!(response.status, StatusCode::NOT_IMPLEMENTED);
        assert!(response.collect_body().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn proxy_backend_streams_request_and_response_chunks() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream_listener.local_addr().unwrap();
        let (request_seen_sender, request_seen_receiver) = tokio::sync::oneshot::channel();
        let (response_release_sender, response_release_receiver) = tokio::sync::oneshot::channel();
        let upstream = tokio::spawn(async move {
            let (mut stream, _) = upstream_listener.accept().await.unwrap();
            let request = read_headers_exact(&mut stream).await;
            assert!(request.starts_with("POST /stream HTTP/1.1\r\n"));
            let mut first = [0; 3];
            stream.read_exact(&mut first).await.unwrap();
            assert_eq!(&first, b"abc");
            request_seen_sender.send(()).unwrap();
            let mut second = [0; 3];
            stream.read_exact(&mut second).await.unwrap();
            assert_eq!(&second, b"def");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc")
                .await
                .unwrap();
            response_release_receiver.await.unwrap();
            stream.write_all(b"def").await.unwrap();
        });
        let backend = Masquerade::build(&parse_config(&format!(
            "type: proxy\nproxy:\n  url: 'http://{upstream_address}'\n"
        )))
        .unwrap();
        let frontend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let frontend_address = frontend.local_addr().unwrap();
        let frontend_task = tokio::spawn(async move {
            axum::serve(
                frontend,
                backend
                    .router()
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let mut client = tokio::net::TcpStream::connect(frontend_address)
            .await
            .unwrap();
        client
            .write_all(b"POST /stream HTTP/1.1\r\nHost: cover.test\r\nContent-Length: 6\r\n\r\nabc")
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), request_seen_receiver)
            .await
            .unwrap()
            .unwrap();
        client.write_all(b"def").await.unwrap();
        let response = read_headers_exact(&mut client).await;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        let mut first = [0; 3];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut first))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&first, b"abc");
        response_release_sender.send(()).unwrap();
        let mut second = [0; 3];
        client.read_exact(&mut second).await.unwrap();
        assert_eq!(&second, b"def");
        upstream.await.unwrap();
        frontend_task.abort();
    }

    #[tokio::test]
    async fn tcp_frontends_advertise_http3_serve_tls_and_redirect() {
        crate::tls::ensure_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        let config = parse_config(
            "type: string\nstring: { content: frontend, statusCode: 418 }\nlistenHTTP: '127.0.0.1:0'\nlistenHTTPS: '127.0.0.1:0'\n",
        );
        let masquerade = Masquerade::build(&config).unwrap();
        let servers = masquerade
            .start_tcp(&config, tls.clone(), 8443)
            .await
            .unwrap()
            .unwrap();
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_der(&certificate).unwrap())
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        for url in [
            format!("http://{}/hello", servers.http_address.unwrap()),
            format!(
                "https://localhost:{}/hello",
                servers.https_address.unwrap().port()
            ),
        ] {
            let response = client.get(url).send().await.unwrap();
            assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
            assert_eq!(
                response.headers()[header::ALT_SVC],
                "h3=\":8443\"; ma=2592000"
            );
            assert_eq!(response.text().await.unwrap(), "frontend");
        }
        drop(servers);

        let redirect_config = parse_config(
            "type: '404'\nlistenHTTP: '127.0.0.1:0'\nlistenHTTPS: '127.0.0.1:0'\nforceHTTPS: true\n",
        );
        let servers = Masquerade::build(&redirect_config)
            .unwrap()
            .start_tcp(&redirect_config, tls, 8443)
            .await
            .unwrap()
            .unwrap();
        let response = client
            .get(format!("http://{}/path?q=1", servers.http_address.unwrap()))
            .header(header::HOST, "example.test")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://example.test/path?q=1"
        );
        assert!(!response.headers().contains_key(header::ALT_SVC));
    }

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let header_end = loop {
            if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                break offset + 4;
            }
            let mut buffer = [0; 1024];
            let size = stream.read(&mut buffer).await.unwrap();
            assert_ne!(size, 0);
            bytes.extend_from_slice(&buffer[..size]);
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or_default();
        while bytes.len() < header_end + length {
            let mut buffer = [0; 1024];
            let size = stream.read(&mut buffer).await.unwrap();
            assert_ne!(size, 0);
            bytes.extend_from_slice(&buffer[..size]);
        }
        String::from_utf8(bytes[..header_end + length].to_vec()).unwrap()
    }

    async fn read_headers(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        loop {
            if let Some(offset) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                return String::from_utf8(bytes[..offset + 4].to_vec()).unwrap();
            }
            let mut buffer = [0; 1024];
            let size = stream.read(&mut buffer).await.unwrap();
            assert_ne!(size, 0);
            bytes.extend_from_slice(&buffer[..size]);
        }
    }

    async fn read_headers_exact(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            bytes.push(stream.read_u8().await.unwrap());
        }
        String::from_utf8(bytes).unwrap()
    }
}
