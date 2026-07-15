use crate::{
    CliError, Result,
    config::HttpProxyConfig,
    runtime::{ClientHandle, normalize_listen},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

const MAX_HEADER_SIZE: usize = 64 * 1024;

pub(crate) async fn serve(config: HttpProxyConfig, client: Arc<ClientHandle>) -> Result<()> {
    let listener = TcpListener::bind(normalize_listen(&config.listen)).await?;
    eprintln!("HTTP proxy listening on {}", listener.local_addr()?);
    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = handle_connection(stream, &config, &client).await;
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    config: &HttpProxyConfig,
    client: &ClientHandle,
) -> Result<()> {
    let request = read_request(&mut stream).await?;
    if !authorized(&request, config) {
        let realm = if config.realm.is_empty() {
            "Hysteria"
        } else {
            &config.realm
        };
        stream
            .write_all(
                format!(
                    "{} 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"{}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    request.version,
                    escape_header_value(realm)
                )
                .as_bytes(),
            )
            .await?;
        return Ok(());
    }

    if request.method.eq_ignore_ascii_case("CONNECT") {
        handle_connect(stream, client, request).await
    } else {
        handle_plain_http(stream, client, request).await
    }
}

async fn handle_connect(
    mut stream: TcpStream,
    client: &ClientHandle,
    request: HttpRequest,
) -> Result<()> {
    let target = normalize_authority(&request.target, 80)?;
    let mut tunnel = match client.tcp(&target).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            write_bad_gateway(&mut stream, &request.version).await?;
            return Err(error.into());
        }
    };
    stream
        .write_all(format!("{} 200 OK\r\n\r\n", request.version).as_bytes())
        .await?;
    if !request.buffered_body.is_empty() {
        tunnel.write_all(&request.buffered_body).await?;
    }
    copy_bidirectional(&mut stream, &mut tunnel).await?;
    Ok(())
}

async fn handle_plain_http(
    mut stream: TcpStream,
    client: &ClientHandle,
    request: HttpRequest,
) -> Result<()> {
    let (target, origin_form) = parse_absolute_http_target(&request.target)?;
    let mut tunnel = match client.tcp(&target).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            write_bad_gateway(&mut stream, &request.version).await?;
            return Err(error.into());
        }
    };
    let mut outbound =
        format!("{} {} {}\r\n", request.method, origin_form, request.version).into_bytes();
    for (name, value) in request.headers {
        if name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("proxy-connection")
        {
            continue;
        }
        outbound.extend_from_slice(name.as_bytes());
        outbound.extend_from_slice(b": ");
        outbound.extend_from_slice(value.as_bytes());
        outbound.extend_from_slice(b"\r\n");
    }
    outbound.extend_from_slice(b"\r\n");
    outbound.extend_from_slice(&request.buffered_body);
    tunnel.write_all(&outbound).await?;
    copy_bidirectional(&mut stream, &mut tunnel).await?;
    Ok(())
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
    buffered_body: Vec<u8>,
}

async fn read_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buffer = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(position) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
        if buffer.len() >= MAX_HEADER_SIZE {
            return Err(CliError::new("HTTP proxy request headers are too large"));
        }
        let mut chunk = [0; 2048];
        let size = stream.read(&mut chunk).await?;
        if size == 0 {
            return Err(CliError::new(
                "connection closed before HTTP request headers",
            ));
        }
        buffer.extend_from_slice(&chunk[..size]);
    };
    let header = std::str::from_utf8(&buffer[..header_end - 4])
        .map_err(|error| CliError::new(format!("invalid HTTP request header: {error}")))?;
    let mut lines = header.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| CliError::new("missing HTTP request line"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| CliError::new("missing HTTP method"))?;
    let target = parts
        .next()
        .ok_or_else(|| CliError::new("missing HTTP request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| CliError::new("missing HTTP version"))?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        return Err(CliError::new("invalid HTTP request line"));
    }
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| CliError::new("invalid HTTP header"))?;
        if name.is_empty() || name.bytes().any(|byte| byte <= b' ' || byte >= 0x7f) {
            return Err(CliError::new("invalid HTTP header name"));
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    Ok(HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        version: version.to_owned(),
        headers,
        buffered_body: buffer[header_end..].to_vec(),
    })
}

fn authorized(request: &HttpRequest, config: &HttpProxyConfig) -> bool {
    if config.username.is_empty() {
        return true;
    }
    request.headers.iter().any(|(name, value)| {
        if !name.eq_ignore_ascii_case("proxy-authorization") {
            return false;
        }
        let Some(encoded) = value
            .get(..6)
            .filter(|prefix| prefix.eq_ignore_ascii_case("basic "))
            .and_then(|_| value.get(6..))
        else {
            return false;
        };
        STANDARD.decode(encoded).is_ok_and(|decoded| {
            decoded == format!("{}:{}", config.username, config.password).as_bytes()
        })
    })
}

fn parse_absolute_http_target(target: &str) -> Result<(String, String)> {
    let remainder = target
        .strip_prefix("http://")
        .ok_or_else(|| CliError::new("HTTP proxy requires an absolute http:// request target"))?;
    let (authority, path) = remainder
        .split_once('/')
        .map_or((remainder, "/".to_owned()), |(authority, path)| {
            (authority, format!("/{path}"))
        });
    if authority.is_empty() {
        return Err(CliError::new("HTTP request target has no host"));
    }
    Ok((normalize_authority(authority, 80)?, path))
}

fn normalize_authority(authority: &str, default_port: u16) -> Result<String> {
    if authority.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(authority.to_owned());
    }
    if authority.starts_with('[') && authority.ends_with(']') {
        return Ok(format!("{authority}:{default_port}"));
    }
    if authority
        .rsplit_once(':')
        .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok())
    {
        Ok(authority.to_owned())
    } else if !authority.is_empty() && !authority.contains(['/', '\r', '\n']) {
        Ok(format!("{authority}:{default_port}"))
    } else {
        Err(CliError::new("invalid HTTP proxy authority"))
    }
}

async fn write_bad_gateway(stream: &mut TcpStream, version: &str) -> Result<()> {
    stream
        .write_all(
            format!("{version} 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    Ok(())
}

fn escape_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|character| !matches!(character, '\r' | '\n' | '"'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_absolute_targets_and_authorities() {
        assert_eq!(
            parse_absolute_http_target("http://example.com/a?q=1").unwrap(),
            ("example.com:80".to_owned(), "/a?q=1".to_owned())
        );
        assert_eq!(
            normalize_authority("example.com:443", 80).unwrap(),
            "example.com:443"
        );
        assert_eq!(normalize_authority("[::1]", 80).unwrap(), "[::1]:80");
    }

    #[test]
    fn validates_basic_proxy_auth() {
        let request = HttpRequest {
            method: "CONNECT".to_owned(),
            target: "example.com:443".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![(
                "Proxy-Authorization".to_owned(),
                "Basic YWxpY2U6c2VjcmV0".to_owned(),
            )],
            buffered_body: Vec::new(),
        };
        let config = HttpProxyConfig {
            listen: String::new(),
            username: "alice".to_owned(),
            password: "secret".to_owned(),
            realm: String::new(),
        };
        assert!(authorized(&request, &config));
    }
}
