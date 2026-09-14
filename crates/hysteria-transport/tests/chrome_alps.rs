//! ALPS TLS-layer tests. The deliberately synthetic ALPN does not claim HTTP/3 integration.
use bytes::{Buf, BufMut};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, crypto::aws_lc_rs, pki_types::ServerName, quic,
};
use std::sync::Arc;

const ALPS: u16 = 17613;
const PROTOCOL: &[u8] = b"test-alps";

#[tokio::test]
async fn quinn_exposes_authenticated_peer_settings() {
    use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};

    for payload in [None, Some(Vec::new()), Some(b"peer-settings".to_vec())] {
        let (mut client, mut server) = configs(false, false);
        if let Some(settings) = &payload {
            client = client
                .with_quic_application_settings(vec![(PROTOCOL.to_vec(), settings.clone())])
                .unwrap();
            server = server
                .with_quic_application_settings(vec![(
                    PROTOCOL.to_vec(),
                    b"server-settings".to_vec(),
                )])
                .unwrap();
        }
        let server = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server).unwrap())),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client).unwrap(),
        )));
        let connecting = client_endpoint
            .connect(server.local_addr().unwrap(), "localhost")
            .unwrap();
        let (client_connection, server_connection) =
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                tokio::join!(connecting, async { server.accept().await.unwrap().await })
            })
            .await
            .expect("loopback QUIC handshake timed out");
        let client_connection = client_connection.unwrap();
        let server_connection = server_connection.unwrap();
        for (connection, expected) in [
            (
                &client_connection,
                payload.as_ref().map(|_| b"server-settings".to_vec()),
            ),
            (&server_connection, payload),
        ] {
            let data = connection
                .handshake_data()
                .unwrap()
                .downcast::<HandshakeData>()
                .unwrap();
            assert_eq!(data.protocol.as_deref(), Some(PROTOCOL));
            assert_eq!(data.peer_application_settings, expected);
        }
        client_connection.close(0_u32.into(), b"done");
        server_connection.close(0_u32.into(), b"done");
    }
}

struct Pair {
    client: quic::ClientConnection,
    server: quic::ServerConnection,
}

#[tokio::test]
async fn h3_applies_early_header_limit_and_rejects_later_reduction() {
    use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

    let (mut client, mut server) = configs(false, false);
    client.alpn_protocols = vec![b"h3".to_vec()];
    server.alpn_protocols.clone_from(&client.alpn_protocols);
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server).unwrap())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client).unwrap(),
    )));
    let connecting = endpoint
        .connect(server.local_addr().unwrap(), "localhost")
        .unwrap();
    let (client, server) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(connecting, async { server.accept().await.unwrap().await })
    })
    .await
    .unwrap();
    let client = client.unwrap();
    let server = server.unwrap();
    let mut builder = h3::client::builder();
    assert!(
        builder
            .authenticated_alps_max_field_section_size(u64::MAX)
            .is_err()
    );
    // This test isolates the driver's hook; ALPS negotiation is tested separately.
    builder
        .authenticated_alps_max_field_section_size(1)
        .unwrap();
    let (mut driver, mut sender) = builder
        .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(client.clone()))
        .await
        .unwrap();
    let request = http::Request::builder()
        .uri("https://localhost/")
        .body(())
        .unwrap();
    assert!(matches!(
        sender.send_request(request).await,
        Err(h3::error::StreamError::HeaderTooBig { max_size: 1, .. })
    ));

    let mut control = server.open_uni().await.unwrap();
    // Control stream, SETTINGS, two payload bytes, MAX_FIELD_SECTION_SIZE = 0.
    control.write_all(&[0, 4, 2, 6, 0]).await.unwrap();
    let error = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        std::future::poll_fn(|cx| driver.poll_close(cx)),
    )
    .await
    .unwrap();
    assert!(
        error
            .to_string()
            .contains("reduces authenticated ALPS header limit"),
        "{error}"
    );
    client.close(0_u32.into(), b"done");
    server.close(0_u32.into(), b"done");
}

fn configs(retry: bool, mutual: bool) -> (ClientConfig, ServerConfig) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let client = ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots.clone());
    let mut client = if mutual {
        client
            .with_client_auth_cert(vec![cert.clone()], key.clone_key().into())
            .unwrap()
    } else {
        client.with_no_client_auth()
    }
    .with_quic_chrome_baseline()
    .unwrap();
    let mut provider = aws_lc_rs::default_provider();
    if retry {
        provider.kx_groups = vec![aws_lc_rs::kx_group::SECP256R1];
    }
    let server = ServerConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap();
    let server = if mutual {
        server.with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                roots.into(),
                Arc::new(aws_lc_rs::default_provider()),
            )
            .build()
            .unwrap(),
        )
    } else {
        server.with_no_client_auth()
    };
    let mut server = server.with_single_cert(vec![cert], key.into()).unwrap();
    client.alpn_protocols = vec![PROTOCOL.to_vec()];
    server.alpn_protocols.clone_from(&client.alpn_protocols);
    server.cert_compressors = vec![rustls::compress::BROTLI_COMPRESSOR];
    server.cert_decompressors = vec![rustls::compress::BROTLI_DECOMPRESSOR];
    client.cert_compressors = vec![rustls::compress::BROTLI_COMPRESSOR];
    (client, server)
}

impl Pair {
    fn new(client: ClientConfig, server: ServerConfig) -> Self {
        Self {
            client: quic::ClientConnection::new(
                Arc::new(client),
                quic::Version::V1,
                ServerName::try_from("localhost").unwrap(),
                vec![],
            )
            .unwrap(),
            server: quic::ServerConnection::new(Arc::new(server), quic::Version::V1, vec![])
                .unwrap(),
        }
    }

    fn finish(&mut self) {
        for _ in 0..16 {
            self.assert_no_unauthenticated_settings();
            let mut flight = Vec::new();
            self.client.write_hs(&mut flight);
            self.server.read_hs(&flight).unwrap();
            self.assert_no_unauthenticated_settings();
            flight.clear();
            self.server.write_hs(&mut flight);
            self.client.read_hs(&flight).unwrap();
            if !self.client.is_handshaking() && !self.server.is_handshaking() {
                return;
            }
        }
        panic!("handshake did not finish");
    }

    fn assert_no_unauthenticated_settings(&self) {
        if self.client.is_handshaking() {
            assert!(self.client.peer_application_settings().is_none());
        }
        if self.server.is_handshaking() {
            assert!(self.server.peer_application_settings().is_none());
        }
    }

    fn assert_matching_exporters(self) {
        let client = quic::Connection::Client(self.client)
            .export_keying_material([0; 32], b"alps", None)
            .unwrap();
        let server = quic::Connection::Server(self.server)
            .export_keying_material([0; 32], b"alps", None)
            .unwrap();
        assert_eq!(client, server);
    }
}

#[test]
fn alps_settings_authenticated_with_retry_and_mutual_authentication() {
    for (retry, mutual, compressed_auth) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, false),
        (false, true, true),
        (true, true, true),
    ] {
        let (client, mut server) = configs(retry, mutual);
        if !compressed_auth {
            server.cert_decompressors.clear();
        }
        let client = client
            .with_quic_application_settings(vec![(PROTOCOL.to_vec(), b"client settings".to_vec())])
            .unwrap();
        let server = server
            .with_quic_application_settings(vec![(PROTOCOL.to_vec(), b"server settings".to_vec())])
            .unwrap();
        let mut pair = Pair::new(client, server);
        pair.finish();
        let mut tickets = Vec::new();
        pair.server.write_hs(&mut tickets);
        assert!(tickets.is_empty(), "ALPS sessions must not issue PSKs yet");
        assert_eq!(
            pair.client.peer_application_settings(),
            Some(b"server settings".as_slice())
        );
        assert_eq!(
            pair.server.peer_application_settings(),
            Some(b"client settings".as_slice())
        );
        pair.assert_matching_exporters();
    }
}

#[test]
fn alps_absent_one_sided_or_different_protocol_is_not_negotiated() {
    for (client_enabled, server_enabled, different) in [
        (false, false, false),
        (true, false, false),
        (false, true, false),
        (true, true, true),
    ] {
        let (mut client, mut server) = configs(false, false);
        if client_enabled {
            client = client
                .with_quic_application_settings(vec![(PROTOCOL.to_vec(), vec![])])
                .unwrap();
        }
        if server_enabled {
            server = server
                .with_quic_application_settings(vec![(
                    if different {
                        b"other".to_vec()
                    } else {
                        PROTOCOL.to_vec()
                    },
                    vec![],
                )])
                .unwrap();
        }
        let mut pair = Pair::new(client, server);
        pair.finish();
        assert!(pair.client.peer_application_settings().is_none());
        assert!(pair.server.peer_application_settings().is_none());
        pair.assert_matching_exporters();
    }
}

#[test]
fn alps_empty_settings_are_distinct_from_no_negotiation() {
    let (client, server) = configs(false, false);
    let mut pair = Pair::new(
        client
            .with_quic_application_settings(vec![(PROTOCOL.to_vec(), vec![])])
            .unwrap(),
        server
            .with_quic_application_settings(vec![(PROTOCOL.to_vec(), vec![])])
            .unwrap(),
    );
    pair.finish();
    assert_eq!(pair.client.peer_application_settings(), Some([].as_slice()));
    assert_eq!(pair.server.peer_application_settings(), Some([].as_slice()));
}

#[test]
fn alps_does_not_resume_a_preexisting_non_alps_session() {
    use rustls::client::ClientSessionStore;

    let (mut client, server) = configs(false, false);
    // Keep several server slots: the vendored cache reserves one slot for insertion.
    let cache = Arc::new(rustls::client::ClientSessionMemoryCache::new(32));
    client.resumption = rustls::client::Resumption::store(cache.clone());
    let mut first = Pair::new(client.clone(), server.clone());
    first.finish();
    for _ in 0..3 {
        let mut tickets = Vec::new();
        first.server.write_hs(&mut tickets);
        first.client.read_hs(&tickets).unwrap();
    }
    let name = ServerName::try_from("localhost").unwrap();
    let ticket = cache
        .take_tls13_ticket(&name)
        .expect("server must issue a usable ticket");
    cache.insert_tls13_ticket(name, ticket);
    assert_eq!(
        first.client.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    let mut control = Pair::new(client.clone(), server.clone());
    control.finish();
    assert_eq!(
        control.client.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    let mut with_alps = Pair::new(
        client
            .with_quic_application_settings(vec![(PROTOCOL.to_vec(), vec![])])
            .unwrap(),
        server
            .with_quic_application_settings(vec![(PROTOCOL.to_vec(), vec![])])
            .unwrap(),
    );
    with_alps.finish();
    assert_eq!(
        with_alps.client.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
    assert_eq!(
        with_alps.client.peer_application_settings(),
        Some([].as_slice())
    );
}

// Modify an EncryptedExtensions flight before delivery. Invalid cases must fail before
// certificate/Finished processing; accepted-but-tampered settings must fail authentication.
fn rewrite_extensions(flight: &[u8], edit: impl FnOnce(&mut Vec<(u16, Vec<u8>)>)) -> Vec<u8> {
    let mut input = flight;
    assert_eq!(input.get_u8(), 8);
    let body_len = usize::try_from(input.get_uint(3)).unwrap();
    let mut body = input.copy_to_bytes(body_len);
    let len = usize::from(body.get_u16());
    assert_eq!(len, body.remaining());
    let mut extensions = Vec::new();
    while body.has_remaining() {
        let id = body.get_u16();
        let len = usize::from(body.get_u16());
        extensions.push((id, body.copy_to_bytes(len).to_vec()));
    }
    edit(&mut extensions);
    let mut encoded = Vec::new();
    for (id, value) in extensions {
        encoded.put_u16(id);
        encoded.put_u16(u16::try_from(value.len()).unwrap());
        encoded.extend(value);
    }
    let mut result = vec![8];
    result.put_uint(u64::try_from(encoded.len() + 2).unwrap(), 3);
    result.put_u16(u16::try_from(encoded.len()).unwrap());
    result.extend(encoded);
    result.extend_from_slice(input);
    result
}

#[test]
fn alps_rejects_invalid_server_negotiation() {
    for case in 0..5 {
        let (mut client, server) = configs(false, false);
        if case != 0 {
            client = client
                .with_quic_application_settings(vec![
                    (PROTOCOL.to_vec(), vec![]),
                    (b"other".to_vec(), vec![]),
                ])
                .unwrap();
        }
        client.check_selected_alpn = false;
        let mut pair = Pair::new(client, server);
        let mut flight = Vec::new();
        pair.client.write_hs(&mut flight);
        pair.server.read_hs(&flight).unwrap();
        flight.clear();
        pair.server.write_hs(&mut flight); // ServerHello
        pair.client.read_hs(&flight).unwrap();
        flight.clear();
        pair.server.write_hs(&mut flight); // EncryptedExtensions, certificates, Finished
        let modified = rewrite_extensions(&flight, |exts| {
            exts.push((ALPS, vec![]));
            if case == 1 {
                exts.retain(|(id, _)| *id != 16);
            } // missing ALPN
            if case == 2 {
                exts.push((ALPS, vec![]));
            } // duplicate
            if case == 3 {
                exts.retain(|(id, _)| *id != 16);
                exts.push((16, vec![0, 6, 5, b'o', b't', b'h', b'e', b'r']));
            }
            if case == 4 {
                exts.retain(|(id, _)| *id != ALPS);
                exts.push((17513, vec![]));
            }
        });
        assert!(pair.client.read_hs(&modified).is_err());
        if case != 2 {
            assert_eq!(
                pair.client.alert(),
                Some(if case == 0 || case == 4 {
                    rustls::AlertDescription::UnsupportedExtension
                } else {
                    rustls::AlertDescription::IllegalParameter
                })
            );
        }
        assert!(pair.client.peer_application_settings().is_none());
        assert!(pair.client.is_handshaking());
    }
}

#[test]
fn alps_rejects_missing_extra_or_tampered_client_settings() {
    for case in 0..5 {
        let (client, server) = configs(false, false);
        let mut pair = Pair::new(
            client
                .with_quic_application_settings(vec![(PROTOCOL.to_vec(), vec![])])
                .unwrap(),
            server
                .with_quic_application_settings(vec![(PROTOCOL.to_vec(), vec![])])
                .unwrap(),
        );
        let mut tested = false;
        for _ in 0..8 {
            let mut flight = Vec::new();
            pair.client.write_hs(&mut flight);
            if flight.first() == Some(&8) {
                let modified = if case == 4 {
                    let mut input = flight.as_slice();
                    input.advance(1);
                    let len = usize::try_from(input.get_uint(3)).unwrap();
                    input.advance(len);
                    input.to_vec() // omit client EncryptedExtensions entirely
                } else {
                    rewrite_extensions(&flight, |exts| match case {
                        0 => exts.clear(),
                        1 => exts.push((12345, vec![])),
                        2 => exts.push((ALPS, vec![])),
                        3 => exts[0].1 = b"tampered".to_vec(),
                        _ => unreachable!(),
                    })
                };
                assert!(pair.server.read_hs(&modified).is_err());
                if case == 3 {
                    assert_eq!(
                        pair.server.alert(),
                        Some(rustls::AlertDescription::DecryptError)
                    );
                }
                assert!(pair.server.peer_application_settings().is_none());
                tested = true;
                break;
            }
            pair.server.read_hs(&flight).unwrap();
            flight.clear();
            pair.server.write_hs(&mut flight);
            pair.client.read_hs(&flight).unwrap();
        }
        assert!(tested);
    }
}

#[test]
fn alps_configuration_validation() {
    let (client, server) = configs(false, false);
    for settings in [
        vec![(vec![], vec![])],
        vec![(vec![1; 256], vec![])],
        vec![(PROTOCOL.to_vec(), vec![0; 65536])],
        vec![(PROTOCOL.to_vec(), vec![0; 16385])],
        vec![(PROTOCOL.to_vec(), vec![]), (PROTOCOL.to_vec(), vec![])],
    ] {
        assert!(
            client
                .clone()
                .with_quic_application_settings(settings.clone())
                .is_err()
        );
        assert!(
            server
                .clone()
                .with_quic_application_settings(settings)
                .is_err()
        );
    }
}
