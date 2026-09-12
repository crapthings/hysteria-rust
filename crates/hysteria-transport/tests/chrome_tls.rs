//! Wire-level tests for the opt-in TLS baseline, not a complete fingerprint assertion.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use bytes::{Buf, BufMut};
use rustls::{ClientConfig, RootCertStore, crypto::aws_lc_rs, pki_types::ServerName, quic};

fn config() -> ClientConfig {
    let mut config = ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    config
}

fn hello(config: ClientConfig) -> Vec<u8> {
    let mut client = quic::ClientConnection::new(
        Arc::new(config),
        quic::Version::V1,
        ServerName::try_from("localhost").unwrap(),
        vec![15, 0],
    )
    .unwrap();
    let mut bytes = Vec::new();
    assert!(client.write_hs(&mut bytes).is_none());
    bytes
}

fn vector16(input: &mut &[u8]) -> Vec<u8> {
    let len = usize::from(input.get_u16());
    input.copy_to_bytes(len).to_vec()
}

struct DecodedHello {
    suites: Vec<u16>,
    extensions: BTreeMap<u16, Vec<u8>>,
    order: Vec<u16>,
}

fn decode(bytes: &[u8]) -> DecodedHello {
    let mut input = bytes;
    assert_eq!(input.get_u8(), 1); // ClientHello
    let size = usize::try_from(input.get_uint(3)).unwrap();
    assert_eq!(size, input.remaining());
    assert_eq!(input.get_u16(), 0x0303);
    input.advance(32); // random
    assert_eq!(input.get_u8(), 0); // no legacy session ID in QUIC
    let suites = vector16(&mut input);
    let suites = suites
        .chunks_exact(2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .collect();
    assert_eq!(input.get_u8(), 1);
    assert_eq!(input.get_u8(), 0); // null compression
    let extensions = vector16(&mut input);
    assert!(!input.has_remaining());
    let mut input = extensions.as_slice();
    let mut result = BTreeMap::new();
    let mut order = Vec::new();
    while input.has_remaining() {
        let id = input.get_u16();
        order.push(id);
        assert!(result.insert(id, vector16(&mut input)).is_none());
    }
    DecodedHello {
        suites,
        extensions: result,
        order,
    }
}

#[test]
fn chrome_tls_baseline_wire_shape_and_default_isolation() {
    let original = config();
    let baseline = original.clone().with_quic_chrome_baseline().unwrap();
    assert!(!baseline.enable_early_data);
    let DecodedHello {
        suites,
        extensions: exts,
        ..
    } = decode(&hello(baseline));
    assert_eq!(suites, [0x1301, 0x1302, 0x1303]);
    for id in [5, 11, 23, 35, 41, 42] {
        assert!(!exts.contains_key(&id));
    }
    assert_eq!(exts[&43], [2, 3, 4]); // TLS 1.3 only
    assert_eq!(exts[&45], [1, 1]); // PSK DHE
    assert_eq!(exts[&27], [2, 0, 2]); // Brotli only
    assert_eq!(exts[&57], [15, 0]); // supplied QUIC parameters unchanged
    assert_eq!(exts[&16], [0, 3, 2, b'h', b'3']);
    assert_eq!(exts[&10], [0, 8, 0x11, 0xec, 0, 0x1d, 0, 0x17, 0, 0x18]);
    assert_eq!(
        exts[&13],
        [0, 16, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1]
    );
    let shares = vector16(&mut exts[&51].as_slice());
    let mut shares = shares.as_slice();
    assert_eq!(shares.get_u16(), 0x11ec);
    assert_eq!(vector16(&mut shares).len(), 1216); // ML-KEM-768 + X25519
    assert_eq!(shares.get_u16(), 0x001d);
    assert_eq!(vector16(&mut shares).len(), 32);
    assert!(!shares.has_remaining());
    let normal = decode(&hello(original)).extensions;
    assert!(!normal.contains_key(&27));
    assert!(!normal.contains_key(&0xfe0d));
    for id in [5, 11, 23] {
        assert!(normal.contains_key(&id));
    }
}

#[test]
fn chrome_ech_grease_wire_shape_and_freshness() {
    let baseline = config().with_quic_chrome_baseline().unwrap();
    let mut payloads = BTreeSet::new();
    let mut keys = BTreeSet::new();
    let mut lengths = BTreeSet::new();
    let mut positions = BTreeSet::new();
    for _ in 0..128 {
        let decoded = decode(&hello(baseline.clone()));
        positions.insert(decoded.order.iter().position(|id| *id == 0xfe0d).unwrap());
        let mut ech = decoded.extensions[&0xfe0d].as_slice();
        assert_eq!(ech.get_u8(), 0); // outer
        assert_eq!(ech.get_u16(), 1); // HKDF-SHA256
        assert_eq!(ech.get_u16(), 1); // AES-128-GCM
        ech.advance(1); // randomized config ID
        let key = vector16(&mut ech);
        assert_eq!(key.len(), 32);
        let payload = vector16(&mut ech);
        assert!([144, 176, 208, 240].contains(&payload.len()));
        assert!(!ech.has_remaining());
        lengths.insert(payload.len());
        assert!(payloads.insert(payload));
        assert!(keys.insert(key));
    }
    assert_eq!(lengths.len(), 4);
    assert!(positions.len() > 1, "ECH must not be pinned to the end");
}

#[test]
fn chrome_baseline_preserves_real_ech_configuration() {
    // An ECHConfigList with an X25519 basepoint public key and an explicit cover name.
    let mut contents = vec![7]; // config ID
    contents.put_u16(0x20); // DHKEM(X25519, HKDF-SHA256)
    contents.put_u16(32);
    contents.push(9);
    contents.extend_from_slice(&[0; 31]);
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1]); // symmetric suite vector
    contents.push(0); // maximum name length
    contents.push(14);
    contents.extend_from_slice(b"public.example");
    contents.put_u16(0); // extensions
    let mut encoded = Vec::new();
    encoded.put_u16(u16::try_from(contents.len() + 4).unwrap());
    encoded.put_u16(0xfe0d);
    encoded.put_u16(u16::try_from(contents.len()).unwrap());
    encoded.extend_from_slice(&contents);
    let ech = rustls::client::EchConfig::new(
        rustls::pki_types::EchConfigListBytes::from(encoded),
        &[aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128],
    )
    .unwrap();
    let config = ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
        .with_ech(ech.into())
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth()
        .with_quic_chrome_baseline()
        .unwrap();
    let decoded = decode(&hello(config));
    let mut sni = decoded.extensions[&0].as_slice();
    let names = vector16(&mut sni);
    let mut names = names.as_slice();
    assert_eq!(names.get_u8(), 0);
    assert_eq!(vector16(&mut names), b"public.example");
    assert_eq!(decoded.extensions[&0xfe0d][5], 7);
    assert_eq!(decoded.order.last(), Some(&0xfe0d)); // real ECH ordering unchanged
}

#[test]
fn brotli_decoder_rejects_malformed_or_wrong_sized_certificates() {
    use rustls::compress::{BROTLI_COMPRESSOR, BROTLI_DECOMPRESSOR, CompressionLevel};

    let input = vec![42; 512];
    let encoded = BROTLI_COMPRESSOR
        .compress(input.clone(), CompressionLevel::Interactive)
        .unwrap();
    let mut output = vec![0; 512];
    BROTLI_DECOMPRESSOR
        .decompress(&encoded, &mut output)
        .unwrap();
    assert_eq!(output, input);
    assert!(
        BROTLI_DECOMPRESSOR
            .decompress(&encoded, &mut [0; 511])
            .is_err()
    );
    assert!(
        BROTLI_DECOMPRESSOR
            .decompress(&encoded, &mut [0; 513])
            .is_err()
    );
    assert!(
        BROTLI_DECOMPRESSOR
            .decompress(&[0xff; 8], &mut output)
            .is_err()
    );
}

fn contains_compressed_certificate(mut flight: &[u8]) -> bool {
    let mut found = false;
    while !flight.is_empty() {
        let kind = flight.get_u8();
        let len = usize::try_from(flight.get_uint(3)).unwrap();
        found |= kind == 25;
        flight.advance(len);
    }
    found
}

#[test]
fn chrome_tls_baseline_rejects_missing_hybrid_group() {
    let mut provider = aws_lc_rs::default_provider();
    provider
        .kx_groups
        .retain(|g| g.name() != rustls::NamedGroup::X25519MLKEM768);
    let config = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    assert!(config.with_quic_chrome_baseline().is_err());
}

#[test]
fn chrome_alps_offer_requires_explicit_settings_and_matching_alpn() {
    let baseline = config().with_quic_chrome_baseline().unwrap();
    assert!(
        !decode(&hello(baseline.clone()))
            .extensions
            .contains_key(&17613)
    );
    let configured = baseline
        .with_quic_application_settings(vec![(b"h3".to_vec(), vec![]), (b"other".to_vec(), vec![])])
        .unwrap();
    let decoded = decode(&hello(configured));
    assert_eq!(decoded.extensions[&17613], [0, 3, 2, b'h', b'3']);
    assert!(!decoded.extensions.contains_key(&17513));
}

#[test]
fn chrome_tls_baseline_mutual_authentication_and_hello_retry() {
    for (retry, compressed) in [(false, false), (true, false), (false, true), (true, true)] {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = certified.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
        let mut roots = RootCertStore::empty();
        roots.add(cert.clone()).unwrap();
        let client_config =
            ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots.clone())
                .with_client_auth_cert(vec![cert.clone()], key.clone_key().into())
                .unwrap()
                .with_quic_chrome_baseline()
                .unwrap();
        let mut provider = aws_lc_rs::default_provider();
        if retry {
            // P-256 is supported but has no initial share, forcing HelloRetryRequest.
            provider.kx_groups = vec![aws_lc_rs::kx_group::SECP256R1];
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            roots.into(),
            Arc::new(aws_lc_rs::default_provider()),
        )
        .build()
        .unwrap();
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider.into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert.clone()], key.into())
            .unwrap();
        if compressed {
            server_config.cert_compressors = vec![rustls::compress::BROTLI_COMPRESSOR];
        }
        let mut server =
            quic::ServerConnection::new(Arc::new(server_config), quic::Version::V1, vec![])
                .unwrap();
        let mut client = quic::ClientConnection::new(
            Arc::new(client_config),
            quic::Version::V1,
            ServerName::try_from("localhost").unwrap(),
            vec![],
        )
        .unwrap();
        let mut hellos = Vec::new();
        let mut saw_compressed_certificate = false;
        for _ in 0..12 {
            let mut flight = Vec::new();
            client.write_hs(&mut flight);
            if flight.first() == Some(&1) {
                hellos.push(decode(&flight));
            }
            server.read_hs(&flight).unwrap();
            flight.clear();
            server.write_hs(&mut flight);
            saw_compressed_certificate |= contains_compressed_certificate(&flight);
            client.read_hs(&flight).unwrap();
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());
        assert_eq!(saw_compressed_certificate, compressed);
        assert_eq!(hellos.len(), if retry { 2 } else { 1 });
        if retry {
            assert_eq!(hellos[0].extensions[&0xfe0d], hellos[1].extensions[&0xfe0d]);
            assert_eq!(hellos[0].order, hellos[1].order);
        }
        assert_eq!(server.peer_certificates().unwrap(), &[cert]);
        assert_eq!(
            client.handshake_kind(),
            Some(if retry {
                rustls::HandshakeKind::FullWithHelloRetryRequest
            } else {
                rustls::HandshakeKind::Full
            })
        );
        let client_secret = quic::Connection::Client(client)
            .export_keying_material([0u8; 32], b"baseline-test", None)
            .unwrap();
        let server_secret = quic::Connection::Server(server)
            .export_keying_material([0u8; 32], b"baseline-test", None)
            .unwrap();
        assert_eq!(client_secret, server_secret);
    }
}

#[test]
fn chrome_tls_baseline_still_rejects_untrusted_certificate() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let mut server_config =
        rustls::ServerConfig::builder_with_provider(aws_lc_rs::default_provider().into())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der())
                    .into(),
            )
            .unwrap();
    server_config.alpn_protocols = vec![b"h3".to_vec()];
    let mut server =
        quic::ServerConnection::new(Arc::new(server_config), quic::Version::V1, vec![15, 0])
            .unwrap();
    let mut client = quic::ClientConnection::new(
        Arc::new(config().with_quic_chrome_baseline().unwrap()),
        quic::Version::V1,
        ServerName::try_from("localhost").unwrap(),
        vec![15, 0],
    )
    .unwrap();
    let mut flight = Vec::new();
    client.write_hs(&mut flight);
    server.read_hs(&flight).unwrap();
    // ServerHello and the encrypted handshake are emitted in separate flights.
    for _ in 0..4 {
        flight.clear();
        server.write_hs(&mut flight);
        match client.read_hs(&flight) {
            Err(rustls::Error::InvalidCertificate(_)) => return,
            Err(error) => panic!("unexpected handshake error: {error:?}"),
            Ok(()) => {}
        }
    }
    panic!("untrusted certificate was not rejected");
}
