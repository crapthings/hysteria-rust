use crate::{CliError, Result, tls};
use base64::Engine as _;
use std::{fs, io::Read as _, path::Path, sync::Arc};

const ECH_KEYS_LABEL: &str = "ECH KEYS";

pub(crate) struct ServerEchKey {
    pub(crate) private_key: Vec<u8>,
    pub(crate) config: Vec<u8>,
}

pub(crate) struct ServerEchMaterial {
    pub(crate) keys: Vec<ServerEchKey>,
    config_list: Vec<u8>,
}

impl ServerEchMaterial {
    pub(crate) fn key_count(&self) -> usize {
        self.keys.len()
    }

    pub(crate) fn encoded_config_list(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(&self.config_list)
    }

    pub(crate) fn apply(self, tls: &mut rustls::ServerConfig) -> Result<()> {
        let suites = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
        let keys = self
            .keys
            .into_iter()
            .map(|key| {
                rustls::server::EchServerKey::from_raw(&key.config, key.private_key, suites)
                    .map_err(|error| CliError::new(format!("invalid ECH server key: {error}")))
            })
            .collect::<Result<Vec<_>>>()?;
        tls.ech_keys = Arc::new(rustls::server::FixedEchKeys::new(keys));
        Ok(())
    }
}

pub(crate) fn load(path: &Path) -> Result<ServerEchMaterial> {
    let mut contents = String::new();
    fs::File::open(path)
        .and_then(|file| file.take(1024 * 1024 + 1).read_to_string(&mut contents))
        .map_err(|error| {
            CliError::new(format!(
                "failed to read ech.keyPath {}: {error}",
                path.display()
            ))
        })?;
    if contents.len() > 1024 * 1024 {
        return Err(CliError::new("ECH key file exceeds 1 MiB"));
    }
    let blob = pem_block(&contents, ECH_KEYS_LABEL)?.ok_or_else(|| {
        CliError::new(format!(
            "invalid ECH keys: no {ECH_KEYS_LABEL:?} PEM block found (generate one with `hysteria ech --public-name <public_name>`)"
        ))
    })?;
    from_keys(parse_keys(&blob)?)
}

pub(crate) fn from_keys(keys: Vec<ServerEchKey>) -> Result<ServerEchMaterial> {
    if keys.is_empty() {
        return Err(CliError::new("invalid ECH keys: no key entries"));
    }
    if keys.iter().any(|key| key.private_key.is_empty()) {
        return Err(CliError::new("invalid ECH keys: empty private key"));
    }
    let body_length = keys.iter().try_fold(0_usize, |length, key| {
        length
            .checked_add(key.config.len())
            .ok_or_else(|| CliError::new("invalid ECH keys: config list is too large"))
    })?;
    let encoded_length = u16::try_from(body_length)
        .map_err(|_| CliError::new("invalid ECH keys: config list is too large"))?;
    for key in &keys {
        rustls::server::EchServerKey::from_raw(
            &key.config,
            key.private_key.clone(),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .map_err(|_| {
            CliError::new("invalid ECH key configuration or mismatched public/private key")
        })?;
    }
    let mut config_list = Vec::with_capacity(body_length + 2);
    config_list.extend_from_slice(&encoded_length.to_be_bytes());
    for key in &keys {
        config_list.extend_from_slice(&key.config);
    }
    tls::validate_ech_config_list(&config_list).map_err(|error| {
        CliError::new(format!("invalid ECH keys: embedded config list: {error}"))
    })?;
    Ok(ServerEchMaterial { keys, config_list })
}

fn pem_block(contents: &str, label: &str) -> Result<Option<Vec<u8>>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let Some((_, remainder)) = contents.split_once(&begin) else {
        return Ok(None);
    };
    let (encoded, _) = remainder.split_once(&end).ok_or_else(|| {
        CliError::new(format!("invalid ECH keys: {label} block has no end marker"))
    })?;
    let encoded: String = encoded
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map(Some)
        .map_err(|error| CliError::new(format!("invalid ECH keys PEM: {error}")))
}

fn parse_keys(mut blob: &[u8]) -> Result<Vec<ServerEchKey>> {
    let mut keys = Vec::new();
    while !blob.is_empty() {
        let (private_key, remainder) = read_u16_prefixed(blob)?;
        let (config, remainder) = read_u16_prefixed(remainder)?;
        keys.push(ServerEchKey {
            private_key: private_key.to_vec(),
            config: config.to_vec(),
        });
        blob = remainder;
    }
    Ok(keys)
}

fn read_u16_prefixed(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let length = data
        .get(..2)
        .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
        .ok_or_else(|| CliError::new("invalid ECH keys: truncated length prefix"))?;
    let end = 2_usize
        .checked_add(length)
        .ok_or_else(|| CliError::new("invalid ECH keys: length prefix overflow"))?;
    let payload = data
        .get(2..end)
        .ok_or_else(|| CliError::new("invalid ECH keys: length prefix exceeds available data"))?;
    Ok((payload, &data[end..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hysteria_transport::{
        ClientHandshake, HysteriaServer, ServerHandshake, connect, make_client_config,
        make_server_config,
    };
    use quinn::Endpoint;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::{io::Write as _, net::SocketAddr, sync::Arc};

    fn key_pem(private_key: &[u8], config: &[u8]) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&u16::try_from(private_key.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(private_key);
        blob.extend_from_slice(&u16::try_from(config.len()).unwrap().to_be_bytes());
        blob.extend_from_slice(config);
        let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
        format!("-----BEGIN ECH KEYS-----\n{encoded}\n-----END ECH KEYS-----\n")
    }

    fn generated_material() -> ServerEchMaterial {
        let suite = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES[0];
        let (public_key, private_key) = suite.generate_key_pair().unwrap();
        let suite_id = suite.suite();
        let public_name = b"public.example.com";
        let mut config = vec![0xfe, 0x0d, 0, 0];
        config.push(0x42);
        config.extend_from_slice(&u16::from(suite_id.kem).to_be_bytes());
        config.extend_from_slice(&u16::try_from(public_key.0.len()).unwrap().to_be_bytes());
        config.extend_from_slice(&public_key.0);
        config.extend_from_slice(&4_u16.to_be_bytes());
        config.extend_from_slice(&u16::from(suite_id.sym.kdf_id).to_be_bytes());
        config.extend_from_slice(&u16::from(suite_id.sym.aead_id).to_be_bytes());
        config.push(128);
        config.push(u8::try_from(public_name.len()).unwrap());
        config.extend_from_slice(public_name);
        config.extend_from_slice(&0_u16.to_be_bytes());
        let contents_len = u16::try_from(config.len() - 4).unwrap();
        config[2..4].copy_from_slice(&contents_len.to_be_bytes());

        let mut config_list = Vec::with_capacity(config.len() + 2);
        config_list.extend_from_slice(&u16::try_from(config.len()).unwrap().to_be_bytes());
        config_list.extend_from_slice(&config);
        ServerEchMaterial {
            keys: vec![ServerEchKey {
                private_key: private_key.secret_bytes().to_vec(),
                config,
            }],
            config_list,
        }
    }

    #[test]
    fn loads_go_compatible_key_blob_and_derives_config_list() {
        let generated = generated_material();
        let key = &generated.keys[0];
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(key_pem(&key.private_key, &key.config).as_bytes())
            .unwrap();
        let material = load(file.path()).unwrap();
        assert_eq!(material.key_count(), 1);
        assert_eq!(
            material.encoded_config_list(),
            generated.encoded_config_list()
        );
    }

    #[test]
    fn rejects_missing_empty_and_truncated_key_entries() {
        let mut missing = tempfile::NamedTempFile::new().unwrap();
        missing.write_all(b"not pem").unwrap();
        assert!(load(missing.path()).is_err());

        let mut empty_private = tempfile::NamedTempFile::new().unwrap();
        empty_private
            .write_all(key_pem(&[], &[0xfe, 0x0d, 0, 1, 0]).as_bytes())
            .unwrap();
        assert!(load(empty_private.path()).is_err());

        assert!(parse_keys(&[0, 4, 1]).is_err());
    }

    #[tokio::test]
    async fn completes_quic_handshake_with_server_ech() {
        let material = generated_material();
        let encoded_config_list = material.encoded_config_list();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate], key)
            .unwrap();
        material.apply(&mut server_tls).unwrap();

        let mut server = HysteriaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            make_server_config(server_tls).unwrap(),
            ServerHandshake::default(),
            Arc::new(
                |_remote: SocketAddr, request: &hysteria_protocol::AuthRequest| {
                    (request.auth == "secret").then(|| "test".to_owned())
                },
            ),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let client_tls =
            crate::tls::client_config(None, true, None, None, Some(&encoded_config_list)).unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(make_client_config(client_tls).unwrap());

        let client = connect(
            &endpoint,
            address,
            "localhost",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        );
        let (accepted, connected) = tokio::join!(server.accept(), client);
        accepted.unwrap().close(b"ECH accepted");
        let (connection, info) = connected.unwrap();
        assert!(info.ech_accepted);
        connection.close(b"ECH accepted");
    }
    fn pump_tls(
        config: rustls::ClientConfig,
        server: rustls::ServerConfig,
        name: &'static str,
    ) -> std::result::Result<rustls::client::EchStatus, rustls::Error> {
        let mut client = rustls::ClientConnection::new(Arc::new(config), name.try_into().unwrap())?;
        let mut server = rustls::ServerConnection::new(Arc::new(server))?;
        for _ in 0..32 {
            let mut bytes = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut bytes).unwrap();
            }
            if !bytes.is_empty() {
                server.read_tls(&mut bytes.as_slice()).unwrap();
                server.process_new_packets()?;
            }
            bytes.clear();
            while server.wants_write() {
                server.write_tls(&mut bytes).unwrap();
            }
            if !bytes.is_empty() {
                client.read_tls(&mut bytes.as_slice()).unwrap();
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(client.ech_status());
            }
        }
        panic!("in-memory ECH handshake did not terminate");
    }

    fn certificate_server(
        names: &[&str],
    ) -> (rustls::ServerConfig, rcgen::CertifiedKey<rcgen::KeyPair>) {
        crate::tls::ensure_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(
            names
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let server = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    certified.signing_key.serialize_der(),
                )),
            )
            .unwrap();
        (server, certified)
    }

    #[test]
    fn ech_rejection_requires_public_trust_even_with_insecure_and_matching_pin() {
        use sha2::{Digest as _, Sha256};
        let directory = tempfile::tempdir().unwrap();
        let trusted = directory.path().join("trusted.pem");
        let (_, unrelated) = certificate_server(&["unrelated.example.com"]);
        std::fs::write(&trusted, unrelated.cert.pem()).unwrap();
        let (server, certificate) = certificate_server(&["public.example.com"]);
        let pin: [u8; 32] = Sha256::digest(certificate.cert.der()).into();
        let ech = generated_material().encoded_config_list();
        let client =
            crate::tls::client_config(Some(&trusted), true, Some(pin), None, Some(&ech)).unwrap();
        let error = pump_tls(client, server, "localhost").unwrap_err();
        assert!(
            matches!(error, rustls::Error::InvalidCertificate(_)),
            "{error:?}"
        );
    }

    #[test]
    fn ech_rejection_checks_public_name_but_does_not_apply_inner_pin() {
        let directory = tempfile::tempdir().unwrap();
        let ca = directory.path().join("ca.pem");
        let ech = generated_material().encoded_config_list();
        for public_name in ["wrong.example.com", "public.example.com"] {
            let (server, certificate) = certificate_server(&[public_name]);
            std::fs::write(&ca, certificate.cert.pem()).unwrap();
            let client =
                crate::tls::client_config(Some(&ca), true, Some([0; 32]), None, Some(&ech))
                    .unwrap();
            let error = pump_tls(client, server, "localhost").unwrap_err();
            if public_name == "wrong.example.com" {
                assert!(
                    matches!(error, rustls::Error::InvalidCertificate(_)),
                    "{error:?}"
                );
            } else {
                // A trusted public-name certificate authenticates the rejection,
                // but ECH-required still prevents an application connection.
                assert!(
                    matches!(
                        error,
                        rustls::Error::PeerIncompatible(
                            rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
                        )
                    ),
                    "{error:?}"
                );
            }
        }
    }

    #[test]
    fn accepted_ech_plain_clients_and_stale_keys_have_distinct_results() {
        let directory = tempfile::tempdir().unwrap();
        let ca = directory.path().join("ca.pem");
        let (mut server, certificate) = certificate_server(&["localhost", "public.example.com"]);
        std::fs::write(&ca, certificate.cert.pem()).unwrap();
        let material = generated_material();
        let public = material.encoded_config_list();
        material.apply(&mut server).unwrap();
        let client =
            crate::tls::client_config(Some(&ca), false, None, None, Some(&public)).unwrap();
        assert_eq!(
            pump_tls(client, server.clone(), "localhost").unwrap(),
            rustls::client::EchStatus::Accepted
        );
        let client = crate::tls::client_config(Some(&ca), false, None, None, None).unwrap();
        assert_eq!(
            pump_tls(client, server.clone(), "localhost").unwrap(),
            rustls::client::EchStatus::NotOffered
        );
        let stale = generated_material().encoded_config_list();
        let client = crate::tls::client_config(Some(&ca), true, None, None, Some(&stale)).unwrap();
        assert!(matches!(
            pump_tls(client, server, "localhost"),
            Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
            ))
        ));
    }
    #[test]
    fn generated_aeads_and_overlapping_rotation_complete_real_handshakes() {
        use crate::ech::{Aead, Options, generate};
        let directory = tempfile::tempdir().unwrap();
        let ca = directory.path().join("ca.pem");
        let (server_base, certificate) = certificate_server(&["localhost", "public.example.com"]);
        std::fs::write(&ca, certificate.cert.pem()).unwrap();
        let old_path = directory.path().join("old.pem");
        let mut options = Options {
            public_name: "public.example.com".into(),
            output: old_path.clone(),
            config_id: Some(12),
            max_name_length: 0,
            aeads: vec![Aead::Aes128Gcm],
            overwrite: false,
            retain_keys: None,
        };
        let old = generate(&options).unwrap();
        for (index, aead) in [Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305]
            .into_iter()
            .enumerate()
        {
            options.output = directory.path().join(format!("{index}.pem"));
            options.aeads = vec![aead];
            options.config_id = Some(13);
            let generated = generate(&options).unwrap();
            let mut server = server_base.clone();
            load(&options.output).unwrap().apply(&mut server).unwrap();
            let client = crate::tls::client_config(
                Some(&ca),
                false,
                None,
                None,
                Some(&generated.client_config),
            )
            .unwrap();
            assert_eq!(
                pump_tls(client, server, "localhost").unwrap(),
                rustls::client::EchStatus::Accepted
            );
        }
        options.output = directory.path().join("rotated.pem");
        options.retain_keys = Some(old_path);
        let rotated = generate(&options).unwrap();
        let mut server = server_base.clone();
        load(&options.output).unwrap().apply(&mut server).unwrap();
        for config in [&old.client_config, &rotated.client_config] {
            let client =
                crate::tls::client_config(Some(&ca), false, None, None, Some(config)).unwrap();
            assert_eq!(
                pump_tls(client, server.clone(), "localhost").unwrap(),
                rustls::client::EchStatus::Accepted
            );
        }
        let retired = directory.path().join("retired.pem");
        crate::ech::prune(&options.output, &retired, &[13], false).unwrap();
        load(&retired).unwrap().apply(&mut server).unwrap();
        let client =
            crate::tls::client_config(Some(&ca), true, None, None, Some(&old.client_config))
                .unwrap();
        assert!(matches!(
            pump_tls(client, server, "localhost"),
            Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::ServerRejectedEncryptedClientHello(_)
            ))
        ));
    }
}
