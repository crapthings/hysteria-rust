use crate::{CliError, Result, tls};
use base64::Engine as _;
use std::{fs, path::Path, sync::Arc};

const ECH_KEYS_LABEL: &str = "ECH KEYS";

struct ServerEchKey {
    private_key: Vec<u8>,
    config: Vec<u8>,
}

pub(crate) struct ServerEchMaterial {
    keys: Vec<ServerEchKey>,
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
    let contents = fs::read_to_string(path).map_err(|error| {
        CliError::new(format!(
            "failed to read ech.keyPath {}: {error}",
            path.display()
        ))
    })?;
    let blob = pem_block(&contents, ECH_KEYS_LABEL)?.ok_or_else(|| {
        CliError::new(format!(
            "invalid ECH keys: no {ECH_KEYS_LABEL:?} PEM block found (generate one with `sing-box generate ech-keypair <public_name>`)"
        ))
    })?;
    let keys = parse_keys(&blob)?;
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
        let config = [0xfe, 0x0d, 0x00, 0x01, 0x00];
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(key_pem(&[7; 32], &config).as_bytes())
            .unwrap();
        let material = load(file.path()).unwrap();
        assert_eq!(material.key_count(), 1);
        let mut list = vec![0, u8::try_from(config.len()).unwrap()];
        list.extend_from_slice(&config);
        assert_eq!(
            material.encoded_config_list(),
            base64::engine::general_purpose::STANDARD.encode(list)
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
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
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
        connected.unwrap().0.close(b"ECH accepted");
    }
}
