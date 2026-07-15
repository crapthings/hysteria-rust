use crate::{CliError, Result};
use base64::Engine as _;
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    client::{EchConfig, EchMode},
    pki_types::{CertificateDer, EchConfigListBytes, PrivateKeyDer, ServerName, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use sha2::{Digest, Sha256};
use std::{fmt, fs::File, io::BufReader, path::Path, sync::Arc};
use x509_parser::{extensions::GeneralName, prelude::FromDer};

pub(crate) fn ensure_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

pub(crate) fn server_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
    sni_guard: &str,
) -> Result<ServerConfig> {
    ensure_crypto_provider();
    let certificates = read_certificates(cert_path)?;
    let key = read_private_key(key_path)?;
    let has_dns_sans = certificate_has_dns_sans(
        certificates
            .first()
            .ok_or_else(|| CliError::new("TLS certificate file contains no certificates"))?,
    )?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let certified_key = CertifiedKey::from_der(certificates, key, &provider)
        .map_err(|error| CliError::new(format!("invalid TLS certificate/key: {error}")))?;
    let guard = SniGuard::parse(sni_guard)?;
    let builder = ServerConfig::builder();
    let builder = if let Some(client_ca_path) = client_ca_path {
        let roots = read_root_store(client_ca_path)?;
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| CliError::new(format!("invalid client CA configuration: {error}")))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    Ok(
        builder.with_cert_resolver(Arc::new(GuardedCertificateResolver {
            certified_key: Arc::new(certified_key),
            guard,
            has_dns_sans,
        })),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SniGuard {
    DnsSan,
    Strict,
    Disable,
}

impl SniGuard {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "dns-san" => Ok(Self::DnsSan),
            "strict" => Ok(Self::Strict),
            "disable" => Ok(Self::Disable),
            _ => Err(CliError::new(
                "unsupported tls.sniGuard; expected dns-san, strict, or disable",
            )),
        }
    }
}

#[derive(Debug)]
struct GuardedCertificateResolver {
    certified_key: Arc<CertifiedKey>,
    guard: SniGuard,
    has_dns_sans: bool,
}

impl ResolvesServerCert for GuardedCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if self.guard == SniGuard::Disable || (self.guard == SniGuard::DnsSan && !self.has_dns_sans)
        {
            return Some(Arc::clone(&self.certified_key));
        }
        let name = ServerName::try_from(client_hello.server_name()?.to_owned()).ok()?;
        let certificate = self.certified_key.end_entity_cert().ok()?;
        let parsed = rustls::server::ParsedCertificate::try_from(certificate).ok()?;
        rustls::client::verify_server_name(&parsed, &name).ok()?;
        Some(Arc::clone(&self.certified_key))
    }
}

fn certificate_has_dns_sans(certificate: &CertificateDer<'_>) -> Result<bool> {
    let (_, certificate) =
        x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
            .map_err(|error| CliError::new(format!("invalid TLS certificate: {error}")))?;
    let alternative_name = certificate
        .subject_alternative_name()
        .map_err(|error| CliError::new(format!("invalid TLS subject alternative name: {error}")))?;
    Ok(alternative_name.is_some_and(|extension| {
        extension
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName(_)))
    }))
}

pub(crate) fn client_config(
    ca_path: Option<&Path>,
    insecure: bool,
    pin: Option<[u8; 32]>,
    client_identity: Option<(&Path, &Path)>,
    ech: Option<&str>,
) -> Result<ClientConfig> {
    let roots = if let Some(ca_path) = ca_path {
        read_root_store(ca_path)?
    } else if insecure {
        RootCertStore::empty()
    } else {
        native_root_store()?
    };
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider));
    let builder = if let Some(value) = ech {
        let config_list = parse_ech_config_list(value)?;
        let config = EchConfig::new(
            EchConfigListBytes::from(config_list),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .map_err(|error| CliError::new(format!("invalid tls.ech config list: {error}")))?;
        builder
            .with_ech(EchMode::Enable(config))
            .map_err(|error| CliError::new(format!("failed to enable tls.ech: {error}")))?
    } else {
        builder
            .with_safe_default_protocol_versions()
            .map_err(|error| CliError::new(format!("failed to configure TLS versions: {error}")))?
    };
    let builder = if insecure || pin.is_some() {
        let normal_verifier = if insecure {
            None
        } else {
            Some(
                rustls::client::WebPkiServerVerifier::builder(Arc::new(roots.clone()))
                    .build()
                    .map_err(|error| {
                        CliError::new(format!("invalid server CA configuration: {error}"))
                    })?,
            )
        };
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(HysteriaServerVerifier::new(
                normal_verifier,
                pin,
            )))
    } else {
        builder.with_root_certificates(roots)
    };
    if let Some((cert_path, key_path)) = client_identity {
        builder
            .with_client_auth_cert(read_certificates(cert_path)?, read_private_key(key_path)?)
            .map_err(|error| CliError::new(format!("invalid client certificate/key: {error}")))
    } else {
        Ok(builder.with_no_client_auth())
    }
}

#[derive(Clone)]
struct HysteriaServerVerifier {
    normal: Option<Arc<rustls::client::WebPkiServerVerifier>>,
    pin: Option<[u8; 32]>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl HysteriaServerVerifier {
    fn new(
        normal: Option<Arc<rustls::client::WebPkiServerVerifier>>,
        pin: Option<[u8; 32]>,
    ) -> Self {
        Self {
            normal,
            pin,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        }
    }
}

pub(crate) fn parse_ech_config_list(value: &str) -> Result<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CliError::new("empty tls.ech config list"));
    }
    if let Some(decoded) = decode_ech_config_list(value) {
        return Ok(decoded);
    }
    let data = std::fs::read(value).map_err(|error| {
        CliError::new(format!(
            "tls.ech is neither a valid base64 config list nor a readable file: {error}"
        ))
    })?;
    if let Some(contents) = decode_ech_pem(&data)? {
        validate_ech_config_list(&contents)?;
        return Ok(contents);
    }
    let text = std::str::from_utf8(&data).map_err(|_| {
        CliError::new("tls.ech file does not contain UTF-8 base64 or ECH CONFIGS PEM")
    })?;
    decode_ech_config_list(text)
        .ok_or_else(|| CliError::new("tls.ech file does not contain a valid ECH config list"))
}

fn decode_ech_config_list(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ]
    .into_iter()
    .find_map(|encoding| {
        let decoded = encoding.decode(value).ok()?;
        validate_ech_config_list(&decoded).ok()?;
        Some(decoded)
    })
}

fn decode_ech_pem(data: &[u8]) -> Result<Option<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN ECH CONFIGS-----";
    const END: &str = "-----END ECH CONFIGS-----";
    let text =
        std::str::from_utf8(data).map_err(|_| CliError::new("tls.ech file is not valid UTF-8"))?;
    let Some((_, remainder)) = text.split_once(BEGIN) else {
        return Ok(None);
    };
    let (encoded, _) = remainder
        .split_once(END)
        .ok_or_else(|| CliError::new("tls.ech ECH CONFIGS PEM block has no end marker"))?;
    let encoded: String = encoded
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map(Some)
        .map_err(|error| CliError::new(format!("invalid tls.ech ECH CONFIGS PEM: {error}")))
}

pub(crate) fn validate_ech_config_list(list: &[u8]) -> Result<()> {
    if list.len() < 2 {
        return Err(CliError::new(
            "malformed tls.ech config list: truncated length",
        ));
    }
    let body_length = usize::from(u16::from_be_bytes([list[0], list[1]]));
    if body_length == 0 || body_length != list.len() - 2 {
        return Err(CliError::new("malformed tls.ech config list length"));
    }
    let mut position = 2;
    while position < list.len() {
        if list.len() - position < 4 {
            return Err(CliError::new("malformed tls.ech config header"));
        }
        let length = usize::from(u16::from_be_bytes([list[position + 2], list[position + 3]]));
        position = position
            .checked_add(4 + length)
            .ok_or_else(|| CliError::new("malformed tls.ech config length"))?;
        if position > list.len() {
            return Err(CliError::new("malformed tls.ech config length"));
        }
    }
    Ok(())
}

impl fmt::Debug for HysteriaServerVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HysteriaServerVerifier")
            .field("normal_verification", &self.normal.is_some())
            .field("certificate_pin", &self.pin.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for HysteriaServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if let Some(normal) = &self.normal {
            normal.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            )?;
        }
        if let Some(expected) = self.pin {
            let actual: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
            if actual != expected {
                return Err(rustls::Error::General(
                    "no certificate matches tls.pinSHA256".to_owned(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn read_root_store(path: &Path) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let certificates = read_certificates(path)?;
    let (added, ignored) = roots.add_parsable_certificates(certificates);
    if added == 0 || ignored != 0 {
        return Err(CliError::new(format!(
            "{} contained {added} usable and {ignored} invalid certificates",
            path.display()
        )));
    }
    Ok(roots)
}

fn native_root_store() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    let (added, _) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        let details = native
            .errors
            .first()
            .map_or_else(String::new, |error| format!(": {error}"));
        return Err(CliError::new(format!(
            "no system root certificates were available{details}"
        )));
    }
    Ok(roots)
}

pub(crate) fn read_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader =
        BufReader::new(File::open(path).map_err(|error| {
            CliError::new(format!("failed to open {}: {error}", path.display()))
        })?);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| CliError::new(format!("failed to parse {}: {error}", path.display())))?;
    if certificates.is_empty() {
        return Err(CliError::new(format!(
            "no certificates in {}",
            path.display()
        )));
    }
    Ok(certificates)
}

fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader =
        BufReader::new(File::open(path).map_err(|error| {
            CliError::new(format!("failed to open {}: {error}", path.display()))
        })?);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|error| CliError::new(format!("failed to parse {}: {error}", path.display())))?
        .ok_or_else(|| CliError::new(format!("no private key in {}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hysteria_transport::{
        ClientHandshake, HysteriaServer, ServerHandshake, connect, make_client_config,
        make_server_config,
    };
    use quinn::Endpoint;
    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::{net::SocketAddr, path::PathBuf};
    use tempfile::TempDir;

    fn ech_config_list() -> Vec<u8> {
        let public_name = b"decoy.example.com";
        let mut contents = vec![0, 0, 0x20, 0, 32];
        contents.extend_from_slice(&[7; 32]);
        contents.extend_from_slice(&[0, 4, 0, 1, 0, 1]);
        contents.push(0);
        contents.push(u8::try_from(public_name.len()).unwrap());
        contents.extend_from_slice(public_name);
        contents.extend_from_slice(&[0, 0]);

        let mut config = vec![0xfe, 0x0d];
        config.extend_from_slice(&u16::try_from(contents.len()).unwrap().to_be_bytes());
        config.extend_from_slice(&contents);
        let mut list = Vec::with_capacity(config.len() + 2);
        list.extend_from_slice(&u16::try_from(config.len()).unwrap().to_be_bytes());
        list.extend_from_slice(&config);
        list
    }

    #[test]
    fn parses_go_compatible_ech_inline_and_file_forms() {
        let list = ech_config_list();
        let standard = base64::engine::general_purpose::STANDARD.encode(&list);
        let url_safe = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&list);
        assert_eq!(parse_ech_config_list(&standard).unwrap(), list);
        assert_eq!(parse_ech_config_list(&url_safe).unwrap(), list);

        let directory = tempfile::tempdir().unwrap();
        let base64_path = directory.path().join("ech.txt");
        std::fs::write(&base64_path, format!("{standard}\n")).unwrap();
        assert_eq!(
            parse_ech_config_list(base64_path.to_str().unwrap()).unwrap(),
            list
        );

        let pem_path = directory.path().join("ech.pem");
        let pem = format!("-----BEGIN ECH CONFIGS-----\n{standard}\n-----END ECH CONFIGS-----\n");
        std::fs::write(&pem_path, pem).unwrap();
        assert_eq!(
            parse_ech_config_list(pem_path.to_str().unwrap()).unwrap(),
            list
        );
        assert!(parse_ech_config_list("").is_err());
        assert!(parse_ech_config_list("not-a-config-or-file").is_err());
    }

    #[test]
    fn builds_tls13_client_config_with_ech() {
        let encoded = base64::engine::general_purpose::STANDARD.encode(ech_config_list());
        client_config(None, true, None, None, Some(&encoded)).unwrap();
    }

    #[test]
    fn pin_verifier_accepts_only_matching_end_entity() {
        let certificate = CertificateDer::from(vec![1, 2, 3, 4]);
        let pin = Sha256::digest(certificate.as_ref()).into();
        let verifier = HysteriaServerVerifier::new(None, Some(pin));
        let server_name = ServerName::try_from("localhost").unwrap();
        assert!(
            verifier
                .verify_server_cert(
                    &certificate,
                    &[],
                    &server_name,
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::ZERO),
                )
                .is_ok()
        );

        let verifier = HysteriaServerVerifier::new(None, Some([0; 32]));
        assert!(
            verifier
                .verify_server_cert(
                    &certificate,
                    &[],
                    &server_name,
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::ZERO),
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn insecure_pin_and_mutual_tls_handshakes() {
        let pki = TestPki::new();
        let server_tls = server_config(&pki.server_cert, &pki.server_key, None, "disable").unwrap();
        let mut server = test_server(server_tls);
        let address = server.local_addr().unwrap();

        let pin: [u8; 32] = Sha256::digest(pki.server.der()).into();
        let client_tls = client_config(None, true, Some(pin), None, None).unwrap();
        let endpoint = client_endpoint(client_tls);
        let (connection, _) = connect(
            &endpoint,
            address,
            "wrong-name-is-ignored",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        )
        .await
        .unwrap();
        connection.close(b"pin verified");
        server.accept().await.unwrap();

        let wrong_tls = client_config(None, true, Some([0; 32]), None, None).unwrap();
        let wrong_endpoint = client_endpoint(wrong_tls);
        assert!(
            connect(
                &wrong_endpoint,
                address,
                "localhost",
                ClientHandshake {
                    auth: "secret".to_owned(),
                    max_rx: 0,
                    max_tx: 0,
                },
            )
            .await
            .is_err()
        );

        drop(server);
        let mtls_server =
            server_config(&pki.server_cert, &pki.server_key, Some(&pki.ca_cert), "").unwrap();
        let mut server = test_server(mtls_server);
        let address = server.local_addr().unwrap();
        let client_tls = client_config(
            Some(&pki.ca_cert),
            false,
            None,
            Some((&pki.client_cert, &pki.client_key)),
            None,
        )
        .unwrap();
        let endpoint = client_endpoint(client_tls);
        let (connection, _) = connect(
            &endpoint,
            address,
            "localhost",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        )
        .await
        .unwrap();
        connection.close(b"mTLS verified");
        server.accept().await.unwrap();

        let anonymous_tls = client_config(Some(&pki.ca_cert), false, None, None, None).unwrap();
        let anonymous_endpoint = client_endpoint(anonymous_tls);
        assert!(
            connect(
                &anonymous_endpoint,
                address,
                "localhost",
                ClientHandshake {
                    auth: "secret".to_owned(),
                    max_rx: 0,
                    max_tx: 0,
                },
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn server_sni_guard_accepts_certificate_names_and_rejects_mismatches() {
        let pki = TestPki::new();
        let client_tls = client_config(None, true, None, None, None).unwrap();

        let guarded_tls =
            server_config(&pki.server_cert, &pki.server_key, None, "dns-san").unwrap();
        let mut guarded = test_server(guarded_tls);
        let address = guarded.local_addr().unwrap();
        let endpoint = client_endpoint(client_tls.clone());
        let (connection, _) = connect(
            &endpoint,
            address,
            "localhost",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        )
        .await
        .unwrap();
        connection.close(b"SNI accepted");
        guarded.accept().await.unwrap();

        let endpoint = client_endpoint(client_tls.clone());
        assert!(
            connect(
                &endpoint,
                address,
                "wrong.example",
                ClientHandshake {
                    auth: "secret".to_owned(),
                    max_rx: 0,
                    max_tx: 0,
                },
            )
            .await
            .is_err()
        );

        drop(guarded);
        let disabled_tls =
            server_config(&pki.server_cert, &pki.server_key, None, "disable").unwrap();
        let mut disabled = test_server(disabled_tls);
        let endpoint = client_endpoint(client_tls);
        let (connection, _) = connect(
            &endpoint,
            disabled.local_addr().unwrap(),
            "wrong.example",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        )
        .await
        .unwrap();
        connection.close(b"SNI guard disabled");
        disabled.accept().await.unwrap();

        drop(disabled);
        let no_san_tls = server_config(&pki.no_san_cert, &pki.no_san_key, None, "dns-san").unwrap();
        let mut no_san = test_server(no_san_tls);
        let endpoint = client_endpoint(client_config(None, true, None, None, None).unwrap());
        let (connection, _) = connect(
            &endpoint,
            no_san.local_addr().unwrap(),
            "any-name-is-accepted.example",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        )
        .await
        .unwrap();
        connection.close(b"DNS-SAN guard bypassed for certificate without DNS SANs");
        no_san.accept().await.unwrap();
    }

    fn test_server(tls: ServerConfig) -> HysteriaServer {
        HysteriaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            make_server_config(tls).unwrap(),
            ServerHandshake::default(),
            Arc::new(
                |_remote: SocketAddr, request: &hysteria_protocol::AuthRequest| {
                    (request.auth == "secret").then(|| "test".to_owned())
                },
            ),
        )
        .unwrap()
    }

    fn client_endpoint(tls: ClientConfig) -> Endpoint {
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(make_client_config(tls).unwrap());
        endpoint
    }

    struct TestPki {
        _directory: TempDir,
        ca_cert: PathBuf,
        server_cert: PathBuf,
        server_key: PathBuf,
        no_san_cert: PathBuf,
        no_san_key: PathBuf,
        client_cert: PathBuf,
        client_key: PathBuf,
        server: Certificate,
    }

    impl TestPki {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            ca_params.key_usages = vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
            ];
            let ca = ca_params.self_signed(&ca_key).unwrap();

            let server_key = KeyPair::generate().unwrap();
            let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
            server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();

            let no_san_key = KeyPair::generate().unwrap();
            let mut no_san_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            no_san_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let no_san = no_san_params.signed_by(&no_san_key, &ca, &ca_key).unwrap();

            let client_key = KeyPair::generate().unwrap();
            let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let client = client_params.signed_by(&client_key, &ca, &ca_key).unwrap();

            let ca_cert = directory.path().join("ca.pem");
            let server_cert = directory.path().join("server.pem");
            let server_key_path = directory.path().join("server.key");
            let no_san_cert = directory.path().join("no-san.pem");
            let no_san_key_path = directory.path().join("no-san.key");
            let client_cert = directory.path().join("client.pem");
            let client_key_path = directory.path().join("client.key");
            std::fs::write(&ca_cert, ca.pem()).unwrap();
            std::fs::write(&server_cert, server.pem()).unwrap();
            std::fs::write(&server_key_path, server_key.serialize_pem()).unwrap();
            std::fs::write(&no_san_cert, no_san.pem()).unwrap();
            std::fs::write(&no_san_key_path, no_san_key.serialize_pem()).unwrap();
            std::fs::write(&client_cert, client.pem()).unwrap();
            std::fs::write(&client_key_path, client_key.serialize_pem()).unwrap();
            Self {
                _directory: directory,
                ca_cert,
                server_cert,
                server_key: server_key_path,
                no_san_cert,
                no_san_key: no_san_key_path,
                client_cert,
                client_key: client_key_path,
                server,
            }
        }
    }
}
