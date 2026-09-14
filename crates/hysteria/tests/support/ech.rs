use base64::Engine as _;
use std::{fs, path::Path};

pub fn generate_ech_key(path: &Path) -> String {
    // The upstream Go implementation's ECH key format and handshake tests use
    // DHKEM(X25519, HKDF-SHA256). Select it explicitly instead of relying on
    // provider ordering, which differs between platforms.
    let suite = rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
        .iter()
        .copied()
        .find(|suite| u16::from(suite.suite().kem) == 0x0020)
        .expect("AWS-LC provider must support X25519 HPKE");
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

    let private = private_key.secret_bytes();
    let mut blob = Vec::new();
    blob.extend_from_slice(&u16::try_from(private.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(private);
    blob.extend_from_slice(&u16::try_from(config.len()).unwrap().to_be_bytes());
    blob.extend_from_slice(&config);
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(blob);
    fs::write(
        path,
        format!("-----BEGIN ECH KEYS-----\n{encoded_key}\n-----END ECH KEYS-----\n"),
    )
    .unwrap();

    let mut config_list = Vec::with_capacity(config.len() + 2);
    config_list.extend_from_slice(&u16::try_from(config.len()).unwrap().to_be_bytes());
    config_list.extend_from_slice(&config);
    base64::engine::general_purpose::STANDARD.encode(config_list)
}
