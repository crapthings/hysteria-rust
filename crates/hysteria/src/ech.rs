//! Offline ECH key generation and explicit overlapping-key rotation.
use crate::{
    CliError, Result,
    server_ech::{self, ServerEchKey},
};
use base64::Engine as _;
use rustls::crypto::hpke::Hpke as _;
use std::{
    collections::HashSet,
    io::Write as _,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Aead {
    #[value(name = "aes-128-gcm")]
    Aes128Gcm,
    #[value(name = "aes-256-gcm")]
    Aes256Gcm,
    #[value(name = "chacha20-poly1305")]
    ChaCha20Poly1305,
}
impl Aead {
    const fn id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 1,
            Self::Aes256Gcm => 2,
            Self::ChaCha20Poly1305 => 3,
        }
    }
}

pub struct Options {
    pub public_name: String,
    pub output: PathBuf,
    pub config_id: Option<u8>,
    pub max_name_length: u8,
    pub aeads: Vec<Aead>,
    pub overwrite: bool,
    pub retain_keys: Option<PathBuf>,
}

/// Contains only public metadata; private key bytes are never returned to the CLI.
pub struct Generated {
    pub output: PathBuf,
    pub public_name: String,
    pub config_id: u8,
    pub key_count: usize,
    pub client_config: String,
}

/// Generates X25519/HKDF-SHA256 ECH keys and atomically writes a private PEM file.
///
/// # Errors
/// Rejects invalid names, duplicate IDs/suites, malformed retained keys, existing
/// files without explicit overwrite, and failed random/crypto/filesystem operations.
pub fn generate(options: &Options) -> Result<Generated> {
    validate_public_name(&options.public_name)?;
    if options.output.as_os_str().is_empty() || options.output == Path::new("-") {
        return Err(CliError::new("ECH output must be a file path, not stdout"));
    }
    let mut keys = match &options.retain_keys {
        Some(path) => server_ech::load(path)?.keys,
        None => Vec::new(),
    };
    let mut used = HashSet::new();
    for key in &keys {
        let parsed = rustls::server::EchServerKey::from_raw(
            &key.config,
            key.private_key.clone(),
            rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES,
        )
        .map_err(|_| CliError::new("retained ECH file contains an invalid or unsupported key"))?;
        if !used.insert(parsed.config_id()) {
            return Err(CliError::new("retained ECH keys have duplicate config IDs"));
        }
    }
    if used.len() >= 256 {
        return Err(CliError::new("all ECH config IDs are already in use"));
    }
    let config_id = choose_id(options.config_id, &used)?;
    keys.insert(0, new_key(options, config_id)?);
    let material = server_ech::from_keys(keys)?;
    let client_config = publish(&material, &options.output, options.overwrite)?;
    Ok(Generated {
        output: options.output.clone(),
        public_name: options.public_name.clone(),
        config_id,
        key_count: material.key_count(),
        client_config,
    })
}

/// Public metadata returned after retiring explicitly unselected keys.
pub struct Pruned {
    pub output: PathBuf,
    pub retained_ids: Vec<u8>,
    pub client_config: String,
}

/// Keeps only explicitly selected key IDs, without generating or replacing keys.
/// The input is unchanged unless output is the same file and overwrite is explicit.
///
/// # Errors
/// Rejects empty/missing/ambiguous IDs, invalid key files and unsafe output paths.
pub fn prune(input: &Path, output: &Path, keep_ids: &[u8], overwrite: bool) -> Result<Pruned> {
    let keep: HashSet<_> = keep_ids.iter().copied().collect();
    if keep.is_empty() || keep.len() != keep_ids.len() {
        return Err(CliError::new("provide at least one distinct --keep-id"));
    }
    let mut material = server_ech::load(input)?;
    let available: HashSet<_> = material.keys.iter().map(|key| key.config[4]).collect();
    if available.len() != material.keys.len() {
        return Err(CliError::new(
            "cannot prune ambiguous duplicate ECH config IDs",
        ));
    }
    if !keep.is_subset(&available) {
        return Err(CliError::new(
            "a requested ECH config ID is not present in the input file",
        ));
    }
    material.keys.retain(|key| keep.contains(&key.config[4]));
    let material = server_ech::from_keys(material.keys)?;
    let client_config = publish(&material, output, overwrite)?;
    Ok(Pruned {
        output: output.to_path_buf(),
        retained_ids: material.keys.iter().map(|key| key.config[4]).collect(),
        client_config,
    })
}

fn publish(
    material: &server_ech::ServerEchMaterial,
    output: &Path,
    overwrite: bool,
) -> Result<String> {
    let client_config = material.encoded_config_list();
    let mut key_blob = Vec::new();
    for key in &material.keys {
        vector(&mut key_blob, &key.private_key)?;
        vector(&mut key_blob, &key.config)?;
    }
    let pem = format!(
        "-----BEGIN ECH KEYS-----\n{}\n-----END ECH KEYS-----\n-----BEGIN ECH CONFIGS-----\n{client_config}\n-----END ECH CONFIGS-----\n",
        base64::engine::general_purpose::STANDARD.encode(key_blob)
    );
    write_private(output, pem.as_bytes(), overwrite)?;
    Ok(client_config)
}

fn choose_id(explicit: Option<u8>, used: &HashSet<u8>) -> Result<u8> {
    if let Some(id) = explicit {
        return if used.contains(&id) {
            Err(CliError::new("ECH config ID conflicts with a retained key"))
        } else {
            Ok(id)
        };
    }
    let candidates: Vec<u8> = (0..=255).filter(|id| !used.contains(id)).collect();
    // Rejection sampling avoids bias when the number of available IDs isn't a power of two.
    let ceiling = 256 / candidates.len() * candidates.len();
    loop {
        let mut random = [0];
        getrandom::fill(&mut random)
            .map_err(|_| CliError::new("failed to generate ECH config ID"))?;
        let value = usize::from(random[0]);
        if value < ceiling {
            return Ok(candidates[value % candidates.len()]);
        }
    }
}

fn new_key(options: &Options, config_id: u8) -> Result<ServerEchKey> {
    if options.aeads.is_empty() {
        return Err(CliError::new("at least one ECH AEAD is required"));
    }
    let mut suites = Vec::new();
    let mut seen = HashSet::new();
    for algorithm in &options.aeads {
        let id = algorithm.id();
        if !seen.insert(id) {
            return Err(CliError::new("duplicate ECH AEAD"));
        }
        suites.extend_from_slice(&1_u16.to_be_bytes());
        suites.extend_from_slice(&id.to_be_bytes());
    }
    let suite = rustls::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
    let (public, private) = suite
        .generate_key_pair()
        .map_err(|_| CliError::new("failed to generate ECH key pair"))?;
    let mut contents = vec![config_id];
    contents.extend_from_slice(&0x0020_u16.to_be_bytes());
    vector(&mut contents, &public.0)?;
    vector(&mut contents, &suites)?;
    contents.push(options.max_name_length);
    contents.push(u8::try_from(options.public_name.len()).expect("validated DNS length"));
    contents.extend_from_slice(options.public_name.as_bytes());
    contents.extend_from_slice(&0_u16.to_be_bytes());
    let mut config = vec![0xfe, 0x0d];
    vector(&mut config, &contents)?;
    Ok(ServerEchKey {
        private_key: private.secret_bytes().to_vec(),
        config,
    })
}

fn vector(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let size = u16::try_from(bytes.len())
        .map_err(|_| CliError::new("ECH material exceeds the wire length limit"))?;
    output.extend_from_slice(&size.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn validate_public_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 253
        || !name.contains('.')
        || name.parse::<std::net::IpAddr>().is_ok()
        || name
            .rsplit('.')
            .next()
            .is_none_or(|label| label.bytes().all(|ch| ch.is_ascii_digit()))
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == b'-')
        })
    {
        return Err(CliError::new(
            "public-name must be an ASCII/punycode DNS name, without a scheme, port, wildcard or trailing dot",
        ));
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8], overwrite: bool) -> Result<()> {
    if path.as_os_str().is_empty() || path == Path::new("-") {
        return Err(CliError::new("ECH output must be a file path, not stdout"));
    }
    if let Ok(metadata) = path.symlink_metadata() {
        if !overwrite {
            return Err(CliError::new(
                "ECH output already exists; use another --output or explicitly request --overwrite",
            ));
        }
        if !metadata.file_type().is_file() {
            return Err(CliError::new(
                "ECH overwrite requires a regular file, not a symlink or directory",
            ));
        }
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".hysteria-ech-")
        .tempfile_in(parent)
        .map_err(|error| CliError::new(format!("cannot create ECH output: {error}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    if overwrite {
        temporary.persist(path)
    } else {
        temporary.persist_noclobber(path)
    }
    .map_err(|error| CliError::new(format!("cannot publish ECH key file: {}", error.error)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(path: PathBuf) -> Options {
        Options {
            public_name: "public.example.com".into(),
            output: path,
            config_id: Some(42),
            max_name_length: 0,
            aeads: vec![Aead::Aes128Gcm, Aead::Aes256Gcm, Aead::ChaCha20Poly1305],
            overwrite: false,
            retain_keys: None,
        }
    }

    #[test]
    fn generation_roundtrips_and_rotation_retains_old_keys_without_id_conflicts() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("old.pem");
        let generated = generate(&options(original.clone())).unwrap();
        let original_bytes = std::fs::read(&original).unwrap();
        let material = server_ech::load(&original).unwrap();
        assert_eq!(material.encoded_config_list(), generated.client_config);
        assert_eq!(
            crate::tls::parse_ech_config_list(original.to_str().unwrap()).unwrap(),
            base64::engine::general_purpose::STANDARD
                .decode(&generated.client_config)
                .unwrap()
        );
        assert!(generate(&options(original.clone())).is_err());
        assert_eq!(std::fs::read(&original).unwrap(), original_bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&original).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let next = directory.path().join("next.pem");
        let mut rotation = options(next.clone());
        rotation.retain_keys = Some(original.clone());
        assert!(generate(&rotation).is_err());
        assert!(!next.exists());
        rotation.config_id = None;
        let generated = generate(&rotation).unwrap();
        assert_ne!(generated.config_id, 42);
        assert_eq!(generated.key_count, 2);
        let material = server_ech::load(&next).unwrap();
        assert_eq!(
            material.keys[1].config,
            server_ech::load(&original).unwrap().keys[0].config
        );
        assert_eq!(std::fs::read(&original).unwrap(), original_bytes);
        let retired_path = directory.path().join("retired.pem");
        let retained = prune(&next, &retired_path, &[generated.config_id], false).unwrap();
        assert_eq!(retained.retained_ids, vec![generated.config_id]);
        let pruned = server_ech::load(&retired_path).unwrap();
        assert_eq!(pruned.keys[0].private_key, material.keys[0].private_key);
        assert_eq!(pruned.keys[0].config, material.keys[0].config);
        let absent = (0..=255)
            .find(|id| *id != 42 && *id != generated.config_id)
            .unwrap();
        assert!(prune(&next, &retired_path, &[absent], true).is_err());
        assert!(prune(&next, &retired_path, &[], true).is_err());
        for key in material.keys {
            assert!(
                rustls::server::EchServerKey::from_raw(
                    &key.config,
                    key.private_key,
                    rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
                )
                .is_ok()
            );
        }
        rotation.overwrite = true;
        assert!(generate(&rotation).is_ok());
    }

    #[test]
    fn invalid_names_duplicate_aeads_and_mismatched_retained_keys_do_not_write_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("ech.pem");
        for name in [
            "",
            "localhost",
            "example.123",
            "example.com.",
            "*.example.com",
            "127.0.0.1",
            "https://example.com",
            "example.com:443",
            "bad_thing.example.com",
        ] {
            let mut config = options(output.clone());
            config.public_name = name.into();
            assert!(generate(&config).is_err());
            assert!(!output.exists());
        }
        let mut config = options(output.clone());
        config.aeads = vec![Aead::Aes128Gcm, Aead::Aes128Gcm];
        assert!(generate(&config).is_err());
        assert!(!output.exists());
        generate(&options(output.clone())).unwrap();
        let mut material = server_ech::load(&output).unwrap();
        material.keys[0].private_key.fill(0);
        let key = material.keys.remove(0);
        let invalid_path = directory.path().join("invalid.pem");
        let mut blob = Vec::new();
        vector(&mut blob, &key.private_key).unwrap();
        vector(&mut blob, &key.config).unwrap();
        std::fs::write(
            &invalid_path,
            format!(
                "-----BEGIN ECH KEYS-----\n{}\n-----END ECH KEYS-----\n",
                base64::engine::general_purpose::STANDARD.encode(blob)
            ),
        )
        .unwrap();
        let target = directory.path().join("never-created.pem");
        let mut retained = options(target.clone());
        retained.retain_keys = Some(invalid_path);
        assert!(generate(&retained).is_err());
        assert!(!target.exists());
        assert!(
            rustls::server::EchServerKey::from_raw(
                &key.config,
                key.private_key,
                rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn overwrite_does_not_follow_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("original");
        std::fs::write(&victim, "preserve").unwrap();
        let link = directory.path().join("link.pem");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let mut config = options(link);
        config.overwrite = true;
        assert!(generate(&config).is_err());
        assert_eq!(std::fs::read_to_string(victim).unwrap(), "preserve");
    }
}
