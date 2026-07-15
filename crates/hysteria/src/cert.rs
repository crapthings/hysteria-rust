use crate::{CliError, Result};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Ia5String, KeyPair,
    KeyUsagePurpose, SanType,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

pub struct CertOptions {
    pub hosts: String,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub valid_for: Duration,
    pub overwrite: bool,
}

#[derive(Debug)]
pub struct CertResult {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub pin_sha256: String,
}

/// Generates a self-signed P-256 certificate and matching private key.
///
/// # Errors
///
/// Returns an error for invalid hosts, output conflicts, invalid validity, or I/O failures.
pub fn generate(options: &CertOptions) -> Result<CertResult> {
    if options.cert_file.as_os_str().is_empty() || options.key_file.as_os_str().is_empty() {
        return Err(CliError::new("certificate and key paths cannot be empty"));
    }
    if options.cert_file == options.key_file {
        return Err(CliError::new("certificate and key paths must be different"));
    }
    if options.valid_for.is_zero() {
        return Err(CliError::new("valid-for must be positive"));
    }
    let hosts = parse_hosts(&options.hosts)?;
    if !options.overwrite {
        ensure_absent(&options.cert_file)?;
        ensure_absent(&options.key_file)?;
    }

    let now = time::OffsetDateTime::now_utc();
    let validity = time::Duration::try_from(options.valid_for)
        .map_err(|error| CliError::new(format!("invalid valid-for duration: {error}")))?;
    let mut params = CertificateParams::default();
    params.not_before = now - time::Duration::minutes(1);
    params.not_after = now + validity;
    params.subject_alt_names = hosts.sans;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, hosts.common_name);
    params.distinguished_name = name;
    let key = KeyPair::generate()
        .map_err(|error| CliError::new(format!("failed to generate private key: {error}")))?;
    let certificate = params
        .self_signed(&key)
        .map_err(|error| CliError::new(format!("failed to generate certificate: {error}")))?;
    write_output(
        &options.cert_file,
        certificate.pem().as_bytes(),
        0o644,
        options.overwrite,
    )?;
    write_output(
        &options.key_file,
        key.serialize_pem().as_bytes(),
        0o600,
        options.overwrite,
    )?;
    let pin_sha256 = format!("{:x}", Sha256::digest(certificate.der().as_ref()));
    Ok(CertResult {
        cert_file: options.cert_file.clone(),
        key_file: options.key_file.clone(),
        pin_sha256,
    })
}

struct ParsedHosts {
    sans: Vec<SanType>,
    common_name: String,
}

fn parse_hosts(value: &str) -> Result<ParsedHosts> {
    let mut seen = HashSet::new();
    let mut sans = Vec::new();
    let mut common_name = None;
    for raw in value.split(',') {
        let host = raw.trim();
        if host.is_empty() {
            return Err(CliError::new("host list contains an empty entry"));
        }
        if !seen.insert(host.to_ascii_lowercase()) {
            continue;
        }
        let unbracketed = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        common_name.get_or_insert_with(|| unbracketed.to_owned());
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            sans.push(SanType::IpAddress(ip));
        } else {
            if host.contains(':') {
                return Err(CliError::new(format!(
                    "host {host:?} is not a valid IP address; omit ports from DNS names"
                )));
            }
            let dns = Ia5String::try_from(host)
                .map_err(|error| CliError::new(format!("invalid DNS name {host:?}: {error}")))?;
            sans.push(SanType::DnsName(dns));
        }
    }
    Ok(ParsedHosts {
        sans,
        common_name: common_name.ok_or_else(|| CliError::new("host list is empty"))?,
    })
}

fn ensure_absent(path: &Path) -> Result<()> {
    match fs::metadata(path) {
        Ok(_) => Err(CliError::new(format!(
            "{} already exists; use --overwrite to replace it",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn write_output(path: &Path, data: &[u8], mode: u32, overwrite: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(overwrite);
    if !overwrite {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::new(format!(
                "{} already exists; use --overwrite to replace it",
                path.display()
            ))
        } else {
            error.into()
        }
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

#[must_use]
pub fn default_host() -> String {
    ["HOSTNAME", "COMPUTERNAME"]
        .into_iter()
        .find_map(|name| std::env::var(name).ok())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "localhost".to_owned())
}

#[must_use]
pub fn format_result(result: &CertResult) -> String {
    format!(
        "Generated self-signed certificate:\n  Certificate: {}\n  Private key: {}\n  pinSHA256: {}\n\nSample TLS config:\n\n# server.yaml\ntls:\n  cert: {}\n  key: {}\n  sniGuard: disable\n\n# client.yaml\ntls:\n  insecure: true\n  pinSHA256: {}\n\nWARNING: insecure: true is only MITM-resistant when paired with the shown pinSHA256.\n",
        result.cert_file.display(),
        result.key_file.display(),
        result.pin_sha256,
        result.cert_file.display(),
        result.key_file.display(),
        result.pin_sha256,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::FromDer;

    #[test]
    fn generates_valid_pair_sans_pin_permissions_and_sample_config() {
        let directory = tempfile::tempdir().unwrap();
        let cert_file = directory.path().join("server.crt");
        let key_file = directory.path().join("server.key");
        let result = generate(&CertOptions {
            hosts: "example.com,127.0.0.1,[::1],example.com".to_owned(),
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
            valid_for: Duration::from_secs(3600),
            overwrite: false,
        })
        .unwrap();
        crate::tls::server_config(&cert_file, &key_file, None, "disable").unwrap();

        let certificates = crate::tls::read_certificates(&cert_file).unwrap();
        let expected_pin = format!("{:x}", Sha256::digest(certificates[0].as_ref()));
        assert_eq!(result.pin_sha256, expected_pin);
        let (_, parsed) =
            x509_parser::certificate::X509Certificate::from_der(certificates[0].as_ref()).unwrap();
        let names = parsed.subject_alternative_name().unwrap().unwrap();
        assert!(names.value.general_names.iter().any(|name| matches!(
            name,
            x509_parser::extensions::GeneralName::DNSName("example.com")
        )));
        assert!(names.value.general_names.iter().any(|name| matches!(
            name,
            x509_parser::extensions::GeneralName::IPAddress(bytes) if *bytes == [127, 0, 0, 1]
        )));
        assert!(names.value.general_names.iter().any(|name| matches!(
            name,
            x509_parser::extensions::GeneralName::IPAddress(bytes) if bytes.len() == 16
        )));

        let output = format_result(&result);
        assert!(output.contains("# server.yaml"));
        assert!(output.contains("sniGuard: disable"));
        assert!(output.contains(&format!("pinSHA256: {expected_pin}")));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(cert_file).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert_eq!(
                fs::metadata(key_file).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn refuses_overwrite_without_flag_and_accepts_it_with_flag() {
        let directory = tempfile::tempdir().unwrap();
        let cert_file = directory.path().join("server.crt");
        let key_file = directory.path().join("server.key");
        fs::write(&cert_file, b"old certificate").unwrap();
        fs::write(&key_file, b"old key").unwrap();
        let mut options = CertOptions {
            hosts: "localhost".to_owned(),
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
            valid_for: Duration::from_secs(3600),
            overwrite: false,
        };
        assert!(
            generate(&options)
                .unwrap_err()
                .to_string()
                .contains("already exists")
        );
        assert_eq!(fs::read(&cert_file).unwrap(), b"old certificate");
        assert_eq!(fs::read(&key_file).unwrap(), b"old key");

        options.overwrite = true;
        generate(&options).unwrap();
        crate::tls::server_config(&cert_file, &key_file, None, "disable").unwrap();
    }

    #[test]
    fn rejects_empty_entries_ports_and_same_output_path() {
        assert!(parse_hosts("example.com,").is_err());
        assert!(parse_hosts("example.com:443").is_err());
        let path = PathBuf::from("same.pem");
        assert!(
            generate(&CertOptions {
                hosts: "localhost".to_owned(),
                cert_file: path.clone(),
                key_file: path,
                valid_for: Duration::from_secs(1),
                overwrite: false,
            })
            .is_err()
        );
    }
}
