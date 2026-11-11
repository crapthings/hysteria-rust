//! Offline deployment diagnostics; no listeners, network requests or runtime startup.
use crate::{Result, config::ServerConfig};
use serde::Serialize;
use std::{fs::File, path::Path};
use x509_parser::prelude::FromDer;

/// A versioned offline report. Passing checks does not establish runtime readiness.
#[derive(Serialize)]
pub struct Report {
    pub schema_version: u8,
    pub mode: &'static str,
    pub passed: bool,
    pub checks: Vec<Check>,
}

/// One diagnostic with a stable identifier and status, plus human-readable guidance.
#[derive(Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: &'static str,
    pub message: String,
    pub hint: &'static str,
}

impl Report {
    fn add(
        &mut self,
        id: &'static str,
        status: &'static str,
        message: impl Into<String>,
        hint: &'static str,
    ) {
        self.passed &= status != "fail";
        self.checks.push(Check {
            id,
            status,
            message: message.into(),
            hint,
        });
    }

    fn result(
        &mut self,
        id: &'static str,
        result: Result<()>,
        success: &'static str,
        hint: &'static str,
    ) {
        match result {
            Ok(()) => self.add(id, "pass", success, ""),
            Err(error) => self.add(id, "fail", error.to_string(), hint),
        }
    }
}

/// Inspects server configuration and local TLS material without starting the server.
#[must_use]
pub fn server(path: &Path) -> Report {
    let mut report = Report {
        schema_version: 1,
        mode: "server",
        passed: true,
        checks: Vec::new(),
    };
    let config = match ServerConfig::load(path) {
        Ok(config) => {
            report.add("configuration_read", "pass", "Configuration parsed", "");
            config
        }
        Err(error) => {
            report.add(
                "configuration_read",
                "fail",
                error.to_string(),
                "Check the configuration path and YAML/JSON schema.",
            );
            return report;
        }
    };
    report.result(
        "configuration_validate",
        config.validate(),
        "Semantic configuration checks passed",
        "Correct the reported configuration field and run doctor again.",
    );
    if let Some(acme) = &config.acme {
        let hint = match acme.kind.as_str() {
            "dns" => {
                "Verify DNS provider credentials and permission to create challenge records; certificate issuance requires network access."
            }
            "http" => {
                "Point domain DNS at this server and allow public TCP 80 to reach the HTTP challenge listener."
            }
            "tls" => {
                "Point domain DNS at this server and allow public TCP 443 to reach the TLS-ALPN challenge listener."
            }
            _ => {
                "Verify domain DNS and enabled HTTP/TLS-ALPN challenge reachability (public TCP 80/443), including any alternate-port forwarding."
            }
        };
        report.add("acme_issuance", "skip", "ACME DNS, challenge reachability, account storage and issuance are not verified offline", hint);
    } else if !config.tls.cert.is_empty() && !config.tls.key.is_empty() {
        let ca = (!config.tls.client_ca.is_empty()).then(|| Path::new(&config.tls.client_ca));
        report.result("tls_material", crate::tls::server_config(Path::new(&config.tls.cert), Path::new(&config.tls.key), ca, &config.tls.sni_guard).map(|_| ()), "Certificate, private key and configured client CA accepted by the TLS loader", "Check readable PEM files, matching certificate/private key and client CA configuration; paths are relative to the working directory.");
        check_validity(&mut report, Path::new(&config.tls.cert));
    } else {
        report.add(
            "tls_material",
            "skip",
            "TLS file checks require both certificate and key paths",
            "Configure tls.cert and tls.key, or ACME.",
        );
    }
    if let Some(ech) = &config.ech {
        report.result(
            "ech_material",
            crate::server_ech::load(Path::new(&ech.key_path)).map(|_| ()),
            "ECH key material parsed",
            "Provide a readable, valid ECH key file.",
        );
    }
    for (id, path) in [
        ("acl_file", config.acl.file.as_str()),
        ("geoip_file", config.acl.geoip.as_str()),
        ("geosite_file", config.acl.geosite.as_str()),
    ] {
        if !path.is_empty() {
            report.result(id, File::open(path).and_then(|file| {
                if file.metadata()?.is_file() { Ok(()) } else { Err(std::io::Error::other("expected a regular file")) }
            }).map_err(Into::into), "Referenced local file is readable (content validity is not established by this check)", "Check the configured path and read permissions; doctor does not download missing files.");
        }
    }
    report.add("runtime_readiness", "skip", "Port availability, bind permissions, firewall, public DNS, client trust and remote services are not verified offline", "Review these deployment conditions separately; doctor does not bind ports or change system settings.");
    report
}

fn check_validity(report: &mut Report, path: &Path) {
    let result = crate::tls::read_certificates(path).and_then(|certs| {
        let mut remaining = i64::MAX;
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        for der in &certs {
            let (_, cert) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
                .map_err(|_| crate::CliError::new("invalid X.509 certificate"))?;
            if cert.validity().not_before.timestamp() > now {
                return Err(crate::CliError::new(
                    "certificate chain contains a certificate that is not yet valid",
                ));
            }
            remaining = remaining.min(cert.validity().not_after.timestamp() - now);
        }
        Ok(remaining)
    });
    match result {
        Err(error) => report.add(
            "tls_validity",
            "fail",
            error.to_string(),
            "Check certificate files, validity dates and the system clock.",
        ),
        Ok(seconds) if seconds <= 0 => report.add(
            "tls_validity",
            "fail",
            "Certificate chain contains an expired certificate",
            "Renew the certificate and install the updated chain.",
        ),
        Ok(seconds) if seconds <= 30 * 86400 => report.add(
            "tls_validity",
            "warn",
            format!("Certificate chain expires in {} days", seconds / 86400),
            "Renew the certificate soon.",
        ),
        Ok(_) => report.add(
            "tls_validity",
            "pass",
            "Certificate chain dates are valid for more than 30 days",
            "",
        ),
    }
}
