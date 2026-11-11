//! Offline deployment diagnostics with an explicit, bounded client connection probe.
use crate::{
    Result,
    config::{ClientConfig, ServerConfig},
};
use serde::Serialize;
use std::{fs::File, path::Path};
use x509_parser::prelude::FromDer;

/// A versioned diagnostic report. Passing checks does not establish full runtime readiness.
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
    pub(crate) fn add(
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

/// Optional explicit remote targets. These probes bypass client routing to test the server.
#[derive(Default)]
pub struct ForwardProbes {
    pub tcp: Option<String>,
    pub udp_echo: Option<String>,
}

/// Inspects client inputs offline, optionally attempting a bounded authenticated connection.
/// No local proxy listener, TUN, system proxy or route configuration is started.
pub async fn client(path: &Path, connect: bool, timeout: std::time::Duration) -> Report {
    client_with_probes(path, connect, timeout, &ForwardProbes::default()).await
}

/// Runs client diagnostics with opt-in TCP connect and UDP echo targets.
/// All network phases share one deadline; no local listeners or host networking are changed.
pub async fn client_with_probes(
    path: &Path,
    connect: bool,
    timeout: std::time::Duration,
    probes: &ForwardProbes,
) -> Report {
    let mut report = Report {
        schema_version: 1,
        mode: "client",
        passed: true,
        checks: Vec::new(),
    };
    let config = match ClientConfig::load(path) {
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
    if config.validate().is_err() {
        report.add(
            "configuration_validate",
            "fail",
            "Invalid client settings",
            "Run check client to identify the configuration field; no network request was made.",
        );
        return report;
    }
    report.add(
        "configuration_validate",
        "pass",
        "Semantic configuration checks passed",
        "",
    );
    if !config.server.starts_with("realm:") && !config.server.starts_with("realm+http:") {
        if crate::runtime::check_client_address(&config.server).is_ok() {
            report.add(
                "server_address",
                "pass",
                "Server address syntax accepted",
                "DNS is not queried offline.",
            );
        } else {
            report.add(
                "server_address",
                "fail",
                "Invalid server hostname, IP address or ports",
                "Use hostname:port or [IPv6]:port; port hopping uses comma-separated ports/ranges.",
            );
        }
    }
    client_local_checks(&mut report, &config);
    if connect && report.passed {
        client_network_checks(&mut report, &config, timeout, probes).await;
    } else {
        report.add(
            "server_resolution",
            "skip",
            "Server address resolution was not attempted",
            "Use --connect to opt into network diagnosis.",
        );
        report.add(
            "server_connection",
            "skip",
            "Remote connection was not tested",
            "Use doctor client --connect after offline checks pass.",
        );
    }
    for id in [
        "quic_tls",
        "hysteria_auth",
        "tcp_forwarding",
        "udp_forwarding",
    ] {
        if !report.checks.iter().any(|check| check.id == id) {
            report.add(id, "skip", "Not attempted", "Active checks require --connect and successful preceding phases; forwarding also requires an explicit target.");
        }
    }
    report.add(
        "forwarding",
        "skip",
        "Local proxy binding and system integration were not tested",
        "Only explicit forwarding targets are tested. No system proxy, routes or DNS were changed.",
    );
    report
}

fn client_local_checks(report: &mut Report, config: &ClientConfig) {
    if config.server.starts_with("realm+http:") || config.realm.insecure {
        report.add("realm_security", "warn", "Rendezvous transport is plaintext or its certificate verification is disabled", "Prefer realm:// with normal rendezvous verification; tls.insecure controls a separate proxy TLS connection.");
    }
    if let Some(tun) = &config.tun {
        crate::tun_diagnostics::inspect(report, tun);
    }
    let ca = (!config.tls.ca.is_empty()).then(|| Path::new(&config.tls.ca));
    let pin = (!config.tls.pin_sha256.is_empty())
        .then(|| crate::config::normalize_certificate_pin(&config.tls.pin_sha256))
        .transpose();
    let identity = (!config.tls.client_certificate.is_empty()).then(|| {
        (
            Path::new(&config.tls.client_certificate),
            Path::new(&config.tls.client_key),
        )
    });
    let material = pin.and_then(|pin| {
        crate::tls::client_config(
            ca,
            config.tls.insecure,
            pin,
            identity,
            (!config.tls.ech.is_empty()).then_some(config.tls.ech.as_str()),
        )
    });
    if material.is_ok() {
        report.add(
            "tls_material",
            "pass",
            "Local TLS trust, client identity and ECH inputs accepted",
            "Remote certificate validity is not established by this check.",
        );
    } else {
        report.add("tls_material", "fail", "Local TLS material could not be loaded", "Check CA/client certificate/private key/ECH files and the system trust store; paths use the working directory.");
    }
    if config.tls.insecure {
        report.add(
            "tls_verification",
            "warn",
            "Certificate verification is disabled (an explicit pin may still apply)",
            "Prefer normal CA verification; review tls.insecure and tls.pinSHA256.",
        );
    }
    let mut addresses = std::collections::HashSet::new();
    for (id, address) in [
        (
            "socks5_listener",
            config.socks5.as_ref().map(|p| p.listen.as_str()),
        ),
        (
            "http_listener",
            config.http.as_ref().map(|p| p.listen.as_str()),
        ),
    ] {
        if let Some(address) = address {
            if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
                if socket.port() != 0 && !addresses.insert(socket) {
                    report.add(
                        id,
                        "fail",
                        "Local proxy listeners use the same TCP address",
                        "Choose distinct local ports.",
                    );
                } else if socket.ip().is_loopback() {
                    report.add(
                        id,
                        "pass",
                        "Configured to listen on loopback",
                        "Port availability is not checked offline.",
                    );
                } else {
                    report.add(
                        id,
                        "warn",
                        "Proxy listener is not restricted to loopback",
                        "Review authentication, bind address and firewall before starting.",
                    );
                }
            } else {
                report.add(
                    id,
                    "skip",
                    "Listener is not a numeric socket address",
                    "Name resolution and binding are deferred to runtime.",
                );
            }
        }
    }
}

async fn client_network_checks(
    report: &mut Report,
    config: &ClientConfig,
    timeout: std::time::Duration,
    probes: &ForwardProbes,
) {
    let realm = config.server.starts_with("realm:") || config.server.starts_with("realm+http:");
    if (realm && config.realm.port_mapping.enabled)
        || !config.quic.sockopts.fd_control_unix_socket.is_empty()
    {
        report.add(
            "server_connection",
            "fail",
            "Active diagnosis refuses enabled router port mapping or external socket control",
            "Disable realm.portMapping.enabled for diagnosis; external FD control is not supported.",
        );
    } else {
        let mut progress = crate::runtime::ProbeProgress::default();
        let result = tokio::time::timeout(
            timeout,
            crate::runtime::probe_client(config, &mut progress, probes),
        )
        .await;
        if realm {
            for (stage, id, label) in [
                (1, "realm_stun", "STUN discovery"),
                (2, "realm_rendezvous", "Rendezvous introduction"),
                (3, "realm_punch", "UDP hole punching"),
            ] {
                let status = match progress.realm_stage.cmp(&stage) {
                    std::cmp::Ordering::Greater => "pass",
                    std::cmp::Ordering::Equal => "fail",
                    std::cmp::Ordering::Less => "skip",
                };
                report.add(id, status, label, if status == "fail" { "This phase did not complete; a timeout does not establish a specific NAT or authentication cause." } else { "" });
            }
        } else {
            report.add(
                "server_resolution",
                if progress.resolved { "pass" } else { "fail" },
                if progress.resolved {
                    "Server address resolved"
                } else {
                    "Server address resolution did not complete"
                },
                "This does not establish server reachability.",
            );
        }
        if !progress.resolved {
            if realm && progress.realm_stage == 0 {
                report.add(
                    "realm_socket",
                    "fail",
                    "Realm socket preparation did not complete",
                    "Check local bind options and permissions.",
                );
            }
            report.add(
                "server_connection",
                "skip",
                "QUIC/TLS and Hysteria authentication were not attempted",
                "Resolve the preceding failure first.",
            );
            return;
        }
        connection_checks(report, &progress, &result);
        for (id, requested, started, passed, hint) in [
            (
                "tcp_forwarding",
                probes.tcp.is_some(),
                progress.tcp.is_some(),
                progress.tcp == Some(true),
                "Check the target listener and server ACL/egress. A TCP connect does not verify the application protocol.",
            ),
            (
                "udp_forwarding",
                probes.udp_echo.is_some(),
                progress.udp.is_some(),
                progress.udp == Some(true),
                "Use a UDP echo target you control; check server UDP support, ACL and target reachability. Timeout alone cannot identify the failing hop.",
            ),
        ] {
            report.add(
                id,
                if !requested || !started {
                    "skip"
                } else if passed {
                    "pass"
                } else {
                    "fail"
                },
                if !requested {
                    "No explicit target supplied"
                } else if !started {
                    "Not attempted before the preceding failure or deadline"
                } else if passed {
                    "Remote forwarding probe completed"
                } else {
                    "Remote forwarding probe did not complete"
                },
                hint,
            );
        }
    }
}

fn connection_checks(
    report: &mut Report,
    progress: &crate::runtime::ProbeProgress,
    result: &std::result::Result<Result<(bool, bool)>, tokio::time::error::Elapsed>,
) {
    report.add("quic_tls", if progress.tls_completed { "pass" } else { "fail" },
        if progress.tls_completed { "QUIC/TLS handshake completed with configured trust policy" } else { "QUIC/TLS handshake did not complete" },
        if progress.tls_completed { "" } else { "Check local socket permissions, UDP reachability, obfuscation, certificate trust and SNI. QUIC and TLS share this phase; a timeout does not identify the cause." });
    report.add("hysteria_auth", if progress.connection.is_some() { "pass" } else if progress.tls_completed { "fail" } else { "skip" },
        if progress.connection.is_some() { "Hysteria HTTP/3 authentication completed" } else { "Hysteria authentication did not complete" },
        if progress.tls_completed && progress.connection.is_none() { "Check credentials and Hysteria server compatibility. An HTTP/3 failure or timeout is not proof of a wrong password." } else { "" });
    if progress.connection.is_some() {
        report.add(
            "server_connection",
            "pass",
            format!(
                "Server authenticated; UDP advertised: {}; ECH accepted: {}",
                progress.connection.unwrap_or_default().0,
                progress.connection.unwrap_or_default().1
            ),
            "UDP advertisement alone does not prove UDP forwarding.",
        );
    } else {
        let code = match result {
            Ok(Err(error)) => error.code().as_str(),
            Err(_) => "timeout",
            _ => "connection_failed",
        };
        report.add(
            "server_connection",
            "fail",
            if result.is_err() {
                "Connection probe timed out; cause is unknown".to_owned()
            } else {
                format!("Connection did not complete ({code})")
            },
            "Review the first failed phase above.",
        );
    }
}
