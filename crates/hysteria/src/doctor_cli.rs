use clap::{Args, ValueEnum};
use hysteria_cli::{CliError, Result};
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
    process::ExitCode,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Server,
    Client,
}

/// Runs local diagnostics and optional client probes with text or versioned JSON output.
#[derive(Debug, Args)]
pub(crate) struct DoctorOptions {
    /// Deployment role to inspect.
    #[arg(value_enum)]
    mode: Mode,
    /// Attempt an authenticated server connection (client only; no proxy listeners).
    #[arg(long)]
    connect: bool,
    /// Resolve a fresh subdomain through system DNS and verify the active Linux Fake-IP cache.
    /// May consume one cache entry; does not start TUN or change DNS/routes.
    #[arg(long, value_name = "DOMAIN", conflicts_with_all = ["connect", "tcp", "udp_echo"], value_parser = probe_domain)]
    dns: Option<String>,
    /// Shared network deadline, 1s to 60s, including optional forwarding probes.
    #[arg(long, default_value = "10s", value_parser = probe_timeout)]
    timeout: std::time::Duration,
    /// Test a remote TCP connection through Hysteria (HOST:PORT; bypasses client routing).
    #[arg(long, requires = "connect", value_parser = probe_target)]
    tcp: Option<String>,
    /// Send a random payload to a UDP echo target you control and verify its reply.
    #[arg(long, requires = "connect", value_parser = probe_target)]
    udp_echo: Option<String>,
    /// Report format; JSON includes versioned check identifiers and statuses.
    #[arg(long, value_enum, default_value = "text")]
    output: crate::check::OutputFormat,
}

impl DoctorOptions {
    pub(crate) fn is_client(&self) -> bool {
        matches!(self.mode, Mode::Client)
    }
    pub(crate) async fn run(&self, path: &Path) -> Result<ExitCode> {
        if (self.connect || self.dns.is_some()) && matches!(self.mode, Mode::Server) {
            return Err(CliError::new(
                "--connect and --dns are supported only by doctor client",
            ));
        }
        let report = match self.mode {
            Mode::Server => hysteria_cli::doctor::server(path),
            Mode::Client if self.dns.is_some() => {
                let domain = self.dns.as_deref().unwrap_or_default();
                hysteria_cli::doctor::dns::client(
                    path,
                    domain,
                    self.timeout,
                    &std::env::current_exe()?,
                    crate::shutdown::signal()?,
                )
                .await
            }
            Mode::Client => {
                hysteria_cli::doctor::client_with_probes(
                    path,
                    self.connect,
                    self.timeout,
                    &hysteria_cli::doctor::ForwardProbes {
                        tcp: self.tcp.clone(),
                        udp_echo: self.udp_echo.clone(),
                    },
                )
                .await
            }
        };
        let mut stdout = io::stdout().lock();
        match self.output {
            crate::check::OutputFormat::Json => {
                serde_json::to_writer(&mut stdout, &report).map_err(|error| {
                    CliError::new(format!("failed to write doctor report: {error}"))
                })?;
                writeln!(stdout)?;
            }
            crate::check::OutputFormat::Text => {
                let width = report
                    .checks
                    .iter()
                    .map(|check| check.id.len())
                    .max()
                    .unwrap_or(0);
                let color = stdout.is_terminal()
                    && std::env::var_os("NO_COLOR").is_none()
                    && std::env::var("TERM").is_ok_and(|term| term != "dumb");
                for check in &report.checks {
                    let status = check.status.to_uppercase();
                    let status = if color {
                        let code = match check.status {
                            "pass" => 32,
                            "fail" => 31,
                            "warn" => 33,
                            _ => 90,
                        };
                        format!("\x1b[{code}m{status}\x1b[0m")
                    } else {
                        status
                    };
                    writeln!(stdout, "[{status}] {:<width$}  {}", check.id, check.message)?;
                    if !check.hint.is_empty() {
                        writeln!(stdout, "  {}", check.hint)?;
                    }
                }
                writeln!(
                    stdout,
                    "{} checks {}. Skipped checks remain unverified.",
                    if self.connect || self.dns.is_some() {
                        "Diagnostic"
                    } else {
                        "Offline"
                    },
                    if report.passed { "passed" } else { "failed" }
                )?;
            }
        }
        stdout.flush()?;
        Ok(if report.passed {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        })
    }
}

fn probe_timeout(value: &str) -> std::result::Result<std::time::Duration, String> {
    let duration = humantime::parse_duration(value).map_err(|_| "invalid timeout".to_owned())?;
    if !(std::time::Duration::from_secs(1)..=std::time::Duration::from_secs(60)).contains(&duration)
    {
        return Err("timeout must be between 1s and 60s".into());
    }
    Ok(duration)
}

fn probe_target(value: &str) -> std::result::Result<String, String> {
    let config = hysteria_cli::routing::RoutingConfig {
        rule_sets: std::collections::BTreeMap::new(),
        version: 1,
        default: hysteria_cli::routing::Action::Proxy,
        rules: vec![],
    };
    hysteria_cli::routing::Router::compile(&config)
        .and_then(|router| router.decide(value, hysteria_cli::routing::Protocol::Tcp))
        .map_err(|_| {
            "expected a hostname/IP and nonzero port; bracket IPv6 addresses".to_owned()
        })?;
    Ok(value.to_owned())
}

fn probe_domain(value: &str) -> std::result::Result<String, String> {
    hysteria_cli::doctor::dns::domain(value).map_err(|error| error.to_string())
}

pub(crate) fn dns_lookup_worker(name: &str) -> Result<()> {
    let reply = hysteria_cli::doctor::dns::lookup_worker(name);
    serde_json::to_writer(io::stdout().lock(), &reply)
        .map_err(|_| CliError::new("could not write DNS worker reply"))
}
