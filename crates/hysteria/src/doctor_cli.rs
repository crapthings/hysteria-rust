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
    /// Connection probe deadline, 1s to 60s; applies only with --connect.
    #[arg(long, default_value = "10s", value_parser = probe_timeout)]
    timeout: std::time::Duration,
    /// Report format; JSON includes versioned check identifiers and statuses.
    #[arg(long, value_enum, default_value = "text")]
    output: crate::check::OutputFormat,
}

impl DoctorOptions {
    pub(crate) async fn run(&self, path: &Path) -> Result<ExitCode> {
        if self.connect && matches!(self.mode, Mode::Server) {
            return Err(CliError::new(
                "--connect is supported only by doctor client",
            ));
        }
        let report = match self.mode {
            Mode::Server => hysteria_cli::doctor::server(path),
            Mode::Client => hysteria_cli::doctor::client(path, self.connect, self.timeout).await,
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
                    if self.connect {
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
