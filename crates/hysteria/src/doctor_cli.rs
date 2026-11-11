use clap::{Args, ValueEnum};
use hysteria_cli::{CliError, Result};
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Mode {
    Server,
}

/// Runs offline deployment diagnostics with text or versioned JSON output.
#[derive(Debug, Args)]
pub(crate) struct DoctorOptions {
    /// Deployment role to inspect (currently server only).
    #[arg(value_enum)]
    mode: Mode,
    /// Report format; JSON includes versioned check identifiers and statuses.
    #[arg(long, value_enum, default_value = "text")]
    output: crate::check::OutputFormat,
}

impl DoctorOptions {
    pub(crate) fn run(&self, path: &Path) -> Result<ExitCode> {
        let report = match self.mode {
            Mode::Server => hysteria_cli::doctor::server(path),
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
                for check in &report.checks {
                    writeln!(
                        stdout,
                        "[{}] {}: {}",
                        check.status.to_uppercase(),
                        check.id,
                        check.message
                    )?;
                    if !check.hint.is_empty() {
                        writeln!(stdout, "  {}", check.hint)?;
                    }
                }
                writeln!(
                    stdout,
                    "Offline checks {}. Skipped checks remain unverified.",
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
