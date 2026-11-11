use clap::{Args, ValueEnum};
use hysteria_cli::{
    CliError, Result,
    config::{ClientConfig, ServerConfig},
};
use serde::Serialize;
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

/// Chooses which role's configuration schema and existing semantic validators to check.
#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum CheckMode {
    Client,
    Server,
}

/// Selects human-readable output or one versioned JSON document on stdout.
#[derive(Clone, Copy, Debug, Default, ValueEnum)]
pub(crate) enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Defines a bounded, offline configuration check independently of daemon startup.
#[derive(Debug, Args)]
pub(crate) struct CheckOptions {
    /// Configuration role to validate; never inferred from file contents.
    #[arg(value_enum)]
    mode: CheckMode,
    /// Output format; JSON reports `schema_version`, mode, valid and an optional error.
    #[arg(long, value_enum, default_value = "text")]
    output: OutputFormat,
}

/// Records a check result without serializing credentials or the input configuration.
#[derive(Serialize)]
struct CheckReport {
    schema_version: u8,
    mode: CheckMode,
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<CheckError>,
}

/// Provides a stable validation error code alongside the existing validation diagnostic.
#[derive(Serialize)]
struct CheckError {
    code: &'static str,
    message: String,
    detail_code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    causes: Vec<String>,
}

/// Loads and validates configuration without invoking runtime listeners, DNS queries or update checks.
impl CheckOptions {
    pub(crate) fn is_client(&self) -> bool {
        matches!(self.mode, CheckMode::Client)
    }
    pub(crate) fn run(&self, path: &Path, diagnostic: bool) -> Result<ExitCode> {
        let result = match self.mode {
            CheckMode::Client => ClientConfig::load(path).and_then(|config| config.validate()),
            CheckMode::Server => ServerConfig::load(path).and_then(|config| config.validate()),
        };
        let report = CheckReport {
            schema_version: 1,
            mode: self.mode,
            valid: result.is_ok(),
            error: result
                .err()
                .map(CliError::configuration)
                .map(|error| CheckError {
                    detail_code: error.code().as_str(),
                    hint: error.hint(),
                    causes: if diagnostic {
                        error.causes()
                    } else {
                        Vec::new()
                    },
                    code: "configuration_invalid",
                    message: error.to_string(),
                }),
        };
        self.write(&report)?;
        Ok(if report.valid {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        })
    }

    fn write(&self, report: &CheckReport) -> Result<()> {
        match self.output {
            OutputFormat::Json => {
                let mut stdout = io::stdout().lock();
                serde_json::to_writer(&mut stdout, report).map_err(|error| {
                    CliError::new(format!("failed to write check report: {error}"))
                })?;
                writeln!(stdout)?;
            }
            OutputFormat::Text => {
                if let Some(error) = &report.error {
                    let mut stderr = io::stderr().lock();
                    writeln!(stderr, "error: {} [{}]", error.message, error.detail_code)?;
                    if let Some(hint) = error.hint {
                        writeln!(stderr, "  hint: {hint}")?;
                    }
                    for cause in &error.causes {
                        writeln!(stderr, "  caused by: {cause}")?;
                    }
                } else {
                    let mode = match report.mode {
                        CheckMode::Client => "client",
                        CheckMode::Server => "server",
                    };
                    writeln!(io::stdout().lock(), "{mode} configuration is valid")?;
                }
            }
        }
        Ok(())
    }
}
