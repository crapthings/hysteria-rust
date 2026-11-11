/// Implements offline configuration validation and its versioned output contract.
mod check;
/// Defines command syntax independently of execution.
mod cli;
/// Formats offline deployment diagnostics.
mod doctor_cli;
/// Generates starter configurations without starting a server.
mod init;
/// Installs platform-specific graceful service termination handlers.
mod shutdown;

use clap::Parser;
use cli::{Cli, Command};
use hysteria_cli::{
    Result,
    config::{ClientConfig, ServerConfig},
    runtime::{ping, serve_client, serve_server, speed_tests},
};
use std::process::ExitCode;

/// Runs the independent CLI and reports command-specific exit status.
#[tokio::main]
async fn main() -> ExitCode {
    let mut args: Vec<_> = std::env::args_os().collect();
    if args.len() == 1 {
        args.push("help".into());
    }
    let cli = Cli::parse_from(args);
    let diagnostic = cli.diagnostic;
    match run(cli).await {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{}", error.report(diagnostic));
            ExitCode::FAILURE
        }
    }
}

/// Dispatches one command while keeping runtime failures distinct from validation failures.
async fn run(cli: Cli) -> Result<ExitCode> {
    let update_checks = !cli.disable_update_check;
    let result = match cli.command.unwrap_or(Command::Client) {
        Command::Check(options) => return options.run(&cli.config, cli.diagnostic),
        Command::Doctor(options) => return options.run(&cli.config),
        Command::Init(options) => options.run(&cli.config, false),
        Command::Guide(options) => options.run(&cli.config, true),
        Command::Client => {
            serve_client(
                ClientConfig::load(&cli.config)?,
                shutdown::signal()?,
                update_checks,
            )
            .await
        }
        Command::Server => {
            serve_server(
                ServerConfig::load(&cli.config)?,
                shutdown::signal()?,
                update_checks,
            )
            .await
        }
        Command::Version => {
            println!("Hysteria 2 Rust {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Ping { address } => {
            let elapsed = ping(ClientConfig::load(&cli.config)?, &address).await?;
            println!(
                "connected to {address} in {}",
                humantime::format_duration(elapsed)
            );
            Ok(())
        }
        Command::Speedtest {
            skip_download,
            skip_upload,
            data_size,
            duration,
            use_bytes,
        } => {
            run_speedtest(
                ClientConfig::load(&cli.config)?,
                data_size,
                &duration,
                !skip_download,
                !skip_upload,
                use_bytes,
            )
            .await
        }
        Command::Share { notext, qr } => {
            let uri = ClientConfig::load(&cli.config)?.share_uri()?;
            if !notext {
                println!("{uri}");
            }
            if qr {
                let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|error| {
                    hysteria_cli::CliError::new(format!("failed to encode QR code: {error}"))
                })?;
                println!(
                    "{}",
                    code.render::<qrcode::render::unicode::Dense1x2>()
                        .quiet_zone(true)
                        .build()
                );
            }
            Ok(())
        }
        Command::CheckUpdate => print_update().await,
        Command::Cert {
            host,
            cert,
            key,
            valid_for,
            overwrite,
        } => {
            let valid_for = humantime::parse_duration(&valid_for).map_err(|error| {
                hysteria_cli::CliError::new(format!("invalid --valid-for: {error}"))
            })?;
            let result = hysteria_cli::cert::generate(&hysteria_cli::cert::CertOptions {
                hosts: host,
                cert_file: cert,
                key_file: key,
                valid_for,
                overwrite,
            })?;
            print!("{}", hysteria_cli::cert::format_result(&result));
            Ok(())
        }
    };
    result.map(|()| ExitCode::SUCCESS)
}

/// Runs the existing speed-test workflow and formats its measurements.
async fn run_speedtest(
    config: ClientConfig,
    data_size: Option<u32>,
    duration: &str,
    download: bool,
    upload: bool,
    use_bytes: bool,
) -> Result<()> {
    let duration = humantime::parse_duration(duration)
        .map_err(|error| hysteria_cli::CliError::new(format!("invalid --duration: {error}")))?;
    let (download, upload) = speed_tests(config, data_size, duration, download, upload).await?;
    if let Some(result) = download {
        println!("download: {}", format_speed(result, use_bytes));
    }
    if let Some(result) = upload {
        println!("upload: {}", format_speed(result, use_bytes));
    }
    Ok(())
}

/// Prints the update service response without changing installed binaries.
async fn print_update() -> Result<()> {
    let response = hysteria_cli::update::check_update().await?;
    if response.has_update {
        println!(
            "update available: {} ({})",
            response.latest_version, response.url
        );
    } else {
        println!("no update available");
    }
    Ok(())
}

/// Formats a throughput measurement in decimal bits or bytes per second.
#[allow(clippy::cast_precision_loss)]
fn format_speed(result: hysteria_cli::runtime::SpeedTestResult, use_bytes: bool) -> String {
    let mut speed = result.bytes as f64 / result.elapsed.as_secs_f64().max(f64::EPSILON);
    let units = if use_bytes {
        ["B/s", "KB/s", "MB/s", "GB/s"]
    } else {
        speed *= 8.0;
        ["bps", "Kbps", "Mbps", "Gbps"]
    };
    let mut unit = 0;
    while speed > 1000.0 && unit < units.len() - 1 {
        speed /= 1000.0;
        unit += 1;
    }
    format!(
        "{speed:.2} {} ({} bytes in {})",
        units[unit],
        result.bytes,
        humantime::format_duration(result.elapsed)
    )
}
