/// Implements offline configuration validation and its versioned output contract.
mod check;
/// Defines command syntax independently of execution.
mod cli;
mod client_setup;
mod client_stdio;
/// Formats offline deployment diagnostics.
mod doctor_cli;
mod ech_cli;
/// Generates starter configurations without starting a server.
mod init;
mod profile;
mod routing_cli;
mod server_share;
mod server_view;
mod service;
/// Installs platform-specific graceful service termination handlers.
mod shutdown;

use clap::Parser;
use cli::{Cli, Command};
use hysteria_cli::{
    Result,
    config::{ClientConfig, ServerConfig},
    runtime::{ping, serve_client_observed, serve_server, speed_tests},
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
    // Command dispatch holds large role configurations; allocate its future once at startup.
    match Box::pin(run(cli)).await {
        Ok(status) => status,
        Err(error) => {
            eprintln!("{}", error.report(diagnostic));
            ExitCode::FAILURE
        }
    }
}

/// Dispatches one command while keeping runtime failures distinct from validation failures.
async fn run(mut cli: Cli) -> Result<ExitCode> {
    if cli.control.is_some() {
        if !matches!(cli.command, None | Some(Command::Client)) {
            return Err(hysteria_cli::CliError::new(
                "--control is supported only by client",
            ));
        }
        if cli.config == std::path::Path::new("-") {
            return Err(hysteria_cli::CliError::new(
                "--control stdio cannot read configuration from stdin; use a file or profile",
            ));
        }
    }
    select_profile(&mut cli)?;
    let update_checks = !cli.disable_update_check;
    if cli.events.is_some() && !matches!(cli.command, None | Some(Command::Client)) {
        return Err(hysteria_cli::CliError::new(
            "--events is supported only by client",
        ));
    }
    let result = match cli.command.unwrap_or(Command::Client) {
        Command::DnsLookup { name } => doctor_cli::dns_lookup_worker(&name),
        Command::Check(options) => return options.run(&cli.config, cli.diagnostic),
        Command::Doctor(options) => return options.run(&cli.config).await,
        Command::Init(options) => options.run(&cli.config, false),
        Command::Guide(options) => options.run(&cli.config, true),
        Command::Client => run_client(&cli.config, update_checks, cli.events, cli.control).await,
        Command::Server(options) => {
            if let Some(command) = options.command {
                return command.run(&cli.config).await.map(|()| ExitCode::SUCCESS);
            }
            serve_server(
                ServerConfig::load(&cli.config)?,
                shutdown::signal()?,
                update_checks,
            )
            .await
        }
        Command::Profile(options) => return options.run(),
        Command::Capabilities(options) => options.run(),
        Command::Route(options) => return options.run(&cli.config),
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
        Command::Share { notext, qr } => print_share(&cli.config, notext, qr),
        Command::CheckUpdate => print_update().await,
        Command::Ech(options) => options.run(),
        Command::Service(options) => options.run(&cli.config),
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

async fn run_client(
    path: &std::path::Path,
    update_checks: bool,
    events: Option<check::OutputFormat>,
    control: Option<client_stdio::ControlMode>,
) -> Result<()> {
    let config = ClientConfig::load(path)?;
    let signal = shutdown::signal()?;
    if control.is_some() {
        return client_stdio::run(config, update_checks, signal).await;
    }
    let events = match events {
        Some(check::OutputFormat::Json) => hysteria_cli::client_events::ClientEvents::json(),
        _ => hysteria_cli::client_events::ClientEvents::text(),
    };
    serve_client_observed(config, signal, update_checks, events).await
}

/// Resolves an explicit profile only for supported client commands.
fn select_profile(cli: &mut Cli) -> Result<()> {
    if let Some(name) = &cli.profile {
        let supported = match &cli.command {
            None
            | Some(
                Command::Client
                | Command::Ping { .. }
                | Command::Speedtest { .. }
                | Command::Share { .. },
            ) => true,
            Some(Command::Route(options)) => options.uses_config(),
            Some(Command::Check(options)) => options.is_client(),
            Some(Command::Doctor(options)) => options.is_client(),
            _ => false,
        };
        if !supported {
            return Err(hysteria_cli::CliError::new(
                "--profile is supported only by client, check client, doctor client, route explain/lint, ping, speedtest and share",
            ));
        }
        cli.config = profile::resolve(name)?;
    }
    Ok(())
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

fn print_share(path: &std::path::Path, notext: bool, qr: bool) -> Result<()> {
    let uri = ClientConfig::load(path)?.share_uri()?;
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
