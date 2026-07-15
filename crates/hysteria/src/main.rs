use clap::{Parser, Subcommand};
use hysteria_cli::{
    Result,
    config::{ClientConfig, ServerConfig},
    runtime::{ping, serve_client, serve_server, speed_tests},
};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "hysteria",
    version,
    about = "Hysteria 2 client and server in Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(short, long, default_value = "config.yaml", global = true)]
    config: PathBuf,
    #[arg(
        long,
        global = true,
        env = "HYSTERIA_DISABLE_UPDATE_CHECK",
        default_value_t = false
    )]
    disable_update_check: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    Client,
    Server,
    Version,
    Ping {
        address: String,
    },
    Speedtest {
        #[arg(long)]
        skip_download: bool,
        #[arg(long)]
        skip_upload: bool,
        #[arg(long)]
        data_size: Option<u32>,
        #[arg(long, default_value = "10s")]
        duration: String,
        #[arg(long)]
        use_bytes: bool,
    },
    Share {
        #[arg(long)]
        notext: bool,
        #[arg(long)]
        qr: bool,
    },
    CheckUpdate,
    Cert {
        #[arg(long, default_value_t = hysteria_cli::cert::default_host())]
        host: String,
        #[arg(long, default_value = "server.crt")]
        cert: PathBuf,
        #[arg(long, default_value = "server.key")]
        key: PathBuf,
        #[arg(long, default_value = "365d")]
        valid_for: String,
        #[arg(long)]
        overwrite: bool,
    },
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let update_checks = !cli.disable_update_check;
    match cli.command.unwrap_or(Command::Client) {
        Command::Client => {
            serve_client(
                ClientConfig::load(&cli.config)?,
                shutdown_signal(),
                update_checks,
            )
            .await
        }
        Command::Server => {
            serve_server(
                ServerConfig::load(&cli.config)?,
                shutdown_signal(),
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
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

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

async fn print_update() -> Result<()> {
    let response = hysteria_cli::update::check_update().await?;
    if response.has_update {
        println!(
            "update available: {} ({}){}",
            response.latest_version,
            response.url,
            if response.urgent { " [urgent]" } else { "" }
        );
    } else {
        println!("no update available");
    }
    Ok(())
}

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
