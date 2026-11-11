//! Read-only local server monitoring commands and terminal presentation.
use crate::check::OutputFormat;
use clap::{Args, Subcommand, ValueEnum};
use hysteria_cli::{
    CliError, Result,
    config::ServerConfig,
    status::{ServerState, ServerStatus},
};
use serde::Serialize;
use std::{
    fmt::Write as _,
    io::{self, IsTerminal, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::Duration,
};

#[derive(Debug, Args)]
pub(crate) struct ServerOptions {
    #[command(subcommand)]
    pub(crate) command: Option<ServerCommand>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ServerCommand {
    /// Export one standard client link offline (contains credentials).
    #[command(display_order = 30)]
    Share(crate::server_share::Options),
    /// Show readiness, uptime and local listeners of the running server.
    #[command(display_order = 10)]
    Status(ViewOptions),
    /// Show aggregate connections and payload traffic (samples for two seconds).
    #[command(display_order = 20)]
    Stats(ViewOptions),
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum Color {
    #[default]
    Auto,
    Always,
    Never,
}

#[derive(Debug, Args)]
pub(crate) struct ViewOptions {
    /// Refresh until Ctrl+C or SIGTERM; redirected JSON is newline-delimited.
    #[arg(long)]
    watch: bool,
    /// Refresh/sample interval, between 1s and 1h.
    #[arg(long, default_value = "2s", value_parser = parse_interval)]
    interval: Duration,
    /// Human-readable text or schema-versioned JSON.
    #[arg(long, value_enum, default_value = "text")]
    output: OutputFormat,
    /// Highlight text; auto respects `NO_COLOR`, `TERM=dumb` and redirected stdout.
    #[arg(long, value_enum, default_value = "auto")]
    color: Color,
}

fn parse_interval(value: &str) -> std::result::Result<Duration, String> {
    let value = humantime::parse_duration(value).map_err(|error| error.to_string())?;
    if !(Duration::from_secs(1)..=Duration::from_secs(3600)).contains(&value) {
        return Err("interval must be between 1s and 1h".into());
    }
    Ok(value)
}

#[derive(Debug, Serialize)]
struct Rates {
    sample_seconds: f64,
    upload_bytes_per_second: f64,
    download_bytes_per_second: f64,
}

#[derive(Serialize)]
struct Report<'a> {
    #[serde(flatten)]
    status: &'a ServerStatus,
    rates: Option<Rates>,
}

fn rates(previous: &ServerStatus, current: &ServerStatus) -> Option<Rates> {
    if previous.instance_id != current.instance_id {
        return None;
    }
    let elapsed = current.uptime_ms.checked_sub(previous.uptime_ms)?;
    if elapsed == 0 {
        return None;
    }
    let uploaded = current.upload_bytes.checked_sub(previous.upload_bytes)?;
    let downloaded = current
        .download_bytes
        .checked_sub(previous.download_bytes)?;
    #[allow(clippy::cast_precision_loss)]
    // Display rates are approximate; JSON totals stay integer.
    let (seconds, uploaded, downloaded) =
        (elapsed as f64 / 1000.0, uploaded as f64, downloaded as f64);
    Some(Rates {
        sample_seconds: seconds,
        upload_bytes_per_second: uploaded / seconds,
        download_bytes_per_second: downloaded / seconds,
    })
}

fn local_address(listen: &str) -> Result<SocketAddr> {
    let listen = if let Some(port) = listen.strip_prefix(':') {
        format!("127.0.0.1:{port}")
    } else if let Some(port) = listen.strip_prefix("localhost:") {
        format!("127.0.0.1:{port}")
    } else {
        listen.to_owned()
    };
    let mut address: SocketAddr = listen.parse().map_err(|_| {
        CliError::new(
            "trafficStats.listen must be a local IP address and port (for example 127.0.0.1:9999)",
        )
    })?;
    if address.ip().is_unspecified() {
        address.set_ip(if address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(CliError::new(
            "status commands require a loopback statistics address and a nonzero port",
        ));
    }
    Ok(address)
}

struct Monitor {
    client: reqwest::Client,
    url: String,
    secret: reqwest::header::HeaderValue,
}

impl Monitor {
    fn new(config: &ServerConfig) -> Result<Self> {
        let stats = &config.traffic_stats;
        if stats.listen.is_empty() || stats.secret.is_empty() {
            return Err(CliError::new(
                "local monitoring requires trafficStats.listen and a nonempty trafficStats.secret; configure a loopback address such as 127.0.0.1:9999 and a separate random secret, then restart the server",
            ));
        }
        let address = local_address(&stats.listen)?;
        let mut secret = reqwest::header::HeaderValue::from_str(&stats.secret)
            .map_err(|_| CliError::new("trafficStats.secret is not a valid HTTP header value"))?;
        secret.set_sensitive(true);
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(3))
            .build()
            .map_err(|_| CliError::new("failed to create local monitoring client"))?;
        Ok(Self {
            client,
            url: format!("http://{address}/v1/status"),
            secret,
        })
    }

    async fn fetch(&self) -> Result<ServerStatus> {
        let mut response = self.client.get(&self.url)
            .header(reqwest::header::AUTHORIZATION, self.secret.clone())
            .send().await.map_err(|_| CliError::new(
                "cannot reach the local statistics interface; check that the server is running and trafficStats.listen matches its configuration"))?;
        match response.status() {
            reqwest::StatusCode::OK => {}
            reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => {
                return Err(CliError::new(
                    "statistics authentication failed; check trafficStats.secret against the running server",
                ));
            }
            reqwest::StatusCode::NOT_FOUND => {
                return Err(CliError::new(
                    "this server does not provide /v1/status; upgrade the running server to a version with monitoring support",
                ));
            }
            status => {
                return Err(CliError::new(format!(
                    "local statistics interface returned HTTP {}",
                    status.as_u16()
                )));
            }
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| CliError::new("failed to read local status response"))?
        {
            if chunk.len() > 64 * 1024 - bytes.len() {
                return Err(CliError::new("local status response exceeds 64 KiB"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let report: ServerStatus = serde_json::from_slice(&bytes).map_err(|_| {
            CliError::new(
                "invalid local status response; check server/client version compatibility",
            )
        })?;
        if report.schema_version != 1 {
            return Err(CliError::new("unsupported server status schema version"));
        }
        Ok(report)
    }
}

impl ServerCommand {
    pub(crate) async fn run(&self, path: &Path) -> Result<()> {
        let (stats, options) = match self {
            Self::Status(options) => (false, options),
            Self::Stats(options) => (true, options),
            Self::Share(options) => return options.run(path),
        };
        let config = ServerConfig::load(path)?;
        let monitor = Monitor::new(&config)?;
        let stop = crate::shutdown::signal()?;
        tokio::pin!(stop);
        let terminal = io::stdout().is_terminal()
            && std::env::var_os("TERM").is_none_or(|value| value != "dumb");
        let color = match options.color {
            Color::Always => true,
            Color::Never => false,
            Color::Auto => terminal && std::env::var_os("NO_COLOR").is_none(),
        };
        let mut previous = None;
        loop {
            let current = tokio::select! { () = &mut stop => return Ok(()), result = monitor.fetch() => result? };
            // A one-shot stats query samples twice instead of claiming an instantaneous speed.
            if stats && !options.watch && previous.is_none() {
                previous = Some(current);
            } else {
                let report = Report {
                    rates: previous.as_ref().and_then(|old| rates(old, &current)),
                    status: &current,
                };
                let text = match options.output {
                    OutputFormat::Json => {
                        serde_json::to_string(&report)
                            .map_err(|_| CliError::new("failed to serialize server status"))?
                            + "\n"
                    }
                    OutputFormat::Text => render(&report, stats, color, options.watch),
                };
                let mut stdout = io::stdout().lock();
                if terminal && options.watch && matches!(options.output, OutputFormat::Text) {
                    stdout.write_all(b"\x1b[2J\x1b[H")?;
                }
                if let Err(error) = stdout
                    .write_all(text.as_bytes())
                    .and_then(|()| stdout.flush())
                {
                    if error.kind() == io::ErrorKind::BrokenPipe {
                        return Ok(());
                    }
                    return Err(error.into());
                }
                if !options.watch {
                    return Ok(());
                }
                previous = Some(current);
            }
            tokio::select! { () = &mut stop => return Ok(()), () = tokio::time::sleep(options.interval) => {} }
        }
    }
}

fn highlight(text: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}

// Values from a monitoring peer must never inject terminal commands or break columns.
fn safe_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_graphic() || *ch == ' ')
        .take(64)
        .collect()
}

fn bytes(value: f64) -> String {
    for (scale, unit) in [
        (1_099_511_627_776.0, "TiB"),
        (1_073_741_824.0, "GiB"),
        (1_048_576.0, "MiB"),
        (1024.0, "KiB"),
    ] {
        if value >= scale {
            return format!("{:.2} {unit}", value / scale);
        }
    }
    format!("{value:.0} B")
}

#[allow(clippy::cast_precision_loss)] // Exact counters remain available in JSON.
fn render(report: &Report<'_>, show_traffic: bool, color: bool, watch: bool) -> String {
    let status = report.status;
    let mut text = format!(
        "\n{}\n",
        highlight(
            if show_traffic {
                "SERVER STATISTICS"
            } else {
                "SERVER STATUS"
            },
            "1;36",
            color
        )
    );
    let state = match status.state {
        ServerState::Ready => highlight("READY", "1;32", color),
        ServerState::Starting => highlight("STARTING", "1;33", color),
    };
    writeln!(text, "  {:<24}{}", "State", state).expect("writing a String cannot fail");
    let mut row = |label: &str, value: String| {
        writeln!(text, "  {label:<24}{value}").expect("writing a String cannot fail");
    };
    row("Version", safe_text(&status.version));
    row(
        "Uptime",
        humantime::format_duration(Duration::from_secs(status.uptime_ms / 1000)).to_string(),
    );
    if !show_traffic {
        row("Started (UTC)", safe_text(&status.started_at));
        for (label, address) in [
            ("QUIC listener", status.listeners.quic),
            ("Statistics listener", status.listeners.statistics),
            ("Masquerade HTTP", status.listeners.masquerade_http),
            ("Masquerade HTTPS", status.listeners.masquerade_https),
        ] {
            row(
                label,
                address.map_or_else(|| "Not active".into(), |value| value.to_string()),
            );
        }
    }
    row("Online identities", status.online_identities.to_string());
    row(
        "QUIC connections",
        status.authenticated_connections.to_string(),
    );
    row("TCP streams", status.active_tcp_streams.to_string());
    row("UDP sessions", status.active_udp_sessions.to_string());
    if show_traffic {
        render_traffic(&mut text, report, color, watch);
    } else {
        text += "\n  READY means local initialization completed, not public reachability.\n";
    }
    if watch {
        text += "  Watching locally. Press Ctrl+C to stop.\n";
    }
    text
}

#[allow(clippy::cast_precision_loss)] // Display uses rounded IEC units; JSON retains integer totals.
fn render_traffic(text: &mut String, report: &Report<'_>, color: bool, watch: bool) {
    let status = report.status;
    write!(
        text,
        "\n  {:<22}{:>16}{:>16}\n",
        "PAYLOAD TRAFFIC", "UPLOAD", "DOWNLOAD"
    )
    .expect("writing a String cannot fail");
    writeln!(
        text,
        "  {:<22}{:>16}{:>16}",
        "Since startup",
        bytes(status.upload_bytes as f64),
        bytes(status.download_bytes as f64)
    )
    .expect("writing a String cannot fail");
    let (up, down) = report.rates.as_ref().map_or_else(
        || {
            let pending = if watch { "Sampling..." } else { "Unavailable" };
            (pending.into(), pending.into())
        },
        |rates| {
            (
                format!("{}/s", bytes(rates.upload_bytes_per_second)),
                format!("{}/s", bytes(rates.download_bytes_per_second)),
            )
        },
    );
    writeln!(text, "  {:<22}{up:>16}{down:>16}", "Sample average")
        .expect("writing a String cannot fail");
    write!(
        text,
        "\n  {:<24}{}\n  {:<24}{}\n",
        "TCP outbound failures",
        highlight(
            &status.tcp_connect_failures.to_string(),
            if status.tcp_connect_failures > 0 {
                "33"
            } else {
                "0"
            },
            color
        ),
        "UDP queue drops",
        highlight(
            &status.udp_queue_drops.to_string(),
            if status.udp_queue_drops > 0 {
                "33"
            } else {
                "0"
            },
            color
        )
    )
    .expect("writing a String cannot fail");
    text.push_str(
        "\n  Upload/download use the client perspective. Payload only; resets on restart.\n",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use hysteria_cli::status::Listeners;

    fn snapshot() -> ServerStatus {
        ServerStatus {
            schema_version: 1,
            instance_id: "first".into(),
            version: "0.1.0-rc.6".into(),
            state: ServerState::Ready,
            started_at: "2026-11-11T00:00:00+00:00".into(),
            uptime_ms: 2_000,
            listeners: Listeners::default(),
            online_identities: 2,
            authenticated_connections: 3,
            active_tcp_streams: 4,
            active_udp_sessions: 5,
            upload_bytes: 1024,
            download_bytes: 2048,
            tcp_connect_failures: 0,
            udp_queue_drops: 0,
        }
    }

    #[test]
    fn sampling_uses_server_time_and_discards_reset_or_restarted_counters() {
        let before = snapshot();
        let mut after = before.clone();
        after.uptime_ms += 2_000;
        after.upload_bytes += 2_048;
        after.download_bytes += 4_096;
        let sample = rates(&before, &after).unwrap();
        assert!((sample.upload_bytes_per_second - 1024.0).abs() < f64::EPSILON);
        assert!((sample.download_bytes_per_second - 2048.0).abs() < f64::EPSILON);
        assert!(rates(&before, &before).is_none());
        after.instance_id = "restarted".into();
        assert!(rates(&before, &after).is_none());
        after.instance_id.clone_from(&before.instance_id);
        after.upload_bytes = 0;
        assert!(rates(&before, &after).is_none());
    }

    #[test]
    fn text_has_aligned_english_columns_and_color_is_only_decoration() {
        let mut status = snapshot();
        status.version = "v1\n\x1b\r\t".into();
        let report = Report {
            status: &status,
            rates: None,
        };
        let plain = render(&report, true, false, false);
        assert!(!plain.contains('\x1b'));
        assert!(plain.contains("  State                   READY\n"));
        assert!(plain.contains("  Version                 v1\n"));
        let traffic: Vec<_> = plain
            .lines()
            .filter(|line| {
                line.contains("PAYLOAD TRAFFIC")
                    || line.contains("Since startup")
                    || line.contains("Sample average")
            })
            .collect();
        assert_eq!(traffic.len(), 3);
        assert!(traffic.iter().all(|line| line.len() == 56));
        let colored = render(&report, true, true, false);
        let ansi = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
        assert_eq!(ansi.replace_all(&colored, ""), plain);
        assert!(colored.contains("\x1b[1;32mREADY"));
        assert!(render(&report, false, false, false).contains("QUIC listener"));
    }

    #[test]
    fn endpoints_cannot_send_secrets_to_remote_or_ambiguous_hosts() {
        for input in [
            "127.0.0.1:9999",
            "[::1]:9999",
            "0.0.0.0:9999",
            "[::]:9999",
            ":9999",
            "localhost:9999",
        ] {
            assert!(local_address(input).unwrap().ip().is_loopback());
        }
        for input in [
            "127.0.0.1:0",
            "192.0.2.1:9999",
            "example.com:9999",
            "http://127.0.0.1:9999",
            "user:password@127.0.0.1:9999",
        ] {
            assert!(local_address(input).is_err());
        }
        assert!(parse_interval("1ms").is_err());
        assert!(parse_interval("2h").is_err());
    }
}
