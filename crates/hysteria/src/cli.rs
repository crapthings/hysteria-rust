use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Defines the public command-line grammar while preserving the default client invocation.
#[derive(Debug, Parser)]
#[command(
    name = "hysteria",
    version,
    about = "Hysteria 2 client and server in Rust",
    after_help = "Quick start:
  hysteria guide server                      Set up a server
  hysteria guide client                      Import a link or set up a client

Role guides:
  hysteria help server                       Setup, run, monitor and share
  hysteria help client                       Setup, run and diagnose
  hysteria help service                      Background services and instances
  hysteria help <command>                    Detailed command options

Running without arguments shows this help."
)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Option<Command>,
    #[arg(
        short,
        long,
        default_value = "config.yaml",
        global = true,
        help = "Configuration file, or - to read YAML/JSON from standard input"
    )]
    pub(crate) config: PathBuf,
    /// Use a named client profile for this invocation; mutually exclusive with --config.
    #[arg(long, global = true, conflicts_with = "config", value_parser = crate::profile::profile_name)]
    pub(crate) profile: Option<String>,
    #[arg(
        long,
        global = true,
        env = "HYSTERIA_DISABLE_UPDATE_CHECK",
        default_value_t = false,
        help = "Disable automatic update checks"
    )]
    pub(crate) disable_update_check: bool,
    /// Include available diagnostic causes in command error reports.
    #[arg(long, global = true)]
    pub(crate) diagnostic: bool,
    /// Client lifecycle format; JSON writes NDJSON to stdout, diagnostics stay on stderr.
    #[arg(long, global = true, value_enum)]
    pub(crate) events: Option<crate::check::OutputFormat>,
    /// Own the client through versioned JSON on stdin/stdout; EOF stops the client.
    #[arg(long, global = true, value_enum, conflicts_with = "events")]
    pub(crate) control: Option<crate::client_stdio::ControlMode>,
}

/// Separates long-running roles from bounded diagnostic and administrative commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Inspect macOS TUN route recovery receipts; --apply explicitly removes owned routes.
    RecoverTunRoutes {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        apply: bool,
    },
    /// Import, list, inspect or remove private client profiles.
    #[command(display_order = 30)]
    Profile(crate::profile::ProfileOptions),
    /// Run the local proxy client.
    #[command(
        long_about = "Run the local Hysteria 2 proxy client in the foreground.

Reads YAML/JSON configuration (default: config.yaml). Configure a server, authentication and at least one local proxy/forwarding mode. Rule-set paths use the configuration file directory; other relative paths use the working directory.",
        after_help = "Setup:
  hysteria guide client -c client.yaml       Guided setup / link import
  hysteria profile import --name jp1         Save a sharing link from stdin/prompt
  hysteria profile list                      List saved client profiles
  hysteria init client -c client.yaml        Editable template

Run:
  hysteria client -c client.yaml             Start local proxies
  hysteria client --profile jp1               Use a saved profile for this run
  hysteria service install client -c client.yaml
                                             Linux background service (root)

Check and diagnose:
  hysteria check client -c client.yaml       Validate configuration offline
  hysteria doctor client -c client.yaml      Inspect local inputs
  hysteria route template lan-bypass         Print a routing fragment
  hysteria route lint --profile jp1           Review rule order
  hysteria route explain example.com:443 --trace -c client.yaml
                                             Explain routing without DNS
  hysteria doctor client --dns example.com -c client.yaml
                                             Verify active Fake-IP DNS capture
  hysteria doctor client --connect -c client.yaml
                                             Test server authentication
  hysteria ping example.com:443 -c client.yaml
                                             Test TCP forwarding
  hysteria speedtest -c client.yaml          Measure throughput

Share:
  hysteria share -c client.yaml              Export a link / optional QR

Advanced input:
  hysteria client --control stdio            GUI control protocol on stdin/stdout
  hysteria client --events json              Lifecycle events on stdout (NDJSON)
  hysteria client --config -                 Read configuration from stdin

Stop with Ctrl+C or Unix SIGTERM.
Server diagnosis requires --connect; --dns probes existing TUN DNS. Both may send network traffic.
A captured --dns probe can consume one persistent Fake-IP entry; throughput tests transfer traffic.
Proxy, TLS, authentication and routing settings belong in the configuration file."
    )]
    #[command(display_order = 40)]
    Client,
    /// Run the remote proxy server.
    #[command(
        long_about = "Run the Hysteria 2 server in the foreground.

Reads YAML/JSON configuration (default: config.yaml). Configure authentication and either certificate/key files or ACME. Relative file paths use the working directory.",
        after_help = "Setup:
  hysteria guide server -c server.yaml       Guided setup
  hysteria init server -c server.yaml        Editable template

Run:
  hysteria server -c server.yaml             Start serving
  hysteria service install server -c server.yaml
                                             Linux background service (root)

Monitor:
  hysteria server status -c server.yaml      View readiness
  hysteria server stats --watch -c server.yaml
                                             Watch traffic

Check and diagnose:
  hysteria check server -c server.yaml       Validate configuration offline
  hysteria doctor server -c server.yaml      Inspect local TLS and deployment

Share:
  hysteria server share --address vpn.example.com:443 -c server.yaml
                                             Export one client link

Advanced tools:
  hysteria cert --host vpn.example.com       Generate a self-signed certificate
  hysteria ech --public-name public.example.com
                                             Generate ECH keys offline
  hysteria server --config -                 Read configuration from stdin

Stop with Ctrl+C or Unix SIGTERM. Relative paths use the working directory.
Doctor is offline; successful checks do not establish network reachability or client trust.
Listen, authentication, TLS/ACME and proxy settings belong in YAML/JSON."
    )]
    #[command(display_order = 30)]
    Server(crate::server_view::ServerOptions),
    /// Install and manage named system services (Linux systemd).
    #[command(after_help = "Examples:
  sudo hysteria service install server -c server.yaml
  sudo hysteria service install client -c client.yaml
  sudo hysteria service install server --name backup -c backup.yaml
  hysteria service status
  hysteria service logs backup --follow
  sudo hysteria service restart backup
  sudo hysteria service uninstall backup

Installation starts the service and enables boot startup by default.
Use --no-start / --no-enable to opt out. System services run as root.
Configuration and binary stay in place; keep their paths available at boot.
Without a name, actions select the only instance. With multiple instances,
provide a name for actions and logs; status lists all instances.")]
    #[command(display_order = 50)]
    Service(crate::service::ServiceOptions),
    /// Validate configuration offline.
    #[command(display_order = 60)]
    Check(crate::check::CheckOptions),
    /// Generate a server/client configuration template or import a client link.
    #[command(display_order = 20)]
    Init(crate::init::InitOptions),
    /// Set up a server or client interactively.
    #[command(
        after_help = "Server: enter a UDP port or realm:// URI at the first prompt.
Client: paste a direct/Realm sharing link, or enter connection settings manually.
Realm setup is offline and never enables router port mapping."
    )]
    #[command(display_order = 10)]
    Guide(crate::init::InitOptions),
    /// Diagnose local inputs; optionally test a client connection with --connect.
    #[command(display_order = 70)]
    Doctor(crate::doctor_cli::DoctorOptions),
    /// Generate routing templates, review rule order and explain decisions offline.
    #[command(display_order = 75)]
    Route(crate::routing_cli::RouteOptions),
    /// Report platform and integration capabilities (JSON by default).
    #[command(display_order = 125)]
    Capabilities(crate::routing_cli::CapabilitiesOptions),
    /// Print version information.
    #[command(display_order = 130)]
    Version,
    /// Test a TCP connection through the server.
    #[command(display_order = 80)]
    Ping {
        /// Remote TCP destination in host:port form.
        address: String,
    },
    /// Measure upload and download speed.
    #[command(display_order = 90)]
    Speedtest {
        /// Skip the download measurement.
        #[arg(long)]
        skip_download: bool,
        /// Skip the upload measurement.
        #[arg(long)]
        skip_upload: bool,
        /// Bytes per transfer; selects size-based mode instead of duration.
        #[arg(long)]
        data_size: Option<u32>,
        /// Duration per transfer when --data-size is omitted.
        #[arg(long, default_value = "10s")]
        duration: String,
        /// Display throughput in bytes per second instead of bits.
        #[arg(long)]
        use_bytes: bool,
    },
    /// Export a client URI or QR code.
    #[command(display_order = 100)]
    Share {
        /// Suppress the sharing URI text.
        #[arg(long)]
        notext: bool,
        /// Print a terminal QR code.
        #[arg(long)]
        qr: bool,
    },
    /// Check for a newer release.
    #[command(display_order = 140)]
    CheckUpdate,
    /// Generate private ECH keys and public client configuration offline.
    #[command(display_order = 120)]
    Ech(crate::ech_cli::EchOptions),
    /// Internal bounded resolver worker; not a public command contract.
    #[command(name = "__dns-lookup", hide = true)]
    DnsLookup { name: String },
    /// Generate a self-signed certificate and key.
    #[command(display_order = 110)]
    Cert {
        /// Comma-separated DNS names or IP addresses for the certificate.
        #[arg(long, default_value_t = hysteria_cli::cert::default_host())]
        host: String,
        /// Output certificate PEM path.
        #[arg(long, default_value = "server.crt")]
        cert: PathBuf,
        /// Output private-key PEM path.
        #[arg(long, default_value = "server.key")]
        key: PathBuf,
        /// Certificate lifetime, for example 365d.
        #[arg(long, default_value = "365d")]
        valid_for: String,
        /// Replace existing certificate and key files.
        #[arg(long)]
        overwrite: bool,
    },
}

/// Protects compatible invocation forms without running any client or server networking.
#[cfg(test)]
mod tests {
    use super::*;

    /// Keeps configuration flags before or after the role and preserves the implicit client mode.
    #[test]
    fn preserves_existing_role_and_config_arguments() {
        for args in [
            vec!["hysteria", "-c", "client.yaml", "client"],
            vec!["hysteria", "client", "-c", "client.yaml"],
            vec!["hysteria", "-c", "client.yaml"],
        ] {
            let cli = Cli::try_parse_from(args).unwrap();
            assert_eq!(cli.config, PathBuf::from("client.yaml"));
            assert!(matches!(cli.command, None | Some(Command::Client)));
        }
        let cli = Cli::try_parse_from(["hysteria", "server", "-c", "-"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Server(_))));
        assert_eq!(cli.config, PathBuf::from("-"));
    }

    /// Requires an explicit validation role instead of guessing from configuration contents.
    #[test]
    fn check_requires_a_supported_role() {
        assert!(Cli::try_parse_from(["hysteria", "check"]).is_err());
        assert!(Cli::try_parse_from(["hysteria", "check", "automatic"]).is_err());
        let cli =
            Cli::try_parse_from(["hysteria", "check", "client", "-c", "-", "--output", "json"])
                .unwrap();
        assert!(matches!(cli.command, Some(Command::Check(_))));
    }
}
