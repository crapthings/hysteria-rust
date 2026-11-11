use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Defines the public command-line grammar while preserving the default client invocation.
#[derive(Debug, Parser)]
#[command(
    name = "hysteria",
    version,
    about = "Hysteria 2 client and server in Rust",
    after_help = "Getting started:
  hysteria guide server       Set up a server step by step
  hysteria doctor server      Check local deployment conditions
  hysteria server             Start the server
  hysteria client -c client.yaml

Detailed help:
  hysteria help server
  hysteria help client
  hysteria help <command>

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
}

/// Separates long-running roles from bounded diagnostic and administrative commands.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Run the local proxy client.
    #[command(
        long_about = "Run the local Hysteria 2 proxy client in the foreground.

Reads YAML/JSON configuration (default: config.yaml). Configure a server, authentication and at least one local proxy/forwarding mode. Relative file paths use the working directory.",
        after_help = "Examples:
  hysteria client -c client.yaml
  hysteria check client -c client.yaml
  hysteria client --config -
  hysteria share -c client.yaml
  hysteria ping example.com:443 -c client.yaml
  hysteria speedtest -c client.yaml

Use --config - to read stdin until EOF. Stop with Ctrl+C or Unix SIGTERM.
--disable-update-check disables automatic update queries.
Proxy, TLS, authentication and routing settings belong in the configuration file."
    )]
    Client,
    /// Run the remote proxy server.
    #[command(
        long_about = "Run the Hysteria 2 server in the foreground.

Reads YAML/JSON configuration (default: config.yaml). Configure authentication and either certificate/key files or ACME. Relative file paths use the working directory.",
        after_help = "Setup and startup:
  hysteria init server -c server.yaml     Generate an editable template
  hysteria guide server -c server.yaml    Guided setup
  hysteria check server -c server.yaml    Validate configuration
  hysteria doctor server -c server.yaml   Inspect local TLS/deployment conditions
  hysteria server -c server.yaml          Start serving

Other options:
  hysteria server --config -             Read configuration from stdin until EOF
  hysteria cert --host example.com       Generate a self-signed certificate

Stop with Ctrl+C or Unix SIGTERM. --disable-update-check disables automatic update queries.
Listen address, authentication, TLS/ACME, ACL and traffic statistics are configured in YAML/JSON.
Doctor is offline; successful checks do not establish network reachability or client trust."
    )]
    Server,
    /// Validate configuration offline.
    Check(crate::check::CheckOptions),
    /// Generate a server configuration template.
    Init(crate::init::InitOptions),
    /// Set up a server interactively.
    Guide(crate::init::InitOptions),
    /// Diagnose local server configuration and TLS.
    Doctor(crate::doctor_cli::DoctorOptions),
    /// Print version information.
    Version,
    /// Test a TCP connection through the server.
    Ping {
        /// Remote TCP destination in host:port form.
        address: String,
    },
    /// Measure upload and download speed.
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
    Share {
        /// Suppress the sharing URI text.
        #[arg(long)]
        notext: bool,
        /// Print a terminal QR code.
        #[arg(long)]
        qr: bool,
    },
    /// Check for a newer release.
    CheckUpdate,
    /// Generate a self-signed certificate and key.
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
        assert!(matches!(cli.command, Some(Command::Server)));
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
