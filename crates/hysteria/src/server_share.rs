//! Offline generation of one client sharing URI from a server configuration.
use clap::Args;
use hysteria_cli::{
    CliError, Result,
    config::ServerConfig,
    sharing::{ServerShareOptions, server_uri},
};
use std::{
    io::{self, Read, Write},
    path::Path,
};

// Independent CLI switches, not mutually exclusive internal states.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Public address for direct mode (required); omit for Realm mode.
    #[arg(long)]
    address: Option<String>,
    /// Select exactly one account from auth.userpass.
    #[arg(long, conflicts_with = "auth_stdin")]
    user: Option<String>,
    /// Read one credential from stdin for HTTP/command authentication (up to 4 KiB).
    #[arg(long)]
    auth_stdin: bool,
    /// Certificate server name when it differs from the public address.
    #[arg(long, default_value = "")]
    sni: String,
    /// Explicitly disable CA/name verification in the generated link.
    #[arg(long)]
    insecure: bool,
    /// Pin the leaf certificate from tls.cert; rotating it requires a new link.
    #[arg(long)]
    pin_cert: bool,
    /// Optional human-readable link name.
    #[arg(long)]
    name: Option<String>,
    /// Also render the link as a terminal QR code.
    #[arg(long)]
    qr: bool,
}

impl Options {
    pub(crate) fn run(&self, path: &Path) -> Result<()> {
        if self.auth_stdin && path == Path::new("-") {
            return Err(CliError::new(
                "--auth-stdin cannot be combined with configuration from stdin",
            ));
        }
        let config = ServerConfig::load(path)?;
        let external_auth = if self.auth_stdin {
            let mut value = String::new();
            io::stdin().lock().take(4097).read_to_string(&mut value)?;
            if value.len() > 4096 {
                return Err(CliError::new("credential exceeds 4 KiB"));
            }
            let value = value.strip_suffix('\n').unwrap_or(&value);
            let value = value.strip_suffix('\r').unwrap_or(value);
            if value.is_empty() || value.contains(['\r', '\n']) {
                return Err(CliError::new(
                    "provide one nonempty credential line on stdin",
                ));
            }
            Some(value.to_owned())
        } else {
            None
        };
        let uri = server_uri(
            &config,
            &ServerShareOptions {
                address: self.address.clone().unwrap_or_default(),
                user: self.user.clone(),
                external_auth,
                sni: self.sni.clone(),
                insecure: self.insecure,
                pin_cert: self.pin_cert,
                name: self.name.clone(),
            },
        )?;
        let qr = if self.qr {
            Some(
                qrcode::QrCode::new(uri.as_bytes())
                    .map_err(|_| CliError::new("sharing URI is too large for a QR code"))?
                    .render::<qrcode::render::unicode::Dense1x2>()
                    .quiet_zone(true)
                    .build(),
            )
        } else {
            None
        };
        let mut output = io::stdout().lock();
        writeln!(output, "{uri}")?;
        if let Some(qr) = qr {
            writeln!(output, "{qr}")?;
        }
        Ok(())
    }
}
