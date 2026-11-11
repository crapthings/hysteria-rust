use base64::Engine;
use clap::{Args, ValueEnum};
use hysteria_cli::{CliError, Result, config::ServerConfig};
use std::{
    fs::OpenOptions,
    io::{self, BufRead, Read, Write},
    path::Path,
};

/// The roles currently supported by the configuration generator.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum InitMode {
    Server,
    Client,
}

/// Generates a small starter configuration with safe defaults.
#[derive(Debug, Args)]
pub(crate) struct InitOptions {
    /// Configuration role to generate.
    #[arg(value_enum)]
    mode: InitMode,
    /// Import a client sharing link (contains credentials; prefer guide client interactively).
    #[arg(long)]
    uri: Option<String>,
    /// Explicitly retain insecure=1 from an imported client link.
    #[arg(long, requires = "uri")]
    allow_insecure: bool,
}

impl InitOptions {
    pub(crate) fn run(&self, path: &Path, interactive: bool) -> Result<()> {
        if matches!(self.mode, InitMode::Server) && (self.uri.is_some() || self.allow_insecure) {
            return Err(CliError::new(
                "--uri and --allow-insecure apply only to client setup",
            ));
        }
        if path != Path::new("-") && path.symlink_metadata().is_ok() {
            return Err(CliError::new(format!(
                "{} already exists; choose another path with --config",
                path.display()
            )));
        }
        let mut input = io::stdin().lock();
        let mut prompts = io::stderr().lock();
        let text = match self.mode {
            InitMode::Server => generate(interactive, &mut input, &mut prompts)?,
            InitMode::Client => crate::client_setup::generate(
                interactive,
                self.uri.as_deref(),
                self.allow_insecure,
                &mut input,
                &mut prompts,
            )?,
        };
        if path == Path::new("-") {
            let mut stdout = io::stdout().lock();
            stdout.write_all(text.as_bytes())?;
            stdout.flush()?;
        } else {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(path).map_err(|error| {
                CliError::new(format!(
                    "cannot create {}: {error}; check the parent directory and permissions, or choose another --config path",
                    path.display()
                ))
            })?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            writeln!(
                prompts,
                "Created {} (password stored in this file).",
                path.display()
            )?;
            if matches!(self.mode, InitMode::Client) {
                summarize_client(&text, path, &mut prompts)?;
                return Ok(());
            }
            let config: ServerConfig = serde_yaml_ng::from_str(&text)
                .map_err(|_| CliError::new("failed to summarize generated configuration"))?;
            writeln!(
                prompts,
                "  Listen: {} (UDP)\n  Authentication: generated password",
                if config.listen.starts_with("realm:") || config.listen.starts_with("realm+http:") {
                    "Realm (address stored in configuration)"
                } else {
                    &config.listen
                }
            )?;
            if let Some(acme) = &config.acme {
                writeln!(
                    prompts,
                    "  Certificates: ACME HTTP for {} (obtained on startup)",
                    acme.domains.join(", ")
                )?;
                writeln!(
                    prompts,
                    "  Prepare: domain DNS and inbound TCP 80 for validation; allow the configured UDP port for clients."
                )?;
            } else {
                writeln!(
                    prompts,
                    "  Certificate: {}\n  Private key: {}",
                    config.tls.cert, config.tls.key
                )?;
                writeln!(
                    prompts,
                    "  Prepare: place your certificate/key at these paths; relative paths use the working directory."
                )?;
            }
            let display = path.display().to_string();
            let argument = if display
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
            {
                display.as_str()
            } else {
                "<your-config-path>"
            };
            writeln!(
                prompts,
                "Next: diagnose the configuration, then start:\n  hysteria doctor server -c {argument}\n  hysteria server -c {argument}"
            )?;
        }
        Ok(())
    }
}

fn summarize_client(text: &str, path: &Path, prompts: &mut impl Write) -> Result<()> {
    let config: hysteria_cli::config::ClientConfig = serde_yaml_ng::from_str(text)
        .map_err(|_| CliError::new("failed to summarize client configuration"))?;
    writeln!(
        prompts,
        "  SOCKS5: {}\n  TLS verification: {}\n  System proxy/routes/DNS: unchanged",
        config
            .socks5
            .as_ref()
            .map_or("disabled", |proxy| proxy.listen.as_str()),
        if config.tls.insecure {
            "DISABLED (explicitly accepted)"
        } else {
            "enabled"
        }
    )?;
    let argument = path
        .to_str()
        .filter(|value| {
            value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
        })
        .unwrap_or("<your-config-path>");
    writeln!(
        prompts,
        "Next: edit placeholders if present, then run:\n  hysteria doctor client -c {argument}\n  hysteria doctor client --connect -c {argument}\n  hysteria client -c {argument}"
    )?;
    Ok(())
}

fn generate(
    interactive: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<String> {
    let mut port = 443;
    let mut realm_address = None;
    let mut certificate = "server.crt".to_owned();
    let mut key = "server.key".to_owned();
    let mut domain = None;
    if interactive {
        writeln!(
            output,
            "Server setup — Enter accepts defaults. A random password is generated automatically."
        )?;
        (port, realm_address) = ask_listen(input, output)?;
        let mode = loop {
            let value = ask(
                input,
                output,
                "Certificate: 1 = existing files, 2 = automatic ACME",
                "1",
            )?;
            if value == "2" && realm_address.is_some() {
                writeln!(
                    output,
                    "Realm guide uses existing certificate files. For automatic issuance, configure DNS-01 ACME separately; HTTP validation is not suitable behind NAT."
                )?;
                continue;
            }
            if value == "1" || value == "2" {
                break value;
            }
            writeln!(output, "Enter 1 or 2.")?;
        };
        if mode == "2" {
            writeln!(
                output,
                "Point your domain at this server. ACME HTTP validation needs inbound TCP port 80 when the server starts."
            )?;
            loop {
                let value = ask(
                    input,
                    output,
                    "Public domain (for example vpn.example.com)",
                    "",
                )?;
                if valid_domain(&value) {
                    domain = Some(value);
                    break;
                }
                writeln!(
                    output,
                    "Enter a domain name without a scheme, path or port."
                )?;
            }
        } else {
            certificate = ask(input, output, "Certificate file", "server.crt")?;
            key = ask(input, output, "Private key file", "server.key")?;
        }
    }
    let mut random = [0u8; 32];
    getrandom::fill(&mut random)
        .map_err(|error| CliError::new(format!("failed to generate password: {error}")))?;
    let password = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
    let tls = if let Some(domain) = domain {
        format!(
            "# Certificate is obtained on server startup, not during setup.\n# Domain must point here; allow inbound TCP 80 for HTTP validation.\nacme:\n  domains:\n    - {}\n  type: http\n",
            serde_json::Value::String(domain)
        )
    } else {
        "# Set paths to your certificate and private key before starting.\n# Relative paths are resolved from the working directory.\n".to_owned()
            + &format!("tls:\n  cert: {}\n  key: {}\n", serde_json::Value::String(certificate), serde_json::Value::String(key))
    };
    let listen_hint = if realm_address.is_some() {
        "# Realm mode uses outbound rendezvous/STUN and UDP hole punching."
    } else {
        "# Listen on all interfaces; allow this UDP port for clients."
    };
    let listen = serde_json::Value::String(realm_address.unwrap_or_else(|| format!(":{port}")));
    let text = format!(
        "# Hysteria server configuration. Keep this file private.\n{listen_hint}\nlisten: {listen}\n\n{tls}\n# Automatically generated password; use the same value on clients.\nauth:\n  type: password\n  password: {password}\n\nmasquerade:\n  type: string\n  string:\n    content: Not Found\n    headers:\n      content-type: text/plain; charset=utf-8\n    statusCode: 404\n"
    );
    let config: ServerConfig = serde_yaml_ng::from_str(&text)
        .map_err(|_| CliError::new("failed to build server configuration"))?;
    config.validate()?;
    Ok(text)
}

pub(crate) fn ask(
    input: &mut impl BufRead,
    output: &mut impl Write,
    label: &str,
    default: &str,
) -> Result<String> {
    write!(output, "{label} [{default}]: ")?;
    output.flush()?;
    let mut value = String::new();
    if (&mut *input).take(65537).read_line(&mut value)? == 0 {
        return Err(CliError::new(
            "setup cancelled: input ended; no configuration written",
        ));
    }
    if value.len() > 65536 {
        return Err(CliError::new(
            "setup input exceeds 64 KiB; no configuration written",
        ));
    }
    let value = value.trim();
    Ok(if value.is_empty() { default } else { value }.to_owned())
}

fn valid_domain(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.parse::<std::net::IpAddr>().is_err()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn ask_listen(input: &mut impl BufRead, output: &mut impl Write) -> Result<(u16, Option<String>)> {
    loop {
        let value = ask(input, output, "UDP port or realm:// address", "443")?;
        if value.starts_with("realm:") || value.starts_with("realm+http:") {
            if hysteria_realm::RealmAddr::parse(&value).is_ok() {
                return Ok((443, Some(value)));
            }
            writeln!(
                output,
                "Invalid Realm address. Include the rendezvous token and realm name."
            )?;
            continue;
        }
        if let Ok(value) = value.parse::<u16>()
            && value != 0
        {
            return Ok((value, None));
        }
        writeln!(output, "Enter a port between 1 and 65535.")?;
    }
}
