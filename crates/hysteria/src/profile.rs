//! User-owned client profiles. Configuration content is never printed by management commands.
use crate::check::OutputFormat;
use clap::{Args, Subcommand};
use hysteria_cli::{CliError, Result, config::ClientConfig};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Debug, Args)]
pub(crate) struct ProfileOptions {
    #[command(subcommand)]
    command: ProfileCommand,
    /// Output format; management results never include credentials or full configuration.
    #[arg(long, global = true, value_enum, default_value = "text")]
    output: OutputFormat,
}
#[derive(Debug, Subcommand)]
enum ProfileCommand {
    /// Import one sharing link from a terminal prompt or stdin; never from an argument.
    Import {
        #[arg(long, value_parser = profile_name)]
        name: String,
        /// Explicitly replace an existing profile using an atomic write.
        #[arg(long)]
        overwrite: bool,
        /// Retain disabled TLS verification if the link requests it.
        #[arg(long)]
        allow_insecure: bool,
    },
    /// List saved profile names, without reading credentials.
    List,
    /// Show a safe summary; authentication and Realm addresses are omitted.
    Show {
        #[arg(value_parser = profile_name)]
        name: String,
    },
    /// Delete this saved profile; running clients are not changed.
    Remove {
        #[arg(value_parser = profile_name)]
        name: String,
    },
}

pub(crate) fn profile_name(name: &str) -> std::result::Result<String, String> {
    let reserved = matches!(name, "con" | "prn" | "aux" | "nul")
        || (name.len() == 4
            && (name.starts_with("com") || name.starts_with("lpt"))
            && name.as_bytes()[3].is_ascii_digit());
    if name.is_empty()
        || name.len() > 64
        || reserved
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
        || !name.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err("use 1–64 lowercase letters, digits, - or _, starting with a letter/digit; reserved system names are not allowed".into());
    }
    Ok(name.to_owned())
}

impl ProfileOptions {
    pub(crate) fn run(&self) -> Result<ExitCode> {
        let result = self.execute();
        let passed = result.is_ok();
        match (self.output, result) {
            (OutputFormat::Json, Ok(report)) => write_json(&report)?,
            (OutputFormat::Json, Err(error)) => write_json(
                &json!({"schema_version":1,"error":{"code":"profile_operation_failed","message":error.to_string()}}),
            )?,
            (OutputFormat::Text, Ok(report)) => print_text(&report)?,
            (OutputFormat::Text, Err(error)) => eprintln!("{}", error.report(false)),
        }
        Ok(if passed {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(3)
        })
    }
    fn execute(&self) -> Result<Value> {
        let root = profile_directory()?;
        match &self.command {
            ProfileCommand::Import {
                name,
                overwrite,
                allow_insecure,
            } => {
                // Check location before asking for sensitive input, without creating state yet.
                check_directory(&root, false)?;
                let target = root.join(format!("{name}.yaml"));
                check_destination(&target, *overwrite)?;
                let uri = read_link()?;
                let content = crate::client_setup::generate(
                    false,
                    Some(&uri),
                    *allow_insecure,
                    &mut io::empty(),
                    &mut io::sink(),
                )?;
                let imported: ClientConfig = serde_yaml_ng::from_str(&content)
                    .map_err(|_| CliError::new("could not validate generated profile"))?;
                check_directory(&root, true)?;
                let _lock = write_lock(&root)?;
                check_destination(&target, *overwrite)?;
                let mut file = tempfile::NamedTempFile::new_in(&root)?;
                private_file(file.as_file())?;
                file.write_all(content.as_bytes())?;
                file.as_file().sync_all()?;
                if *overwrite {
                    file.persist(&target)
                        .map_err(|_| CliError::new("could not replace profile"))?;
                } else {
                    file.persist_noclobber(&target).map_err(|_| {
                        CliError::new("profile already exists or could not be saved")
                    })?;
                }
                sync_directory(&root)?;
                Ok(
                    json!({"schema_version":1,"action":"import","name":name,"saved":true,"path":target,"tls_verification":!imported.tls.insecure,"socks5":"127.0.0.1:1080"}),
                )
            }
            ProfileCommand::List => {
                if !check_directory(&root, false)? {
                    return Ok(json!({"schema_version":1,"action":"list","profiles":[]}));
                }
                let mut names = Vec::new();
                for entry in fs::read_dir(&root)? {
                    let path = entry?.path();
                    if path.extension().is_some_and(|ext| ext == "yaml")
                        && let Some(name) = path.file_stem().and_then(|name| name.to_str())
                        && profile_name(name).is_ok()
                    {
                        check_file(&path)?;
                        names.push(name.to_owned());
                    }
                }
                names.sort();
                Ok(json!({"schema_version":1,"action":"list","profiles":names}))
            }
            ProfileCommand::Show { name } => {
                let path = resolve(name)?;
                let config = ClientConfig::load(&path).and_then(|c| { c.validate()?; Ok(c) })
                    .map_err(|_| CliError::new("profile configuration is invalid; use check client --profile NAME for diagnosis"))?;
                let realm =
                    config.server.starts_with("realm:") || config.server.starts_with("realm+http:");
                Ok(
                    json!({"schema_version":1,"action":"show","name":name,"path":path,
                    "connection_type":if realm {"realm"} else {"direct"},
                    "server":if realm {None} else {Some(hysteria_cli::sharing::normalize_address(&config.server).map_err(|_| CliError::new("invalid server address in profile"))?)},
                    "tls_verification":!config.tls.insecure,
                    "socks5":config.socks5.as_ref().map(|p| &p.listen),
                    "routing":config.routing.is_some(),"credentials":"hidden"}),
                )
            }
            ProfileCommand::Remove { name } => {
                resolve(name)?;
                let _lock = write_lock(&root)?;
                let path = resolve(name)?;
                fs::remove_file(path)?;
                sync_directory(&root)?;
                Ok(json!({"schema_version":1,"action":"remove","name":name,"removed":true}))
            }
        }
    }
}

pub(crate) fn resolve(name: &str) -> Result<PathBuf> {
    profile_name(name).map_err(CliError::new)?;
    let root = profile_directory()?;
    if !check_directory(&root, false)? {
        return Err(CliError::new(
            "profile not found; use profile list or profile import",
        ));
    }
    let path = root.join(format!("{name}.yaml"));
    check_file(&path)?;
    Ok(path)
}
fn profile_directory() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("HYSTERIA_PROFILE_DIR") {
        return absolute(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    let root = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(target_os = "macos")]
    let root = std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library/Application Support"));
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    absolute(
        root.ok_or_else(|| {
            CliError::new(
                "cannot locate user configuration directory; set an absolute HYSTERIA_PROFILE_DIR",
            )
        })?
        .join("hysteria/profiles"),
    )
}
fn absolute(path: PathBuf) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(CliError::new("profile directory must be an absolute path"));
    }
    Ok(path)
}
fn check_directory(path: &Path, create: bool) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(CliError::new(
                    "profile directory must be a real directory, not a symlink",
                ));
            }
            check_private(&metadata)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if !create {
                return Ok(false);
            }
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(path)?;
            check_directory(path, false)
        }
        Err(error) => Err(error.into()),
    }
}
fn check_private(metadata: &fs::Metadata) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::new(
                "profile storage is accessible to other users; restrict the directory to 0700 and files to 0600",
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = metadata;
    Ok(())
}
fn check_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            CliError::new("profile not found; use profile list or profile import")
        } else {
            error.into()
        }
    })?;
    if !metadata.is_file() {
        return Err(CliError::new(
            "profile must be a regular file, not a symlink",
        ));
    }
    check_private(&metadata)
}
fn check_destination(path: &Path, overwrite: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            check_file(path)?;
            if !overwrite {
                return Err(CliError::new(
                    "profile already exists; choose another name or use --overwrite",
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
fn private_file(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(())
}
fn write_lock(root: &Path) -> Result<fs::File> {
    let path = root.join(".lock");
    match fs::symlink_metadata(&path) {
        Ok(_) => check_file(&path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    file.try_lock().map_err(|_| {
        CliError::new("profile store is busy; retry after the other operation completes")
    })?;
    Ok(file)
}
fn sync_directory(root: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(root)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}
fn read_link() -> Result<String> {
    let input = io::stdin();
    if input.is_terminal() {
        let mut output = io::stderr().lock();
        writeln!(
            output,
            "Paste one sharing link. Input is visible in this terminal; it is not printed in results."
        )?;
        return crate::init::ask(&mut input.lock(), &mut output, "Sharing link", "");
    }
    let mut input = input.lock().take(65_537);
    let mut text = String::new();
    input
        .read_to_string(&mut text)
        .map_err(|_| CliError::new("could not read sharing link from stdin as UTF-8"))?;
    if text.len() > 65_536 {
        return Err(CliError::new("sharing link exceeds 64 KiB"));
    }
    Ok(text.trim().to_owned())
}
fn write_json(value: &Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer(&mut out, value)
        .map_err(|_| CliError::new("cannot write profile result"))?;
    writeln!(out)?;
    Ok(())
}
fn print_text(value: &Value) -> Result<()> {
    let mut out = io::stdout().lock();
    if let Some(names) = value["profiles"].as_array() {
        if names.is_empty() {
            writeln!(out, "No profiles. Use: hysteria profile import --name NAME")?;
        } else {
            writeln!(out, "Profiles")?;
            for name in names {
                writeln!(out, "  {}", name.as_str().unwrap_or_default())?;
            }
        }
    } else {
        let color = out.is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").is_ok_and(|term| term != "dumb");
        writeln!(
            out,
            "{}",
            if color {
                "\x1b[1;36mClient profile\x1b[0m"
            } else {
                "Client profile"
            }
        )?;
        for (key, label) in [
            ("name", "Name"),
            ("path", "File"),
            ("action", "Action"),
            ("connection_type", "Connection"),
            ("server", "Server"),
            ("socks5", "SOCKS5"),
            ("tls_verification", "Verify TLS"),
            ("routing", "Routing"),
            ("credentials", "Credentials"),
        ] {
            if let Some(item) = value.get(key) {
                let text = if item.is_null() {
                    "Hidden / not configured".into()
                } else if let Some(text) = item.as_str() {
                    text.to_owned()
                } else {
                    item.to_string()
                };
                writeln!(out, "  {label:<12} {text}")?;
            }
        }
        if value["action"] == "import" {
            writeln!(
                out,
                "Run: hysteria client --profile {}",
                value["name"].as_str().unwrap_or_default()
            )?;
        }
    }
    Ok(())
}
