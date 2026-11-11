//! Linux systemd integration. No shell, network setup, or implicit privilege escalation.
use clap::{Args, Subcommand, ValueEnum};
use hysteria_cli::{CliError, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};

const MARKER: &str = "# hysteria-service-v1 ";

#[derive(Debug, Args)]
pub(crate) struct ServiceOptions {
    #[command(subcommand)]
    command: Option<Action>,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Validate, register, start and enable a system service (Linux; requires root).
    Install {
        #[arg(value_enum)]
        role: Role,
        /// Instance name; defaults to server or client.
        #[arg(long, value_parser = valid_name)]
        name: Option<String>,
        /// Register without starting immediately.
        #[arg(long)]
        no_start: bool,
        /// Do not enable startup at boot.
        #[arg(long)]
        no_enable: bool,
    },
    /// Show all managed instances.
    List,
    /// Show systemd state; this does not establish proxy readiness.
    Status { name: Option<String> },
    /// Validate configuration and start an instance.
    Start { name: Option<String> },
    /// Stop an instance; boot startup remains unchanged.
    Stop { name: Option<String> },
    /// Validate configuration before stopping and restarting an instance.
    Restart { name: Option<String> },
    /// Print recent journal entries; add --follow to stream them.
    Logs {
        name: Option<String>,
        #[arg(short, long)]
        follow: bool,
    },
    /// Stop, disable and unregister an instance; preserve configuration and keys.
    Uninstall { name: Option<String> },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Role {
    Server,
    Client,
}
impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Instance {
    name: String,
    role: Role,
    executable: PathBuf,
    config: PathBuf,
    directory: PathBuf,
}
impl Instance {
    fn unit(&self) -> String {
        format!("hysteria-{}.service", self.name)
    }

    fn render(&self) -> Result<String> {
        valid_name(&self.name).map_err(CliError::new)?;
        let exe = unit_path(&self.executable, true)?;
        let config = unit_path(&self.config, true)?;
        let directory = unit_path(&self.directory, false)?;
        let role = self.role.as_str();
        let metadata = serde_json::to_string(self).map_err(|error| {
            CliError::new(format!("could not encode service metadata: {error}"))
        })?;
        Ok(format!(
            "{MARKER}{metadata}\n[Unit]\nDescription=Hysteria {role} ({})\nWants=network-online.target\nAfter=network-online.target\nStartLimitIntervalSec=60\nStartLimitBurst=5\n\n[Service]\nType=exec\nWorkingDirectory={directory}\nExecStartPre=:{exe} check {role} --config {config}\nExecStart=:{exe} {role} --config {config} --disable-update-check\nRestart=on-failure\nRestartSec=5\nTimeoutStopSec=30\nUMask=0077\nStandardOutput=journal\nStandardError=journal\n\n[Install]\nWantedBy=multi-user.target\n",
            self.name
        ))
    }
}

fn valid_name(name: &str) -> std::result::Result<String, String> {
    if name.is_empty()
        || name.len() > 48
        || !name.as_bytes()[0].is_ascii_alphanumeric()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("instance name must be 1-48 ASCII letters, digits, '-' or '_', starting with a letter or digit".into());
    }
    Ok(name.to_owned())
}

fn unit_path(path: &Path, exec: bool) -> Result<String> {
    let text = path
        .to_str()
        .filter(|text| !text.chars().any(char::is_control))
        .ok_or_else(|| CliError::new("service paths must be UTF-8 without control characters"))?;
    if !path.is_absolute() {
        return Err(CliError::new("service paths must be absolute"));
    }
    // WorkingDirectory is a raw path, not an ExecStart word list. Quotes are
    // literal there; a trailing backslash would continue the unit-file line.
    if !exec {
        if text.ends_with([' ', '\\']) {
            return Err(CliError::new(
                "service working directory cannot end in a space or backslash",
            ));
        }
        return Ok(text.replace('%', "%%"));
    }
    let text = text
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    Ok(format!("\"{text}\""))
}

trait Runner {
    fn systemctl(&self, args: &[&str]) -> Result<Output>;
    fn check(&self, instance: &Instance) -> Result<()>;
    fn recent_logs(&self, instance: &Instance) -> Result<String>;
}
struct SystemRunner;
impl Runner for SystemRunner {
    fn systemctl(&self, args: &[&str]) -> Result<Output> {
        Ok(Command::new(system_tool("systemctl")?)
            .args(["--system", "--no-pager", "--no-ask-password"])
            .args(args)
            .env("SYSTEMD_COLORS", "0")
            .output()?)
    }
    fn recent_logs(&self, instance: &Instance) -> Result<String> {
        let output = Command::new(system_tool("journalctl")?)
            .args([
                "--unit",
                &instance.unit(),
                "--lines=15",
                "--no-pager",
                "--output=short",
                "--since=-2min",
            ])
            .output()?;
        if !output.status.success() {
            return Ok(String::new());
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .chars()
            .take(8192)
            .collect())
    }
    fn check(&self, instance: &Instance) -> Result<()> {
        let status = Command::new(&instance.executable)
            .current_dir(&instance.directory)
            .args(["check", instance.role.as_str(), "--config"])
            .arg(&instance.config)
            .status()?;
        if !status.success() {
            return Err(CliError::new(
                "configuration check failed; service was not started or restarted",
            ));
        }
        Ok(())
    }
}
fn system_tool(name: &str) -> Result<PathBuf> {
    ["/usr/bin", "/bin"]
        .into_iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|path| path.is_file())
        .ok_or_else(|| {
            CliError::new(format!(
                "{name} is required; only Linux systems running systemd are supported"
            ))
        })
}

struct Manager<R> {
    directory: PathBuf,
    runner: R,
}
impl<R: Runner> Manager<R> {
    fn instances(&self) -> Result<Vec<Instance>> {
        let mut instances = Vec::new();
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with("hysteria-")
                || !name.ends_with(".service")
                || !entry.file_type()?.is_file()
            {
                continue;
            }
            let text = fs::read_to_string(entry.path())?;
            let Some(metadata) = text
                .lines()
                .next()
                .and_then(|line| line.strip_prefix(MARKER))
            else {
                continue;
            };
            let instance: Instance = serde_json::from_str(metadata)
                .map_err(|_| CliError::new(format!("invalid service metadata in {name}")))?;
            if instance.unit() != name || instance.render()? != text {
                return Err(CliError::new(format!(
                    "managed unit {name} has been edited; restore it before using service commands"
                )));
            }
            instances.push(instance);
        }
        instances.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(instances)
    }
    fn select(&self, name: Option<&str>) -> Result<Instance> {
        if let Some(name) = name {
            valid_name(name).map_err(CliError::new)?;
        }
        let mut instances = self.instances()?;
        if let Some(name) = name {
            return instances
                .into_iter()
                .find(|i| i.name == name)
                .ok_or_else(|| {
                    CliError::new(format!(
                        "instance '{name}' is not installed; run hysteria service list"
                    ))
                });
        }
        if instances.len() == 1 {
            return Ok(instances.remove(0));
        }
        Err(CliError::new(if instances.is_empty() {
            "no managed instances; run hysteria service install server -c server.yaml".into()
        } else {
            format!(
                "multiple instances; specify a name: {}",
                instances
                    .iter()
                    .map(|i| i.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }))
    }
    fn ctl(&self, args: &[&str]) -> Result<String> {
        let output = self.runner.systemctl(args)?;
        if !output.status.success() {
            return Err(CliError::new(format!(
                "systemctl {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
    fn install(&self, instance: &Instance, no_start: bool, no_enable: bool) -> Result<()> {
        let unit = instance.unit();
        let path = self.directory.join(&unit);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(CliError::new(format!(
                "instance '{}' already exists at {}; nothing was overwritten",
                instance.name,
                path.display()
            )));
        }
        // Validate and serialize everything before writing a unit or invoking systemd.
        let rendered = instance.render()?;
        self.runner.check(instance)?;
        // Refuse collisions with vendor units, aliases and runtime units as well.
        let state = self.ctl(&["show", &unit, "--property=LoadState", "--value"])?;
        if state.trim() != "not-found" {
            return Err(CliError::new(format!(
                "systemd already knows {unit}; choose another name"
            )));
        }
        let mut file = tempfile::NamedTempFile::new_in(&self.directory)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.as_file()
                .set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        file.write_all(rendered.as_bytes())?;
        file.as_file().sync_all()?;
        file.persist_noclobber(&path)
            .map_err(|error| CliError::new(format!("could not register {unit}: {error}")))?;
        // Keep the registration on operational failure so status/logs/uninstall can recover it.
        let result = (|| {
            self.ctl(&["daemon-reload"])?;
            if !no_enable {
                self.ctl(&["enable", &unit])?;
            }
            if !no_start {
                self.activate(instance, "start", false)?;
            }
            Ok(())
        })();
        result.map_err(|error: CliError| CliError::new(format!("{unit} was registered, but setup did not finish: {error}. Inspect 'hysteria service status {}' and 'hysteria service logs {}', or uninstall it", instance.name, instance.name)))?;
        heading("Service installed");
        self.show(instance)?;
        println!(
            "  Configuration  {}\n  Working dir    {}\n  Run as         root\n\n  Logs           hysteria service logs {}",
            instance.config.display(),
            instance.directory.display(),
            instance.name
        );
        Ok(())
    }
    fn activate(&self, instance: &Instance, action: &str, validate: bool) -> Result<()> {
        if validate {
            self.runner.check(instance)?;
        }
        if let Err(error) = self.ctl(&[action, &instance.unit()]) {
            self.failure_logs(instance);
            return Err(error);
        }
        // Type=exec confirms exec, not application readiness. Catch immediate exits too.
        std::thread::sleep(std::time::Duration::from_millis(500));
        let state = self.ctl(&[
            "show",
            &instance.unit(),
            "--property=ActiveState",
            "--value",
        ])?;
        if state.trim() != "active" {
            self.failure_logs(instance);
            return Err(CliError::new(format!(
                "instance '{}' is {}; inspect: hysteria service logs {}",
                instance.name,
                state.trim(),
                instance.name
            )));
        }
        Ok(())
    }
    fn failure_logs(&self, instance: &Instance) {
        if let Ok(logs) = self.runner.recent_logs(instance)
            && !logs.trim().is_empty()
        {
            eprintln!("Recent service logs:\n{logs}");
        }
    }
    fn show(&self, instance: &Instance) -> Result<()> {
        let width = instance.name.len().max(8);
        table_header(width);
        self.row(instance, width)
    }
    fn row(&self, instance: &Instance, width: usize) -> Result<()> {
        let data = self.ctl(&[
            "show",
            &instance.unit(),
            "--property=ActiveState,SubState,UnitFileState,MainPID",
        ])?;
        let get = |key: &str| {
            data.lines()
                .find_map(|line| {
                    line.split_once('=')
                        .filter(|(k, _)| *k == key)
                        .map(|(_, v)| v)
                })
                .unwrap_or("unknown")
        };
        println!(
            "  {:<width$} {:<8} {:<14} {:<12} {}",
            instance.name,
            instance.role.as_str(),
            get("ActiveState"),
            get("UnitFileState"),
            get("MainPID")
        );
        Ok(())
    }
    fn list(&self, name: Option<&str>) -> Result<()> {
        let instances = if name.is_some() {
            vec![self.select(name)?]
        } else {
            self.instances()?
        };
        if instances.is_empty() {
            println!(
                "No managed services.\n\n  Install  hysteria service install server -c server.yaml"
            );
            return Ok(());
        }
        heading("Hysteria services");
        let width = instances
            .iter()
            .map(|instance| instance.name.len())
            .max()
            .unwrap_or(8)
            .max(8);
        table_header(width);
        for instance in &instances {
            self.row(instance, width)?;
        }
        println!(
            "\nState describes the process, not proxy readiness.\n  Logs     hysteria service logs [NAME]\n  Restart  hysteria service restart [NAME]"
        );
        Ok(())
    }
    fn uninstall(&self, instance: &Instance) -> Result<()> {
        self.ctl(&["stop", &instance.unit()])?;
        self.ctl(&["disable", &instance.unit()])?;
        fs::remove_file(self.directory.join(instance.unit()))?;
        self.ctl(&["daemon-reload"])?;
        println!(
            "Service '{}' removed. Configuration, certificates and keys were preserved.",
            instance.name
        );
        Ok(())
    }
}

fn table_header(width: usize) {
    println!(
        "  {:<width$} {:<8} {:<14} {:<12} PID",
        "INSTANCE", "ROLE", "STATE", "BOOT"
    );
}

fn heading(text: &str) {
    if std::io::stdout().is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|v| v != "dumb")
    {
        println!("\x1b[1;36m{text}\x1b[0m\n");
    } else {
        println!("{text}\n");
    }
}

impl ServiceOptions {
    pub(crate) fn run(self, config: &Path) -> Result<()> {
        if !cfg!(target_os = "linux") || !Path::new("/run/systemd/system").is_dir() {
            return Err(CliError::new(
                "service management requires Linux running systemd; use 'hysteria server -c server.yaml' or 'hysteria client -c client.yaml' in the foreground on this platform",
            ));
        }
        let manager = Manager {
            directory: PathBuf::from("/etc/systemd/system"),
            runner: SystemRunner,
        };
        let action = self.command.unwrap_or(Action::List);
        if matches!(
            action,
            Action::Install { .. }
                | Action::Start { .. }
                | Action::Stop { .. }
                | Action::Restart { .. }
                | Action::Uninstall { .. }
        ) {
            // Root is required for system units; do not invoke sudo or polkit implicitly.
            let uid = fs::read_to_string("/proc/self/status")?;
            let root = uid
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(2))
                == Some("0");
            if !root {
                let command = std::env::args()
                    .map(|arg| format!("'{}'", arg.replace('\'', "'\\''")))
                    .collect::<Vec<_>>()
                    .join(" ");
                return Err(CliError::new(format!(
                    "system service changes require root. Run from the same working directory:\n  sudo -- {command}"
                )));
            }
        }
        match action {
            Action::Install {
                role,
                name,
                no_start,
                no_enable,
            } => {
                if config == Path::new("-") {
                    return Err(CliError::new(
                        "services require a persistent configuration file; stdin is not supported",
                    ));
                }
                let instance = Instance {
                    name: name.unwrap_or_else(|| role.as_str().into()),
                    role,
                    executable: std::env::current_exe()?.canonicalize()?,
                    config: config.canonicalize()?,
                    directory: std::env::current_dir()?.canonicalize()?,
                };
                manager.install(&instance, no_start, no_enable)
            }
            Action::List => manager.list(None),
            Action::Status { name } => manager.list(name.as_deref()),
            Action::Start { ref name } | Action::Restart { ref name } => {
                let verb = if matches!(action, Action::Start { .. }) {
                    "start"
                } else {
                    "restart"
                };
                let instance = manager.select(name.as_deref())?;
                manager.activate(&instance, verb, true)?;
                manager.show(&instance)
            }
            Action::Stop { name } => {
                let instance = manager.select(name.as_deref())?;
                manager.ctl(&["stop", &instance.unit()])?;
                manager.show(&instance)
            }
            Action::Uninstall { name } => manager.uninstall(&manager.select(name.as_deref())?),
            Action::Logs { name, follow } => {
                let instance = manager.select(name.as_deref())?;
                let mut command = Command::new(system_tool("journalctl")?);
                command.args(["--unit", &instance.unit(), "--lines=50", "--no-pager"]);
                if follow {
                    command.arg("--follow");
                }
                if !command.status()?.success() {
                    return Err(CliError::new(
                        "journalctl failed; journal access may require elevated permissions",
                    ));
                }
                Ok(())
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        os::unix::process::ExitStatusExt,
    };

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<Vec<String>>>,
        invalid: Cell<bool>,
        fail: Cell<bool>,
        existing: Cell<bool>,
        fail_start: Cell<bool>,
        inactive: Cell<bool>,
    }
    impl Runner for Fake {
        fn recent_logs(&self, _: &Instance) -> Result<String> {
            self.calls.borrow_mut().push(vec!["logs".into()]);
            Ok("mock startup failure".into())
        }
        fn check(&self, _: &Instance) -> Result<()> {
            self.calls.borrow_mut().push(vec!["check".into()]);
            if self.invalid.get() {
                Err(CliError::new("invalid configuration"))
            } else {
                Ok(())
            }
        }
        fn systemctl(&self, args: &[&str]) -> Result<Output> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|s| (*s).into()).collect());
            let stdout = if args.contains(&"--property=LoadState") {
                if self.existing.get() {
                    "loaded\n"
                } else {
                    "not-found\n"
                }
            } else if args.contains(&"--property=ActiveState") {
                if self.inactive.get() {
                    "failed\n"
                } else {
                    "active\n"
                }
            } else {
                "ActiveState=inactive\nSubState=dead\nUnitFileState=disabled\nMainPID=0\n"
            };
            Ok(Output {
                status: std::process::ExitStatus::from_raw(
                    i32::from(self.fail.get() || (self.fail_start.get() && args[0] == "start"))
                        << 8,
                ),
                stdout: stdout.as_bytes().to_vec(),
                stderr: b"mock failure".to_vec(),
            })
        }
    }
    fn instance(name: &str) -> Instance {
        Instance {
            name: name.into(),
            role: Role::Server,
            executable: "/opt/hysteria".into(),
            config: "/etc/hysteria/server.yaml".into(),
            directory: "/etc/hysteria".into(),
        }
    }
    fn fixture() -> (tempfile::TempDir, Manager<Fake>) {
        let temp = tempfile::tempdir().unwrap();
        let manager = Manager {
            directory: temp.path().into(),
            runner: Fake::default(),
        };
        (temp, manager)
    }
    #[test]
    fn failed_start_retains_registration_and_prints_recovery_logs() {
        for immediate_exit in [false, true] {
            let (_temp, manager) = fixture();
            manager.runner.fail_start.set(!immediate_exit);
            manager.runner.inactive.set(immediate_exit);
            let error = manager
                .install(&instance("server"), false, false)
                .unwrap_err();
            assert!(error.to_string().contains("was registered"));
            assert_eq!(manager.select(None).unwrap().name, "server");
            assert!(manager.runner.calls.borrow().iter().any(|c| c[0] == "logs"));
            manager.uninstall(&instance("server")).unwrap();
            assert!(manager.instances().unwrap().is_empty());
        }
    }
    #[test]
    fn symlink_collision_does_not_change_target() {
        let (_temp, manager) = fixture();
        let target = manager.directory.join("keep");
        fs::write(&target, "untouched").unwrap();
        std::os::unix::fs::symlink(&target, manager.directory.join("hysteria-server.service"))
            .unwrap();
        assert!(manager.install(&instance("server"), true, true).is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
        assert!(manager.runner.calls.borrow().is_empty());
    }
    #[test]
    fn generated_unit_matches_linux_parser_fixture() {
        let instance = Instance {
            name: "fixture".into(),
            role: Role::Server,
            executable: "/bin/true".into(),
            config: "/tmp/a b/$NAME%test.yaml".into(),
            directory: "/tmp".into(),
        };
        assert_eq!(
            instance.render().unwrap(),
            include_str!("../tests/support/service/hysteria-fixture.service")
        );
    }
    #[test]
    fn escaping_prevents_unit_directives_specifiers_and_environment_expansion() {
        let path = Path::new("/opt/a b/%n/$HOME/\"quote\\file");
        assert_eq!(
            unit_path(path, true).unwrap(),
            "\"/opt/a b/%%n/$HOME/\\\"quote\\\\file\""
        );
        assert!(unit_path(Path::new("/bad\nExecStart=/bin/false"), true).is_err());
        assert!(unit_path(Path::new("relative"), true).is_err());
        for name in ["", "../main", "-evil", "a.service", "x\n", "名字"] {
            assert!(valid_name(name).is_err());
        }
        assert!(valid_name("edge-2_test").is_ok());
    }
    #[test]
    fn installation_validates_before_mutation_and_never_overwrites() {
        let (_temp, manager) = fixture();
        manager.runner.invalid.set(true);
        assert!(manager.install(&instance("server"), true, true).is_err());
        assert_eq!(fs::read_dir(&manager.directory).unwrap().count(), 0);
        assert_eq!(
            *manager.runner.calls.borrow(),
            vec![vec!["check".to_owned()]]
        );
        manager.runner.invalid.set(false);
        manager.install(&instance("server"), true, true).unwrap();
        let path = manager.directory.join("hysteria-server.service");
        let content = fs::read(&path).unwrap();
        assert!(manager.install(&instance("server"), false, false).is_err());
        assert_eq!(fs::read(&path).unwrap(), content);
        assert!(
            !manager
                .runner
                .calls
                .borrow()
                .iter()
                .any(|c| c[0] == "start" || c[0] == "enable")
        );
        assert_eq!(manager.select(None).unwrap().name, "server");
    }
    #[test]
    fn defaults_enable_then_start_and_failures_remain_recoverable() {
        let (_temp, manager) = fixture();
        manager.install(&instance("server"), false, false).unwrap();
        let calls = manager.runner.calls.borrow();
        let verbs: Vec<_> = calls.iter().map(|c| c[0].as_str()).collect();
        assert_eq!(
            &verbs[..5],
            &["check", "show", "daemon-reload", "enable", "start"]
        );
        drop(calls);
        manager.runner.fail.set(true);
        assert!(manager.uninstall(&instance("server")).is_err());
        assert_eq!(manager.instances().unwrap().len(), 1);
    }
    #[test]
    fn multiple_instances_require_selection_and_uninstall_preserves_config() {
        let (_temp, manager) = fixture();
        manager.install(&instance("server"), true, true).unwrap();
        let config = manager.directory.join("keep.yaml");
        fs::write(&config, "private configuration").unwrap();
        let mut backup = instance("backup");
        backup.config = config.clone();
        manager.install(&backup, true, true).unwrap();
        assert!(
            manager
                .select(None)
                .unwrap_err()
                .to_string()
                .contains("multiple instances")
        );
        let selected = manager.select(Some("backup")).unwrap();
        manager.uninstall(&selected).unwrap();
        assert_eq!(manager.select(None).unwrap().name, "server");
        assert_eq!(fs::read_to_string(config).unwrap(), "private configuration");
        let calls = manager.runner.calls.borrow();
        let tail: Vec<_> = calls.iter().rev().take(3).map(|c| c[0].as_str()).collect();
        assert_eq!(tail, ["daemon-reload", "disable", "stop"]);
    }
    #[test]
    fn invalid_restart_never_stops_running_instance() {
        let (_temp, manager) = fixture();
        manager.runner.invalid.set(true);
        assert!(
            manager
                .activate(&instance("server"), "restart", true)
                .is_err()
        );
        assert_eq!(
            *manager.runner.calls.borrow(),
            vec![vec!["check".to_owned()]]
        );
    }
    #[test]
    fn refuses_unmanaged_collisions_and_tampered_metadata() {
        let (_temp, manager) = fixture();
        manager.runner.existing.set(true);
        assert!(manager.install(&instance("server"), true, true).is_err());
        assert_eq!(fs::read_dir(&manager.directory).unwrap().count(), 0);
        manager.runner.existing.set(false);
        manager.install(&instance("server"), true, true).unwrap();
        let path = manager.directory.join("hysteria-server.service");
        fs::write(
            &path,
            format!("{}\n# edited", fs::read_to_string(&path).unwrap()),
        )
        .unwrap();
        assert!(manager.instances().is_err());
    }
}
