//! Versioned, process-based GUI integration: capabilities and offline route explanation.
use crate::check::OutputFormat;
use clap::{Args, Subcommand};
use hysteria_cli::{
    CliError, Result,
    config::ClientConfig,
    routing::{Action, Protocol, Router, RoutingConfig},
};
use std::{
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

#[derive(Debug, Args)]
pub(crate) struct CapabilitiesOptions {
    #[arg(long, value_enum, default_value = "json")]
    output: OutputFormat,
}
impl CapabilitiesOptions {
    pub(crate) fn run(&self) -> Result<()> {
        let report = serde_json::json!({
            "schema_version":1, "core_version":env!("CARGO_PKG_VERSION"), "platform":std::env::consts::OS,
            "dns_capture_probe":cfg!(target_os="linux"), "configuration_check":true, "route_explain":true, "route_trace":true, "route_lint":true, "routing_templates":["proxy-all","lan-bypass","block-udp443"],
            "profiles":{"schema_version":1,"scope":"user","implicit_default":false,"import_source":"stdin-uri"},
            "routing":{"version":1,"actions":["proxy","direct","reject"],"matchers":["domain","suffix","ip","cidr","lan","loopback","all","set"],"protocols":["tcp","udp"],"inbounds":if cfg!(target_os="linux") { vec!["socks5","http","tcpForwarding","udpForwarding","tun"] } else { vec!["socks5","http","tcpForwarding","udpForwarding"] },"local_rule_sets":true,"remote_rule_sets":false,"dns_for_matching":false,"process_matching":cfg!(target_os="macos"),"process_inbounds":if cfg!(target_os="macos") { vec!["http-tcp","socks5-tcp"] } else { vec![] },"process_matchers":["process-name","process-path"],"process_unknown":"reject","process_tun":false,"process_udp":false,"geoip":false,"geosite":false,"live_reload":true},
            "socket_options":{"bind_interface":cfg!(any(target_os="linux", target_os="macos")),"fwmark":cfg!(target_os="linux"),"fd_control_unix_socket":cfg!(target_os="linux"),"protects_system_dns":false,"interface_loss_stops_client":cfg!(target_os="macos")},
            "tun":{"session_tracking":cfg!(target_os="macos"),"parent_loss_shutdown":cfg!(target_os="macos"),"route_journal":cfg!(target_os="macos"),"route_recovery":cfg!(target_os="macos"),"compiled":cfg!(any(target_os="linux", target_os="macos", target_os="windows")),"routing_supported":cfg!(target_os="linux"),"fake_dns":cfg!(target_os="linux"),"system_dns_configuration":false,"read_only_preflight":cfg!(target_os="linux"),"permission_check":"not_performed"},
            "control":{"transport":"cli-json","stdio":crate::client_stdio::capabilities(),"routing_apply":true,"persistent_ipc":false,"events":true,"event_transport":"stdout-ndjson","event_schema_version":1,"configuration_apply":false,"privileged_helper":false,"embedded":{"api_version":1,"tcp_connections":true,"traffic_sample":true,"status":true,"routing_stats":true,"events":true,"shutdown":true,"routing_apply":true,"routing_explain":true,"routing_history":true}}
        });
        match self.output {
            OutputFormat::Json => write_json(&report),
            OutputFormat::Text => {
                println!(
                    "Client capabilities\n  Platform          {}\n  API schema        1\n  Routing           v1: proxy / direct / reject\n  Entries           SOCKS5, HTTP, TCP/UDP forwarding\n  GUI integration   client --control stdio; offline check / route explain\n  Process routing   {}\n  TUN routing       {}\n  Live control      Owned stdin/stdout JSON session\n  Permissions       Not checked",
                    std::env::consts::OS,
                    if cfg!(target_os = "macos") {
                        "Local HTTP/SOCKS TCP (exact name/path)"
                    } else {
                        "Not available"
                    },
                    if cfg!(target_os = "linux") {
                        "Protected Linux egress"
                    } else {
                        "Not available"
                    }
                );
                Ok(())
            }
        }
    }
}
#[derive(Debug, Args)]
pub(crate) struct RouteOptions {
    #[command(subcommand)]
    command: RouteCommand,
}
#[derive(Debug, Subcommand)]
enum RouteCommand {
    /// Print a routing-only configuration fragment; never edit a file or start networking.
    Template {
        #[arg(value_enum)]
        preset: Preset,
        #[arg(long, value_enum, default_value = "yaml")]
        output: TemplateFormat,
    },
    /// Report rules fully covered by one earlier rule; never reorder or apply changes.
    Lint {
        /// Exit 3 when warnings are found (default: warnings do not fail).
        #[arg(long)]
        strict: bool,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
    /// Explain a destination using the live routing algorithm, without DNS or traffic.
    Explain {
        /// Destination hostname/IP with a port; bracket IPv6 addresses.
        destination: String,
        #[arg(long, value_enum, default_value = "tcp")]
        protocol: Protocol,
        /// Show why earlier rules did not match; later rules are marked not evaluated.
        #[arg(long)]
        trace: bool,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
}
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum Preset {
    ProxyAll,
    LanBypass,
    BlockUdp443,
}
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum TemplateFormat {
    Yaml,
    Json,
}
#[derive(serde::Serialize)]
struct Explanation {
    #[serde(flatten)]
    decision: hysteria_cli::routing::Decision,
    routing_enabled: bool,
    rules_total: usize,
    matched_rule_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_rule_set: Option<hysteria_cli::routing::RuleSetMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace: Option<Vec<TraceLine>>,
}
#[derive(serde::Serialize)]
struct TraceLine {
    #[serde(flatten)]
    step: hysteria_cli::routing::RuleTrace,
    text: String,
}
impl RouteOptions {
    pub(crate) fn uses_config(&self) -> bool {
        !matches!(self.command, RouteCommand::Template { .. })
    }
    pub(crate) fn run(&self, path: &Path) -> Result<ExitCode> {
        match &self.command {
            RouteCommand::Template { preset, output } => {
                template(*preset, *output)?;
                Ok(ExitCode::SUCCESS)
            }
            RouteCommand::Lint { strict, output } => lint(path, *strict, *output),
            RouteCommand::Explain {
                destination,
                protocol,
                trace,
                output,
            } => {
                let result = explain(path, destination, *protocol, *trace);
                match result {
                    Ok(report) => {
                        match output {
                            OutputFormat::Json => write_json(&report)?,
                            OutputFormat::Text => print_explanation(&report)?,
                        }
                        Ok(ExitCode::SUCCESS)
                    }
                    Err(error) => failure(error, *output),
                }
            }
        }
    }
}
fn routing(config: &ClientConfig) -> RoutingConfig {
    config.routing.clone().unwrap_or(RoutingConfig {
        rule_sets: std::collections::BTreeMap::new(),
        version: 1,
        default: Action::Proxy,
        rules: vec![],
    })
}
fn template(preset: Preset, output: TemplateFormat) -> Result<()> {
    let (rules, note) = match preset {
        Preset::ProxyAll => (
            vec![],
            "Send all requests through the configured Hysteria server.",
        ),
        Preset::LanBypass => (
            vec!["direct(lan)", "direct(loopback)", "direct(localhost)"],
            "Bypass literal private/loopback addresses and localhost. Domains resolving to private IPs need explicit domain rules; matching does not query DNS.",
        ),
        Preset::BlockUdp443 => (
            vec!["reject(all, udp/443)"],
            "Block UDP port 443 only. This is not a block of every QUIC endpoint and does not guarantee TCP fallback.",
        ),
    };
    let config = RoutingConfig {
        rule_sets: std::collections::BTreeMap::new(),
        version: 1,
        default: Action::Proxy,
        rules: rules.into_iter().map(str::to_owned).collect(),
    };
    Router::compile(&config)?;
    let fragment = serde_json::json!({"routing":config});
    match output {
        TemplateFormat::Json => write_json(&fragment),
        TemplateFormat::Yaml => {
            let mut out = io::stdout().lock();
            writeln!(
                out,
                "# Routing fragment only; merge into a client configuration after review."
            )?;
            writeln!(out, "# {note}")?;
            writeln!(
                out,
                "{}",
                serde_yaml_ng::to_string(&fragment)
                    .map_err(|_| CliError::new("cannot serialize routing template"))?
                    .trim_end()
            )?;
            Ok(())
        }
    }
}
fn lint(path: &Path, strict: bool, output: OutputFormat) -> Result<ExitCode> {
    let result = (|| {
        let config = ClientConfig::load(path)?;
        config.validate()?;
        let settings = routing(&config);
        let router = Router::compile(&settings)?;
        Ok::<_, CliError>((
            config.routing.is_some(),
            settings.rules.len(),
            router.shadow_warnings(),
        ))
    })();
    let (enabled, total, warnings) = match result {
        Ok(value) => value,
        Err(error) => return failure(error, output),
    };
    match output {
        OutputFormat::Json => write_json(
            &serde_json::json!({"schema_version":1,"routing_version":1,"routing_enabled":enabled,"rules_total":total,"valid":true,"strict":strict,"analysis":"single_rule_full_coverage","warnings":warnings}),
        )?,
        OutputFormat::Text => {
            let mut out = io::stdout().lock();
            writeln!(out, "Offline routing review")?;
            writeln!(out, "  Rules       {total}")?;
            if !enabled {
                writeln!(out, "  Routing     Disabled; requests use proxy")?;
            }
            if warnings.is_empty() {
                writeln!(out, "  Findings    No provably shadowed rules found")?;
            }
            for warning in &warnings {
                let status = highlight(&out, "WARN", 33);
                writeln!(
                    out,
                    "  {status}  Rule #{:<4} is fully covered by rule #{} ({} → {})",
                    warning.rule,
                    warning.covered_by,
                    action(warning.action),
                    action(warning.covering_action)
                )?;
            }
            writeln!(
                out,
                "Only full coverage by a single earlier rule is checked. No configuration changed."
            )?;
        }
    }
    Ok(if strict && !warnings.is_empty() {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    })
}
fn explain(path: &Path, destination: &str, protocol: Protocol, trace: bool) -> Result<Explanation> {
    let config = ClientConfig::load(path)?;
    config.validate()?;
    if config.tun.as_ref().is_some_and(|tun| tun.dns.is_some()) {
        let host = destination
            .rsplit_once(':')
            .map_or(destination, |(host, _)| host)
            .trim_matches(['[', ']']);
        if host
            .parse()
            .is_ok_and(hysteria_cli::fake_dns::is_fake_address)
        {
            return Err(CliError::new(
                "explain the original domain; live Fake-IP mapping is not queried by offline route explain",
            ));
        }
    }
    let settings = routing(&config);
    let router = Router::compile(&settings)?;
    let mut decision = router.decide(destination, protocol)?;
    if config.routing.is_none() {
        decision.reason = "routing_disabled";
    }
    let matched_rule_set = router.matched_rule_set(&decision);
    let matched_rule_text = decision
        .matched_rule
        .map(|index| settings.rules[index - 1].clone());
    let trace = if trace {
        Some(
            router
                .trace(destination, protocol)?
                .into_iter()
                .map(|step| TraceLine {
                    text: settings.rules[step.rule - 1].clone(),
                    step,
                })
                .collect(),
        )
    } else {
        None
    };
    Ok(Explanation {
        decision,
        routing_enabled: config.routing.is_some(),
        rules_total: settings.rules.len(),
        matched_rule_text,
        matched_rule_set,
        trace,
    })
}
fn print_explanation(report: &Explanation) -> Result<()> {
    let mut out = io::stdout().lock();
    let decision = &report.decision;
    let host = if decision.host.contains(':') {
        format!("[{}]", decision.host)
    } else {
        decision.host.clone()
    };
    let color = match decision.outbound {
        Action::Proxy => 36,
        Action::Direct => 32,
        Action::Reject => 31,
    };
    let choice = highlight(&out, action(decision.outbound), color);
    writeln!(
        out,
        "Offline route decision\n  Destination  {host}:{}\n  Protocol     {}\n  Outbound     {choice}",
        decision.port,
        match decision.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    )?;
    if let (Some(index), Some(text)) = (decision.matched_rule, &report.matched_rule_text) {
        writeln!(out, "  Rule         #{index} {}", one_line(text))?;
        writeln!(
            out,
            "  Reason       First matching rule; later rules are not evaluated"
        )?;
    } else {
        writeln!(
            out,
            "  Rule         Default\n  Reason       {}",
            if report.routing_enabled {
                "No rule matched; using routing.default"
            } else {
                "Client routing is disabled; using proxy"
            }
        )?;
    }
    if let Some(source) = &report.matched_rule_set {
        writeln!(out, "  Rule set     {}", one_line(&source.name))?;
        writeln!(
            out,
            "  Source       {}:{}",
            one_line(&source.file),
            source.line
        )?;
    }
    writeln!(
        out,
        "  DNS lookup   Not performed\n  Scope        Supplied configuration; not the running process"
    )?;
    if decision.host.parse::<std::net::IpAddr>().is_err() {
        writeln!(
            out,
            "IP/CIDR/lan rules do not resolve this domain. Add a domain rule when needed."
        )?;
    }
    if let Some(trace) = &report.trace {
        writeln!(out, "\nRule evaluation")?;
        for line in trace {
            writeln!(
                out,
                "  #{:<4} {:<20} {}",
                line.step.rule,
                line.step.outcome.replace('_', " "),
                one_line(&line.text)
            )?;
        }
    }
    Ok(())
}
fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}
fn action(value: Action) -> &'static str {
    match value {
        Action::Proxy => "proxy",
        Action::Direct => "direct",
        Action::Reject => "reject",
    }
}
fn highlight(out: &impl std::io::IsTerminal, text: &str, color: u8) -> String {
    if out.is_terminal()
        && std::env::var_os("NO_COLOR").is_none()
        && std::env::var("TERM").is_ok_and(|term| term != "dumb")
    {
        format!("\x1b[{color}m{text}\x1b[0m")
    } else {
        text.to_owned()
    }
}
fn failure(error: CliError, output: OutputFormat) -> Result<ExitCode> {
    let error = CliError::configuration(error);
    match output {
        OutputFormat::Json => write_json(
            &serde_json::json!({"schema_version":1,"error":{"code":error.code().as_str(),"message":error.to_string()}}),
        )?,
        OutputFormat::Text => eprintln!("{}", error.report(false)),
    }
    Ok(ExitCode::from(3))
}
fn write_json(value: &impl serde::Serialize) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, value)
        .map_err(|error| CliError::new(format!("cannot write JSON: {error}")))?;
    writeln!(output)?;
    Ok(())
}
