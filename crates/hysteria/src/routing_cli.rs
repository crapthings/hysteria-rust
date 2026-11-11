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
            "configuration_check":true, "route_explain":true,
            "routing":{"version":1,"actions":["proxy","direct","reject"],"matchers":["domain","suffix","ip","cidr","lan","loopback","all"],"protocols":["tcp","udp"],"inbounds":if cfg!(target_os="linux") { vec!["socks5","http","tcpForwarding","udpForwarding","tun"] } else { vec!["socks5","http","tcpForwarding","udpForwarding"] },"dns_for_matching":false,"process_matching":false,"geoip":false,"geosite":false,"live_reload":false},
            "tun":{"compiled":cfg!(any(target_os="linux", target_os="macos", target_os="windows")),"routing_supported":cfg!(target_os="linux"),"fake_dns":cfg!(target_os="linux"),"system_dns_configuration":false,"permission_check":"not_performed"},
            "control":{"transport":"cli-json","persistent_ipc":false,"events":false,"configuration_apply":false,"privileged_helper":false}
        });
        match self.output {
            OutputFormat::Json => write_json(&report),
            OutputFormat::Text => {
                println!(
                    "Client capabilities\n  Platform          {}\n  API schema        1\n  Routing           v1: proxy / direct / reject\n  Entries           SOCKS5, HTTP, TCP/UDP forwarding\n  GUI integration   CLI JSON: check client / route explain\n  Process routing   Not available\n  TUN routing       {}\n  Live control IPC  Not available\n  Permissions       Not checked",
                    std::env::consts::OS,
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
    /// Explain a destination using the live routing algorithm, without DNS or traffic.
    Explain {
        /// Destination hostname/IP with a port; bracket IPv6 addresses.
        destination: String,
        #[arg(long, value_enum, default_value = "tcp")]
        protocol: Protocol,
        #[arg(long, value_enum, default_value = "text")]
        output: OutputFormat,
    },
}
impl RouteOptions {
    pub(crate) fn run(&self, path: &Path) -> Result<ExitCode> {
        let RouteCommand::Explain {
            destination,
            protocol,
            output,
        } = &self.command;
        let result = (|| {
            let config = ClientConfig::load(path)?;
            config.validate()?;
            let default = RoutingConfig {
                version: 1,
                default: Action::Proxy,
                rules: Vec::new(),
            };
            if config.tun.as_ref().is_some_and(|tun| tun.dns.is_some()) {
                let host = destination
                    .rsplit_once(':')
                    .map_or(destination.as_str(), |(host, _)| host)
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
            let router = Router::compile(config.routing.as_ref().unwrap_or(&default))?;
            let mut decision = router.decide(destination, *protocol)?;
            if config.routing.is_none() {
                decision.reason = "routing_disabled";
            }
            Ok(decision)
        })();
        match result {
            Ok(decision) => {
                match output {
                    OutputFormat::Json => write_json(&decision)?,
                    OutputFormat::Text => println!(
                        "Offline route decision\n  Destination  {destination}\n  Protocol     {:?}\n  Outbound     {:?}\n  Rule         {}\n  Reason       {}\n  DNS lookup   Not performed",
                        protocol,
                        decision.outbound,
                        decision
                            .matched_rule
                            .map_or_else(|| "default".into(), |n| n.to_string()),
                        decision.reason
                    ),
                }
                Ok(ExitCode::SUCCESS)
            }
            Err(error) => {
                let error = CliError::configuration(error);
                match output {
                    OutputFormat::Json => write_json(
                        &serde_json::json!({"schema_version":1,"error":{"code":error.code().as_str(),"message":error.to_string()}}),
                    )?,
                    OutputFormat::Text => eprintln!("{}", error.report(false)),
                }
                Ok(ExitCode::from(3))
            }
        }
    }
}
fn write_json(value: &impl serde::Serialize) -> Result<()> {
    let mut output = io::stdout().lock();
    serde_json::to_writer(&mut output, value)
        .map_err(|error| CliError::new(format!("cannot write JSON: {error}")))?;
    writeln!(output)?;
    Ok(())
}
