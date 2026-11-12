//! Versioned client lifecycle observations, separate from ordinary stderr diagnostics.
use serde::Serialize;
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
enum Format {
    Silent,
    Text,
    Json,
}
struct State {
    #[cfg(test)]
    recorded: Vec<&'static str>,
    format: Format,
    sequence: u64,
    stopping: bool,
    broken: bool,
    control_closed: bool,
}
/// A shared, ordered event writer. JSON uses stdout; text uses stderr.
/// Events contain fixed messages and codes, never configuration or peer error text.
#[derive(Clone)]
pub struct ClientEvents {
    state: Arc<Mutex<State>>,
    pub(crate) telemetry: Option<Arc<crate::client_control::Telemetry>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub schema_version: u8,
    pub sequence: u64,
    pub event: &'static str,
    pub message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub component: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_revision: Option<u64>,
}
impl Default for ClientEvents {
    fn default() -> Self {
        Self::new(Format::Silent)
    }
}
impl ClientEvents {
    fn new(format: Format) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                #[cfg(test)]
                recorded: Vec::new(),
                format,
                sequence: 0,
                stopping: false,
                broken: false,
                control_closed: false,
            })),
            telemetry: None,
        }
    }
    pub(crate) fn embedded(telemetry: Arc<crate::client_control::Telemetry>) -> Self {
        Self {
            telemetry: Some(telemetry),
            ..Self::default()
        }
    }
    /// Creates aligned terminal observations on stderr.
    #[must_use]
    pub fn text() -> Self {
        Self::new(Format::Text)
    }
    /// Creates schema-versioned NDJSON observations on stdout.
    #[must_use]
    pub fn json() -> Self {
        Self::new(Format::Json)
    }
    #[cfg(test)]
    pub(crate) fn recorded(&self) -> Vec<&'static str> {
        self.state.lock().unwrap().recorded.clone()
    }
    pub(crate) fn emit(
        &self,
        event: &'static str,
        component: Option<&'static str>,
        error_code: Option<&'static str>,
    ) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        self.emit_locked(&mut state, event, component, error_code, None);
    }
    pub(crate) fn request_shutdown(&self, stop: &tokio::sync::watch::Sender<bool>) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.control_closed = true;
        stop.send_replace(true);
    }
    pub(crate) fn apply_routing(
        &self,
        candidate: crate::client_routing::PreparedRouting,
        expected: u64,
    ) -> std::result::Result<u64, crate::client_routing::RoutingUpdateError> {
        use crate::client_routing::RoutingUpdateError;
        let mut state = self
            .state
            .lock()
            .map_err(|_| RoutingUpdateError::Internal)?;
        let telemetry = self
            .telemetry
            .as_ref()
            .ok_or(RoutingUpdateError::RoutingDisabled)?;
        if state.control_closed || state.stopping || !telemetry.is_running() {
            return Err(RoutingUpdateError::NotRunning);
        }
        telemetry.routing.apply(candidate, expected, |revision| {
            self.emit_locked(&mut state, "routing_updated", None, None, Some(revision));
        })
    }
    fn emit_locked(
        &self,
        state: &mut State,
        event: &'static str,
        component: Option<&'static str>,
        error_code: Option<&'static str>,
        routing_revision: Option<u64>,
    ) {
        if state.stopping && !matches!(event, "stopped" | "failed") {
            return;
        }
        if event == "stopping" || event == "stopped" {
            state.stopping = true;
        }
        state.sequence += 1;
        #[cfg(test)]
        state.recorded.push(event);
        let entry = Observation {
            schema_version: 1,
            sequence: state.sequence,
            event,
            message: message(event),
            component,
            error_code,
            routing_revision,
        };
        if let Some(telemetry) = &self.telemetry {
            telemetry.observe(&entry);
        }
        if state.broken {
            return;
        }
        let result = match state.format {
            Format::Silent => Ok(()),
            Format::Json => {
                let mut output = io::stdout().lock();
                serde_json::to_writer(&mut output, &entry)
                    .map_err(io::Error::other)
                    .and_then(|()| writeln!(output))
                    .and_then(|()| output.flush())
            }
            Format::Text => {
                let mut output = io::stderr().lock();
                let color = output.is_terminal()
                    && std::env::var_os("NO_COLOR").is_none()
                    && std::env::var("TERM").is_ok_and(|term| term != "dumb");
                let title = event.replace('_', " ").to_uppercase();
                let label = format!("{title:<20}");
                let label = if color {
                    let code = match event {
                        "connected" | "local_ready" => 32,
                        "failed" | "connection_failed" => 31,
                        "disconnected" => 33,
                        _ => 36,
                    };
                    format!("\x1b[{code}m{label}\x1b[0m")
                } else {
                    label
                };
                writeln!(
                    output,
                    "{label}  {}{}",
                    entry.message,
                    component.map_or_else(String::new, |part| format!(" ({part})"))
                )
            }
        };
        // A closed event consumer must not crash the proxy or produce an error flood.
        if result.is_err() {
            state.broken = true;
        }
    }
}
fn message(event: &str) -> &'static str {
    match event {
        "routing_updated" => "Routing rules updated for new flows",
        "starting" => "Starting client",
        "waiting_for_request" => "Server connection will start on the next proxy request",
        "local_ready" => "Local inbound ready; this does not verify server connectivity",
        "connecting" => "Connecting to the server",
        "connected" => "Server authenticated; remote forwarding is not yet verified",
        "connection_failed" => "Connection attempt failed; new requests may retry after one second",
        "connection_cancelled" => "Connection attempt cancelled",
        "disconnected" => "Server disconnected; reconnect on the next proxy request",
        "stopping" => "Stopping client",
        "stopped" => "Client stopped",
        "failed" => "Client failed; see stderr diagnostics",
        _ => "Client state changed",
    }
}
