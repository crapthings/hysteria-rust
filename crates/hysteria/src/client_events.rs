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
}
/// A shared, ordered event writer. JSON uses stdout; text uses stderr.
/// Events contain fixed messages and codes, never configuration or peer error text.
#[derive(Clone)]
pub struct ClientEvents(Arc<Mutex<State>>);

#[derive(Serialize)]
struct Observation {
    schema_version: u8,
    sequence: u64,
    event: &'static str,
    message: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    component: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<&'static str>,
}
impl Default for ClientEvents {
    fn default() -> Self {
        Self::new(Format::Silent)
    }
}
impl ClientEvents {
    fn new(format: Format) -> Self {
        Self(Arc::new(Mutex::new(State {
            #[cfg(test)]
            recorded: Vec::new(),
            format,
            sequence: 0,
            stopping: false,
            broken: false,
        })))
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
        self.0.lock().unwrap().recorded.clone()
    }
    pub(crate) fn emit(
        &self,
        event: &'static str,
        component: Option<&'static str>,
        error_code: Option<&'static str>,
    ) {
        let Ok(mut state) = self.0.lock() else { return };
        if state.broken || (state.stopping && !matches!(event, "stopped" | "failed")) {
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
        };
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
