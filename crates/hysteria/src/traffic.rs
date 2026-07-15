use crate::{CliError, Result};
use axum::{
    Router,
    body::Bytes,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use hysteria_transport::{StreamStats, StreamStatsSnapshot, TrafficLogger};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime},
};
use tokio::{net::TcpListener, task::JoinHandle};

const INDEX_HTML: &str = "<!DOCTYPE html><html lang=\"en\"><head> <meta charset=\"UTF-8\"> <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"> <title>Hysteria Traffic Stats API Server</title> <style>body{font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; padding: 0; background-color: #f4f4f4;}.container{padding: 20px; background-color: #fff; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); border-radius: 5px;}</style></head><body> <div class=\"container\"> <p>This is a Hysteria Traffic Stats API server.</p><p>Check the documentation for usage.</p></div></body></html>";

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct TrafficEntry {
    pub tx: u64,
    pub rx: u64,
}

#[derive(Debug, Default)]
struct TrafficState {
    stats: HashMap<String, TrafficEntry>,
    online: HashMap<String, usize>,
    kicked: HashSet<String>,
    streams: HashMap<(u32, u64), Arc<StreamStats>>,
}

#[derive(Debug, Clone)]
pub(crate) struct TrafficStats {
    state: Arc<Mutex<TrafficState>>,
    secret: Arc<str>,
}

impl TrafficStats {
    pub(crate) fn new(secret: impl Into<Arc<str>>) -> Self {
        Self {
            state: Arc::new(Mutex::new(TrafficState::default())),
            secret: secret.into(),
        }
    }

    pub(crate) async fn start_http(self, listen: &str) -> Result<TrafficStatsHttpServer> {
        let listener = TcpListener::bind(listen).await.map_err(|error| {
            CliError::new(format!(
                "failed to bind traffic stats server {listen}: {error}"
            ))
        })?;
        let address = listener.local_addr()?;
        let router = Router::new()
            .route("/", get(index))
            .route("/traffic", get(traffic))
            .route("/online", get(online))
            .route("/kick", post(kick))
            .route("/dump/streams", get(dump_streams))
            .with_state(self);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Ok(TrafficStatsHttpServer { address, task })
    }

    fn authorized(&self, headers: &HeaderMap) -> bool {
        self.secret.is_empty()
            || headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .is_some_and(|value| value == self.secret.as_ref())
    }
}

impl TrafficLogger for TrafficStats {
    fn log_traffic(&self, id: &str, tx: u64, rx: u64) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.kicked.remove(id) {
            return false;
        }
        let entry = state.stats.entry(id.to_owned()).or_default();
        entry.tx = entry.tx.wrapping_add(tx);
        entry.rx = entry.rx.wrapping_add(rx);
        true
    }

    fn log_online_state(&self, id: &str, online: bool) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if online {
            *state.online.entry(id.to_owned()).or_default() += 1;
        } else if let Some(count) = state.online.get_mut(id) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                state.online.remove(id);
            }
        }
    }

    fn trace_stream(&self, stats: Arc<StreamStats>) {
        let snapshot = stats.snapshot();
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .streams
            .insert((snapshot.connection_id, snapshot.stream_id), stats);
    }

    fn untrace_stream(&self, connection_id: u32, stream_id: u64) {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .streams
            .remove(&(connection_id, stream_id));
    }
}

pub(crate) struct TrafficStatsHttpServer {
    pub(crate) address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for TrafficStatsHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn index(State(service): State<TrafficStats>, headers: HeaderMap) -> Response {
    if !service.authorized(&headers) {
        return unauthorized();
    }
    axum::response::Html(INDEX_HTML).into_response()
}

async fn traffic(
    State(service): State<TrafficStats>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    if !service.authorized(&headers) {
        return unauthorized();
    }
    let clear = query.get("clear").is_some_and(|value| parse_go_bool(value));
    let snapshot = {
        let mut state = service.state.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = state.stats.clone();
        if clear {
            state.stats.clear();
        }
        snapshot
    };
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        axum::Json(snapshot),
    )
        .into_response()
}

async fn online(State(service): State<TrafficStats>, headers: HeaderMap) -> Response {
    if !service.authorized(&headers) {
        return unauthorized();
    }
    let snapshot = service
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .online
        .clone();
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        axum::Json(snapshot),
    )
        .into_response()
}

async fn kick(State(service): State<TrafficStats>, headers: HeaderMap, body: Bytes) -> Response {
    if !service.authorized(&headers) {
        return unauthorized();
    }
    let Ok(ids) = serde_json::from_slice::<Vec<String>>(&body) else {
        return (StatusCode::BAD_REQUEST, "invalid JSON request body\n").into_response();
    };
    service
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .kicked
        .extend(ids);
    StatusCode::OK.into_response()
}

#[derive(Debug, Serialize)]
struct DumpStreamEntry {
    state: String,
    auth: String,
    connection: u32,
    stream: u64,
    req_addr: String,
    hooked_req_addr: String,
    tx: u64,
    rx: u64,
    initial_at: String,
    last_active_at: String,
    #[serde(skip)]
    initial_time: SystemTime,
    #[serde(skip)]
    last_active_time: SystemTime,
}

impl From<StreamStatsSnapshot> for DumpStreamEntry {
    fn from(snapshot: StreamStatsSnapshot) -> Self {
        Self {
            state: snapshot.state.as_str().to_owned(),
            auth: snapshot.auth_id,
            connection: snapshot.connection_id,
            stream: snapshot.stream_id,
            req_addr: snapshot.request_address,
            hooked_req_addr: snapshot.hooked_request_address,
            tx: snapshot.tx,
            rx: snapshot.rx,
            initial_at: format_rfc3339_nanos_local(snapshot.initial_at),
            last_active_at: format_rfc3339_nanos_local(snapshot.last_active_at),
            initial_time: snapshot.initial_at,
            last_active_time: snapshot.last_active_at,
        }
    }
}

impl DumpStreamEntry {
    fn text_line(&self, now: SystemTime) -> String {
        let state = self.state.to_ascii_uppercase();
        let connection = format!("{:08X}", self.connection);
        let request = nonempty_or_dash(&self.req_addr);
        let hooked = nonempty_or_dash(&self.hooked_req_addr);
        let lifetime = format_go_elapsed(elapsed(now, self.initial_time));
        let last_active = format_go_elapsed(elapsed(now, self.last_active_time));
        format_dump_stream_line(
            &state,
            &self.auth,
            &connection,
            &self.stream.to_string(),
            request,
            hooked,
            &self.tx.to_string(),
            &self.rx.to_string(),
            &lifetime,
            &last_active,
        )
    }
}

#[derive(Serialize)]
struct DumpStreamsResponse {
    streams: Vec<DumpStreamEntry>,
}

async fn dump_streams(State(service): State<TrafficStats>, headers: HeaderMap) -> Response {
    if !service.authorized(&headers) {
        return unauthorized();
    }
    let mut entries = service
        .state
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .streams
        .values()
        .map(|stats| stats.snapshot().into())
        .collect::<Vec<DumpStreamEntry>>();
    entries.sort_unstable_by(|left, right| {
        (&left.auth, left.connection, left.stream).cmp(&(
            &right.auth,
            right.connection,
            right.stream,
        ))
    });
    let wants_text = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/plain"));
    if wants_text {
        return dump_streams_text(&entries);
    }
    let mut body = serde_json::to_vec(&DumpStreamsResponse { streams: entries })
        .expect("stream dump values are JSON serializable");
    body.push(b'\n');
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/json; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

fn dump_streams_text(entries: &[DumpStreamEntry]) -> Response {
    let mut body = format_dump_stream_line(
        "State",
        "Auth",
        "Connection",
        "Stream",
        "Req-Addr",
        "Hooked-Req-Addr",
        "TX-Bytes",
        "RX-Bytes",
        "Lifetime",
        "Last-Active",
    );
    body.push('\n');
    let now = SystemTime::now();
    for entry in entries {
        body.push_str(&entry.text_line(now));
        body.push('\n');
    }
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

#[allow(clippy::too_many_arguments)]
fn format_dump_stream_line(
    state: &str,
    auth: &str,
    connection: &str,
    stream: &str,
    request: &str,
    hooked: &str,
    tx: &str,
    rx: &str,
    lifetime: &str,
    last_active: &str,
) -> String {
    format!(
        "{state:<8} {auth:<12} {connection:>12} {stream:>8} {tx:>12} {rx:>12} {lifetime:>12} {last_active:>12} {request:<16} {hooked}"
    )
}

fn nonempty_or_dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

fn elapsed(now: SystemTime, earlier: SystemTime) -> Duration {
    now.duration_since(earlier).unwrap_or(Duration::ZERO)
}

fn format_rfc3339_nanos_local(time: SystemTime) -> String {
    let local = chrono::DateTime::<chrono::Local>::from(time);
    if local.timestamp_subsec_nanos() == 0 {
        return local.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    }
    let mut value = local.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let zone_start = value[20..]
        .find(['+', '-', 'Z'])
        .map_or(value.len(), |index| index + 20);
    let fractional_end = value[..zone_start].trim_end_matches('0').len();
    value.replace_range(fractional_end..zone_start, "");
    value
}

fn format_go_elapsed(duration: Duration) -> String {
    let unit_nanos = if duration < Duration::from_secs(600) {
        1_000_000_u128
    } else {
        1_000_000_000
    };
    let rounded_nanos = (duration.as_nanos() + unit_nanos / 2) / unit_nanos * unit_nanos;
    format_go_duration(rounded_nanos)
}

fn format_go_duration(nanos: u128) -> String {
    if nanos == 0 {
        return "0s".to_owned();
    }
    if nanos < 1_000_000_000 {
        return format!("{}ms", nanos / 1_000_000);
    }
    let total_seconds = nanos / 1_000_000_000;
    let fractional = nanos % 1_000_000_000;
    let hours = total_seconds / 3600;
    let minutes = total_seconds % 3600 / 60;
    let seconds = total_seconds % 60;
    let seconds = if fractional == 0 {
        format!("{seconds}s")
    } else {
        let fractional = format!("{fractional:09}");
        format!("{seconds}.{}s", fractional.trim_end_matches('0'))
    };
    match (hours, minutes) {
        (0, 0) => seconds,
        (0, _) => format!("{minutes}m{seconds}"),
        _ => format!("{hours}h{minutes}m{seconds}"),
    }
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response()
}

fn parse_go_bool(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[tokio::test]
    async fn serves_compatible_traffic_online_clear_and_kick_api() {
        crate::tls::ensure_crypto_provider();
        let stats = TrafficStats::new("top-secret");
        stats.log_online_state("alice", true);
        assert!(stats.log_traffic("alice", 12, 7));
        let server = stats.clone().start_http("127.0.0.1:0").await.unwrap();
        let client = reqwest::Client::new();
        let root = format!("http://{}", server.address);

        assert_eq!(
            client
                .get(format!("{root}/traffic"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let traffic = client
            .get(format!("{root}/traffic?clear=true"))
            .header("Authorization", "top-secret")
            .send()
            .await
            .unwrap()
            .json::<HashMap<String, TrafficEntry>>()
            .await
            .unwrap();
        assert_eq!(traffic["alice"], TrafficEntry { tx: 12, rx: 7 });
        let cleared = client
            .get(format!("{root}/traffic"))
            .header("Authorization", "top-secret")
            .send()
            .await
            .unwrap()
            .json::<HashMap<String, TrafficEntry>>()
            .await
            .unwrap();
        assert!(cleared.is_empty());

        let online = client
            .get(format!("{root}/online"))
            .header("Authorization", "top-secret")
            .send()
            .await
            .unwrap()
            .json::<HashMap<String, usize>>()
            .await
            .unwrap();
        assert_eq!(online["alice"], 1);
        let dump = client
            .get(format!("{root}/dump/streams"))
            .header("Authorization", "top-secret")
            .send()
            .await
            .unwrap();
        assert_eq!(
            dump.headers()[reqwest::header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        assert_eq!(dump.text().await.unwrap(), "{\"streams\":[]}\n");
        assert_eq!(
            client
                .post(format!("{root}/kick"))
                .header("Authorization", "top-secret")
                .json(&vec!["alice"])
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert!(!stats.log_traffic("alice", 1, 0));
        assert!(stats.log_traffic("alice", 1, 0));
    }

    #[test]
    fn formats_go_style_elapsed_durations() {
        assert_eq!(format_go_elapsed(Duration::ZERO), "0s");
        assert_eq!(format_go_elapsed(Duration::from_micros(499)), "0s");
        assert_eq!(format_go_elapsed(Duration::from_micros(500)), "1ms");
        assert_eq!(format_go_elapsed(Duration::from_millis(1_234)), "1.234s");
        assert_eq!(format_go_elapsed(Duration::from_millis(61_234)), "1m1.234s");
        assert_eq!(format_go_elapsed(Duration::from_secs(600)), "10m0s");
        assert_eq!(format_go_elapsed(Duration::from_secs(3_661)), "1h1m1s");
    }

    #[test]
    fn formats_rfc3339_nanos_with_local_offset_and_trimmed_fraction() {
        let formatted = format_rfc3339_nanos_local(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_micros(123_400),
        );
        assert!(formatted.contains(".1234"));
        assert!(!formatted.contains(".123400"));
        assert!(
            formatted.ends_with('Z')
                || formatted[19..].contains('+')
                || formatted[19..].contains('-')
        );
    }

    #[test]
    fn formats_netstat_columns_in_go_order() {
        let line = format_dump_stream_line(
            "ESTAB",
            "alice",
            "12AB34CD",
            "7",
            "example.com:443",
            "-",
            "12",
            "34",
            "1.234s",
            "5ms",
        );
        assert_eq!(
            line,
            "ESTAB    alice            12AB34CD        7           12           34       1.234s          5ms example.com:443  -"
        );
    }
}
