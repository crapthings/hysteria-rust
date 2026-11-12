//! Owned child-process control transport. Blocking OS pipes live on dedicated threads,
//! never Tokio's blocking pool (which would wait for an uncancellable stdin read).
use hysteria_cli::{
    CliError, Result,
    client_control::{ClientControl, ClientRuntime, PreparedRouting, RoutingUpdateError},
    config::ClientConfig,
    routing::{Protocol, RoutingConfig},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    future::Future,
    io::{self, BufRead, Write},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::{broadcast, mpsc, oneshot};

const MAX_REQUEST: usize = 1024 * 1024;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const INPUT_QUEUE: usize = 4;
const OUTPUT_QUEUE: usize = 8;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const HEARTBEAT: Duration = Duration::from_secs(2);
const MAX_ID: u64 = 9_007_199_254_740_991;

pub(crate) fn capabilities() -> Value {
    json!({"schema_version":1,"transport":"stdio-ndjson","methods":["status","traffic.sample","routing.stats","routing.history","routing.explain","routing.validate","routing.apply","events.subscribe","shutdown"],"max_request_bytes":MAX_REQUEST,"max_response_bytes":MAX_RESPONSE,"input_queue":INPUT_QUEUE,"output_queue":OUTPUT_QUEUE,"write_timeout_ms":5000,"heartbeat_interval_ms":2000,"automatic_events":true,"routing_apply":true})
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub(crate) enum ControlMode {
    Stdio,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    id: u64,
    method: String,
    #[serde(default = "empty_params")]
    params: Value,
}
fn empty_params() -> Value {
    json!({})
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Validate {
    routing: RoutingConfig,
    #[serde(default)]
    base_directory: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Apply {
    prepared_id: u64,
    expected_revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Explain {
    address: String,
    protocol: Protocol,
}

struct Session {
    last_id: u64,
    prepared: Option<(u64, PreparedRouting)>,
}
fn failure(id: Option<u64>, code: &str, message: &str) -> Value {
    json!({"schema_version":1,"type":"response","id":id,"error":{"code":code,"message":message}})
}
fn success(id: u64, result: Value) -> Value {
    let mut response = json!({"schema_version":1,"type":"response","id":id});
    response["result"] = result;
    response
}
fn params<T: serde::de::DeserializeOwned>(id: u64, value: Value) -> std::result::Result<T, Value> {
    if !value.is_object() {
        return Err(failure(
            Some(id),
            "invalid_params",
            "Method parameters must be an object",
        ));
    }
    serde_json::from_value(value)
        .map_err(|_| failure(Some(id), "invalid_params", "Invalid method parameters"))
}
impl Session {
    async fn dispatch(
        &mut self,
        request: Request,
        control: &ClientControl,
    ) -> std::result::Result<Value, Value> {
        let id = request.id;
        if id == 0 || id > MAX_ID || id <= self.last_id {
            return Err(failure(
                Some(id),
                "invalid_id",
                "IDs must increase and be integers from 1 through 9007199254740991",
            ));
        }
        self.last_id = id;
        if request.schema_version != 1 {
            return Err(failure(
                Some(id),
                "unsupported_version",
                "Supported schema_version is 1",
            ));
        }
        match request.method.as_str() {
            "status" | "traffic.sample" | "routing.stats" | "routing.history"
            | "events.subscribe" | "shutdown" => {
                let _: Empty = params(id, request.params)?;
                Ok(match request.method.as_str() {
                    "status" => json!(control.status()),
                    "traffic.sample" => json!(control.traffic_sample()),
                    "routing.stats" => json!(control.routing_stats()),
                    "routing.history" => json!({"revisions":control.routing_history()}),
                    // Events are automatic for the lifetime of this control process.
                    "events.subscribe" => json!({"subscribed":true,"status":control.status()}),
                    _ => json!({"shutdown_requested":true}),
                })
            }
            "routing.explain" => {
                let p: Explain = params(id, request.params)?;
                control
                    .routing_explain(&p.address, p.protocol)
                    .map(|r| json!(r))
                    .map_err(|_| {
                        failure(
                            Some(id),
                            "explain_failed",
                            "Routing is disabled or destination is invalid",
                        )
                    })
            }
            "routing.validate" => {
                if request
                    .params
                    .get("routing")
                    .is_some_and(|value| !value.is_object())
                {
                    return Err(failure(
                        Some(id),
                        "invalid_params",
                        "routing must be an object",
                    ));
                }
                let p: Validate = params(id, request.params)?;
                let candidate=PreparedRouting::load(p.routing,p.base_directory).await
                    .map_err(|_|failure(Some(id),"invalid_routing","Check routing syntax, limits and local rule-set files; nothing was applied"))?;
                let reply = json!({"prepared_id":id,"warnings":candidate.warnings()});
                self.prepared = Some((id, candidate));
                Ok(reply)
            }
            "routing.apply" => {
                let p: Apply = params(id, request.params)?;
                if self
                    .prepared
                    .as_ref()
                    .is_none_or(|(token, _)| *token != p.prepared_id)
                {
                    return Err(failure(
                        Some(id),
                        "unknown_prepared",
                        "Prepare a routing candidate with routing.validate first",
                    ));
                }
                let (_, candidate) = self.prepared.take().expect("candidate checked above");
                control
                    .apply_routing(candidate, p.expected_revision)
                    .map(|revision| json!({"revision":revision}))
                    .map_err(|error| apply_failure(id, error))
            }
            _ => Err(failure(
                Some(id),
                "unknown_method",
                "Unsupported control method",
            )),
        }
    }
}
fn apply_failure(id: u64, error: RoutingUpdateError) -> Value {
    let mut details = serde_json::to_value(error).expect("routing error is serializable");
    details["message"] =
        json!("Routing update rejected; inspect the error code and query current status");
    json!({"schema_version":1,"type":"response","id":id,"error":details})
}

async fn send(output: &mpsc::Sender<Vec<u8>>, value: &Value) -> Result<()> {
    let mut bytes =
        serde_json::to_vec(value).map_err(|_| CliError::new("control output encoding failed"))?;
    if bytes.len() >= MAX_RESPONSE {
        return Err(CliError::new("control response exceeds size limit"));
    }
    bytes.push(b'\n');
    output
        .send(bytes)
        .await
        .map_err(|_| CliError::new("control output closed"))
}
async fn forward_events(
    mut events: broadcast::Receiver<hysteria_cli::client_events::Observation>,
    output: mpsc::Sender<Vec<u8>>,
    control: ClientControl,
) -> Result<()> {
    let mut heartbeat =
        tokio::time::interval_at(tokio::time::Instant::now() + HEARTBEAT, HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let (value, stopped) = tokio::select! {
            event=events.recv()=>match event {
                Ok(event)=>{
                    let stopped=event.event=="stopped";
                    (json!({"schema_version":1,"type":"event","event":event}),stopped)
                },
                Err(broadcast::error::RecvError::Lagged(missed))=>(json!({"schema_version":1,"type":"event","event":{"event":"events_lagged","missed":missed,"status":control.status()}}),false),
                Err(broadcast::error::RecvError::Closed)=>return Ok(()),
            },
            _=heartbeat.tick()=>{
                let status=control.status();
                (json!({"schema_version":1,"type":"heartbeat","instance_id":status.instance_id,"latest_event_sequence":status.sequence}),false)
            }
        };
        send(&output, &value).await?;
        if stopped {
            return Ok(());
        }
    }
}
async fn requests(
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    control: ClientControl,
) -> Result<()> {
    let mut session = Session {
        last_id: 0,
        prepared: None,
    };
    while let Some(bytes) = input.recv().await {
        let parsed = if bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
            serde_json::from_slice::<Request>(&bytes).ok()
        } else {
            None
        };
        let Some(request) = parsed else {
            send(
                &output,
                &failure(
                    None,
                    "invalid_request",
                    "Expected one versioned JSON request per line",
                ),
            )
            .await?;
            continue;
        };
        let shutdown = request.method == "shutdown";
        let id = request.id;
        let reply = match session.dispatch(request, &control).await {
            Ok(value) => success(id, value),
            Err(error) => {
                send(&output, &error).await?;
                continue;
            }
        };
        send(&output, &reply).await?;
        if shutdown {
            control.shutdown();
            return Ok(());
        }
    }
    Ok(())
}

/// A full frame is required; never allocate an unbounded line with `read_until`.
fn read_frame(reader: &mut impl BufRead) -> std::result::Result<Option<Vec<u8>>, &'static str> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| "control stdin read failed")?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Err("control request ended without a newline")
            };
        }
        let end = available.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let take = end.unwrap_or(available.len());
        if line.len() + take > MAX_REQUEST {
            return Err("control request exceeds size limit");
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}
type InputError = Arc<Mutex<Option<&'static str>>>;
fn input_thread(control: ClientControl) -> Result<(mpsc::Receiver<Vec<u8>>, InputError)> {
    let (sender, receiver) = mpsc::channel(INPUT_QUEUE);
    let error: InputError = Arc::default();
    let recorded = Arc::clone(&error);
    std::thread::Builder::new()
        .name("client-control-input".into())
        .spawn(move || {
            let mut reader = io::stdin().lock();
            loop {
                match read_frame(&mut reader) {
                    Ok(Some(bytes)) => {
                        if sender.blocking_send(bytes).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(message) => {
                        *recorded
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(message);
                        break;
                    }
                }
            }
            control.shutdown();
        })
        .map_err(|_| CliError::new("cannot start control input thread"))?;
    Ok((receiver, error))
}
type WriteJob = (Vec<u8>, oneshot::Sender<io::Result<()>>);
fn output_thread(writer: impl Write + Send + 'static) -> Result<mpsc::Sender<WriteJob>> {
    let (sender, mut receiver) = mpsc::channel::<WriteJob>(1);
    std::thread::Builder::new()
        .name("client-control-output".into())
        .spawn(move || {
            let mut writer = writer;
            while let Some((bytes, done)) = receiver.blocking_recv() {
                let result = writer.write_all(&bytes).and_then(|()| writer.flush());
                let failed = result.is_err();
                let _ = done.send(result);
                if failed {
                    break;
                }
            }
        })
        .map_err(|_| CliError::new("cannot start control output thread"))?;
    Ok(sender)
}
async fn write_output(
    mut output: mpsc::Receiver<Vec<u8>>,
    writer: mpsc::Sender<WriteJob>,
    deadline: Duration,
) -> Result<()> {
    while let Some(bytes) = output.recv().await {
        let result = tokio::time::timeout(deadline, async {
            let (done, completed) = oneshot::channel();
            writer.send((bytes, done)).await.map_err(|_| ())?;
            completed.await.map_err(|_| ())?.map_err(|_| ())
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            return Err(CliError::new("control stdout closed or write timed out"));
        }
    }
    Ok(())
}

/// The runtime remains independently polled while control input/output is slow.
pub(crate) async fn run(
    config: ClientConfig,
    update_checks: bool,
    signal: impl Future<Output = ()> + Send,
) -> Result<()> {
    let (control, runtime) = ClientRuntime::prepare(config, update_checks)?;
    let events = control.subscribe_events();
    let writer = output_thread(io::stdout())?;
    let (input, input_error) = input_thread(control.clone())?;
    let (output, receiver) = mpsc::channel(OUTPUT_QUEUE);
    send(
        &output,
        &json!({"schema_version":1,"type":"hello","core_version":env!("CARGO_PKG_VERSION"),"control":capabilities(),"status":control.status(),"traffic":control.traffic_sample()}),
    ).await?;
    let mut event_task = tokio::spawn(forward_events(events, output.clone(), control.clone()));
    let mut events_done = false;
    let mut writer = tokio::spawn(write_output(receiver, writer, WRITE_TIMEOUT));
    let mut requests = tokio::spawn(requests(input, output.clone(), control.clone()));
    let mut runtime = Box::pin(runtime.run());
    tokio::pin!(signal);
    let mut stopping = false;
    let mut writer_done = false;
    let mut requests_done = false;
    let mut protocol_error = None;
    let result = loop {
        tokio::select! {
            result=&mut runtime => break result,
            ()=&mut signal, if !stopping => { stopping=true; control.shutdown(); },
            result=&mut writer, if !writer_done => {
                writer_done=true;
                protocol_error=Some(match result { Ok(Err(e))=>e,_=>CliError::new("control output ended unexpectedly") });
                control.shutdown();
            },
            result=&mut requests, if !requests_done => {
                requests_done=true;
                match result { Ok(Ok(()))=>{},Ok(Err(e))=>protocol_error=Some(e),Err(_)=>protocol_error=Some(CliError::new("control request task failed")) }
                control.shutdown();
            },
            result=&mut event_task, if !events_done => {
                events_done=true;
                match result { Ok(Ok(()))=>{},Ok(Err(e))=>{ protocol_error=Some(e); control.shutdown(); },Err(_)=>{ protocol_error=Some(CliError::new("control event task failed")); control.shutdown(); } }
            }
        }
    };
    control.shutdown();
    if !requests_done {
        requests.abort();
        let _ = requests.await;
    }
    if !writer_done && protocol_error.is_none() {
        let drained = tokio::time::timeout(WRITE_TIMEOUT, async {
            if !events_done {
                let joined = (&mut event_task).await;
                events_done = true;
                joined.map_err(|_| CliError::new("control event task failed"))??;
            }
            let control_error = input_error.lock().unwrap_or_else(std::sync::PoisonError::into_inner).map(|_| "input_error");
            send(
                &output,
                &json!({"schema_version":1,"type":"closed","status":control.status(),"traffic":control.traffic_sample(),"control_error":control_error}),
            )
            .await
        })
        .await;
        match drained {
            Ok(Ok(())) => {}
            Ok(Err(e)) => protocol_error = Some(e),
            Err(_) => protocol_error = Some(CliError::new("control final output timed out")),
        }
    }
    if !events_done {
        event_task.abort();
        let _ = event_task.await;
    }
    drop(output);
    if !writer_done {
        match tokio::time::timeout(WRITE_TIMEOUT, &mut writer).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => protocol_error = Some(error),
            _ => {
                writer.abort();
                protocol_error = Some(CliError::new("control output did not finish"));
            }
        }
    }
    result?;
    if let Some(message) = *input_error
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
    {
        return Err(CliError::new(message));
    }
    if let Some(error) = protocol_error {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_is_bounded_and_requires_complete_lines() {
        let mut stream = io::Cursor::new(b"{}\r\n{}\n");
        assert_eq!(read_frame(&mut stream).unwrap().unwrap(), b"{}\r\n");
        assert_eq!(read_frame(&mut stream).unwrap().unwrap(), b"{}\n");
        assert!(read_frame(&mut stream).unwrap().is_none());
        assert!(read_frame(&mut io::Cursor::new(b"{}")).is_err());
        let mut exact = vec![b' '; MAX_REQUEST - 3];
        exact.extend_from_slice(b"{}\n");
        assert_eq!(
            read_frame(&mut io::Cursor::new(exact))
                .unwrap()
                .unwrap()
                .len(),
            MAX_REQUEST
        );
        assert!(read_frame(&mut io::Cursor::new(vec![b'x'; MAX_REQUEST + 1])).is_err());
    }
    #[tokio::test]
    async fn oversized_output_is_rejected_before_enqueue() {
        let (sender, mut receiver) = mpsc::channel(1);
        assert!(
            send(&sender, &json!("x".repeat(MAX_RESPONSE)))
                .await
                .is_err()
        );
        assert!(receiver.try_recv().is_err());
    }
}
