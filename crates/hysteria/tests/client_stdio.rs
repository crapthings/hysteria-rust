//! A GUI represented by a real parent process with owned stdin/stdout pipes.
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, Lines},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdin, ChildStdout, Command},
};

struct Gui {
    child: Child,
    input: Option<ChildStdin>,
    output: Option<Lines<BufReader<ChildStdout>>>,
    id: u64,
    local: SocketAddr,
}
impl Gui {
    async fn start(directory: &Path, remote: SocketAddr) -> Self {
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let path = directory.join("client.json");
        std::fs::write(&path,serde_json::to_vec(&json!({"server":"127.0.0.1:1","auth":"secret-not-in-protocol","tls":{"insecure":true},"routing":{"version":1,"default":"direct"},"tcpForwarding":[{"listen":local.to_string(),"remote":remote.to_string()}]})).unwrap()).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args([
                "client",
                "--control",
                "stdio",
                "--disable-update-check",
                "-c",
            ])
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let output = Some(BufReader::new(child.stdout.take().unwrap()).lines());
        let mut gui = Self {
            child,
            input,
            output,
            id: 0,
            local,
        };
        let hello = gui.next().await;
        assert_eq!(hello["type"], "hello");
        assert_eq!(hello["traffic"]["traffic"]["direct"]["upload_bytes"], 0);
        loop {
            let message = gui.next().await;
            if message["event"]["event"] == "local_ready" {
                break;
            }
            assert_ne!(message["type"], "closed");
        }
        gui
    }
    async fn next(&mut self) -> Value {
        let line = tokio::time::timeout(
            Duration::from_secs(15),
            self.output.as_mut().unwrap().next_line(),
        )
        .await
        .unwrap()
        .unwrap()
        .expect("control stdout closed");
        assert!(!line.contains("secret-not-in-protocol"));
        let value: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(value["schema_version"], 1);
        value
    }
    async fn raw(&mut self, bytes: &[u8]) {
        self.input.as_mut().unwrap().write_all(bytes).await.unwrap();
    }
    async fn reply(&mut self, id: Value) -> Value {
        loop {
            let message = self.next().await;
            if message["type"] == "response" && message["id"] == id {
                return message;
            }
            assert_ne!(message["type"], "closed");
        }
    }
    async fn call(&mut self, method: &str, params: Value) -> Value {
        self.id += 1;
        let mut request = serde_json::to_vec(
            &json!({"schema_version":1,"id":self.id,"method":method,"params":params}),
        )
        .unwrap();
        request.push(b'\n');
        self.raw(&request).await;
        self.reply(json!(self.id)).await
    }
    async fn closed(&mut self) {
        loop {
            let message = self.next().await;
            if message["type"] == "closed" {
                assert_eq!(message["status"]["lifecycle"], "stopped");
                break;
            }
        }
    }
    async fn exit(&mut self, success: bool) {
        let status = tokio::time::timeout(Duration::from_secs(15), self.child.wait())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.success(), success);
        let _listener = TcpListener::bind(self.local).await.unwrap();
    }
}
async fn echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut buffer = [0; 64];
                while let Ok(n) = stream.read(&mut buffer).await {
                    if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, task)
}
async fn roundtrip(stream: &mut TcpStream) {
    stream.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
}

#[tokio::test]
async fn gui_prepares_applies_observes_and_shuts_down_without_closing_stdin() {
    tokio::time::timeout(Duration::from_secs(25),async {
        let directory=tempfile::tempdir().unwrap();let (remote,echo)=echo().await;
        let mut gui=Gui::start(directory.path(),remote).await;
        let mut old=TcpStream::connect(gui.local).await.unwrap();roundtrip(&mut old).await;
        assert_eq!(gui.call("status",json!({})).await["result"]["routing_revision"],1);
        assert_eq!(gui.call("events.subscribe",json!({})).await["result"]["subscribed"],true);
        let file=directory.path().join("sites.txt");std::fs::write(&file,"suffix:example.com\n").unwrap();
        let prepared=gui.call("routing.validate",json!({"routing":{"version":1,"default":"reject","ruleSets":{"sites":{"file":"sites.txt"}},"rules":["direct(set:sites)"]},"base_directory":directory.path()})).await;
        let token=prepared["result"]["prepared_id"].clone();assert!(token.is_u64());
        assert_eq!(gui.call("routing.validate",json!({"routing":{"version":1,"rules":["bad(all)"]}})).await["error"]["code"],"invalid_routing");
        std::fs::remove_file(file).unwrap();
        assert_eq!(gui.call("routing.apply",json!({"prepared_id":token,"expected_revision":1})).await["result"]["revision"],2);
        assert_eq!(gui.call("routing.apply",json!({"prepared_id":token,"expected_revision":2})).await["error"]["code"],"unknown_prepared");
        assert_eq!(gui.call("routing.explain",json!({"address":"www.example.com:443","protocol":"tcp"})).await["result"]["decision"]["outbound"],"direct");
        roundtrip(&mut old).await;
        let mut blocked=TcpStream::connect(gui.local).await.unwrap();let _=blocked.write_all(b"new").await;assert_eq!(blocked.read(&mut [0;4]).await.unwrap_or(0),0);
        assert_eq!(gui.call("routing.stats",json!({})).await["result"]["default"]["tcp_attempts"],1);
        assert_eq!(gui.call("routing.history",json!({})).await["result"]["revisions"][0]["default"]["tcp_attempts"],1);
        let candidate=gui.call("routing.validate",json!({"routing":{"version":1,"default":"proxy"}})).await;
        let response=gui.call("routing.apply",json!({"prepared_id":candidate["result"]["prepared_id"],"expected_revision":1})).await;
        assert_eq!(response["error"]["code"],"revision_conflict");assert_eq!(response["error"]["actual"],2);
        assert_eq!(gui.call("shutdown",json!({})).await["result"]["shutdown_requested"],true);
        gui.closed().await;gui.exit(true).await;echo.abort();
    }).await.unwrap();
}

#[tokio::test]
async fn malformed_requests_do_not_change_state_and_eof_stops_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let mut gui = Gui::start(directory.path(), "127.0.0.1:1".parse().unwrap()).await;
    gui.raw(b"{secret-not-in-protocol\n").await;
    assert_eq!(
        gui.reply(Value::Null).await["error"]["code"],
        "invalid_request"
    );
    gui.raw(b"[1,1,\"shutdown\",{}]\n").await;
    assert_eq!(
        gui.reply(Value::Null).await["error"]["code"],
        "invalid_request"
    );
    assert_eq!(
        gui.call("status", json!([])).await["error"]["code"],
        "invalid_params"
    );
    assert_eq!(
        gui.call("routing.validate", json!({"routing":[1]})).await["error"]["code"],
        "invalid_params"
    );
    assert_eq!(
        gui.call("status", json!({"password":"secret-not-in-protocol"}))
            .await["error"]["code"],
        "invalid_params"
    );
    assert_eq!(
        gui.call("not.a.method", json!({})).await["error"]["code"],
        "unknown_method"
    );
    let repeated = format!(
        "{{\"schema_version\":1,\"id\":{},\"method\":\"shutdown\"}}\n",
        gui.id
    );
    gui.raw(repeated.as_bytes()).await;
    assert_eq!(
        gui.reply(json!(gui.id)).await["error"]["code"],
        "invalid_id"
    );
    gui.id += 1;
    let unsupported = format!(
        "{{\"schema_version\":2,\"id\":{},\"method\":\"shutdown\"}}\n",
        gui.id
    );
    gui.raw(unsupported.as_bytes()).await;
    assert_eq!(
        gui.reply(json!(gui.id)).await["error"]["code"],
        "unsupported_version"
    );
    assert_eq!(
        gui.call("status", json!({})).await["result"]["routing_revision"],
        1
    );
    drop(gui.input.take());
    gui.closed().await;
    gui.exit(true).await;
}

#[tokio::test]
async fn oversized_or_truncated_input_is_fatal_and_releases_listeners() {
    for oversized in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let mut gui = Gui::start(directory.path(), "127.0.0.1:1".parse().unwrap()).await;
        let bytes = if oversized {
            vec![b'x'; 1024 * 1024 + 1]
        } else {
            b"{\"id\":".to_vec()
        };
        let _ = gui.input.as_mut().unwrap().write_all(&bytes).await;
        drop(gui.input.take());
        gui.closed().await;
        gui.exit(false).await;
    }
}

#[tokio::test]
async fn closed_stdout_stops_even_with_stdin_still_open() {
    let directory = tempfile::tempdir().unwrap();
    let mut gui = Gui::start(directory.path(), "127.0.0.1:1".parse().unwrap()).await;
    loop {
        let message = gui.next().await;
        if message["type"] == "heartbeat" {
            assert!(message["latest_event_sequence"].is_u64());
            assert!(message.get("sequence").is_none());
            break;
        }
    }
    drop(gui.output.take());
    // No new request: heartbeat detects a lost reader even while otherwise idle.
    gui.exit(false).await;
}

#[tokio::test]
async fn stalled_gui_does_not_block_forwarding_and_is_disconnected() {
    let directory = tempfile::tempdir().unwrap();
    let (remote, echo) = echo().await;
    let mut gui = Gui::start(directory.path(), remote).await;
    let mut input = gui.input.take().unwrap();
    let flood = tokio::spawn(async move {
        for id in 1..=2000 {
            let line = format!("{{\"schema_version\":1,\"id\":{id},\"method\":\"status\"}}\n");
            if input.write_all(line.as_bytes()).await.is_err() {
                break;
            }
        }
    });
    // Keep stdout open but deliberately stop consuming it.
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut stream = TcpStream::connect(gui.local).await.unwrap();
        roundtrip(&mut stream).await;
    })
    .await
    .unwrap();
    gui.exit(false).await;
    flood.abort();
    echo.abort();
}

#[tokio::test]
async fn control_conflicts_fail_before_reading_stdin() {
    for args in [
        vec!["client", "--control", "stdio", "-c", "-"],
        vec!["client", "--control", "stdio", "--events", "json"],
        vec!["server", "--control", "stdio"],
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        assert!(
            !tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn sigterm_cleans_up_with_idle_control_input() {
    let directory = tempfile::tempdir().unwrap();
    let mut gui = Gui::start(directory.path(), "127.0.0.1:1".parse().unwrap()).await;
    assert!(
        Command::new("kill")
            .args(["-TERM", &gui.child.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    gui.closed().await;
    gui.exit(true).await;
}
