use super::*;

async fn relay_and_reconnect(handle: &Arc<ClientHandle>, obfuscated: bool) {
    // Repeat after invalidation to exercise the real runtime's reconnect path.
    for round in 0..2 {
        tokio::time::timeout(Duration::from_secs(15), async {
            let client = handle.client().await.unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = listener.local_addr().unwrap().to_string();
            let payload = format!("chrome-go-tcp-{obfuscated}-{round}").into_bytes();
            let exchange = async {
                let mut tunnel = handle.tcp(&target).await.unwrap();
                tunnel.write_all(&payload).await.unwrap();
                let mut received = vec![0; payload.len()];
                tunnel.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload);
            };
            let echo = async {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut received = vec![0; payload.len()];
                stream.read_exact(&mut received).await.unwrap();
                assert_eq!(received, payload);
                stream.write_all(&received).await.unwrap();
            };
            tokio::join!(exchange, echo);

            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = socket.local_addr().unwrap().to_string();
            let mut session = handle.udp().await.unwrap();
            // Both a small datagram and a payload requiring Hysteria fragmentation.
            // The 4096-byte protocol limit includes the Hysteria header.
            assert!(matches!(
                session.send(&vec![0; 4096], &target).await,
                Err(hysteria_transport::TransportError::DatagramTooLarge(_))
            ));
            for size in [32, 3000] {
                let payload = vec![0x5a; size];
                session.send(&payload, &target).await.unwrap();
                let mut received = vec![0; size + 1];
                let (length, peer) = socket.recv_from(&mut received).await.unwrap();
                assert_eq!(&received[..length], payload);
                socket.send_to(&received[..length], peer).await.unwrap();
                let (reply, _) = session.receive().await.unwrap();
                assert_eq!(reply, payload);
            }
            handle.invalidate(&client).await;
        })
        .await
        .expect("Chrome TCP/UDP relay or reconnect timed out");
    }
}
use sha2::{Digest, Sha256};
use std::process::{Child, Command, Stdio};

#[path = "../tests/support/ech.rs"]
mod ech;

struct GoServer(Child);

impl Drop for GoServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[ignore = "requires HYSTERIA_GO_BIN built from the CI-pinned Go revision"]
async fn chrome_runtime_go_tcp_udp_interop() {
    let binary = std::env::var("HYSTERIA_GO_BIN").expect("set HYSTERIA_GO_BIN explicitly");
    tls::ensure_crypto_provider();
    let directory = tempfile::tempdir().unwrap();
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    std::fs::write(&cert, certified.cert.pem()).unwrap();
    std::fs::write(&key, certified.key_pair.serialize_pem()).unwrap();
    let identity = rcgen::generate_simple_self_signed(vec!["client.local".to_owned()]).unwrap();
    let client_cert = directory.path().join("client.pem");
    let client_key = directory.path().join("client.key");
    std::fs::write(&client_cert, identity.cert.pem()).unwrap();
    std::fs::write(&client_key, identity.key_pair.serialize_pem()).unwrap();
    let ech_key = directory.path().join("ech.pem");
    let ech_config = ech::generate_ech_key(&ech_key);
    for (obfuscated, secure) in [(false, false), (true, false), (false, true), (true, true)] {
        let reserved = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        let obfs = if obfuscated {
            "obfs:\n  type: salamander\n  salamander:\n    password: interop-obfs\n"
        } else {
            ""
        };
        let path = directory.path().join("server.yaml");
        let cert_path = serde_yaml_ng::to_string(&cert.to_string_lossy()).unwrap();
        let key_path = serde_yaml_ng::to_string(&key.to_string_lossy()).unwrap();
        let security = if secure {
            format!(
                "  clientCA: {}\nech:\n  keyPath: {}\n",
                serde_yaml_ng::to_string(&client_cert.to_string_lossy())
                    .unwrap()
                    .trim(),
                serde_yaml_ng::to_string(&ech_key.to_string_lossy())
                    .unwrap()
                    .trim()
            )
        } else {
            String::new()
        };
        std::fs::write(&path, format!(
            "listen: {address}\ntls:\n  cert: {}\n  key: {}\n{security}auth:\n  type: password\n  password: secret\n{obfs}",
            cert_path.trim(), key_path.trim(),
        )).unwrap();
        drop(reserved);
        let mut server = GoServer(
            Command::new(&binary)
                .args(["server", "--config"])
                .arg(&path)
                .env("HYSTERIA_DISABLE_UPDATE_CHECK", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut config: ClientConfig = serde_yaml_ng::from_str(&format!(
            "server: {address}\nauth: secret\nlazy: true\nquic: {{ disableChromeParrot: false }}\ntls: {{ sni: localhost }}\n{obfs}"
        ))
        .unwrap();
        config.tls.ca = cert.to_string_lossy().into_owned();
        if secure {
            config.tls.pin_sha256 = format!("{:x}", Sha256::digest(certified.cert.der()));
            config.tls.client_certificate = client_cert.to_string_lossy().into_owned();
            config.tls.client_key = client_key.to_string_lossy().into_owned();
            config.tls.ech.clone_from(&ech_config);
        }
        let handle = ClientHandle::new(config.clone(), false).await.unwrap();
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                assert!(server.0.try_wait().unwrap().is_none(), "Go server exited");
                if handle.client().await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .expect("Go server startup/Chrome authentication timed out");

        relay_and_reconnect(&handle, obfuscated).await;
        handle.close().await;
        if secure {
            let mut wrong_pin = config.clone();
            wrong_pin.tls.pin_sha256 = "00".repeat(32);
            let mut anonymous = config.clone();
            anonymous.tls.client_certificate.clear();
            anonymous.tls.client_key.clear();
            let mut wrong_ca = config.clone();
            wrong_ca.tls.ca = client_cert.to_string_lossy().into_owned();
            for invalid in [wrong_pin, anonymous, wrong_ca] {
                assert!(
                    tokio::time::timeout(Duration::from_secs(10), connect_client(&invalid))
                        .await
                        .expect("TLS rejection timed out")
                        .is_err()
                );
            }
        }
    }
}
