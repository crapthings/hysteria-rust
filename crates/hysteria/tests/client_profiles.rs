//! Private profile management uses isolated temporary storage, never the user's real profiles.
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Output, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};
const LINK: &str = "hy2://private-auth-sentinel@127.0.0.1:50000/?sni=localhost&obfs=salamander&obfs-password=obfs-secret-sentinel";
fn command(root: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hysteria"));
    cmd.env("HYSTERIA_PROFILE_DIR", root)
        .env("HYSTERIA_DISABLE_UPDATE_CHECK", "true")
        .kill_on_drop(true);
    cmd
}
async fn execute(root: &Path, args: &[&str], input: &str) -> Output {
    let mut child = command(root)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes()).await;
    }
    tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
        .await
        .unwrap()
        .unwrap()
}
fn document(output: &Output) -> Value {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("private-auth-sentinel"), "{text}");
        assert!(!text.contains("obfs-secret-sentinel"), "{text}");
        assert!(!text.contains("realm-token-sentinel"), "{text}");
    }
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    value
}
async fn import(root: &Path, name: &str, link: &str, overwrite: bool) -> Output {
    let mut args = vec!["profile", "import", "--name", name, "--output", "json"];
    if overwrite {
        args.push("--overwrite");
    }
    execute(root, &args, link).await
}
#[tokio::test]
async fn import_inspect_select_and_remove_are_private_and_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    let empty = execute(&root, &["profile", "list", "--output", "json"], "").await;
    assert_eq!(document(&empty)["profiles"], json!([]));
    assert!(!root.exists());
    let output = import(&root, "jp1", LINK, false).await;
    assert!(output.status.success(), "{output:?}");
    assert_eq!(document(&output)["saved"], true);
    let show = execute(&root, &["profile", "show", "jp1", "--output", "json"], "").await;
    assert_eq!(document(&show)["server"], "127.0.0.1:50000");
    assert_eq!(document(&show)["credentials"], "hidden");
    for args in [
        vec!["check", "client", "--profile", "jp1", "--output", "json"],
        vec!["doctor", "client", "--profile", "jp1", "--output", "json"],
        vec![
            "route",
            "explain",
            "example.com:443",
            "--profile",
            "jp1",
            "--output",
            "json",
        ],
    ] {
        let output = execute(&root, &args, "").await;
        assert!(output.status.success(), "{output:?}");
        document(&output);
    }
    let lint = execute(
        &root,
        &["route", "lint", "--profile", "jp1", "--output", "json"],
        "",
    )
    .await;
    assert!(lint.status.success());
    assert_eq!(document(&lint)["routing_enabled"], false);
    let conflict = execute(
        &root,
        &["check", "client", "--profile", "jp1", "-c", "missing.yaml"],
        "",
    )
    .await;
    assert_eq!(conflict.status.code(), Some(2));
    let wrong_role = execute(&root, &["server", "--profile", "jp1"], "").await;
    assert!(!wrong_role.status.success());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(root.join("jp1.yaml"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let remove = execute(&root, &["profile", "remove", "jp1", "--output", "json"], "").await;
    assert_eq!(document(&remove)["removed"], true);
    assert!(!root.join("jp1.yaml").exists());
    let missing = execute(&root, &["profile", "show", "jp1", "--output", "json"], "").await;
    assert_eq!(missing.status.code(), Some(3));
    assert_eq!(
        document(&missing)["error"]["code"],
        "profile_operation_failed"
    );
}
#[tokio::test]
async fn replacement_failures_preserve_saved_profile_and_realm_tokens_are_hidden() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    assert!(import(&root, "jp1", LINK, false).await.status.success());
    let before = fs::read(root.join("jp1.yaml")).unwrap();
    for (link, overwrite) in [
        (LINK, false),
        ("invalid-private-auth-sentinel", true),
        ("hy2://private-auth-sentinel@example.com/?insecure=1", true),
    ] {
        let output = import(&root, "jp1", link, overwrite).await;
        assert_eq!(output.status.code(), Some(3));
        document(&output);
        assert_eq!(fs::read(root.join("jp1.yaml")).unwrap(), before);
    }
    let output = import(
        &root,
        "jp1",
        "hy2://private-auth-sentinel@example.com:8443",
        true,
    )
    .await;
    assert!(output.status.success());
    document(&output);
    assert_ne!(fs::read(root.join("jp1.yaml")).unwrap(), before);
    let realm = "hysteria2+realm://realm-token-sentinel@rendezvous.example/room?auth=private-auth-sentinel&sni=localhost";
    let output = import(&root, "realm", realm, false).await;
    assert!(output.status.success(), "{output:?}");
    document(&output);
    let output = execute(&root, &["profile", "show", "realm", "--output", "json"], "").await;
    assert_eq!(document(&output)["connection_type"], "realm");
    assert!(document(&output)["server"].is_null());
    let names = execute(&root, &["profile", "list", "--output", "json"], "").await;
    assert_eq!(document(&names)["profiles"], json!(["jp1", "realm"]));
}
#[tokio::test]
async fn invalid_names_inputs_and_unapproved_insecure_import_do_not_create_storage() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    for name in [
        "../escape",
        "/tmp/escape",
        "JP1",
        "con",
        "com1",
        ".hidden",
        "a/b",
        "a\\b",
    ] {
        let output = import(&root, name, LINK, false).await;
        assert_eq!(output.status.code(), Some(2));
        assert!(!root.exists());
    }
    for link in [
        "hy2://private-auth-sentinel@example.com/?insecure=1".to_owned(),
        "x".repeat(65_537),
        format!("{LINK}\n{LINK}"),
    ] {
        let output = import(&root, "jp1", &link, false).await;
        assert_eq!(output.status.code(), Some(3));
        document(&output);
        assert!(!root.exists());
    }
    let output = execute(
        &root,
        &[
            "profile",
            "import",
            "--name",
            "jp1",
            "--allow-insecure",
            "--output",
            "json",
        ],
        "hy2://private-auth-sentinel@example.com/?insecure=1",
    )
    .await;
    assert!(output.status.success());
    assert_eq!(document(&output)["tls_verification"], false);
}
#[cfg(unix)]
#[tokio::test]
async fn unsafe_permissions_symlinks_and_competing_writers_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    assert!(import(&root, "jp1", LINK, false).await.status.success());
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(root.join(".lock"))
        .unwrap();
    lock.lock().unwrap();
    let output = import(&root, "jp1", LINK, true).await;
    assert_eq!(output.status.code(), Some(3));
    document(&output);
    drop(lock);
    let target = root.join("jp1.yaml");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        execute(&root, &["profile", "show", "jp1", "--output", "json"], "")
            .await
            .status
            .code(),
        Some(3)
    );
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    let original = fs::read(&target).unwrap();
    symlink(&target, root.join("alias.yaml")).unwrap();
    assert_eq!(
        import(&root, "alias", LINK, true).await.status.code(),
        Some(3)
    );
    assert_eq!(
        execute(
            &root,
            &["profile", "remove", "alias", "--output", "json"],
            ""
        )
        .await
        .status
        .code(),
        Some(3)
    );
    assert_eq!(fs::read(&target).unwrap(), original);
    let alias = dir.path().join("alias");
    symlink(&root, &alias).unwrap();
    assert_eq!(
        import(&alias, "jp2", LINK, false).await.status.code(),
        Some(3)
    );
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        import(&root, "jp2", LINK, false).await.status.code(),
        Some(3)
    );
}
#[tokio::test]
async fn profile_can_start_client_without_an_implicit_default_or_remote_connection() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("profiles");
    assert!(import(&root, "jp1", LINK, false).await.status.success());
    let path = root.join("jp1.yaml");
    let mut value: Value = serde_yaml_ng::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["socks5"]["listen"] = json!("127.0.0.1:0");
    value["routing"] = json!({"version":1,"default":"reject"});
    fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let mut child = command(&root)
        .args(["client", "--profile", "jp1", "--events", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let event: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_ne!(event["event"], "connecting");
            if event["event"] == "local_ready" {
                assert_eq!(event["component"], "socks5");
                break;
            }
        }
    })
    .await
    .unwrap();
    child.kill().await.unwrap();
    child.wait().await.unwrap();
    assert!(!root.join("default").exists());
    assert!(!root.join("current").exists());
}
