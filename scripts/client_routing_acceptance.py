#!/usr/bin/env python3
"""Explicit Linux CLI acceptance using private profiles and loopback fixtures.

Run with a fresh private directory and a Linux binary; no root or network changes.
The caller owns the directory and must remove generated credentials after review.
"""
import argparse
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import socket
import struct
import subprocess
import threading
import time


def receive(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected socket closure")
        data += chunk
    return data


def wait_for(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("acceptance condition timed out")


def select_ports():
    for base in range(50000, 50200, 20):
        ports = [base + offset for offset in (0, 1, 2, 3, 4, 8, 9, 10)]
        try:
            with contextlib.ExitStack() as stack:
                for port in ports:
                    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                        sock = stack.enter_context(socket.socket(socket.AF_INET, kind))
                        sock.bind(("0.0.0.0", port))
            return ports
        except OSError:
            continue
    raise RuntimeError("no unused loopback test block near 50000")


class Acceptance:
    def __init__(self, binary, work):
        self.binary, self.work = binary, work
        assert platform.system() == "Linux", "Linux acceptance only"
        assert work.is_dir() and work.stat().st_mode & 0o077 == 0
        assert not (work / "profiles").exists(), "use a fresh directory"
        self.env = dict(os.environ, HYSTERIA_PROFILE_DIR=str(work / "profiles"),
                        HYSTERIA_DISABLE_UPDATE_CHECK="true", NO_COLOR="1", TERM="dumb")
        self.ports = select_ports()
        (self.server_port, self.socks_port, self.http_port, self.tcp_port,
         self.udp_port, self.target_port, self.echo_port, self.reject_port) = self.ports
        self.auth = secrets.token_urlsafe(32)
        self.children, self.fixtures, self.handles = [], [], []
        self.http_hits, self.udp_hits, self.cases = [], [], []
        self.client_number = 0
        self.server = self.client = None
        self.work.joinpath("caller").mkdir(mode=0o700)

    def cli(self, *args, data=None, code=0, secret=False):
        result = subprocess.run([str(self.binary), *map(str, args)], input=data,
                                capture_output=True, text=True, env=self.env,
                                cwd=self.work / "caller", timeout=20)
        if result.returncode != code:
            failure = {"args": list(map(str, args)), "exit_code": result.returncode,
                       "stdout": "[omitted]" if secret else result.stdout.replace(self.auth, "[redacted]"),
                       "stderr": result.stderr.replace(self.auth, "[redacted]")}
            (self.work / "command-failure.json").write_text(json.dumps(failure, indent=2))
            raise AssertionError(f"unexpected command exit {result.returncode}; inspect command-failure.json")
        if not secret:
            assert self.auth not in result.stdout + result.stderr
            assert "\x1b[" not in result.stdout + result.stderr
        return result.stdout

    def report(self, *args, **kwargs):
        value = json.loads(self.cli(*args, "--output", "json", **kwargs))
        assert value["schema_version"] == 1
        return value

    def passed(self, name):
        self.cases.append(name)
        print("PASS " + name, flush=True)

    def fixture(self):
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.http_hits.append((self.server.server_port, self.client_address[0], self.path))
                body = json.dumps({"peer": self.client_address[0], "path": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        for port in (self.target_port, self.reject_port):
            server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
            self.fixtures.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()

        def echo(sock):
            while sock.fileno() >= 0:
                try:
                    data, peer = sock.recvfrom(65535)
                    owner.udp_hits.append((sock.getsockname()[1], peer[0], data))
                    sock.sendto(data, peer)
                except OSError:
                    return

        for address, port in (("127.0.0.1", self.echo_port), ("127.0.0.3", self.echo_port),
                              ("127.0.0.1", self.reject_port)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((address, port))
            self.fixtures.append(sock)
            threading.Thread(target=echo, args=(sock,), daemon=True).start()

    def spawn(self, *args, label):
        out = self.work / (label + ".events")
        err = self.work / (label + ".log")
        handles = [out.open("w"), err.open("w")]
        self.handles.extend(handles)
        child = subprocess.Popen([str(self.binary), *map(str, args)], env=self.env,
                                 cwd=self.work / "caller", stdout=handles[0], stderr=handles[1])
        self.children.append(child)
        return child, out, err

    def start_server(self):
        child, _, log = self.spawn("server", "-c", self.work / "server.json",
                                   label="server-" + str(len(self.children)))
        self.server = child

        def ready():
            assert child.poll() is None, "test server exited; inspect private log"
            return "server listening" in log.read_text()

        wait_for(ready)

    def events(self):
        text = self.event_file.read_text()
        return [json.loads(line) for line in text.splitlines(keepends=True) if line.endswith("\n")]

    def start_client(self):
        self.client_number += 1
        self.client, self.event_file, _ = self.spawn(
            "client", "--profile", "qa", "--events", "json", label=f"client-{self.client_number}")

        def ready():
            assert self.client.poll() is None, "test client exited; inspect private log"
            return sum(e["event"] == "local_ready" for e in self.events()) == 4

        wait_for(ready)

    @staticmethod
    def stop(child):
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)
            assert child.wait(timeout=8) == 0, "graceful test process shutdown failed"

    def stop_client(self):
        self.stop(self.client)
        events = self.events()
        assert events[-1]["event"] == "stopped"
        names = [e["event"] for e in events]
        assert "stopping" in names and "failed" not in names
        stop = names.index("stopping")
        assert all(name in ("stopping", "stopped") for name in names[stop:])
        seq = [e["sequence"] for e in events]
        assert seq == sorted(set(seq))
        assert all(e["schema_version"] == 1 for e in events)
        assert self.auth not in self.event_file.read_text()

    def http(self, host, peer, mode="socks", port=None, failure=False, tag=None):
        args = ["curl", "--silent", "--show-error", "--fail", "--max-time", "6", "--noproxy", ""]
        if mode == "socks":
            args += ["--proxy", f"socks5h://127.0.0.1:{self.socks_port}"]
        elif mode in ("http", "connect"):
            args += ["--proxy", f"http://127.0.0.1:{self.http_port}"]
            if mode == "connect":
                args.append("--proxytunnel")
        else:
            args += ["--proxy", ""]
        path = "/" + (tag or secrets.token_hex(8))
        args.append(f"http://{host}:{port or self.target_port}{path}")
        result = subprocess.run(args, capture_output=True, text=True, timeout=8)
        if failure:
            assert result.returncode != 0, "expected proxy request to fail"
            assert not any(hit[2] == path for hit in self.http_hits), "failed request reached target"
        else:
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout) == {"peer": peer, "path": path}

    def socks_udp(self):
        stream = socket.create_connection(("127.0.0.1", self.socks_port), timeout=4)
        self.handles.append(stream)
        stream.sendall(b"\x05\x01\x00")
        assert receive(stream, 2) == b"\x05\x00"
        stream.sendall(b"\x05\x03\x00\x01" + bytes(6))
        reply = receive(stream, 10)
        assert reply[:4] == b"\x05\x00\x00\x01"
        relay = ("127.0.0.1", struct.unpack("!H", reply[8:10])[0])
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        self.handles.append(sock)
        return sock, relay

    def udp(self, sock, relay, host, peer, port=None, failure=False, forwarded=False):
        payload = secrets.token_bytes(24)
        packet = payload if forwarded else (b"\0\0\0\x01" + socket.inet_aton(host)
                                             + struct.pack("!H", port or self.echo_port) + payload)
        sock.settimeout(0.6 if failure else 4)
        sock.sendto(packet, relay)
        try:
            reply, _ = sock.recvfrom(65535)
        except socket.timeout:
            assert failure, "UDP echo timed out"
            assert not any(hit[2] == payload for hit in self.udp_hits)
            return
        assert not failure and reply.endswith(payload)
        assert any(hit[1] == peer and hit[2] == payload for hit in self.udp_hits)

    def run(self):
        self.fixture()
        for args in ((), ("help",), ("help", "client"), ("help", "server")):
            assert "Usage:" in self.cli(*args)
        assert not (self.work / "profiles").exists()
        assert self.report("capabilities")["routing"]["local_rule_sets"]
        self.passed("help and capability discovery are offline")

        self.cli("cert", "--host", "localhost", "--valid-for", "1d",
                 "--cert", self.work / "cert.pem", "--key", self.work / "key.pem")
        server = {"listen": f"127.0.0.1:{self.server_port}",
                  "tls": {"cert": str(self.work / "cert.pem"), "key": str(self.work / "key.pem")},
                  "auth": {"type": "password", "password": self.auth},
                  "outbounds": [{"name": "default", "type": "direct", "direct": {"bindIPv4": "127.0.0.2"}}],
                  "quic": {"maxIdleTimeout": "4s"}}
        (self.work / "server.json").write_text(json.dumps(server))
        assert self.report("check", "server", "-c", self.work / "server.json")["valid"]
        link = self.cli("server", "share", "-c", self.work / "server.json", "--address",
                        f"127.0.0.1:{self.server_port}", "--sni", "localhost", secret=True)
        imported = self.report("profile", "import", "--name", "qa", data=link)
        self.profile = Path(imported["path"])
        original = self.profile.read_text()
        assert imported["tls_verification"] is True
        assert self.profile.stat().st_mode & 0o077 == 0
        self.report("profile", "import", "--name", "qa", data=link, code=3)
        self.report("profile", "import", "--name", "qa", "--overwrite", data="invalid-uri\n", code=3)
        assert self.profile.read_text() == original
        assert self.report("profile", "list")["profiles"] == ["qa"]
        self.report("profile", "show", "qa")
        self.passed("standard share link import, private profile and overwrite protection")

        self.rules = [f"reject(all,*/{self.reject_port})", "direct(set:local_names)",
                      f"direct(127.0.0.1,udp/{self.echo_port})", "reject(suffix:blocked.invalid)", "direct(lan)"]
        routing = {"version": 1, "default": "proxy", "ruleSets": {"local_names": {"file": "local.txt"}},
                   "rules": self.rules}
        self.rule_file = self.profile.parent / "local.txt"
        self.rule_file.write_text("# Explicit local domain bypass\nlocalhost\nsuffix:direct.invalid\n")
        assert original.count("127.0.0.1:1080") == 1 and original.count("tls:\n") == 1
        text = original.replace("127.0.0.1:1080", f"127.0.0.1:{self.socks_port}")
        text = text.replace("tls:\n", "tls:\n  ca: " + json.dumps(str(self.work / "cert.pem")) + "\n")
        text += "http: " + json.dumps({"listen": f"127.0.0.1:{self.http_port}"}) + "\n"
        text += "quic: " + json.dumps({"maxIdleTimeout": "4s", "keepAlivePeriod": "1s"}) + "\n"
        text += "tcpForwarding: " + json.dumps([{"listen": f"127.0.0.1:{self.tcp_port}", "remote": f"127.0.0.1:{self.target_port}"}]) + "\n"
        text += "udpForwarding: " + json.dumps([{"listen": f"127.0.0.1:{self.udp_port}", "remote": f"127.0.0.3:{self.echo_port}"}]) + "\n"
        self.profile.write_text(text + "routing: " + json.dumps(routing) + "\n")
        assert self.report("check", "client", "--profile", "qa")["valid"]
        assert self.report("doctor", "client", "--profile", "qa")["passed"]
        assert self.report("route", "lint", "--profile", "qa", "--strict")["warnings"] == []
        cases = [(f"localhost:{self.target_port}", "direct"), ("a.direct.invalid:443", "direct"),
                 (f"127.0.0.1:{self.target_port}", "proxy"), ("ads.blocked.invalid:443", "reject"),
                 ("10.1.2.3:443", "direct"), ("[fc00::1]:443", "direct"),
                 (f"localhost:{self.reject_port}", "reject")]
        for target, action in cases:
            result = self.report("route", "explain", target, "--trace", "--profile", "qa")
            assert result["outbound"] == action
        example = self.cli("route", "explain", f"localhost:{self.target_port}", "--trace", "--profile", "qa")
        (self.work / "explain.txt").write_text(example)
        valid = self.profile.read_text()
        routing["rules"] = self.rules + ["direct(localhost)"]
        self.profile.write_text(text + "routing: " + json.dumps(routing) + "\n")
        warning = self.report("route", "lint", "--profile", "qa", "--strict", code=3)
        assert warning["warnings"][0]["covered_by"] == 2
        routing["rules"] = ["direct(localhost,)"]
        self.profile.write_text(text + "routing: " + json.dumps(routing) + "\n")
        assert not self.report("check", "client", "--profile", "qa", code=3)["valid"]
        self.profile.write_text(valid)
        self.passed("config-relative small rule set, explanations, strict lint and invalid filter")

        self.start_server()
        probe = self.report("doctor", "client", "--profile", "qa", "--connect", "--timeout", "5s",
                            "--tcp", f"127.0.0.1:{self.target_port}", "--udp-echo", f"127.0.0.1:{self.echo_port}")
        assert probe["passed"]
        (self.work / "doctor.json").write_text(json.dumps(probe, indent=2))
        self.passed("TLS verification, authentication and TCP/UDP active diagnosis")
        self.start_client()
        assert "connected" not in [e["event"] for e in self.events()]
        for mode in ("socks", "http", "connect"):
            self.http("localhost", "127.0.0.1", mode)
        assert "connected" not in [e["event"] for e in self.events()]
        for mode in ("socks", "http", "connect"):
            self.http("127.0.0.1", "127.0.0.2", mode)
            self.http("localhost", None, mode, port=self.reject_port, failure=True)
        self.http("127.0.0.1", "127.0.0.2", "forward", port=self.tcp_port)
        self.passed("real curl SOCKS5, HTTP, CONNECT and TCP forwarding with observed outbound source")
        sock, relay = self.socks_udp()
        self.udp(sock, relay, "127.0.0.1", "127.0.0.1")
        self.udp(sock, relay, "127.0.0.3", "127.0.0.2")
        self.udp(sock, relay, "127.0.0.1", None, port=self.reject_port, failure=True)
        self.udp(sock, relay, "127.0.0.1", "127.0.0.1")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as forward:
            self.udp(forward, ("127.0.0.1", self.udp_port), "127.0.0.3", "127.0.0.2", forwarded=True)
        self.passed("one SOCKS5 UDP association mixes direct/proxy/reject; explicit UDP forwarding")

        self.stop(self.server)
        wait_for(lambda: any(e["event"] == "disconnected" for e in self.events()))
        self.http("localhost", "127.0.0.1")
        self.udp(sock, relay, "127.0.0.1", "127.0.0.1")
        self.http("127.0.0.1", None, failure=True, tag="offline-proxy")
        self.udp(sock, relay, "127.0.0.3", None, failure=True)
        self.start_server()
        time.sleep(1.2)
        self.http("127.0.0.1", "127.0.0.2")
        self.udp(sock, relay, "127.0.0.3", "127.0.0.2")
        assert self.client.poll() is None
        names = [e["event"] for e in self.events()]
        assert names.count("connected") >= 2
        self.passed("server outage preserves direct traffic, no proxy fallback; same client and UDP association recover")

        self.rule_file.write_text("suffix:never.invalid\n")
        changed = self.report("route", "explain", f"localhost:{self.target_port}", "--profile", "qa")
        assert changed["outbound"] == "proxy"
        self.http("localhost", "127.0.0.1")
        self.stop_client()
        self.start_client()
        self.http("localhost", "127.0.0.2")
        self.stop_client()
        self.passed("rule files stay immutable while running; explicit restart applies the new snapshot")
        self.stop(self.server)
        assert all(child.poll() == 0 for child in self.children)
        self.report("profile", "remove", "qa")
        assert self.report("profile", "list")["profiles"] == []
        assert not any(hit[0] == self.reject_port for hit in self.http_hits + self.udp_hits)
        self.passed("SIGTERM event order, process exit and profile removal")

    def close(self):
        for child in reversed(self.children):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
        for handle in self.handles:
            handle.close()
        for fixture in self.fixtures:
            if isinstance(fixture, http.server.HTTPServer):
                fixture.shutdown()
                fixture.server_close()
            else:
                fixture.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    test = Acceptance(args.binary.resolve(), args.work.resolve())
    result = {"platform": platform.platform(), "binary_sha256": hashlib.sha256(test.binary.read_bytes()).hexdigest(),
              "ports": test.ports, "cases": test.cases, "passed": False}
    def timeout_handler(*_):
        raise TimeoutError("overall acceptance timeout")

    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(180)
    try:
        test.run()
        result["passed"] = True
    finally:
        signal.alarm(0)
        test.close()
        (test.work / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("ACCEPTANCE " + json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
