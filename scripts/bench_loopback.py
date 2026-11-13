#!/usr/bin/env python3
"""Bounded loopback comparison; no host networking changes or external targets.

For implementation comparisons use identical optimized compiler settings.
Different build profiles can also be compared explicitly.
This Python-driven smoke benchmark is not a line-rate or Internet performance test.
"""
import argparse
import json
import os
import platform
import signal
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def percentile(values, fraction):
    return sorted(values)[min(len(values) - 1, int((len(values) - 1) * fraction))]


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Echo:
    def __init__(self, kind):
        self.sock = socket.socket(socket.AF_INET, kind)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.1)
        self.port = self.sock.getsockname()[1]
        self.stopped = threading.Event()
        self.workers = []
        self.kind = kind
        if kind == socket.SOCK_STREAM:
            self.sock.listen()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stream(self, conn):
        with conn:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.settimeout(0.1)
            while not self.stopped.is_set():
                try:
                    data = conn.recv(65536)
                    if not data:
                        return
                    conn.sendall(data)
                except socket.timeout:
                    continue
                except OSError:
                    return

    def run(self):
        while not self.stopped.is_set():
            try:
                if self.kind == socket.SOCK_STREAM:
                    conn, _ = self.sock.accept()
                    worker = threading.Thread(target=self.stream, args=(conn,), daemon=True)
                    self.workers.append(worker)
                    worker.start()
                else:
                    data, address = self.sock.recvfrom(65535)
                    self.sock.sendto(data, address)
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.stopped.set()
        self.sock.close()
        self.thread.join(2)
        for worker in self.workers:
            worker.join(2)


def stop(child):
    # wait4 returns per-process resource usage; do not call Popen.poll/wait first.
    try:
        child.send_signal(signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 3
    while True:
        pid, status, usage = os.wait4(child.pid, os.WNOHANG)
        if pid:
            child.returncode = os.waitstatus_to_exitcode(status)
            return {"cpu_seconds": usage.ru_utime + usage.ru_stime,
                    "max_rss_bytes": usage.ru_maxrss * (1 if platform.system() == "Darwin" else 1024)}
        if time.monotonic() > deadline:
            child.kill()
        time.sleep(0.01)


def ready(path, marker):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if marker in path.read_text(errors="replace"):
            return
        time.sleep(0.02)
    raise RuntimeError(f"startup timed out: {path.read_text(errors='replace')}")


def udp_run(port, size, seconds):
    payload = bytes((i % 251 for i in range(size)))
    sent = received = 0
    rtts = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.5)
        sock.connect(("127.0.0.1", port))
        start = time.monotonic()
        while time.monotonic() - start < seconds:
            before = time.monotonic()
            sock.send(payload)
            sent += 1
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            if data != payload:
                raise RuntimeError("UDP payload mismatch")
            received += 1
            rtts.append((time.monotonic() - before) * 1000)
    elapsed = time.monotonic() - start
    return {"payload_bytes": size, "sent": sent, "received": received,
            "echo_mbps": received * size * 8 / elapsed / 1e6,
            "rtt_p50_ms": statistics.median(rtts) if rtts else None,
            "rtt_p95_ms": percentile(rtts, 0.95) if rtts else None}


def tcp_run(port, seconds):
    payload = b"\x00" * 65536
    count = 0
    with socket.create_connection(("127.0.0.1", port), timeout=6) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        def roundtrip():
            sock.sendall(payload)
            data = bytearray()
            while len(data) < len(payload):
                chunk = sock.recv(len(payload) - len(data))
                if not chunk:
                    raise RuntimeError("TCP closed")
                data.extend(chunk)
            if data != payload:
                raise RuntimeError("TCP payload mismatch")

        first = time.monotonic()
        roundtrip()
        first_ms = (time.monotonic() - first) * 1000
        start = time.monotonic()
        while time.monotonic() - start < seconds:
            roundtrip()
            count += len(payload)
    return {"echo_mbps": count * 8 / (time.monotonic() - start) / 1e6,
            "first_64k_echo_ms": first_ms}


def first_flight(port, payload):
    samples = []
    for _ in range(5):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.settimeout(2)
            before = time.monotonic()
            sock.sendto(payload, ("127.0.0.1", port))
            data, _ = sock.recvfrom(65535)
            if data != payload:
                raise RuntimeError("first-flight payload mismatch")
            samples.append((time.monotonic() - before) * 1000)
    return {"samples_ms": samples, "p50_ms": statistics.median(samples)}


def measure(binary, sniff, seconds, fixture, fast_open=False, server_binary=None, client_binary=None):
    tcp = Echo(socket.SOCK_STREAM)
    udp = Echo(socket.SOCK_DGRAM)
    processes = []
    resources = {}
    try:
        with tempfile.TemporaryDirectory(prefix="hysteria-loopback-") as directory:
            root = Path(directory)
            subprocess.run([binary, "cert", "--host", "localhost", "--cert", str(root / "cert.pem"),
                            "--key", str(root / "key.pem")], check=True, capture_output=True, timeout=10)
            server_port = free_port(socket.SOCK_DGRAM)
            tcp_port = free_port(socket.SOCK_STREAM)
            udp_port = free_port(socket.SOCK_DGRAM)
            server = {"listen": f"127.0.0.1:{server_port}",
                      "tls": {"cert": str(root / "cert.pem"), "key": str(root / "key.pem")},
                      "auth": {"type": "password", "password": "loopback-benchmark-only"},
                      "sniff": {"enable": sniff}}
            client = {"server": f"127.0.0.1:{server_port}", "auth": "loopback-benchmark-only",
                      "tls": {"sni": "localhost", "ca": str(root / "cert.pem")},
                      "fastOpen": fast_open,
                      "tcpForwarding": [{"listen": f"127.0.0.1:{tcp_port}", "remote": f"127.0.0.1:{tcp.port}"}],
                      "udpForwarding": [{"listen": f"127.0.0.1:{udp_port}", "remote": f"127.0.0.1:{udp.port}"}]}
            for role, config, marker in [("server", server, "Hysteria server listening"),
                                         ("client", client, "UDP forwarding")]:
                config_path = root / f"{role}.json"
                config_path.write_text(json.dumps(config))
                log = root / f"{role}.log"
                with log.open("wb") as output:
                    executable = (server_binary if role == "server" else client_binary) or binary
                    child = subprocess.Popen([executable, role, "--disable-update-check", "-c", str(config_path)],
                                             stdin=subprocess.DEVNULL, stdout=output, stderr=output)
                processes.append((role, child))
                ready(log, marker)
            # Warm up the established connection before measuring sustained traffic.
            udp_run(udp_port, 64, 0.2)
            result = {"sniff": sniff, "tcp": tcp_run(tcp_port, seconds),
                      "udp_1200": udp_run(udp_port, 1200, seconds),
                      "udp_3000": udp_run(udp_port, 3000, seconds),
                      "plain_first": first_flight(udp_port, b"plain UDP"),
                      "incomplete_quic_first": first_flight(udp_port, fixture)}
            for role, child in reversed(processes):
                resources[role] = stop(child)
            processes.clear()
            result["process_lifetime_resources"] = resources
            return result
    finally:
        for _, child in reversed(processes):
            stop(child)
        tcp.close()
        udp.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", required=True, help="label=/absolute/path")
    parser.add_argument("--client-binary", help="Fixed client executable for comparing only server builds")
    parser.add_argument("--server-binary", help="Fixed server executable for comparing only client builds")
    parser.add_argument("--output", required=True)
    parser.add_argument("--sniff", choices=("both", "off", "on"), default="both")
    parser.add_argument("--seconds", type=float, default=2)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--fast-open", action="store_true", help="Enable client fastOpen for an explicit comparison")
    args = parser.parse_args()
    if args.seconds <= 0 or args.repeats < 1:
        parser.error("seconds and repeats must be positive")
    if not hasattr(os, "wait4"):
        parser.error("resource measurement currently requires Unix wait4")
    binaries = [(label, str(Path(path).resolve())) for label, path in (value.split("=", 1) for value in args.binary)]
    client_binary = str(Path(args.client_binary).resolve()) if args.client_binary else None
    server_binary = str(Path(args.server_binary).resolve()) if args.server_binary else None
    fixture = (Path(__file__).resolve().parents[1] / "crates/hysteria/tests/fixtures/quic-sniff/quic-chrome153-0.bin").read_bytes()
    report = {"platform": platform.platform(), "seconds_per_workload": args.seconds, "fast_open": args.fast_open, "fixed_server_binary": server_binary, "fixed_client_binary": client_binary,
              "method": "single outstanding echo request; not maximum throughput; resource usage includes process startup and all workloads",
              "runs": []}
    for repeat in range(args.repeats):
        for sniff in ((False, True) if args.sniff == "both" else (args.sniff == "on",)):
            for label, binary in (binaries if repeat % 2 == 0 else reversed(binaries)):
                print(f"{label}: repeat={repeat + 1} sniff={sniff}", flush=True)
                report["runs"].append({"label": label, "repeat": repeat + 1, **measure(binary, sniff, args.seconds, fixture, args.fast_open, server_binary, client_binary)})
                Path(args.output).write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
