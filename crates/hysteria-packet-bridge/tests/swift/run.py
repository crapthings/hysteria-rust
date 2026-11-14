#!/usr/bin/env python3
"""Compile a Swift C-ABI client and exercise TCP/UDP over loopback Hysteria."""
import argparse
import json
import os
import pathlib
import queue
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[2]


def echo_servers(stop):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.settimeout(0.2)
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp.bind(("127.0.0.1", 0))
    tcp.listen()
    tcp.settimeout(0.2)
    errors = []

    def udp_loop():
        try:
            while not stop.is_set():
                try:
                    packet, peer = udp.recvfrom(65535)
                    udp.sendto(packet, peer)
                except socket.timeout:
                    continue
        except OSError as error:
            if not stop.is_set():
                errors.append(str(error))

    def tcp_loop():
        try:
            while not stop.is_set():
                try:
                    connection, _ = tcp.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(0.2)
                    while not stop.is_set():
                        try:
                            packet = connection.recv(65535)
                        except socket.timeout:
                            continue
                        if not packet:
                            break
                        connection.sendall(packet)
        except OSError as error:
            if not stop.is_set():
                errors.append(str(error))

    threads = [threading.Thread(target=udp_loop), threading.Thread(target=tcp_loop)]
    for thread in threads:
        thread.start()
    return udp, tcp, threads, errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library-dir", required=True, type=pathlib.Path)
    parser.add_argument("--hysteria", required=True, type=pathlib.Path)
    parser.add_argument("--header", type=pathlib.Path,
                        help="use a header shipped with the selected library")
    parser.add_argument("--swift-source", action="append", type=pathlib.Path,
                        help="override the default smoke source; may be specified multiple times")
    parser.add_argument("--swift-parse-as-library", action="store_true",
                        help="compile Swift sources with -parse-as-library")
    parser.add_argument("--network-extension", action="store_true",
                        help="link the macOS NetworkExtension framework")
    parser.add_argument("--static-library", action="store_true",
                        help="link macOS system dependencies for the static packet library")
    args = parser.parse_args()
    library_dir = args.library_dir.resolve(strict=True)
    hysteria = args.hysteria.resolve(strict=True)
    header = (args.header or ROOT / "include/hysteria_packet_bridge.h").resolve(strict=True)
    if sys.platform != "darwin":
        parser.error("this Swift smoke test currently targets macOS")

    with tempfile.TemporaryDirectory(prefix="hy2-swift-bridge-") as temporary:
        temp = pathlib.Path(temporary)
        binary = temp / "swift-packet-test"
        sources = args.swift_source or [ROOT / "tests/swift/PacketBridgeSmoke.swift"]
        swift_options = (["-parse-as-library"] if args.swift_parse_as_library else [])
        swift_options += (["-framework", "NetworkExtension"] if args.network_extension else [])
        if args.static_library:
            swift_options += ["-framework", "Security", "-framework", "SystemConfiguration", "-liconv", "-lresolv"]
        subprocess.run([
            "swiftc", *swift_options, *(str(source.resolve(strict=True)) for source in sources),
            "-import-objc-header", str(header),
            "-L", str(library_dir), "-lhysteria_packet_bridge",
            "-Xlinker", "-rpath", "-Xlinker", str(library_dir),
            "-o", str(binary),
        ], check=True)
        cert = temp / "cert.pem"
        key = temp / "key.pem"
        subprocess.run([
            str(hysteria), "cert", "--host", "localhost", "--cert", str(cert),
            "--key", str(key), "--valid-for", "1h",
        ], check=True, capture_output=True)
        server_config = temp / "server.json"
        server_config.write_text(json.dumps({
            "listen": "127.0.0.1:0", "tls": {"cert": str(cert), "key": str(key)},
            "auth": {"type": "password", "password": "swift-fixture-password"},
        }))
        os.chmod(server_config, 0o600)
        server = subprocess.Popen([
            str(hysteria), "server", "--disable-update-check", "-c", str(server_config),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, bufsize=1)
        lines = queue.Queue()

        def drain():
            for line in server.stderr:
                lines.put(line.rstrip())

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        stop = threading.Event()
        sockets = []
        threads = []
        try:
            address = None
            for _ in range(50):
                try:
                    line = lines.get(timeout=0.2)
                except queue.Empty:
                    if server.poll() is not None:
                        raise RuntimeError("loopback server exited before readiness")
                    continue
                prefix = "Hysteria server listening on "
                if line.startswith(prefix):
                    address = line[len(prefix):]
                    break
            if address is None:
                raise RuntimeError("loopback server did not become ready")
            udp, tcp, threads, errors = echo_servers(stop)
            sockets = [udp, tcp]
            client_config = json.dumps({
                "server": address, "auth": "swift-fixture-password",
                "tls": {"sni": "localhost", "ca": str(cert)},
                "fastOpen": True, "tun": {"name": "swift-packet-test", "mtu": 1400},
            }).encode()
            result = subprocess.run([
                str(binary), str(udp.getsockname()[1]), str(tcp.getsockname()[1]),
            ], input=client_config, capture_output=True, timeout=40)
            print(result.stdout.decode(), end="")
            if result.returncode:
                sys.stderr.write(result.stderr.decode())
                raise RuntimeError(f"Swift test exited {result.returncode}")
            if errors:
                raise RuntimeError(f"echo fixture failed: {errors}")
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=3)
            for sock in sockets:
                sock.close()
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
            reader.join(timeout=2)
            server.stderr.close()


if __name__ == "__main__":
    main()
