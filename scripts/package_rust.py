#!/usr/bin/env python3
"""Build one Rust release artifact and its SHA-256 checksum."""

from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent


def host_target() -> str:
    output = subprocess.check_output(["rustc", "-vV"], text=True)
    for line in output.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ")
    raise RuntimeError("rustc did not report a host target")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--builder",
        choices=("cargo", "cross"),
        default="cargo",
        help="build frontend; use cross for containerized cross-compilation",
    )
    parser.add_argument(
        "--toolchain",
        help="optional rustup toolchain, for example nightly for build-std targets",
    )
    parser.add_argument(
        "--target",
        help="Rust target triple (defaults to rustc's host target)",
    )
    parser.add_argument(
        "--output-dir",
        type=pathlib.Path,
        default=ROOT / "build" / "rust",
    )
    parser.add_argument(
        "--variant",
        choices=("baseline", "avx"),
        default="baseline",
        help="CPU variant; avx uses the x86-64-v3 feature level",
    )
    args = parser.parse_args()

    target = args.target or host_target()
    if args.variant == "avx" and not target.startswith("x86_64-"):
        parser.error("--variant avx requires an x86_64 target")
    env = os.environ.copy()
    if args.variant == "avx":
        rustflags = env.get("RUSTFLAGS", "").strip()
        env["RUSTFLAGS"] = f"{rustflags} -C target-cpu=x86-64-v3".strip()
    command = [args.builder]
    if args.toolchain:
        command.append(f"+{args.toolchain}")
    command.extend(
        [
            "build",
            "--locked",
            "--release",
            "--package",
            "hysteria-cli",
            "--target",
            target,
        ]
    )
    subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        env=env,
    )

    executable_suffix = ".exe" if "windows" in target else ""
    target_dir = pathlib.Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    if not target_dir.is_absolute():
        target_dir = ROOT / target_dir
    source = target_dir / target / "release" / f"hysteria{executable_suffix}"
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    variant_suffix = "-avx" if args.variant == "avx" else ""
    artifact = output_dir / (
        f"hysteria-rust-{target}{variant_suffix}{executable_suffix}"
    )
    shutil.copy2(source, artifact)

    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    checksum = artifact.with_name(f"{artifact.name}.sha256")
    checksum.write_text(f"{digest}  {artifact.name}\n", encoding="ascii")
    print(artifact)
    print(checksum)
    return 0


if __name__ == "__main__":
    sys.exit(main())
