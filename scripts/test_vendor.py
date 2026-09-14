#!/usr/bin/env python3
"""Run standalone protocol tests with bounded build-cache defaults."""

import argparse
import os
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SUITES = {
    "h3": ["--features", "i-implement-a-third-party-backend-and-opt-into-breaking-changes"],
    "quinn-proto": [],
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=["all", *SUITES], default="all", nargs="?")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    environment = os.environ.copy()
    defaults = {
        "CARGO_PROFILE_DEV_DEBUG": "0",
        "CARGO_PROFILE_TEST_DEBUG": "0",
        "CARGO_INCREMENTAL": "0",
        "CARGO_TARGET_DIR": str(ROOT / "target" / "vendor-tests"),
    }
    for key, value in defaults.items():
        environment.setdefault(key, value)
    # Cargo runs from ROOT; make explicitly supplied relative paths unambiguous.
    environment["CARGO_TARGET_DIR"] = str(Path(environment["CARGO_TARGET_DIR"]).resolve())
    for key in defaults:
        print(f"{key}={environment[key]}", flush=True)
    suites = SUITES if args.suite == "all" else [args.suite]
    for suite in suites:
        command = ["cargo", "test", "--manifest-path", f"vendor/{suite}/Cargo.toml",
                   "--locked", "--lib", *SUITES[suite]]
        if args.offline:
            command.append("--offline")
        print(shlex.join(command), flush=True)
        if not args.dry_run:
            subprocess.run(command, cwd=ROOT, env=environment, check=True)


if __name__ == "__main__":
    main()
