#!/usr/bin/env python3
"""Build and pin the experimental macOS packet ABI artifact in the Rust repository."""
import argparse
import hashlib
import json
import platform
import os
from pathlib import Path
import shutil
import subprocess


# Builds one native macOS static packet core and records immutable source/artifact provenance.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    parser.add_argument('--profile', choices=['debug', 'release'], default='release')
    parser.add_argument('--source-commit', help='Full base commit for an exported working-tree snapshot')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if platform.system() != 'Darwin' or platform.machine() not in ('arm64', 'x86_64'):
        parser.error('build on native macOS arm64 or x86_64')
    command = ['cargo', 'build', '--locked', '-p', 'hysteria-packet-bridge']
    if args.profile == 'release':
        command.append('--release')
    environment = dict(os.environ, MACOSX_DEPLOYMENT_TARGET="14.0")
    subprocess.run(command, cwd=root, env=environment, check=True)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    artifacts = {}
    for source in [root / 'target' / args.profile / 'libhysteria_packet_bridge.a',
                   root / 'crates/hysteria-packet-bridge/include/hysteria_packet_bridge.h']:
        destination = output / source.name
        shutil.copy2(source, destination)
        artifacts[source.name] = {'sha256': hashlib.sha256(destination.read_bytes()).hexdigest()}
    commit = args.source_commit or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
    import re
    if not re.fullmatch('[0-9a-f]{40}', commit):
        parser.error('source commit must be a full Git SHA')
    sources = {}
    for path in (root / 'crates').rglob('*'):
        if path.is_file() and path.suffix in ('.rs', '.toml', '.h') and not any(part.startswith('._') or part == '.DS_Store' for part in path.parts):
            sources[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name in ['Cargo.toml', 'Cargo.lock']:
        sources[name] = hashlib.sha256((root / name).read_bytes()).hexdigest()
    encoded = json.dumps(sources, indent=2, sort_keys=True).encode()
    (output / 'source-hashes.json').write_bytes(encoded)
    manifest = {'schema_version': 1, 'abi_version': 1, 'commit': commit,
                'source_state': 'development snapshot; source hashes supplied, not remote attestation',
                'platform': 'macos', 'minimum_macos': '14.0', 'architecture': platform.machine(), 'profile': args.profile,
                'source_manifest_sha256': hashlib.sha256(encoded).hexdigest(), 'artifacts': artifacts}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(output / 'manifest.json')


if __name__ == '__main__':
    main()
