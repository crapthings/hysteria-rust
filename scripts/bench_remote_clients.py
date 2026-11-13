#!/usr/bin/env python3
"""Compare direct and existing loopback proxies with bounded curl transfers.

Run on the client host (for example jp1). This tool does not start clients, change
routes, install services, or read client credentials. Use optimized client builds.
"""
import argparse
import json
import os
import statistics
import subprocess
import time
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='Fixed HTTP(S) download object; avoid redirects and dynamic responses')
    parser.add_argument('--proxy-url', help='Optional origin URL as seen by the proxy server (for example its loopback fixture)')
    parser.add_argument('--proxy', action='append', default=[], metavar='NAME=URL', help='Existing loopback HTTP or socks5h listener; repeat for Go/Rust')
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--max-seconds', type=int, default=20)
    parser.add_argument('--max-bytes', type=int, default=16 * 1024 * 1024)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    for value in [args.url] + ([args.proxy_url] if args.proxy_url else []):
        target = urlsplit(value)
        if target.scheme not in ('http', 'https') or not target.hostname or target.username or target.password:
            parser.error('URLs must be HTTP(S) without embedded credentials')
    if not 1 <= args.rounds <= 20 or not 1 <= args.max_seconds <= 120 or not 1 <= args.max_bytes <= 256 * 1024 * 1024:
        parser.error('rounds, time or byte limit out of bounds')
    modes = [('direct', '')]
    for value in args.proxy:
        name, sep, address = value.partition('=')
        proxy = urlsplit(address)
        if not sep or not name or name in [item[0] for item in modes] or proxy.scheme not in ('http', 'socks5h') or proxy.hostname not in ('127.0.0.1', '::1') or proxy.username or proxy.password:
            parser.error('proxies require unique NAME and an unauthenticated loopback HTTP/socks5h URL')
        modes.append((name, address))
    environment = {key: value for key, value in os.environ.items() if key.lower() not in ('http_proxy', 'https_proxy', 'all_proxy', 'no_proxy')}
    results = []
    for round_index in range(args.rounds):
        # Rotate order so one client is not always measured against a cold origin.
        order = modes[round_index % len(modes):] + modes[:round_index % len(modes)]
        for name, proxy in order:
            command = ['curl', '--disable', '--silent', '--output', os.devnull,
                       '--proxy', proxy, '--noproxy', '' if proxy else '*',
                       '--connect-timeout', '8', '--max-time', str(args.max_seconds),
                       '--max-filesize', str(args.max_bytes), '--range', f'0-{args.max_bytes - 1}',
                       '--write-out', '%{json}', (args.proxy_url or args.url) if proxy else args.url]
            start = time.monotonic()
            response = subprocess.run(command, env=environment, capture_output=True, text=True, timeout=args.max_seconds + 5)
            try:
                metrics = json.loads(response.stdout)
            except json.JSONDecodeError:
                metrics = {}
            status = metrics.get('http_code', 0)
            success = response.returncode == 0 and status in (200, 206) and metrics.get('size_download', 0) > 0
            results.append({'mode': name, 'round': round_index + 1, 'success': success,
                            'curl_exit': response.returncode, 'wall_seconds': time.monotonic() - start,
                            **{key: metrics.get(key) for key in ('http_code', 'http_version', 'remote_ip', 'time_namelookup', 'time_connect', 'time_appconnect', 'time_starttransfer', 'time_total', 'size_download', 'speed_download')}})
    summaries = {}
    for name, _ in modes:
        samples = [item for item in results if item['mode'] == name]
        good = [item for item in samples if item['success']]
        summaries[name] = {'attempts': len(samples), 'successes': len(good), 'failures': len(samples) - len(good),
                           'median_ttfb_seconds': statistics.median(item['time_starttransfer'] for item in good) if good else None,
                           'median_download_mbps': statistics.median(item['speed_download'] * 8 / 1e6 for item in good) if good else None}
    report = {'schema_version': 1, 'note': 'Warm client sessions; each curl uses a new application connection. Proxy connect timings describe the local listener. Range support, DNS and cache behavior can affect comparisons.',
              'limits': {'rounds': args.rounds, 'max_seconds_per_transfer': args.max_seconds, 'max_bytes_per_transfer': args.max_bytes},
              'summary': summaries, 'samples': results}
    with open(args.output, 'x') as handle:
        json.dump(report, handle, indent=2)
        handle.write('\n')
    print(json.dumps(summaries, indent=2))


if __name__ == '__main__':
    main()
