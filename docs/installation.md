# Installation and upgrades


Download a binary and its matching `.sha256` file from
[GitHub Releases](https://github.com/crapthings/hysteria-rust/releases).
Each executable includes **both client and server**; Rust and Go are not required.

| Platform | Binary |
| --- | --- |
| Linux x64 / amd64 | `hysteria-rust-linux-x64` |
| Linux ARM64 / aarch64 | `hysteria-rust-linux-arm64` |
| Linux ARMv7, hard-float | `hysteria-rust-linux-armv7` |
| macOS Intel | `hysteria-rust-macos-x64` |
| macOS Apple Silicon | `hysteria-rust-macos-arm64` |
| Windows x64 | `hysteria-rust-windows-x64.exe` |
| Windows ARM64 | `hysteria-rust-windows-arm64.exe` |

Linux binaries require glibc. Alpine/musl builds and other targets are not
routinely published or tested.

For Linux x64, verify the checksum, then install:

```shell
sha256sum --check hysteria-rust-linux-x64.sha256
chmod +x hysteria-rust-linux-x64
sudo install -m 755 hysteria-rust-linux-x64 /usr/local/bin/hysteria
hysteria version
```

On macOS, verify with `shasum -a 256 -c FILE.sha256`, then `chmod +x FILE`.
On Windows, compare the hash with the checksum file before running:

```powershell
Get-FileHash .\hysteria-rust-windows-x64.exe -Algorithm SHA256
Get-Content .\hysteria-rust-windows-x64.exe.sha256
.\hysteria-rust-windows-x64.exe version
```

Commands below assume the executable is available on PATH as `hysteria`.
To run without installing, use `./FILE` on Unix or `.\FILE.exe` on Windows.

## Upgrade and rollback


1. Read the [release notes](https://github.com/crapthings/hysteria-rust/releases) and back up the executable and configuration.
2. Verify the new binary's checksum, stop the service, and replace the executable.
3. Restart the service and check its version and a real client connection.
4. If validation fails, stop the service, restore the backup, and start it again.

