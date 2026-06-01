\# 🛡️ Trust Sentinel



\*\*Lightweight device integrity guardian — "Can this device still be trusted right now?"\*\*



Trust Sentinel is \*\*not\*\* an antivirus, EDR, XDR, SIEM, or threat-hunting platform. It's a \*\*smoke alarm for device trust\*\*: always on, silent, and clear when something is wrong.



\---



\## How It Works



| Engine | Description |

|--------|-------------|

| \*\*Trust Shield\*\* | Rotating HMAC-SHA256 token generated every 30 seconds from a device-bound secret |

| \*\*Baseline Engine\*\* | Captures DNS, hosts file hash, startup entries, services, and listening ports on first run |

| \*\*Integrity Engine\*\* | Compares current system state against baseline every 5 minutes |

| \*\*Trust State\*\* | 🟢 Trusted / 🟡 Warning / 🔴 Compromised |



\---



\## Features



\- 🔐 Rotating trust token (HMAC-SHA256, 64-char hex, refreshes every 30s)

\- 📋 Real system data: DNS, hosts, startup, services, listening ports

\- 🔍 Tamper detection — hosts file modification, new services, DNS changes

\- 📝 Local event logging with timestamps and severity

\- ⚡ <0.1% CPU, \~25MB RAM

\- 🚫 100% offline — no cloud, no API keys, no telemetry

\- 🔄 Auto-starts on login



\---



\## Quick Start



\### Prerequisites

\- Windows 10/11 (64-bit)

\- \[Rust](https://rustup.rs) (MSVC toolchain)



\### Build \& Run

```bash

git clone https://github.com/n33r4j1910/trust-sentinel.git

cd trust-sentinel

cargo build --release

target\\release\\trust-sentinel-daemon.exe





Open http://127.0.0.1:12788 in your browser.



Auto-Start

Shortcut is in: %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\TrustSentinel.lnk



API

GET http://127.0.0.1:12788



json

{

&#x20; "trust\_state": "Trusted",

&#x20; "token": "a3f2c1b8d5e6f7a9...",

&#x20; "last\_check": "2026-06-01T12:00:00Z",

&#x20; "latest\_events": \[]

}

Project Structure

text

trust-sentinel/

├── daemon/src/main.rs    # Core engine (trust token, baseline, integrity)

├── tray/src/main.rs      # System tray app (WIP)

└── Cargo.toml            # Workspace config

Runtime data: C:\\ProgramData\\Trust Sentinel\\



seed.bin — device secret



baseline.json — HMAC-signed snapshot



events.log — security events



Security

HMAC-SHA256 signed baseline (tamper detection)



Time-windowed tokens (replay prevention)



Localhost-only HTTP (no network exposure)



TPM 2.0 sealing planned



Roadmap

Rotating trust token



Real system data collection



Integrity monitoring



Windows auto-start



TPM 2.0 hardware-rooted trust



Real-time ETW event monitoring



Credential file guard



Linux \& macOS support



Working tray icon



Contributing

PRs welcome! Key areas: TPM integration, ETW monitoring, Linux/macOS ports, tray icon.



bash

git clone https://github.com/n33r4j1910/trust-sentinel.git

cd trust-sentinel

cargo build

Keywords

endpoint-security trust-agent device-integrity hmac-sha256 trust-token zero-trust privacy-first offline-security rust-security windows-security tpm baseline-monitoring integrity-verification open-source-security



MIT © 2026



"Maximum security value per CPU cycle consumed."



text



Save, close. Then push:



```cmd

cd C:\\trust-sentinel

git add README.md

git commit -m "Update README with real data collection features"

git push

