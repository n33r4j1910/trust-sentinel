\# 🛡️ Trust Sentinel — Lightweight Endpoint Trust Agent



\*\*A hardware-rooted, privacy-first device integrity guardian that continuously answers: "Can this device still be trusted right now?"\*\*



> Zero cloud. Zero telemetry. Zero signatures. Maximum security per CPU cycle consumed.



\[!\[Rust](https://img.shields.io/badge/Rust-1.96%2B-orange)](https://rustup.rs)

\[!\[Platform](https://img.shields.io/badge/Platform-Windows%2011%2F10-blue)](https://github.com/n33r4j1910/trust-sentinel)

\[!\[License](https://img.shields.io/badge/License-MIT-green)](LICENSE)



\---



\## 📖 Table of Contents



\- \[What is Trust Sentinel?](#what-is-trust-sentinel)

\- \[Key Concepts](#key-concepts)

\- \[Features](#features)

\- \[Architecture](#architecture)

\- \[Project Structure](#project-structure)

\- \[How It Works](#how-it-works)

\- \[Quick Start](#quick-start)

\- \[API Reference](#api-reference)

\- \[Trust States](#trust-states)

\- \[Data Storage](#data-storage)

\- \[Security Design](#security-design)

\- \[Resource Footprint](#resource-footprint)

\- \[Technology Stack](#technology-stack)

\- \[Roadmap](#roadmap)

\- \[Contributing](#contributing)

\- \[License](#license)



\---



\## What is Trust Sentinel?



Trust Sentinel is \*\*not\*\* an antivirus, EDR, XDR, SIEM, or threat-hunting platform.



It is a \*\*lightweight security guardian\*\* that continuously evaluates whether your device can still be trusted — using cryptographic attestation, system baseline monitoring, and behavioral integrity checks.



Think of it as a \*\*smoke alarm for device trust\*\*: always on, silent, and clear when something is wrong.



\---



\## Key Concepts



| Concept | Description |

|---------|-------------|

| \*\*Trust Shield\*\* | Rotating HMAC-SHA256 cryptographic token generated every 30 seconds from a device-bound secret |

| \*\*Baseline Engine\*\* | Captures a snapshot of critical system state on first run |

| \*\*Integrity Engine\*\* | Compares current system state against baseline every 5 minutes |

| \*\*Trust State Engine\*\* | Calculates device trustworthiness: Trusted / Warning / Compromised |



\---



\## Features



\- 🔐 \*\*Rotating Trust Token\*\* — HMAC-SHA256 (64-character hex), refreshed every 30 seconds

\- 📋 \*\*System Baseline\*\* — DNS servers, hosts file hash, startup entries, services, listening ports

\- 🔍 \*\*Integrity Monitoring\*\* — Event-driven comparison against baseline every 5 minutes

\- 🟢🟡🔴 \*\*Trust States\*\* — Trusted (100) / Warning (75) / Compromised (0)

\- 📝 \*\*Event Logging\*\* — Timestamped security events with severity and details

\- 🔒 \*\*Tamper Detection\*\* — Baseline file is HMAC-signed; any modification triggers alert

\- ⚡ \*\*Ultra-Lightweight\*\* — <0.1% CPU, \~25MB RAM, no noticeable performance impact

\- 🌐 \*\*Local API\*\* — HTTP endpoint at `127.0.0.1:12788` for status queries

\- 🚫 \*\*100% Offline\*\* — No cloud, no API keys, no telemetry, no accounts

\- 🛡️ \*\*Privacy-First\*\* — Zero data leaves your device

\- 🔄 \*\*Auto-Start\*\* — Runs silently on system login via Windows Startup folder



\---



\## Architecture



┌─────────────────────────────────────┐

│ Browser Dashboard │ http://127.0.0.1:12788

│ or Tray Icon (WIP) │

└──────────────┬──────────────────────┘

│ HTTP GET

┌──────────────▼──────────────────────┐

│ Trust Sentinel Daemon │

│ │

│ ┌─────────┐ ┌──────────┐ ┌────┐ │

│ │ Trust │ │Integrity │ │HTTP│ │

│ │ Shield │ │Engine │ │API │ │

│ └────┬────┘ └────┬─────┘ └────┘ │

│ │ │ │

│ ┌────▼────┐ ┌────▼─────┐ │

│ │ Seed + │ │Baseline │ │

│ │ Token │ │Diff + │ │

│ │ Gen │ │State Calc│ │

│ └─────────┘ └──────────┘ │

│ │

│ ┌──────────────────────────────┐ │

│ │ Local Event Logger │ │

│ └──────────────────────────────┘ │

└─────────────────────────────────────┘





\### Data Flow



\[Startup]

│

├─► Load/Create Device Seed (seed.bin)

├─► Load/Create System Baseline (baseline.json)

├─► Start HTTP Server (127.0.0.1:12788)

│

├─► \[Every 30s] ──► Generate HMAC-SHA256 Token

│

└─► \[Every 5min] ─► Collect Current State

│

├─► Compare vs Baseline

├─► Log Differences

└─► Update Trust State





\---



\## Project Structure



trust-sentinel/

│

├── README.md # This file

├── .gitignore # Git ignore rules

├── Cargo.toml # Rust workspace configuration

├── Cargo.lock # Dependency lock file

│

├── daemon/ # 🖥️ Background Trust Engine

│ ├── Cargo.toml # Daemon dependencies

│ └── src/

│ └── main.rs # Core logic (\~300 lines)

│ ├── get\_or\_create\_seed() # Device secret management

│ ├── generate\_token() # 30-second HMAC token

│ ├── collect\_current\_state() # System state snapshot

│ ├── load\_or\_create\_baseline() # Baseline management

│ ├── check\_integrity() # Diff + trust calculation

│ ├── diff\_states() # State comparison

│ ├── sign\_state() # HMAC signing

│ └── log\_event() # Event logger

│

└── tray/ # 🔔 System Tray Application (WIP)

├── Cargo.toml # Tray dependencies

└── src/

├── main.rs # Tray icon + daemon polling

├── green.ico # Trusted icon

├── yellow.ico # Warning icon

├── red.ico # Compromised icon

└── gray.ico # Initialising icon





\### Data Files (Runtime)



C:\\ProgramData\\Trust Sentinel

├── seed.bin # 32-byte random device secret

├── baseline.json # HMAC-signed system baseline

└── events.log # JSON-lines event log





\---



\## How It Works



\### 1. Trust Shield (Every 30 Seconds)





Token = HMAC-SHA256(device\_seed, floor(unix\_time / 30))





\- A 32-byte random seed is generated on first run

\- Every 30 seconds, the current time window is used as a counter

\- HMAC-SHA256 produces a 64-character hex token

\- The 30-second window prevents replay attacks



\### 2. Baseline Engine (On First Run)



Captures a snapshot of:

\- \*\*DNS Servers\*\* — Currently configured DNS

\- \*\*Hosts File Hash\*\* — SHA256 of `C:\\Windows\\System32\\drivers\\etc\\hosts`

\- \*\*Startup Entries\*\* — Programs that run on boot

\- \*\*Services\*\* — Windows services

\- \*\*Listening Ports\*\* — Open TCP/UDP ports



The baseline is stored as JSON and \*\*signed with HMAC\*\* using the device seed to detect tampering.



\### 3. Integrity Engine (Every 5 Minutes)



1\. Load baseline and verify its HMAC signature

2\. Collect current system state

3\. Diff against baseline:

&#x20;  - DNS servers changed?

&#x20;  - Hosts file modified?

&#x20;  - New startup entries?

&#x20;  - New or removed services?

&#x20;  - New listening ports?

4\. Log any differences as security events

5\. Update trust state



\### 4. Trust State Engine



| State | Condition |

|-------|-----------|

| 🟢 \*\*Trusted\*\* | Zero differences from baseline |

| 🟡 \*\*Warning\*\* | One difference detected |

| 🔴 \*\*Compromised\*\* | Multiple differences or baseline tampered |



\---



\## Quick Start



\### Prerequisites



\- \*\*Windows 10/11\*\* (64-bit)

\- \*\*Rust\*\* (MSVC toolchain) — \[Install from rustup.rs](https://rustup.rs)

\- \*\*Visual Studio Build Tools\*\* with "Desktop development with C++"



\### Build from Source



```bash

\# Clone the repository

git clone https://github.com/n33r4j1910/trust-sentinel.git

cd trust-sentinel



\# Build (optimized release)

cargo build --release



\# Start the daemon

target\\release\\trust-sentinel-daemon.exe



Open Your Browser



http://127.0.0.1:12788



You will see JSON output



{

&#x20; "trust\_state": "Trusted",

&#x20; "token": "b55206e071cca42cc7da7525a3b46c292fc70ea0d9da929bae68d7adf7d3d8f5",

&#x20; "last\_check": "2026-05-31T18:22:41.929Z",

&#x20; "latest\_events": \[]

}





Auto-Start on Login

A shortcut is placed in the Windows Startup folder during setup:



%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\TrustSentinel.lnk



The daemon starts silently every time you log in.



Stop the daemon - taskkill /f /im trust-sentinel-daemon.exe



API Reference 



GET / — Get Trust Status

URL: http://127.0.0.1:12788



Response:



json

{

&#x20; "trust\_state": "Trusted",

&#x20; "token": "a3f2c1b8d5e6f7a9...",

&#x20; "last\_check": "2026-06-01T12:00:00.000Z",

&#x20; "latest\_events": \[]

}





Field	Type	Description

trust\_state	String	Trusted, Warning, or Compromised

token	String	Current 64-char HMAC-SHA256 trust token

last\_check	ISO 8601	Timestamp of last integrity check

latest\_events	Array	Last 5 security events





Security Design

Layer	Mechanism

Device Secret	32-byte random seed stored in C:\\ProgramData\\Trust Sentinel\\seed.bin

Token Generation	HMAC-SHA256 with time-based counter (30-second window)

Replay Prevention	Time-windowed tokens; old tokens invalid after 30 seconds

Baseline Integrity	HMAC-SHA256 signature verified on every read

Tamper Detection	Baseline signature mismatch → immediate Compromised state

No External Calls	Zero network connections; HTTP server binds to 127.0.0.1 only



Planned: TPM 2.0 Integration

Currently the seed is file-based. The roadmap includes sealing the seed to TPM PCRs (Platform Configuration Registers) so that any modification to the boot chain or kernel makes the seed unreadable — providing true hardware-rooted trust.



Resource Footprint

* Metric	Value
* Idle CPU	<0.1%
* RAM	\~25-30 MB
* Disk	<5 MB (binary + data)
* Network	None (localhost only)
* Battery Impact	Negligible
* Measured on Windows 11, Intel i5, 8GB RAM.



Technology Stack



* Component	Technology
* Language	Rust (Edition 2021)
* Cryptography	ring, hmac, sha2
* Serialization	serde, serde\_json
* Time	chrono
* HTTP Server	std::net::TcpListener (zero-dependency)
* Tray (WIP)	tray-icon, reqwest





Roadmap



* Rotating HMAC-SHA256 trust token



* System baseline capture \& comparison



* Trust state engine (Trusted/Warning/Compromised)



* Local HTTP API



* Event logging



* Windows auto-start



* TPM 2.0 hardware-rooted trust sealing



* Real-time event monitoring (ETW/eBPF)



* Credential file guard (SSH keys, browser passwords, cloud tokens)



* Working system tray icon



* Linux support (eBPF + TPM2)



* macOS support (Endpoint Security + Secure Enclave)



* Remote attestation (optional, privacy-preserving)



* Encrypted local database (SQLCipher)



* User allow-listing for legitimate changes





Contributing



* Contributions are welcome! Areas where help is especially valuable:



* Windows ETW integration for real-time event monitoring



* TPM 2.0 PCR sealing using Windows TBS API



* Linux port using eBPF (aya-rs) and TPM2-TSS



* macOS port using Endpoint Security framework



* Tray icon fixes for production use



* Security audit and red-team testing



Development Setup



bash

git clone https://github.com/n33r4j1910/trust-sentinel.git

cd trust-sentinel

cargo build

cargo run --bin trust-sentinel-daemon

Keywords

endpoint-security trust-agent device-integrity hmac-sha256 trust-token zero-trust privacy-first offline-security rust-security windows-security tpm baseline-monitoring lightweight-edr osquery-alternative device-attestation integrity-verification security-daemon open-source-security



License

MIT © 2026 Trust Sentinel Contributors



"Maximum security value per CPU cycle consumed."



text



Save, close, then push:



```cmd

git add README.md

git commit -m "Add comprehensive README with architecture, API docs, and keywords"

git push

