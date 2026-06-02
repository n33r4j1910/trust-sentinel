# 🛡️ Trust Sentinel

**Lightweight, hardware-rooted endpoint trust agent for Windows.**

> "Can this device still be trusted right now?" — Answered every 30 seconds using TPM 2.0.

[![Rust](https://img.shields.io/badge/Rust-1.96%2B-orange)](https://rustup.rs)
[![Platform](https://img.shields.io/badge/Windows-10%2F11-blue)](https://github.com/n33r4j1910/trust-sentinel)
[![TPM](https://img.shields.io/badge/TPM-2.0-green)](https://github.com/n33r4j1910/trust-sentinel)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

Trust Sentinel is **not** an antivirus, EDR, XDR, or SIEM. It is a **device integrity guardian** — a smoke alarm for trust that runs silently, uses minimal resources, and never calls home.

---

## ✨ Features

### 🔐 Trust Shield
- **TPM 2.0 hardware-rooted** seed generation (`tpm_sealed: true`)
- **HMAC-SHA256 rotating trust token** every 30 seconds (64-char hex)
- Time-windowed tokens prevent replay attacks
- Falls back to file-based seed if TPM unavailable

### 📋 Integrity Monitoring (every 5 min)
- DNS server changes
- Hosts file modifications (SHA256 hash)
- Startup entries (Registry + Startup folder)
- Listening ports (TCP LISTENING only)
- Windows Firewall profile changes
- HMAC-signed baseline prevents tampering

### 🔴 Intrusion Detection (every 10 sec)
- **Port scan detection** — alerts on 20+ ports from single external IP
- **Brute force detection** — 5+ failed logins in 60 seconds (Event ID 4625)
- **Risky port alerts** — RDP, SMB, SSH, Telnet, and 13 more
- **Firewall change monitoring** — detects disabled profiles

### 🖥️ System Tray
- 🟢 Trusted / 🟡 Warning / 🔴 Compromised
- Round icon, updates every 2 seconds
- Silent startup, no popup windows

### 🔄 Self-Healing
- Watchdog auto-restarts daemon + tray if crashed
- Auto-resets baseline after repeated legitimate changes

### 🚫 Privacy-First
- 100% offline — zero cloud, zero telemetry, zero accounts
- HTTP server binds to `127.0.0.1` only
- All data stored locally in `C:\ProgramData\Trust Sentinel\`

---

## 🚀 Quick Start

### Prerequisites
- Windows 10/11 (64-bit)
- [Rust](https://rustup.rs) (MSVC toolchain)
- TPM 2.0 (optional — falls back to file-based seed)

### Build
```bash
git clone https://github.com/n33r4j1910/trust-sentinel.git
cd trust-sentinel
cargo build --release

Run
bash
target\release\trust-sentinel-daemon.exe
Open http://127.0.0.1:12788

Auto-Start
Shortcut installed at:

text
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\TrustSentinel.lnk
📊 Resource Footprint
Metric	Value
CPU (idle)	<0.1%
RAM	~25-30 MB
Disk	<5 MB
Network	None (localhost only)
Battery	Negligible

🏗️ Architecture

text
trust-sentinel/
├── daemon/                  # Background trust engine
│   ├── Cargo.toml
│   └── src/main.rs          # TPM, token, integrity, intrusion detection
├── tray/                    # System tray application
│   ├── Cargo.toml
│   └── src/main.rs          # Live trust status icon
├── start.bat                # Silent launcher + watchdog loop
└── Cargo.toml               # Workspace root
Runtime data: C:\ProgramData\Trust Sentinel\

tpm_seed.bin — TPM 2.0 generated seed

seed.bin — File-based fallback seed

baseline.json — HMAC-signed system snapshot

events.log — JSON-lines security event log

📡 API

GET http://127.0.0.1:12788

json
{
  "trust_state": "Trusted",
  "token": "a3f2c1b8d5e6f7a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
  "tpm_sealed": true,
  "last_check": "2026-06-02T12:00:00Z",
  "latest_events": []
}

🔒 Security

Layer	Mechanism
Seed generation	TPM 2.0 RNGCryptoServiceProvider
Token	HMAC-SHA256, 30-second time window
Baseline integrity	HMAC-SHA256 signature verified every read
Replay prevention	Time-windowed tokens expire after 30s
Network	Localhost-only HTTP, zero external connections
Tamper detection	Signature mismatch → immediate Compromised state

🧪 Tested Attack Scenarios
✅ Hosts file modification → Detected

✅ DNS server change → Detected

✅ New startup entry → Detected

✅ Firewall profile change → Detected

✅ Port scan simulation → Detected

✅ Brute force login → Detected

✅ Agent termination → Watchdog restarts

✅ Baseline tampering → Signature mismatch alert


📋 Trust States

State	Condition	Icon
Trusted	Zero unauthorized changes	🟢
Warning	One change detected	🟡
Compromised	Multiple changes or tampering	🔴

🛣️ Roadmap

Rotating trust token (HMAC-SHA256)

TPM 2.0 hardware-rooted seed

System baseline monitoring

Intrusion detection (port scan, brute force, risky ports)

System tray with live status

Watchdog auto-restart

Auto-healing baseline

Real-time ETW event monitoring

Credential file guard (SSH keys, browser passwords)

Linux support (eBPF + TPM2-TSS)

macOS support (Endpoint Security + Secure Enclave)

Remote attestation (optional, privacy-preserving)

Encrypted local database (SQLCipher)

🤝 Contributing

PRs welcome. Key areas: ETW integration, Linux/macOS ports, TPM PCR sealing, security audits.

bash
git clone https://github.com/n33r4j1910/trust-sentinel.git
cd trust-sentinel
cargo build

📚 Keywords
endpoint-security trust-agent device-integrity tpm-2.0 hmac-sha256 trust-token zero-trust privacy-first offline rust windows-security intrusion-detection port-scan brute-force baseline-monitoring hardware-rooted-trust device-attestation integrity-verification open-source lightweight

📄 License
MIT © 2026