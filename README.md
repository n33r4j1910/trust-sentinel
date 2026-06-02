# 🛡️ Trust Sentinel

### Your device's silent guardian. No cloud. No nonsense.

Trust Sentinel answers one question, every 30 seconds: **"Can this device still be trusted?"**

It's not antivirus. It's not EDR. It doesn't scan files or chase signatures. It watches the handful of signals that actually matter — your DNS, hosts file, startup programs, open ports, and firewall. When something changes that shouldn't, it alerts you. When someone attacks, it blocks them.

All powered by your TPM 2.0 chip. All running offline.

---

## What It Does

- 🔐 **Generates a rotating trust token** every 30 seconds using HMAC-SHA256 and your TPM 2.0
- 📋 **Takes a snapshot** of your system's critical state (DNS, hosts, startup, ports, firewall)
- 🔍 **Watches for changes** every 5 minutes — and tells you exactly what changed
- 🔴 **Detects attacks** — port scans, brute force login attempts, risky open ports
- 🛑 **Fights back** — automatically blocks attacking IPs via Windows Firewall
- 🩹 **Heals itself** — resets baseline after legitimate changes, restarts if crashed
- 🖥️ **Shows trust status** as a green/yellow/red dot in your system tray

## What It Doesn't Do

- ❌ No file scanning
- ❌ No virus signatures
- ❌ No cloud uploads
- ❌ No AI models
- ❌ No packet inspection
- ❌ No user tracking
- ❌ No performance impact

---

## Quick Start

### You'll need
- Windows 10 or 11 (64-bit)
- [Rust](https://rustup.rs) installed
- TPM 2.0 (recommended, but works without it)

### Build and run

```bash
git clone https://github.com/n33r4j1910/trust-sentinel.git
cd trust-sentinel
cargo build --release
target\release\trust-sentinel-daemon.exe

Then open http://127.0.0.1:12788 in your browser.

You'll see:

json
{
  "trust_state": "Trusted",
  "token": "a3f2c1b8...",
  "tpm_sealed": true,
  "last_check": "2026-06-02T12:00:00Z",
  "latest_events": []
}

Make it start with Windows

A shortcut is placed in your Startup folder automatically. Restart your PC — the green dot appears on its own.

How It Works
Trust Shield
Every 30 seconds, Trust Sentinel generates a 64-character token using your device's unique seed (stored in TPM when available). If anyone tampers with your system, the baseline signature won't match and trust drops.

Integrity Monitoring
On first run, it captures your DNS servers, hosts file hash, startup programs, listening ports, and firewall state. Every 5 minutes it compares. A single change = Warning. Multiple changes = Compromised.

Intrusion Detection
Every 10 seconds, it checks:

Port scans — 20+ connections from one external IP = attacker blocked via Firewall

Brute force — 5+ failed Windows logins in 60 seconds = RDP port blocked

Risky ports — alerts if RDP (3389), SMB (445), SSH (22), and 14 other dangerous ports are open

Self-Protection
Watchdog restarts the daemon or tray if either crashes

Baseline auto-resets after repeated legitimate changes

All data signed with HMAC — tampering is detected instantly

System Impact
Metric	Value
CPU (idle)	<0.1%
RAM	~30 MB
Disk	<5 MB
Network	None (localhost only)
Battery	Negligible
It won't slow down your machine. Even on older laptops.

Privacy

Everything stays on your device.

No accounts

No API keys

No telemetry

No cloud uploads

HTTP server only accessible from 127.0.0.1

Project Layout

text
trust-sentinel/
├── daemon/src/main.rs    # The brain — trust engine, integrity, intrusion detection
├── tray/src/main.rs      # System tray — green/yellow/red dot
├── start.bat             # Silent launcher with watchdog loop
├── startup.vbs           # Invisible startup script
└── Cargo.toml            # Rust workspace

Real Attacks It Catches

✅ Modified hosts file (DNS poisoning)

✅ New startup entries (malware persistence)

✅ Firewall disabled

✅ Port scan from external IP → blocked

✅ Brute force RDP login → blocked

✅ Risky port exposure (RDP, SMB, etc.)

✅ Baseline file tampering

Things You Can Build On Top

Real-time ETW event monitoring (currently polls every 5 min)

Credential file guard (SSH keys, browser passwords, cloud tokens)

Linux support via eBPF + TPM2-TSS

macOS support via Endpoint Security + Secure Enclave

Remote attestation for fleet deployments

Encrypted SQLite database

Keywords
endpoint-security trust-agent device-integrity tpm-2.0 hmac-sha256 zero-trust offline privacy-first rust windows-security intrusion-detection port-scan brute-force firewall self-healing hardware-rooted-trust device-attestation baseline-monitoring open-source lightweight no-cloud

License
MIT