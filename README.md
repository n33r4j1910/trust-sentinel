Trust Sentinel

**Your device's silent guardian. No cloud. No nonsense.**

Trust Sentinel answers one question, every 30 seconds: *"Can this device still be trusted right now?"*

---

## What It Is

Trust Sentinel is a lightweight, hardware-rooted endpoint trust agent. Think of it as a **smoke alarm for your device** — always on, silent, and loud when something's actually wrong.

It's not antivirus. It's not EDR. It doesn't scan files or chase virus signatures. It watches the handful of signals that actually matter — and fights back when someone attacks.

---

## Why You Need It

Your antivirus looks for known malware. Your firewall blocks suspicious traffic. But who's watching for:

- Your hosts file being hijacked?
- Your DNS servers being changed?
- A new program adding itself to startup?
- Someone scanning your ports right now?
- PowerShell running suspicious commands?
- Your SSH keys being accessed?

**Trust Sentinel watches all of this. And it fights back.**

---

## What It Does

### 🔐 Trust Shield
Every 30 seconds, Trust Sentinel generates a 64-character trust token using a secret sealed inside your TPM 2.0 chip. If anything tampers with your boot chain, the token stops. No token = no trust.

### 📋 Integrity Monitoring
Takes a snapshot of your system's clean state — DNS, hosts file, startup programs, open ports, firewall status, Windows Update. Every 5 minutes, it checks. Something changed? You'll know.

### 🔴 Intrusion Detection & Auto-Blocking
- **Port scans** → detected and attacker IP automatically blocked
- **Brute force logins** → detected and RDP port automatically blocked
- **Suspicious PowerShell** → flagged
- **Credential file access** → flagged
- **USB storage devices** → flagged
- **New network connections** → flagged
- **Phishing domains** → checked against 80,000+ known bad domains
- **Ransomware** → canary files and mass write detection

### 🩹 Self-Healing
If something crashes, it restarts. If the baseline gets stale, it resets. If logs get too big, they rotate. Trust Sentinel takes care of itself.

### 🖥️ Settings Dashboard
Open `http://127.0.0.1:12788/dashboard` and you get a clean panel to toggle features, adjust intervals, view events, and export logs. No cloud. No accounts.

---

## What It Doesn't Do

- ❌ No file scanning (use Windows Defender)
- ❌ No virus signatures
- ❌ No AI models
- ❌ No cloud uploads
- ❌ No user tracking
- ❌ No packet inspection
- ❌ No interference with other software

**Trust Sentinel is the smoke alarm. Your antivirus is the fire extinguisher. Your firewall is the locked door. You need all three.**

---

## Quick Start

### You'll need
- Windows 10 or 11 (64-bit)
- [Rust](https://rustup.rs) installed
- TPM 2.0 recommended (works without it)

### Build and run
```bash
git clone https://github.com/n33r4j1910/trust-sentinel.git
cd trust-sentinel
cargo build --release
target\release\trust-sentinel-daemon.exe

Open http://127.0.0.1:12788 for the API, or http://127.0.0.1:12788/dashboard for the settings panel.

Trust States

State	Meaning
🟢 Trusted	No unauthorized changes detected
🟡 Warning	One change detected — worth a look
🔴 Compromised	Multiple changes or tampering — action needed

Complete Feature List

Category	Features
Trust		TPM 2.0 PCR-bound encryption, rotating HMAC-SHA256 token, AES-256-GCM encrypted logs
Integrity	DNS, hosts, startup, ports, firewall, Windows Update
Detection	Port scan, brute force, risky ports, suspicious commands, credential access, USB, phishing domains, ransomware
Prevention	Auto-block attacker IPs, auto-block RDP on brute force
Self-Protection	Binary integrity check, memory-locked seed, ACL folder lock, watchdog, self-healing, log rotation, unkillable daemon
UX		System tray (green/yellow/red), settings dashboard, export logs, reset baseline
Privacy		100% offline, no cloud, no telemetry, localhost only

System Impact

Metric	Value
CPU (idle)	<0.1%
RAM		~30 MB
Disk		<10 MB
Network		None
Runs fine on older laptops. Won't slow you down.

**How It Compares**

Threat				            Antivirus	Firewall	Trust Sentinel
Known malware			          ✅		    ❌		      ❌
Suspicious network traffic	❌		    ✅		      ✅ + blocks
Hosts file hijacking		    ❌		    ❌		      ✅
DNS poisoning			          ❌		    ❌		      ✅
New startup persistence		  ⚠️		    ❌		      ✅
Firewall disabled		        ❌		    ❌		      ✅
Port scans			            ❌		    ❌		      ✅ + blocks
Brute force logins		      ❌		    ❌		      ✅ + blocks
Suspicious PowerShell		    ⚠️		    ❌		      ✅
USB storage insertion		    ❌		    ❌		      ✅
Ransomware behavior		      ⚠️		    ❌		      ✅
Phishing domains		        ❌		    ❌		      ✅ (80K+ list)
Hardware trust (TPM)		    ❌		    ❌		      ✅
Privacy

Everything stays on your device. Period, No accounts required, No API keys, No telemetry, No cloud uploads, HTTP server only accessible from your own machine

Known Limitations

Credential guard detects file writes, not reads (Windows audit policy required for read detection)

User-context features (credential monitoring, USB detection) work best when run as logged-in user

Some checks use PowerShell (native API migration in progress)


Keywords

endpoint-security trust-agent device-integrity tpm-2.0 hmac-sha256 zero-trust offline privacy-first rust windows-security intrusion-detection port-scan brute-force ransomware phishing self-healing hardware-rooted-trust open-source lightweight no-cloud

MIT © 2026
