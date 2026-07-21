[TrustSentinel.zip](https://github.com/user-attachments/files/30222845/TrustSentinel.zip)

# 🛡️ Trust Sentinel

> **Your device's silent guardian. No cloud. No nonsense.**

Trust Sentinel is a lightweight Windows guardian (smoke detector). Just download, double-click and always protected. It auto-detects DNS hijacking, ARP spoofing, rogue WiFi, phishing domains, ransomware, and USB threats then repairs them automatically. Sets stealth mode on public networks. Updates itself weekly. Zero cloud, Zero network, Zero telemetry and Zero AI. All run locally with < ~30MB RAM & 1% CPU usage and everything stays on your PC. Free. Open source.

---

## 🚀 What is Trust Sentinel?

Trust Sentinel is a lightweight **endpoint trust agent**.

Think of it as a **smoke alarm for your computer**.

- ✅ Always running
- ✅ Silent until something is wrong
- ✅ Detects security changes instantly
- ✅ Automatically repairs common threats
- ✅ Completely offline
- ✅ Tested: 64/69 VirusTotal clean, 0/100 CAPE sandbox score

It is **not** an antivirus or EDR.

Instead of scanning millions of files or downloading virus signatures, Trust Sentinel watches the handful of security signals that actually matter.

---

# 🎯 Why Trust Sentinel?

Your existing security tools already do a good job...

- Windows Defender scans malware.
- Your Firewall blocks unwanted connections.
- Browser Safe Browsing blocks many malicious websites.

But who watches for things like:

- Hosts file hijacking?
- DNS server changes?
- Startup persistence?
- Active port scanning?
- ARP spoofing?
- Rogue Wi-Fi hotspots?
- Ransomware encryption?
- Firewall being disabled?
- Phishing domains already cached on your PC?

**Trust Sentinel does.**

It detects these attacks immediately — and whenever possible, repairs them automatically.

---

# ✨ Key Features

## 🔍 Integrity Monitoring

Trust Sentinel creates a trusted baseline of your system and continuously compares it against the current state.

Monitored items include:

- DNS configuration
- Hosts file
- Startup applications
- Listening ports
- Windows Firewall
- ARP table
- Connected Wi-Fi SSID

Every few minutes, the baseline is verified.

If something changes unexpectedly — you'll know.

---

## 🚨 Intrusion Detection

Trust Sentinel detects active attacks including:

- 🔍 Port scans → auto-blocks attacker IP
- 🌐 ARP spoofing (MITM) → flushes ARP cache
- 📶 Rogue / Evil Twin Wi-Fi → auto-enables stealth
- 🎣 Phishing domains (80,000+ blacklist) → clears DNS cache
- 🔐 Ransomware (Canary file monitoring) → disables network
- 💾 USB storage insertion → auto-ejects device
- 🔑 Unknown startup entries → auto-removes
- 🔌 New listening ports → auto-blocks

---

## 🩹 Automatic Self-Healing

When possible, Trust Sentinel repairs security issues automatically.

| Threat | Action |
|---------|--------|
| Hosts file hijacked | Restore from trusted backup |
| DNS modified | Reset to automatic |
| Firewall disabled | Re-enable Firewall |
| ARP poisoning | Flush ARP cache |
| DNS cache poisoning | Clear DNS cache |
| Port scanning | Block attacker IP via Firewall |
| Unknown startup | Remove from registry/startup |
| New listening port | Block via Firewall |
| USB storage inserted | Auto-eject device |
| Ransomware detected | Disable network adapter |

---

## 🥷 Stealth Mode

One click makes your device nearly invisible on public networks.

Stealth Mode:

- Disables Network Discovery
- Blocks incoming connections
- Stops File Sharing
- Reduces attack surface

Perfect for:

- Airports
- Hotels
- Cafés
- Conferences
- Public Wi-Fi

**Auto-Stealth:** Set your home WiFi once. Every other network gets stealth automatically.

---

## 💚 System Tray Status

Trust Sentinel always stays in your system tray.

| Status | Meaning |
|---------|---------|
| 🟢 **Trusted** | Everything is healthy |
| 🟡 **Warning** | A change requires attention — popup + browser opens |
| 🔴 **Compromised** | Active attack or multiple issues — popup + browser opens |
| 🟠 **Stealth** | Device hidden from network |

Hover over the icon to view detected issues and recommended actions.

---

# ❌ What Trust Sentinel Doesn't Do

Trust Sentinel intentionally focuses on system trust — not malware scanning.

It does **not**:

- ❌ Scan files
- ❌ Use virus signatures
- ❌ Run AI models
- ❌ Upload your data
- ❌ Track users
- ❌ Inspect network packets
- ❌ Replace your antivirus

Think of your security like this:

| Tool | Purpose |
|------|---------|
| Antivirus | Fire extinguisher |
| Firewall | Locked front door |
| **Trust Sentinel** | Smoke alarm |

You need all three.

---

# ⚡ Quick Start

1. Download the latest release.
2. Extract `TrustSentinel.zip`.
3. Run `start_silent.vbs` (silent) or `trust-sentinel-daemon.exe` (visible).
4. Allow Administrator permissions (recommended for auto-repair).
5. Let Trust Sentinel create your trusted baseline.
6. Set your home WiFi: `POST http://127.0.0.1:12789/home`
7. Continue using your PC normally.

---

# 🛡️ Trust States

| State | Meaning |
|-------|---------|
| 🟢 **Trusted** | No unauthorized changes detected |
| 🟡 **Warning** | One suspicious change detected |
| 🔴 **Compromised** | Multiple changes or attack in progress |
| 🟠 **Stealth** | Device hidden from network |

---

# 📋 Complete Feature List

| Category | Features |
|----------|----------|
| **Integrity Monitoring** | DNS, Hosts file, Startup Programs, Listening Ports, Firewall, ARP Table, Wi-Fi SSID |
| **Intrusion Detection** | Port Scanning, ARP Spoofing, Phishing Domains (80K+), Ransomware Canaries, USB Storage, Evil Twin Wi-Fi |
| **Automatic Repair** | Hosts Restore, DNS Reset, Firewall Recovery, ARP Flush, DNS Cache Clear, Port Blocking, Startup Removal, USB Eject, Network Kill |
| **Stealth Mode** | Block Incoming Connections, Disable Discovery, Stop File Sharing, Auto-Stealth on New WiFi |
| **User Experience** | System Tray (Green/Yellow/Red/Orange), Rich Tooltips, Popup Alerts, Baseline Reset, One-Click Repair |
| **Privacy** | Fully Offline, No Accounts, No Telemetry, Localhost Only |

---

# ⚙️ Performance

Designed to stay invisible.

| Metric | Usage |
|--------|-------|
| CPU (Idle) | **<0.1%** |
| RAM | **~30 MB** |
| Disk Space | **<10 MB** |
| Network Usage | **None** |

Runs comfortably on older laptops without affecting performance.

---

# 📊 Comparison

| Capability | Antivirus | Firewall | Trust Sentinel |
|------------|-----------|----------|----------------|
| Known Malware | ✅ | ❌ | ❌ |
| Hosts File Hijacking | ❌ | ❌ | ✅ Auto Repair |
| DNS Poisoning | ❌ | ❌ | ✅ Auto Repair |
| ARP Spoofing | ❌ | ❌ | ✅ Auto Repair |
| Firewall Disabled | ❌ | ❌ | ✅ Auto Repair |
| Port Scan Detection | ❌ | ❌ | ✅ Auto Block |
| Ransomware Behaviour | ⚠️ Partial | ❌ | ✅ Early Detection + Network Kill |
| Phishing Domains | ❌ | ❌ | ✅ 80K+ Database + DNS Clear |
| USB Storage Detection | ❌ | ❌ | ✅ Auto Eject |
| Startup Persistence | ⚠️ Partial | ❌ | ✅ Auto Remove |
| Evil Twin Wi-Fi | ❌ | ❌ | ✅ Auto Stealth |
| Stealth Mode | ❌ | ❌ | ✅ |
| New Listening Ports | ❌ | ❌ | ✅ Auto Block |

---

# 🔒 Privacy First

Trust Sentinel was designed around one principle:

> **Your security should never come at the cost of your privacy.**

- ✅ 100% Offline
- ✅ No Cloud Services
- ✅ No Accounts
- ✅ No Login
- ✅ No API Keys
- ✅ No Telemetry
- ✅ No Analytics
- ✅ No Tracking
- ✅ Localhost Only

**Everything stays on your device. Period.**

---

# 🧪 Security Testing

Trust Sentinel has been tested through multiple sandbox environments:

| Test | Result |
|------|--------|
| VirusTotal (69 engines) | **64/69 Clean (93%)** — 5 false positives from unsigned binary |
| CAPE Sandbox | **0/100 Malicious Score** — All behaviors by design |
| Sigma Rules | **6 matches** — All from expected PowerShell monitoring |

[View full results](https://github.com/n33r4j1910/trust-sentinel)

---

# ⚠️ Current Limitations

- Hosts file repair requires Administrator privileges.
- Some system checks currently rely on PowerShell (native Windows API migration is underway).
- Credential Guard currently detects file **writes**, not **reads**.
- Auto-repair pauses during Stealth Mode to prevent firewall conflicts.
- User-context features (USB monitoring and credential monitoring) work best when running under the logged-in user account.

---

# 🛣️ Roadmap

Future improvements include:

- Native Windows API implementation
- TPM-backed hardware trust verification
- Secure Boot verification
- BitLocker health monitoring
- VPN drop detection
- Linux support
- macOS support
- Code signing via SignPath.io

---

# 🏷️ Keywords
endpoint-security
trust-agent
device-integrity
zero-trust
offline
privacy-first
windows-security
intrusion-detection
self-healing
auto-repair
ransomware
phishing
port-scan
arp-spoofing
stealth-mode
tpm-2.0
rust
lightweight
no-cloud
open-source


---

# 📄 License

Licensed under the **MIT License**.

© 2026 Trust Sentinel
