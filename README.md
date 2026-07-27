[TrustSentinel.zip](https://github.com/user-attachments/files/30222845/TrustSentinel.zip)

# 🛡️ Trust Sentinel

> **Your device's silent guardian. No cloud. No nonsense.**

Trust Sentinel is a lightweight Windows guardian (smoke detector). Just download, double-click and always protected. It auto-detects DNS hijacking, ARP spoofing, rogue WiFi, phishing domains, ransomware canary alerts, and USB threats — then repairs them automatically. Sets stealth mode on public networks. Phishing blocklist updates weekly. Zero cloud, minimal network (blocklist only), zero telemetry, zero AI. All run locally with <30MB RAM & <1% CPU. Everything stays on your PC. Free. Open source.

---

## 🚀 What is Trust Sentinel?

Trust Sentinel is a lightweight **endpoint trust agent**.

Think of it as a **smoke alarm for your computer**.

- ✅ Always running
- ✅ Silent until something is wrong
- ✅ Detects 12 threat types instantly
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
- Ransomware canary alerts?
- Firewall being disabled?
- Phishing domains already cached on your PC?
- Root CA certificates being installed?
- Scheduled tasks being added?
- Proxy settings being changed?

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
- Scheduled Tasks
- Proxy settings
- Root CA certificates
- Windows Defender status
- Running services
- Network devices

Every few minutes, the baseline is verified.

If something changes unexpectedly — you'll know.

---

## 🚨 Intrusion Detection

Trust Sentinel detects active attacks including:

- 🔍 Port scans → auto-blocks attacker IP
- 🌐 ARP spoofing (MITM) → flushes ARP cache
- 📶 Wi-Fi network change → auto-enables stealth
- 🎣 Phishing domains (80,000+ blocklist) → clears DNS cache
- 🔐 Ransomware canary alert → disables network
- 💾 USB storage insertion → auto-ejects device
- 🔑 Unknown startup entries → auto-removes
- 🔌 New listening ports → auto-blocks
- 📋 Rogue root CA → alerts on HTTPS interception
- 🔒 Windows Defender disabled → alerts
- 📅 New scheduled tasks → alerts
- 🌐 Proxy settings changed → alerts

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
| Ransomware canary alert | Disable network adapter |

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

Hover over the icon to view detected issues. Dashboard opens automatically on alerts.

---

## 🖥️ Dashboard

Open `http://127.0.0.1:12789/dashboard` for one-click controls:

- Reset Baseline
- Enable/Disable Stealth
- Set Home WiFi
- Auto-Repair

Token-based authentication on all actions.

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
6. Set your home WiFi: Open `http://127.0.0.1:12789/dashboard` → click "Set Home WiFi"
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
| **Integrity Monitoring** | DNS, Hosts file, Startup Programs, Listening Ports, Firewall, ARP Table, Wi-Fi SSID, Scheduled Tasks, Proxy, Root CAs, Defender, Services, Network Devices |
| **Intrusion Detection** | Port Scanning, ARP Spoofing, Phishing Domains (80K+), Ransomware Canary, USB Storage, Wi-Fi Change, Root CA, Defender Disabled, Proxy Change |
| **Automatic Repair** | Hosts Restore, DNS Reset, Firewall Recovery, ARP Flush, DNS Cache Clear, Port Blocking, Startup Removal, USB Eject, Network Kill |
| **Stealth Mode** | Block Incoming, Disable Discovery, Stop File Sharing, Auto-Stealth on New WiFi |
| **User Experience** | System Tray (Green/Yellow/Red/Orange), Tooltips, Popup Alerts, Dashboard, One-Click Repair |
| **Privacy** | Fully Offline, No Accounts, No Telemetry, Localhost Only |

---

# ⚙️ Performance

Designed to stay invisible.

| Metric | Usage |
|--------|-------|
| CPU (Idle) | **<0.1%** |
| RAM | **~30 MB** |
| Disk Space | **<10 MB** |
| Network Usage | **Minimal (blocklist only)** |

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
| Ransomware Canary | ⚠️ Partial | ❌ | ✅ Early Detection |
| Phishing Domains | ❌ | ❌ | ✅ 80K+ Database |
| USB Storage Detection | ❌ | ❌ | ✅ Auto Eject |
| Startup Persistence | ⚠️ Partial | ❌ | ✅ Auto Remove |
| Wi-Fi Change Detection | ❌ | ❌ | ✅ Auto Stealth |
| Stealth Mode | ❌ | ❌ | ✅ |
| Root CA Detection | ❌ | ❌ | ✅ |
| Defender Monitoring | ❌ | ❌ | ✅ |
| Proxy Detection | ❌ | ❌ | ✅ |

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
| Live Testing | **10/12 tests passed** — API, auth, dashboard, detection verified |

---

# ⚠️ Current Limitations

- Hosts file repair requires Administrator privileges.
- Some system checks rely on PowerShell (native API migration underway).
- Ransomware detection threshold set to 5 files to avoid false positives.
- CORS restricted to localhost for security.

---

# 🛣️ Roadmap

- Native Windows API implementation
- TPM-backed hardware trust verification
- VPN drop detection
- Linux support
- macOS support
- Code signing via SignPath.io (in progress)

---

# 🏷️ Keywords
endpoint-security trust-agent device-integrity zero-trust offline privacy-first windows-security intrusion-detection self-healing auto-repair ransomware phishing port-scan arp-spoofing stealth-mode root-ca-detection proxy-detection defender-monitoring rust lightweight no-cloud open-source

---

# 📄 License

Licensed under the **MIT License**.

© 2026 Trust Sentinel