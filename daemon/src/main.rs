use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const HTTP_PORT: u16 = 12789;
const SCAN_THRESHOLD: usize = 15;
const DATA_DIR: &str = "C:\\ProgramData\\Trust Sentinel";
const HOSTS_BACKUP: &str = "C:\\ProgramData\\Trust Sentinel\\hosts.backup";

static PHISHING_BLOCKLIST: OnceLock<HashSet<String>> = OnceLock::new();

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct SystemState {
    dns_servers: Vec<String>,
    hosts_hash: String,
    startup_entries: Vec<String>,
    listening_ports: Vec<String>,
    firewall_profiles: Vec<String>,
    arp_table: Vec<String>,
    wifi_ssid: String,
}

#[derive(Debug, Serialize, Clone)]
struct DaemonStatus {
    trust_state: String,
    token: String,
    last_check: String,
    latest_events: Vec<String>,
}

fn main() {
    let _ = fs::create_dir_all(DATA_DIR);
    backup_hosts();
    let seed = random_seed();
    let baseline = Arc::new(Mutex::new(collect_state()));
    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let b1 = baseline.clone(); let e1 = events.clone(); let s1 = seed.clone();
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", HTTP_PORT)).unwrap();
        println!("Trust Sentinel on http://127.0.0.1:{}", HTTP_PORT);
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                if req.contains("POST /home") {
                    let ssid = get_wifi();
                    let _ = fs::write(std::path::PathBuf::from(DATA_DIR).join("home_wifi.txt"), &ssid);
                    stealth_off();
                    let st = DaemonStatus { trust_state: "Trusted".into(), token: token_str(&s1), last_check: Utc::now().to_rfc3339(), latest_events: vec![format!("Home WiFi set: {}", ssid)] };
                    let json = serde_json::to_string(&st).unwrap();
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes());
                    continue;
                }

                if req.contains("POST /reset") {
                    let _ = fs::remove_file(std::path::PathBuf::from(DATA_DIR).join("stealth.flag"));
                    let cur = collect_state(); *b1.lock().unwrap() = cur; e1.lock().unwrap().clear();
                    let st = DaemonStatus { trust_state: "Trusted".into(), token: token_str(&s1), last_check: Utc::now().to_rfc3339(), latest_events: vec![] };
                    let json = serde_json::to_string(&st).unwrap();
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes());
                    continue;
                }
                if req.contains("POST /stealth") { stealth_on(); let st = DaemonStatus { trust_state: "Stealth".into(), token: token_str(&s1), last_check: Utc::now().to_rfc3339(), latest_events: vec!["Stealth ON".into()] }; let json = serde_json::to_string(&st).unwrap(); let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes()); continue; }
                if req.contains("POST /visible") { stealth_off(); let st = DaemonStatus { trust_state: "Visible".into(), token: token_str(&s1), last_check: Utc::now().to_rfc3339(), latest_events: vec!["Stealth OFF".into()] }; let json = serde_json::to_string(&st).unwrap(); let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes()); continue; }
                if req.contains("POST /repair") { let fixed = auto_repair(); let st = DaemonStatus { trust_state: "Trusted".into(), token: token_str(&s1), last_check: Utc::now().to_rfc3339(), latest_events: fixed }; let json = serde_json::to_string(&st).unwrap(); let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes()); continue; }

                let stealth_flag = std::path::PathBuf::from(DATA_DIR).join("stealth.flag");
                if stealth_flag.exists() {
                    let st = DaemonStatus { trust_state: "Stealth".into(), token: token_str(&s1), last_check: Utc::now().to_rfc3339(), latest_events: vec!["Stealth mode active - device hidden".into()] };
                    let json = serde_json::to_string(&st).unwrap();
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes());
                    continue;
                }

                let cur = collect_state();
                let bl = b1.lock().unwrap(); let ev = e1.lock().unwrap();
                let diffs = diff(&bl, &cur);
                let intruder = detect_port_scan();
                let phishing = check_phishing();
                let ransomware = check_ransomware();
                let usb_threat = check_usb();
                let mut state = if diffs.is_empty() { "Trusted" } else if diffs.len() == 1 { "Warning" } else { "Compromised" };
                let mut extra: Vec<String> = Vec::new();
                if !intruder.is_empty() { state = "Compromised"; extra.push(format!("port_scan: {}", intruder)); }
                if !phishing.is_empty() { if state == "Trusted" { state = "Warning"; } extra.push(format!("phishing: {}", phishing)); }
                if ransomware { state = "Compromised"; extra.push("ransomware: Canary files modified!".into()); }
                if !usb_threat.is_empty() { extra.push(format!("usb: {}", usb_threat)); }
                let token = token_str(&s1);
                let mut all: Vec<String> = ev.iter().rev().take(5).cloned().collect();
                all.extend(extra);
                let st = DaemonStatus { trust_state: state.into(), token, last_check: Utc::now().to_rfc3339(), latest_events: all };
                let json = serde_json::to_string(&st).unwrap();
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes());
            }
        }
    });

    let b2 = baseline.clone(); let e2 = events.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(300));
        let cur = collect_state();
        let bl = b2.lock().unwrap();
        let diffs = diff(&bl, &cur);
        if !diffs.is_empty() {
            let repaired = auto_repair();
            let mut ev = e2.lock().unwrap();
            for r in &repaired { ev.push(r.clone()); }
        }
    });

    // Auto-stealth: default stealth ON, only off on home WiFi
    let e_stealth = events.clone();
    std::thread::spawn(move || {
        let home_file = std::path::PathBuf::from(DATA_DIR).join("home_wifi.txt");
        // Default: enable stealth on startup
        stealth_on();
        loop {
            std::thread::sleep(Duration::from_secs(30));
            if let Ok(home) = fs::read_to_string(&home_file) {
                let home = home.trim().to_string();
                let current = get_wifi();
                if !home.is_empty() && current == home {
                    stealth_off();
                } else if !home.is_empty() && current != home && current != "Unknown" {
                    stealth_on();
                }
            }
        }
    });

    let e3 = events.clone(); std::thread::spawn(move || loop { std::thread::sleep(Duration::from_secs(120)); if !check_phishing().is_empty() { clear_dns(); let mut ev = e3.lock().unwrap(); ev.push("auto_repair: DNS cache cleared".into()); } });
    let e4 = events.clone(); std::thread::spawn(move || loop { std::thread::sleep(Duration::from_secs(30)); if check_ransomware() { let mut ev = e4.lock().unwrap(); ev.push("ransomware: Canary files modified - disconnect now!".into()); } });
    let e5 = events.clone(); std::thread::spawn(move || loop { std::thread::sleep(Duration::from_secs(30)); let usb = check_usb(); if !usb.is_empty() { let mut ev = e5.lock().unwrap(); ev.push(format!("usb: {}", usb)); } });
    loop { std::thread::sleep(Duration::from_secs(60)); }
}

fn random_seed() -> Vec<u8> { let r = SystemRandom::new(); let mut s = [0u8; 32]; r.fill(&mut s).unwrap(); s.to_vec() }
fn token_str(seed: &[u8]) -> String { let c = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30; let mut m = HmacSha256::new_from_slice(seed).unwrap(); m.update(&c.to_be_bytes()); hex::encode(m.finalize().into_bytes()) }
fn collect_state() -> SystemState { SystemState { dns_servers: get_dns(), hosts_hash: get_hosts_hash(), startup_entries: get_startup(), listening_ports: get_ports(), firewall_profiles: get_firewall(), arp_table: get_arp(), wifi_ssid: get_wifi() } }

fn backup_hosts() { let _ = fs::copy("C:\\Windows\\System32\\drivers\\etc\\hosts", HOSTS_BACKUP); }

fn auto_repair() -> Vec<String> {
    let mut fixed = Vec::new();
    if let Ok(orig) = fs::read_to_string(HOSTS_BACKUP) {
        let cur = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts").unwrap_or_default();
        if orig != cur { let _ = fs::write("C:\\Windows\\System32\\drivers\\etc\\hosts", &orig); fixed.push("auto_repair: Hosts restored".into()); }
    }
    let _ = Command::new("ipconfig").args(["/flushdns"]).output();
    let _ = Command::new("netsh").args(["interface", "ip", "set", "dns", "Wi-Fi", "dhcp"]).output();
    fixed.push("auto_repair: DNS reset".into());
    let _ = Command::new("powershell").args(["-NoProfile","-Command","Set-NetFirewallProfile -All -Enabled True"]).output();
    fixed.push("auto_repair: Firewall re-enabled".into());
    let _ = Command::new("arp").args(["-d"]).output();
    fixed.push("auto_repair: ARP flushed".into());
    fixed
}

fn clear_dns() { let _ = Command::new("ipconfig").args(["/flushdns"]).output(); }

fn stealth_on() {
    let _ = fs::write(std::path::PathBuf::from(DATA_DIR).join("stealth.flag"), "1");
    let _ = Command::new("powershell").args(["-NoProfile","-Command",
        "Set-NetFirewallProfile -All -DefaultInboundAction Block;",
        "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Disable-NetFirewallRule;",
        "Get-NetFirewallRule -DisplayGroup 'File and Printer Sharing' | Disable-NetFirewallRule;",
        "Stop-Service -Name 'FDResPub','SSDPSRV','upnphost' -Force;",
        "Set-Service -Name 'FDResPub','SSDPSRV','upnphost' -StartupType Disabled;"
    ]).output();
}

fn stealth_off() {
    let _ = fs::remove_file(std::path::PathBuf::from(DATA_DIR).join("stealth.flag"));
    let _ = Command::new("powershell").args(["-NoProfile","-Command",
        "Set-NetFirewallProfile -All -DefaultInboundAction Allow;",
        "Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Enable-NetFirewallRule;",
        "Set-Service -Name 'FDResPub','SSDPSRV','upnphost' -StartupType Manual;"
    ]).output();
}

fn get_dns() -> Vec<String> { let mut d = Vec::new(); if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | ForEach-Object {$_.ServerAddresses -join ','}"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { for a in l.split(',') { let a = a.trim().to_string(); if !a.is_empty() && !d.contains(&a) { d.push(a); } } } } if d.is_empty() { d.push("Unknown".into()); } d }
fn get_hosts_hash() -> String { if let Ok(c) = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts") { hex::encode(ring::digest::digest(&ring::digest::SHA256, c.as_bytes())) } else { "unreadable".into() } }
fn get_startup() -> Vec<String> { let mut e = Vec::new(); let sf = std::env::var("APPDATA").unwrap_or_default() + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"; if let Ok(d) = fs::read_dir(&sf) { for f in d.flatten() { e.push(f.file_name().to_string_lossy().to_string()); } } if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run').PSObject.Properties | Where-Object {$_.Name -ne 'PSPath'} | Select-Object -ExpandProperty Name"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { let l = l.trim().to_string(); if !l.is_empty() { e.push(l); } } } if e.is_empty() { e.push("None".into()); } e }
fn get_ports() -> Vec<String> { let mut p = Vec::new(); if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) { let parts: Vec<&str> = l.split_whitespace().collect(); if parts.len() >= 4 && parts[3] == "LISTENING" { let a = parts[1].to_string(); if a != "0.0.0.0:0" && !a.ends_with(&format!(":{}", HTTP_PORT)) { p.push(a); } } } } p.sort(); p.dedup(); p }
fn get_firewall() -> Vec<String> { let mut p = Vec::new(); if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-NetFirewallProfile | ForEach-Object {$_.Name+':'+($_.Enabled ? 'ON':'OFF')}"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { let l = l.trim().to_string(); if !l.is_empty() { p.push(l); } } } if p.is_empty() { p.push("Unknown".into()); } p }
fn get_arp() -> Vec<String> { let mut a = Vec::new(); if let Ok(o) = Command::new("arp").args(["-a"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { let l = l.trim().to_string(); if l.contains("dynamic") || l.contains("static") { a.push(l); } } } if a.is_empty() { a.push("None".into()); } a }
fn get_wifi() -> String { if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","(Get-NetConnectionProfile | Where-Object {$_.InterfaceAlias -like '*Wi*' -or $_.InterfaceAlias -like '*Wireless*'} | Select-Object -First 1).Name"]).output() { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if !s.is_empty() { return s; } } "Unknown".into() }
fn detect_port_scan() -> String { let mut ip_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new(); if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) { let parts: Vec<&str> = l.split_whitespace().collect(); if parts.len() >= 3 && parts[3] == "ESTABLISHED" { if let Some(ip) = parts[2].rsplitn(2, ':').nth(1) { if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") { *ip_counts.entry(ip.to_string()).or_insert(0) += 1; } } } } } for (ip, count) in &ip_counts { if *count > SCAN_THRESHOLD { return ip.clone(); } } String::new() }
fn check_phishing() -> String { let hosts_path = std::path::PathBuf::from(DATA_DIR).join("phishing_hosts.txt"); let blocklist = PHISHING_BLOCKLIST.get_or_init(|| { let mut set = HashSet::new(); if let Ok(c) = fs::read_to_string(&hosts_path) { for l in c.lines() { let l = l.trim(); if l.starts_with("0.0.0.0") || l.starts_with("127.0.0.1") { if let Some(d) = l.split_whitespace().nth(1) { set.insert(d.to_lowercase()); } } } } set }); if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-DnsClientCache | Select-Object -ExpandProperty Entry | Where-Object { $_ -match '^[a-zA-Z]' }"]).output() { for e in String::from_utf8_lossy(&o.stdout).lines() { let e = e.trim().to_lowercase(); if !e.is_empty() && blocklist.contains(&e) { return e; } } } String::new() }
fn check_ransomware() -> bool { let canary_dir = std::path::PathBuf::from(DATA_DIR).join("canary"); let _ = fs::create_dir_all(&canary_dir); let canary_files = ["test.docx", "test.pdf", "test.jpg", "test.txt", "test.xlsx"]; let mut modified = 0; for fname in &canary_files { let p = canary_dir.join(fname); if !p.exists() { let _ = fs::write(&p, b"TRUST SENTINEL CANARY"); } if let Ok(meta) = fs::metadata(&p) { if let Ok(mt) = meta.modified() { if let Ok(d) = SystemTime::now().duration_since(mt) { if d.as_secs() < 30 { modified += 1; } } } } } modified >= 2 }
fn check_usb() -> String { if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -match 'storage|flash|drive'} | Select-Object -ExpandProperty FriendlyName"]).output() { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if !s.is_empty() { return s; } } String::new() }

fn diff(a: &SystemState, b: &SystemState) -> Vec<(String, String)> {
    let mut d = Vec::new();
    if a.dns_servers != b.dns_servers { d.push(("dns_change".into(), "DNS changed".into())); }
    if a.hosts_hash != b.hosts_hash { d.push(("hosts_change".into(), "Hosts modified".into())); }
    if a.startup_entries != b.startup_entries { d.push(("startup_change".into(), "Startup changed".into())); }
    if a.listening_ports != b.listening_ports { d.push(("port_change".into(), "Ports changed".into())); }
    if a.firewall_profiles != b.firewall_profiles { d.push(("firewall_change".into(), "Firewall changed".into())); }
    if a.arp_table != b.arp_table { d.push(("arp_change".into(), "ARP changed".into())); }
    if a.wifi_ssid != b.wifi_ssid { d.push(("wifi_change".into(), format!("WiFi: {}", b.wifi_ssid))); }
    d
}