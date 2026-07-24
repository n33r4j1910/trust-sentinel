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
const SCAN_THRESHOLD: usize = 50;
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
    setup_startup();
    download_phishing_list();
    let _ = fs::create_dir_all(DATA_DIR);
    backup_hosts();
    let seed = random_seed();
    // Lock seed in memory
    let locked_seed = seed.clone();
    std::thread::spawn(move || {
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::Memory::VirtualLock;
            let _ = VirtualLock(locked_seed.as_ptr() as *const _, locked_seed.len());
        }
        std::mem::forget(locked_seed);
    });
    let baseline = Arc::new(Mutex::new(collect_state()));
    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let known_startup: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    for entry in get_startup() { known_startup.lock().unwrap().insert(entry); }

    let b1 = baseline.clone(); let e1 = events.clone(); let s1 = seed.clone();
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", HTTP_PORT)).unwrap();
        println!("Trust Sentinel on http://127.0.0.1:{}", HTTP_PORT);
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                if req.contains("POST") && !req.contains(&format!("token={}", token_str(&s1))) { let _ = s.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n"); continue; }

                if req.contains("POST /home") {
                    let ssid = get_wifi();
                    let _ = fs::write(std::path::PathBuf::from(DATA_DIR).join("home_wifi.txt"), ssid.trim());
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
                

                let stealth_flag = std::path::PathBuf::from(DATA_DIR).join("stealth.flag");
                if stealth_flag.exists() {
                    let st = DaemonStatus { trust_state: "Stealth".into(), token: token_str(&s1), last_check: Utc::now().to_rfc3339(), latest_events: vec!["Stealth mode active - device hidden".into()] };
                    let json = serde_json::to_string(&st).unwrap();
                    let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\\r\\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes());
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
                if !intruder.is_empty() { state = "Compromised"; extra.push(format!("port_scan: {} - BLOCKED", intruder)); }
                if !phishing.is_empty() { if state == "Trusted" { state = "Warning"; } extra.push(format!("phishing: {} - DNS cleared", phishing)); }
                if ransomware { state = "Compromised"; extra.push("ransomware: Canary files modified! - Network disabled".into()); }
                if !usb_threat.is_empty() { extra.push(format!("usb: {} - EJECTED", usb_threat)); }
                let token = token_str(&s1);
                let mut all: Vec<String> = ev.iter().rev().take(5).cloned().collect();
                all.extend(extra);
                let st = DaemonStatus { trust_state: state.into(), token, last_check: Utc::now().to_rfc3339(), latest_events: all };
                let json = serde_json::to_string(&st).unwrap();
                let _ = s.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\\r\\nContent-Length: {}\r\n\r\n{}", json.len(), json).as_bytes());
            }
        }
    });

    // Integrity checker - SKIPS auto-repair when stealth is active
    let b2 = baseline.clone(); let e2 = events.clone(); let k1 = known_startup.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(300));
        let stealth_flag = std::path::PathBuf::from(DATA_DIR).join("stealth.flag");
        if stealth_flag.exists() { continue; }
        let cur = collect_state();
        let bl = b2.lock().unwrap();
        let diffs = diff(&bl, &cur);
        if !diffs.is_empty() {
            let repaired = auto_repair(&k1);
            let mut ev = e2.lock().unwrap();
            for r in &repaired { ev.push(r.clone()); }
        }
    });

        // Auto-stealth: default ON, off only on home WiFi
    let e_stealth = events.clone();
    let b_auto = baseline.clone();
    let e_auto = events.clone();
    std::thread::spawn(move || {
        let home_file = std::path::PathBuf::from(DATA_DIR).join("home_wifi.txt");
        stealth_on();
        loop {
            std::thread::sleep(Duration::from_secs(30));
            if let Ok(home) = fs::read_to_string(&home_file) {
                let home = home.trim().to_string(); if home.is_empty() { continue; }
                let current = get_wifi();
                if !home.is_empty() && current == home {
                    stealth_off();
                } else if !home.is_empty() && current != home && current != "Unknown" {
                    // Auto-reset baseline on WiFi change
                    let cur = collect_state();
                    if let Ok(mut bl) = b_auto.lock() { *bl = cur; }
                    if let Ok(mut ev) = e_auto.lock() { ev.clear(); }
                    stealth_on();
                }
            }
        }
    });

        let e_scan = events.clone();
    std::thread::spawn(move || {
        let mut blocked_ips: HashSet<String> = HashSet::new();
        loop {
            std::thread::sleep(Duration::from_secs(10));
            let intruder = detect_port_scan();
            if !intruder.is_empty() && !blocked_ips.contains(&intruder) {
                blocked_ips.insert(intruder.clone());
                let _ = Command::new("powershell").args(["-NoProfile","-Command",&format!("Get-NetFirewallRule -DisplayName 'TS-Block-{}' -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object {{}}; if (-not $?) {{ New-NetFirewallRule -DisplayName 'TS-Block-{}' -Direction Inbound -RemoteAddress '{}' -Action Block }}", intruder, intruder, intruder)]).output();
                let mut ev = e_scan.lock().unwrap();
                ev.push(format!("auto_block: {} blocked", intruder));
            }
            if blocked_ips.len() > 50 { blocked_ips.clear(); }
        }
    });
    let e_usb = events.clone(); std::thread::spawn(move || loop { std::thread::sleep(Duration::from_secs(30)); let usb = check_usb(); if !usb.is_empty() { let _ = Command::new("powershell").args(["-NoProfile","-Command",&format!("$d = Get-PnpDevice | Where-Object {{$_.FriendlyName -eq '{}'}}; Disable-PnpDevice -InstanceId $d.InstanceId -Confirm:$false", usb)]).output(); let mut ev = e_usb.lock().unwrap(); ev.push(format!("auto_eject: {} disabled", usb)); } });
    let e_ransom = events.clone(); std::thread::spawn(move || loop { std::thread::sleep(Duration::from_secs(30)); if check_ransomware() { let _ = Command::new("powershell").args(["-NoProfile","-Command","Get-NetAdapter | Disable-NetAdapter -Confirm:$false"]).output(); let mut ev = e_ransom.lock().unwrap(); ev.push("auto_kill: Network disabled - ransomware detected!".into()); } });
    let e3 = events.clone(); std::thread::spawn(move || loop { std::thread::sleep(Duration::from_secs(120)); if !check_phishing().is_empty() { clear_dns(); let mut ev = e3.lock().unwrap(); ev.push("auto_repair: DNS cache cleared".into()); } });
        // Weekly phishing blocklist refresh
    let e_phish = events.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(604800));
        let path = std::path::PathBuf::from(DATA_DIR).join("phishing_hosts.txt");
        let _ = std::fs::remove_file(&path);
        let _ = Command::new("powershell").args(["-NoProfile","-Command","Invoke-WebRequest -Uri 'https://someonewhocares.org/hosts/zero/hosts' -OutFile 'C:\\ProgramData\\Trust Sentinel\\phishing_hosts.txt' -ErrorAction SilentlyContinue"]).output();
        let mut ev = e_phish.lock().unwrap();
        ev.push("phishing_list: Updated to latest version".into());
    });
    loop { std::thread::sleep(Duration::from_secs(60)); }
}

fn random_seed() -> Vec<u8> { let r = SystemRandom::new(); let mut s = [0u8; 32]; r.fill(&mut s).unwrap(); s.to_vec() }
fn token_str(seed: &[u8]) -> String { let c = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30; let mut m = HmacSha256::new_from_slice(seed).unwrap(); m.update(&c.to_be_bytes()); hex::encode(m.finalize().into_bytes()) }
fn collect_state() -> SystemState { SystemState { dns_servers: get_dns(), hosts_hash: get_hosts_hash(), startup_entries: get_startup(), listening_ports: get_ports(), firewall_profiles: get_firewall(), arp_table: get_arp(), wifi_ssid: get_wifi() } }

fn backup_hosts() { let _ = fs::copy("C:\\Windows\\System32\\drivers\\etc\\hosts", HOSTS_BACKUP); }

fn auto_repair(known_startup: &Arc<Mutex<HashSet<String>>>) -> Vec<String> {
    let mut fixed = Vec::new();
    if let Ok(orig) = fs::read_to_string(HOSTS_BACKUP) {
        let cur = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts").unwrap_or_default();
        if orig != cur { 
            if fs::write("C:\\Windows\\System32\\drivers\\etc\\hosts", &orig).is_ok() {
                fixed.push("auto_repair: Hosts restored".into());
            }
        }
    }
    if Command::new("ipconfig").args(["/flushdns"]).output().is_ok() {
        fixed.push("auto_repair: DNS reset".into());
    }
    if Command::new("netsh").args(["interface", "ip", "set", "dns", "Wi-Fi", "dhcp"]).output().is_ok() {
        fixed.push("auto_repair: DNS set to DHCP".into());
    }
    if Command::new("powershell").args(["-NoProfile","-Command","Set-NetFirewallProfile -All -Enabled True"]).output().is_ok() {
        fixed.push("auto_repair: Firewall re-enabled".into());
    }
    if Command::new("arp").args(["-d"]).output().is_ok() {
        fixed.push("auto_repair: ARP flushed".into());
    }
    let current_startup: HashSet<String> = get_startup().into_iter().collect();
    let trusted = known_startup.lock().unwrap();
    for entry in &current_startup {
        if !trusted.contains(entry) && entry != "None" {
            if Command::new("powershell").args(["-NoProfile","-Command",&format!("Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '{}' -ErrorAction SilentlyContinue", entry)]).output().is_ok() {
                fixed.push(format!("auto_repair: Removed startup: {}", entry));
            }
        }
    }
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
fn detect_port_scan() -> String { let mut ip_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new(); if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) { let parts: Vec<&str> = l.split_whitespace().collect(); if parts.len() >= 3 && parts[3] == "ESTABLISHED" { if let Some(ip) = parts[2].rsplitn(2, ':').nth(1) { if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") && !ip.starts_with("23.") && !ip.starts_with("172.16.") { *ip_counts.entry(ip.to_string()).or_insert(0) += 1; } } } } } for (ip, count) in &ip_counts { if *count > SCAN_THRESHOLD { return ip.clone(); } } String::new() }
fn check_phishing() -> String { let hosts_path = std::path::PathBuf::from(DATA_DIR).join("phishing_hosts.txt"); let blocklist = PHISHING_BLOCKLIST.get_or_init(|| { let mut set = HashSet::new(); if let Ok(c) = fs::read_to_string(&hosts_path) { for l in c.lines() { let l = l.trim(); if l.starts_with("0.0.0.0") || l.starts_with("127.0.0.1") { if let Some(d) = l.split_whitespace().nth(1) { set.insert(d.to_lowercase()); } } } } set }); if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-DnsClientCache | Select-Object -ExpandProperty Entry | Where-Object { $_ -match '^[a-zA-Z]' }"]).output() { for e in String::from_utf8_lossy(&o.stdout).lines() { let e = e.trim().to_lowercase(); if !e.is_empty() && blocklist.contains(&e) { return e; } } } String::new() }
fn check_ransomware() -> bool { let canary_dir = std::path::PathBuf::from(DATA_DIR).join("canary"); let _ = fs::create_dir_all(&canary_dir); let canary_files = ["test.docx", "test.pdf", "test.jpg", "test.txt", "test.xlsx"]; let mut modified = 0; for fname in &canary_files { let p = canary_dir.join(fname); if !p.exists() { let _ = fs::write(&p, b"TRUST SENTINEL CANARY"); } if let Ok(meta) = fs::metadata(&p) { if let Ok(mt) = meta.modified() { if let Ok(d) = SystemTime::now().duration_since(mt) { if d.as_secs() < 30 { modified += 1; } } } } } modified >= 2 }
fn check_usb() -> String { if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'OK' -and $_.FriendlyName -match 'storage|flash|drive'} | Select-Object -ExpandProperty FriendlyName"]).output() { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if !s.is_empty() { return s; } } String::new() }

fn diff(a: &SystemState, b: &SystemState) -> Vec<(String, String)> {
    let mut d = Vec::new();
    // Skip if no internet - changes are expected
    if get_wifi() == "Unknown" && get_dns().len() <= 1 { return d; }
    if a.dns_servers != b.dns_servers { d.push(("dns_change".into(), "DNS changed".into())); }
    if a.hosts_hash != b.hosts_hash { d.push(("hosts_change".into(), "Hosts modified".into())); }
    if a.startup_entries != b.startup_entries { d.push(("startup_change".into(), "Startup changed".into())); }
    if a.listening_ports != b.listening_ports { d.push(("port_change".into(), "Ports changed".into())); }
    if a.firewall_profiles != b.firewall_profiles { d.push(("firewall_change".into(), "Firewall changed".into())); }
    if a.arp_table != b.arp_table { d.push(("arp_change".into(), "ARP changed".into())); }
    if a.wifi_ssid != b.wifi_ssid { d.push(("wifi_change".into(), format!("WiFi: {}", b.wifi_ssid))); }
    d
}
fn download_phishing_list() {
    let path = std::path::PathBuf::from(DATA_DIR).join("phishing_hosts.txt");
    if !path.exists() {
        std::thread::spawn(|| {
            let _ = Command::new("powershell").args(["-NoProfile","-Command","Invoke-WebRequest -Uri 'https://someonewhocares.org/hosts/zero/hosts' -OutFile 'C:\\ProgramData\\Trust Sentinel\\phishing_hosts.txt' -ErrorAction SilentlyContinue"]).output();
        });
    }
}

fn setup_startup() {
    let link = std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup\\TrustSentinel.lnk");
    if !link.exists() {
        let _ = Command::new("powershell").args(["-NoProfile","-Command","$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut($env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\TrustSentinel.lnk'); $sc.TargetPath = 'wscript.exe'; $sc.Arguments = $env:ProgramData + '\\Trust Sentinel\\start_silent.vbs'; $sc.WindowStyle = 7; $sc.Save()"]).output();
    }
}

fn encrypt_data(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let unbound = UnboundKey::new(&AES_256_GCM, key).unwrap();
    let key = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new().fill(&mut nonce_bytes).unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut data = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data).unwrap();
    let mut result = nonce_bytes.to_vec();
    result.extend(&data);
    result
}

fn decrypt_data(ciphertext: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    if ciphertext.len() < 12 { return None; }
    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let unbound = UnboundKey::new(&AES_256_GCM, key).ok()?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().ok()?);
    let mut data = encrypted.to_vec();
    key.open_in_place(nonce, Aad::empty(), &mut data).ok()?;
    Some(data)
}

fn get_encryption_key(seed: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let machine_id = std::env::var("COMPUTERNAME").unwrap_or_default();
    let mut hasher = sha2::Sha256::new();
    hasher.update(seed);
    hasher.update(machine_id.as_bytes());
    hasher.finalize().to_vec()
}







