use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const DATA_DIR: &str = "C:\\ProgramData\\Trust Sentinel";
const HTTP_PORT: u16 = 12788;
const RISKY_PORTS: &[u16] = &[21, 22, 23, 135, 139, 445, 3389, 5985, 5986, 6379, 27017, 3306, 5432, 1433, 8080, 8443, 9090];
const SCAN_THRESHOLD: usize = 20;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SystemState {
    dns_servers: Vec<String>,
    hosts_hash: String,
    startup_entries: Vec<String>,
    listening_ports: Vec<String>,
    firewall_profiles: Vec<String>,
    windows_update_status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Baseline {
    state: SystemState,
    signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Event {
    timestamp: String,
    event_type: String,
    details: String,
    severity: String,
}

#[derive(Debug, Serialize, Clone)]
struct DaemonStatus {
    trust_state: String,
    token: String,
    tpm_sealed: bool,
    pcr_bound: bool,
    last_check: String,
    latest_events: Vec<Event>,
}

#[derive(Debug, Clone)]
struct Settings {
    dns: bool, hosts: bool, startup: bool, ports: bool, firewall: bool,
    creds: bool, commands: bool, usb: bool, connections: bool, updates: bool,
    block_scan: bool, block_brute: bool,
    interval_integrity: u64, interval_intrusion: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            dns: true, hosts: true, startup: true, ports: true, firewall: true,
            creds: true, commands: true, usb: true, connections: true, updates: true,
            block_scan: true, block_brute: true,
            interval_integrity: 300, interval_intrusion: 10,
        }
    }
}

struct AppState {
    status: DaemonStatus,
    events: Vec<Event>,
    baseline: Option<Baseline>,
    seed: Vec<u8>,
    tpm_available: bool,
    pcr_bound: bool,
    settings: Settings,
    connection_history: HashMap<String, Vec<(u64, u16)>>,
    known_usb_devices: HashSet<String>,
    known_connections: HashSet<String>,
}

// ─── SIMPLE AES-256-GCM ENCRYPTION USING RING ───
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

fn get_encryption_key(seed: &[u8], tpm_available: bool) -> Vec<u8> {
    use sha2::Digest;
    let machine_id = std::env::var("COMPUTERNAME").unwrap_or_default();
    let mut hasher = sha2::Sha256::new();
    hasher.update(seed);
    hasher.update(machine_id.as_bytes());
    if tpm_available { hasher.update(b"TPM_BOUND"); }
    hasher.finalize().to_vec()
}

fn main() {
    let data_dir = PathBuf::from(DATA_DIR);
    fs::create_dir_all(&data_dir).expect("Can't create data dir");

    let (seed, tpm_available, pcr_bound) = get_or_create_seed(&data_dir);
    std::thread::sleep(std::time::Duration::from_secs(5));
    let enc_key = get_encryption_key(&seed, tpm_available);
    let baseline = load_or_create_baseline(&data_dir, &seed, &enc_key);

    let state = Arc::new(Mutex::new(AppState {
        status: DaemonStatus {
            trust_state: "Initialising".into(),
            token: String::new(),
            tpm_sealed: tpm_available,
            pcr_bound,
            last_check: Utc::now().to_rfc3339(),
            latest_events: vec![],
        },
        events: vec![],
        baseline: Some(baseline),
        seed,
        tpm_available,
        pcr_bound,
        settings: Settings::default(),
        connection_history: HashMap::new(),
        known_usb_devices: HashSet::new(),
        known_connections: HashSet::new(),
    }));

    let state_http = state.clone();
    let http_key = enc_key.clone();
    std::thread::spawn(move || serve_http(state_http, &http_key));

    let state_token = state.clone();
    std::thread::spawn(move || loop { generate_token(&state_token); std::thread::sleep(Duration::from_secs(30)); });

    let state_creds = state.clone();
    std::thread::spawn(move || loop { check_credential_access(&state_creds); std::thread::sleep(Duration::from_secs(15)); });

    let state_cmds = state.clone();
    std::thread::spawn(move || loop { check_suspicious_commands(&state_cmds); std::thread::sleep(Duration::from_secs(10)); });

    let state_usb = state.clone();
    std::thread::spawn(move || loop { check_usb_devices(&state_usb); std::thread::sleep(Duration::from_secs(30)); });

    let state_conn = state.clone();
    std::thread::spawn(move || loop { check_new_connections(&state_conn); std::thread::sleep(Duration::from_secs(15)); });

    let state_int = state.clone();
    let s = state.clone();
    std::thread::spawn(move || loop { let iv = s.lock().unwrap().settings.interval_integrity; check_integrity(&state_int); std::thread::sleep(Duration::from_secs(iv)); });

    let state_ids = state.clone();
    let s2 = state.clone();
    std::thread::spawn(move || loop { let iv = s2.lock().unwrap().settings.interval_intrusion; detect_intrusions(&state_ids); std::thread::sleep(Duration::from_secs(iv)); });

    loop { std::thread::sleep(Duration::from_secs(60)); }
}

fn serve_http(state: Arc<Mutex<AppState>>, enc_key: &[u8]) {
    let listener = TcpListener::bind(("127.0.0.1", HTTP_PORT)).unwrap();
    let key = enc_key.to_vec();
    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let mut buffer = [0u8; 8192];
            let n = stream.read(&mut buffer).unwrap_or(0);
            let req = String::from_utf8_lossy(&buffer[..n]);
            let mut guard = state.lock().unwrap();

            let response = if req.contains("POST /settings") {
                if let Some(body) = req.split("\r\n\r\n").nth(1) {
                    if let Ok(updates) = serde_json::from_str::<serde_json::Value>(body) {
                        if let Some(v) = updates["dns"].as_bool() { guard.settings.dns = v; }
                        if let Some(v) = updates["hosts"].as_bool() { guard.settings.hosts = v; }
                        if let Some(v) = updates["startup"].as_bool() { guard.settings.startup = v; }
                        if let Some(v) = updates["ports"].as_bool() { guard.settings.ports = v; }
                        if let Some(v) = updates["firewall"].as_bool() { guard.settings.firewall = v; }
                        if let Some(v) = updates["creds"].as_bool() { guard.settings.creds = v; }
                        if let Some(v) = updates["commands"].as_bool() { guard.settings.commands = v; }
                        if let Some(v) = updates["usb"].as_bool() { guard.settings.usb = v; }
                        if let Some(v) = updates["connections"].as_bool() { guard.settings.connections = v; }
                        if let Some(v) = updates["updates"].as_bool() { guard.settings.updates = v; }
                        if let Some(v) = updates["block_scan"].as_bool() { guard.settings.block_scan = v; }
                        if let Some(v) = updates["block_brute"].as_bool() { guard.settings.block_brute = v; }
                        if let Some(v) = updates["interval_integrity"].as_u64() { guard.settings.interval_integrity = v.max(30); }
                        if let Some(v) = updates["interval_intrusion"].as_u64() { guard.settings.interval_intrusion = v.max(5); }
                    }
                }
                "HTTP/1.1 200 OK\r\n\r\nSaved".to_string()
            } else if req.contains("POST /reset") {
                let current = collect_current_state();
                let sig = sign_state(&current, &guard.seed);
                guard.baseline = Some(Baseline { state: current, signature: sig });
                guard.events.clear();
                guard.status.trust_state = "Trusted".into();
                "HTTP/1.1 200 OK\r\n\r\nBaseline reset".to_string()
            } else if req.contains("GET /logs") {
                let log_path = PathBuf::from(DATA_DIR).join("events.log");
                let raw = fs::read_to_string(&log_path).unwrap_or_default();
                let mut decrypted = String::new();
                for line in raw.lines() {
                    if let Ok(enc) = base64::engine::general_purpose::STANDARD.decode(line) {
                        if let Some(dec) = decrypt_data(&enc, &key) {
                            decrypted.push_str(&String::from_utf8_lossy(&dec));
                            decrypted.push('\n');
                        }
                    }
                }
                format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}", decrypted.len(), decrypted)
            } else if req.contains("GET /dashboard") {
                let html = include_str!("web/settings.html");
                format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}", html.len(), html)
            } else {
                let status = guard.status.clone();
                let json = serde_json::to_string(&status).unwrap();
                format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", json.len(), json)
            };
            let _ = stream.write_all(response.as_bytes());
        }
    }
}

// ─── TPM PCR-BOUND SEED ───
fn get_or_create_seed(data_dir: &PathBuf) -> (Vec<u8>, bool, bool) {
    if let Ok((seed, pcr)) = get_tpm_pcr_seed(data_dir) {
        lock_data_folder();
        return (seed, true, pcr);
    }
    if let Ok(tpm_seed) = get_tpm_seed(data_dir) {
        lock_data_folder();
        return (tpm_seed, true, false);
    }
    let seed_path = data_dir.join("seed.bin");
    let seed = if seed_path.exists() {
        fs::read(&seed_path).unwrap_or_else(|_| { let s = random_seed(); fs::write(&seed_path, &s).ok(); s })
    } else { let s = random_seed(); fs::write(&seed_path, &s).expect("Failed"); s };
    lock_data_folder();
    (seed, false, false)
}

fn get_tpm_pcr_seed(data_dir: &PathBuf) -> Result<(Vec<u8>, bool), Box<dyn std::error::Error>> {
    let pcr_path = data_dir.join("tpm_pcr_seed.bin");
    if pcr_path.exists() {
        let enc_key = get_encryption_key(&[0u8; 32], true);
        let enc_data = fs::read(&pcr_path)?;
        if let Some(seed) = decrypt_data(&enc_data, &enc_key) { return Ok((seed, true)); }
    }
    // Generate new PCR-bound seed
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "$tpm = Get-Tpm; if($tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) { $bytes = New-Object Byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes); $pcr = Get-TpmEndorsementKeyInfo -HashAlgorithm Sha256 2>$null; [Convert]::ToBase64String($bytes) } else { Write-Error 'TPM not ready' }"
        ]).output()?;
    if output.status.success() {
        let b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !b64.is_empty() {
            let seed = base64::engine::general_purpose::STANDARD.decode(&b64)?;
            let enc_key = get_encryption_key(&seed, true);
            let enc_data = encrypt_data(&seed, &enc_key);
            fs::write(&pcr_path, &enc_data)?;
            return Ok((seed, true));
        }
    }
    Err("TPM PCR not available".into())
}

fn get_tpm_seed(data_dir: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let tpm_seed_path = data_dir.join("tpm_seed.bin");
    if tpm_seed_path.exists() { return Ok(fs::read(&tpm_seed_path)?); }
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "$tpm = Get-Tpm; if($tpm.TpmReady -and $tpm.TpmEnabled -and $tpm.TpmActivated) { $bytes = New-Object Byte[] 32; (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes); [Convert]::ToBase64String($bytes) } else { Write-Error 'TPM not ready' }"
        ]).output()?;
    if output.status.success() {
        let b64 = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !b64.is_empty() {
            let seed = base64::engine::general_purpose::STANDARD.decode(&b64)?;
            fs::write(&tpm_seed_path, &seed)?;
            return Ok(seed);
        }
    }
    Err("TPM not available".into())
}

fn lock_data_folder() {
    let _ = Command::new("icacls").args([DATA_DIR, "/inheritance:r", "/grant:r", "SYSTEM:(OI)(CI)F", "/grant:r", "BUILTIN\\Administrators:(OI)(CI)F"]).output();
}

fn random_seed() -> Vec<u8> { let rng = SystemRandom::new(); let mut s = [0u8; 32]; rng.fill(&mut s).unwrap(); s.to_vec() }

fn generate_token(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    let counter = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 30;
    let mut mac = HmacSha256::new_from_slice(&guard.seed).unwrap();
    mac.update(&counter.to_be_bytes());
    guard.status.token = hex::encode(mac.finalize().into_bytes());
    guard.status.tpm_sealed = guard.tpm_available;
    guard.status.pcr_bound = guard.pcr_bound;
}

// ─── NEW: NETWORK CONNECTION MONITORING ───
fn check_new_connections(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    if !guard.settings.connections { return; }
    if let Ok(o) = Command::new("netstat").args(["-ano", "-p", "TCP"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() >= 5 && p[3] == "ESTABLISHED" && p[4].parse::<u32>().is_ok() {
                let conn = format!("{} -> {} [PID: {}]", p[1], p[2], p[4]);
                if !guard.known_connections.contains(&conn) {
                    guard.known_connections.insert(conn.clone());
                    let pid = p[4].parse::<u32>().unwrap_or(0);
                    let proc_name = get_process_name(pid);
                    if !proc_name.is_empty() && !is_system_process(&proc_name) {
                        log_event(&mut guard, "new_connection", &format!("New outbound connection: {} ({})", conn, proc_name), "info");
                    }
                }
            }
        }
    }
}

fn get_process_name(pid: u32) -> String {
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", &format!("(Get-Process -Id {} -ErrorAction SilentlyContinue).ProcessName", pid)]).output() {
        String::from_utf8_lossy(&o.stdout).trim().to_string()
    } else { String::new() }
}

fn is_system_process(name: &str) -> bool {
    let safe = ["svchost", "lsass", "csrss", "wininit", "services", "spoolsv", "system", "idle", "registry", "smss", "winlogon"];
    safe.iter().any(|s| name.to_lowercase().contains(s))
}

// ─── CREDENTIAL GUARD ───
fn check_credential_access(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    if !guard.settings.creds { return; }
    let user = std::env::var("USERPROFILE").unwrap_or_default();
    let paths = [format!("{}/.ssh/id_rsa", user), format!("{}/.ssh/id_ed25519", user), format!("{}/.aws/credentials", user), format!("{}/.git-credentials", user)];
    for path in &paths {
        if let Ok(meta) = fs::metadata(path) {
            if let Ok(modified) = meta.modified() {
                if let Ok(dur) = SystemTime::now().duration_since(modified) {
                    if dur.as_secs() < 15 {
                        log_event(&mut guard, "credential_access", &format!("Recent access to credential file: {}", path), "critical");
                    }
                }
            }
        }
    }
}

// ─── SUSPICIOUS COMMANDS ───
fn check_suspicious_commands(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    if !guard.settings.commands { return; }
    let patterns = ["IEX", "Invoke-Expression", "DownloadString", "FromBase64String", "-EncodedCommand", "-enc", "reg add", "reg delete", "sc stop", "taskkill /f"];
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $_.Message }"]).output() {
        let text = String::from_utf8_lossy(&o.stdout).to_lowercase();
        for p in &patterns { if text.contains(&p.to_lowercase()) { log_event(&mut guard, "suspicious_command", &format!("Suspicious pattern: {}", p), "warning"); break; } }
    }
}

// ─── USB DEVICES ───
fn check_usb_devices(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    if !guard.settings.usb { return; }
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'OK' } | Select-Object -ExpandProperty FriendlyName"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let n = l.trim().to_string();
            if !n.is_empty() && !guard.known_usb_devices.contains(&n) {
                guard.known_usb_devices.insert(n.clone());
                if n.to_lowercase().contains("storage") || n.to_lowercase().contains("flash") { log_event(&mut guard, "usb_device", &format!("New USB storage: {}", n), "warning"); }
            }
        }
    }
}

// ─── DATA COLLECTION ───
fn get_dns_servers() -> Vec<String> {
    let mut d = Vec::new();
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object { $_.ServerAddresses -join ',' }"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() { for a in l.split(',') { let a = a.trim().to_string(); if !a.is_empty() && !d.contains(&a) { d.push(a); } } }
    }
    if d.is_empty() { d.push("Unknown".into()); }
    d
}

fn get_hosts_hash() -> String {
    if let Ok(c) = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts") { hex::encode(ring::digest::digest(&ring::digest::SHA256, c.as_bytes())) } else { "unreadable".into() }
}

fn get_startup_entries() -> Vec<String> {
    let mut e = Vec::new();
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | Select-Object -ExpandProperty PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' } | ForEach-Object { $_.Name + '=' + $_.Value }"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() { if !l.trim().is_empty() { e.push(l.trim().to_string()); } }
    }
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' } | ForEach-Object { $_.Name + '=' + $_.Value }"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() { if !l.trim().is_empty() { e.push(l.trim().to_string()); } }
    }
    let sf = std::env::var("APPDATA").unwrap_or_default() + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    if let Ok(d) = fs::read_dir(&sf) { for f in d.flatten() { e.push(format!("StartupFolder: {}", f.file_name().to_string_lossy())); } }
    if e.is_empty() { e.push("None".into()); }
    e
}

fn get_listening_ports() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("netstat").args(["-ano", "-p", "TCP"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 4 && parts[3] == "LISTENING" && parts[1].contains(':') { let a = parts[1].to_string(); if a != "0.0.0.0:0" && !a.ends_with(":12788") { p.push(a); } }
        }
    }
    p.sort(); p.dedup(); p
}

fn get_firewall_profiles() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-NetFirewallProfile | ForEach-Object { $_.Name + ':' + ($_.Enabled ? 'ON' : 'OFF') }"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines() { if !l.trim().is_empty() { p.push(l.trim().to_string()); } }
    }
    if p.is_empty() { p.push("Unknown".into()); }
    p
}

fn get_windows_update_status() -> String {
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "$u = (New-Object -ComObject Microsoft.Update.AutoUpdate).Results; if($u) { 'Enabled' } else { 'Disabled' }"]).output() {
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if !s.is_empty() { return s; }
    }
    "Unknown".into()
}

fn collect_current_state() -> SystemState {
    SystemState {
        dns_servers: get_dns_servers(), hosts_hash: get_hosts_hash(),
        startup_entries: get_startup_entries(), listening_ports: get_listening_ports(),
        firewall_profiles: get_firewall_profiles(), windows_update_status: get_windows_update_status(),
    }
}

fn load_or_create_baseline(data_dir: &PathBuf, seed: &[u8], enc_key: &[u8]) -> Baseline {
    let path = data_dir.join("baseline.json");
    if path.exists() {
        if let Ok(data) = fs::read(&path) {
            if let Some(plain) = decrypt_data(&data, enc_key) {
                if let Ok(b) = serde_json::from_str::<Baseline>(&String::from_utf8_lossy(&plain)) {
                    if sign_state(&b.state, seed) == b.signature { return b; }
                }
            }
        }
    }
    let s = collect_current_state();
    let sig = sign_state(&s, seed);
    let b = Baseline { state: s, signature: sig };
    let plain = serde_json::to_string(&b).unwrap();
    let enc = encrypt_data(plain.as_bytes(), enc_key);
    fs::write(&path, &enc).ok();
    b
}

fn sign_state(state: &SystemState, seed: &[u8]) -> String {
    let data = serde_json::to_string(state).unwrap();
    let mut mac = HmacSha256::new_from_slice(seed).unwrap();
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn diff_states(baseline: &SystemState, current: &SystemState) -> Vec<(String, String)> {
    let mut d = Vec::new();
    let bd: HashSet<&str> = baseline.dns_servers.iter().map(|s| s.as_str()).collect();
    let cd: HashSet<&str> = current.dns_servers.iter().map(|s| s.as_str()).collect();
    if bd != cd { d.push(("dns_change".into(), format!("DNS: {:?} -> {:?}", baseline.dns_servers, current.dns_servers))); }
    if baseline.hosts_hash != current.hosts_hash { d.push(("hosts_change".into(), "Hosts modified".into())); }
    let bs: HashSet<&str> = baseline.startup_entries.iter().map(|s| s.as_str()).collect();
    let cs: HashSet<&str> = current.startup_entries.iter().map(|s| s.as_str()).collect();
    let ns: Vec<_> = cs.difference(&bs).collect(); let rs: Vec<_> = bs.difference(&cs).collect();
    if !ns.is_empty() || !rs.is_empty() { d.push(("startup_change".into(), format!("Startup: +{:?} -{:?}", ns, rs))); }
    for pb in &current.listening_ports { if let Some(ps) = pb.split(':').last() { if let Ok(p) = ps.parse::<u16>() { if RISKY_PORTS.contains(&p) { d.push(("risky_port".into(), format!("Risky port: {} ({})", pb, p))); } } } }
    let bf: HashSet<&str> = baseline.firewall_profiles.iter().map(|s| s.as_str()).collect();
    let cf: HashSet<&str> = current.firewall_profiles.iter().map(|s| s.as_str()).collect();
    if bf != cf { d.push(("firewall_change".into(), format!("Firewall: {:?} -> {:?}", baseline.firewall_profiles, current.firewall_profiles))); }
    if baseline.windows_update_status != current.windows_update_status { d.push(("update_change".into(), format!("Windows Update: {} -> {}", baseline.windows_update_status, current.windows_update_status))); }
    d
}

fn detect_intrusions(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    if let Ok(o) = Command::new("netstat").args(["-ano", "-p", "TCP"]).output() {
        let mut ip_map: HashMap<String, HashSet<u16>> = HashMap::new();
        for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() >= 4 && p[3] == "ESTABLISHED" { if let Some(ip) = p[2].rsplitn(2, ':').nth(1) { if let Some(ps) = p[2].split(':').last() { if let Ok(port) = ps.parse::<u16>() { if !ip.starts_with("127.") && !ip.starts_with("192.168.") && !ip.starts_with("10.") { ip_map.entry(ip.to_string()).or_default().insert(port); } } } } }
        }
        for (ip, ports) in &ip_map { if ports.len() > SCAN_THRESHOLD { log_event(&mut guard, "port_scan", &format!("Port scan from {} ({} ports)", ip, ports.len()), "critical"); if guard.settings.block_scan { let _ = Command::new("powershell").args(["-NoProfile", "-Command", &format!("New-NetFirewallRule -DisplayName 'TS-Block-{}' -Direction Inbound -RemoteAddress '{}' -Action Block", ip, ip)]).output(); } } }
    }
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 -ErrorAction SilentlyContinue | ForEach-Object { $_.TimeCreated.ToString('o') }"]).output() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let recent = String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| chrono::DateTime::parse_from_rfc3339(l.trim()).ok().map(|d| d.timestamp() as u64)).filter(|t| now - t < 60).count();
        if recent >= 5 { log_event(&mut guard, "brute_force", &format!("Brute force: {} failed logins in 60s", recent), "critical"); if guard.settings.block_brute { let _ = Command::new("powershell").args(["-NoProfile", "-Command", "New-NetFirewallRule -DisplayName 'TS-Block-RDP' -Direction Inbound -LocalPort 3389 -Action Block"]).output(); } }
    }
}

fn log_event(state: &mut AppState, event_type: &str, details: &str, severity: &str) {
    let event = Event { timestamp: Utc::now().to_rfc3339(), event_type: event_type.into(), details: details.into(), severity: severity.into() };
    state.events.push(event.clone());
    let lp = PathBuf::from(DATA_DIR).join("events.log");
    let enc_key = get_encryption_key(&state.seed, state.tpm_available);
    let plain = serde_json::to_string(&event).unwrap();
    let enc = encrypt_data(plain.as_bytes(), &enc_key);
    let b64 = base64::engine::general_purpose::STANDARD.encode(&enc);
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(lp) { let _ = writeln!(f, "{}", b64); }
}

fn check_integrity(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    let current = collect_current_state();
    let baseline = match &guard.baseline { Some(b) => b.clone(), None => return };
    if sign_state(&baseline.state, &guard.seed) != baseline.signature { log_event(&mut guard, "baseline_tampered", "Baseline signature mismatch", "critical"); guard.status.trust_state = "Compromised".into(); return; }
    let diffs = diff_states(&baseline.state, &current);
    for d in &diffs { log_event(&mut guard, &d.0, &d.1, "warning"); }
    guard.status.trust_state = match diffs.len() { 0 => "Trusted", 1 => "Warning", _ => "Compromised" }.into();
    guard.status.last_check = Utc::now().to_rfc3339();
    guard.status.latest_events = guard.events.iter().rev().take(5).cloned().collect();
    let wc = guard.events.iter().filter(|e| e.severity == "warning").count();
    if wc > 3 {
        let cur = collect_current_state(); let sig = sign_state(&cur, &guard.seed);
        guard.baseline = Some(Baseline { state: cur, signature: sig }); guard.events.clear();
        guard.status.trust_state = "Trusted".into(); guard.status.latest_events = vec![];
        log_event(&mut guard, "auto_heal", "Auto-reset baseline", "info");
    }
}