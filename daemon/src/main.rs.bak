use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
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
struct SystemState { dns_servers: Vec<String>, hosts_hash: String, startup_entries: Vec<String>, listening_ports: Vec<String>, firewall_profiles: Vec<String>, windows_update_status: String }
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Baseline { state: SystemState, signature: String }
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Event { timestamp: String, event_type: String, details: String, severity: String }
#[derive(Debug, Serialize, Clone)]
struct DaemonStatus { trust_state: String, token: String, tpm_sealed: bool, pcr_bound: bool, last_check: String, latest_events: Vec<Event> }

#[derive(Debug, Clone)]
struct Settings { dns: bool, hosts: bool, startup: bool, ports: bool, firewall: bool, creds: bool, commands: bool, usb: bool, connections: bool, updates: bool, block_scan: bool, block_brute: bool, interval_integrity: u64, interval_intrusion: u64 }
impl Default for Settings { fn default() -> Self { Self { dns: true, hosts: true, startup: true, ports: true, firewall: true, creds: true, commands: true, usb: true, connections: true, updates: true, block_scan: true, block_brute: true, interval_integrity: 300, interval_intrusion: 10 } } }

struct AppState { status: DaemonStatus, events: Vec<Event>, baseline: Option<Baseline>, seed: Vec<u8>, tpm_available: bool, pcr_bound: bool, settings: Settings, connection_history: HashMap<String, Vec<(u64, u16)>>, known_usb_devices: HashSet<String>, known_connections: HashSet<String> }
static PHISHING_BLOCKLIST: OnceLock<HashSet<String>> = OnceLock::new();

fn encrypt_data(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    let unbound = UnboundKey::new(&AES_256_GCM, key).unwrap(); let key = LessSafeKey::new(unbound);
    let mut nonce_bytes = [0u8; 12]; SystemRandom::new().fill(&mut nonce_bytes).unwrap();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes); let mut data = plaintext.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut data).unwrap();
    let mut result = nonce_bytes.to_vec(); result.extend(&data); result
}

fn decrypt_data(ciphertext: &[u8], key: &[u8]) -> Option<Vec<u8>> {
    use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
    if ciphertext.len() < 12 { return None; }
    let (nonce_bytes, encrypted) = ciphertext.split_at(12);
    let unbound = UnboundKey::new(&AES_256_GCM, key).ok()?; let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().ok()?); let mut data = encrypted.to_vec();
    key.open_in_place(nonce, Aad::empty(), &mut data).ok()?; Some(data)
}

fn get_encryption_key(seed: &[u8], tpm_available: bool) -> Vec<u8> {
    use sha2::Digest; let machine_id = std::env::var("COMPUTERNAME").unwrap_or_default();
    let mut hasher = sha2::Sha256::new(); hasher.update(seed); hasher.update(machine_id.as_bytes());
    if tpm_available { hasher.update(b"TPM_BOUND"); } hasher.finalize().to_vec()
}

fn self_integrity_check() {
    let exe_path = std::env::current_exe().unwrap_or_default();
    if let Ok(data) = fs::read(&exe_path) {
        let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, &data));
        let hash_path = PathBuf::from(DATA_DIR).join("agent.hash");
        if hash_path.exists() { if let Ok(expected) = fs::read_to_string(&hash_path) { if expected.trim() != hash { log_event_direct("agent_tampered", "Binary hash mismatch!", "critical"); std::process::exit(1); } } }
        else { let _ = fs::write(&hash_path, &hash); }
    }
}

fn lock_seed_in_memory(seed: &[u8]) { let locked = seed.to_vec(); let ptr = locked.as_ptr(); let len = locked.len(); #[cfg(windows)] unsafe { use windows::Win32::System::Memory::VirtualLock; let _ = VirtualLock(ptr as *const _, len); } std::mem::forget(locked); }

fn rotate_event_log(data_dir: &PathBuf, max_entries: usize) { let log_path = data_dir.join("events.log"); if log_path.exists() { if let Ok(c) = fs::read_to_string(&log_path) { let lines: Vec<&str> = c.lines().collect(); if lines.len() > max_entries { let t: Vec<&str> = lines.iter().skip(lines.len()-max_entries).cloned().collect(); fs::write(&log_path, t.join("\n")).ok(); } } } }

fn log_event_direct(event_type: &str, details: &str, severity: &str) { let event = Event { timestamp: Utc::now().to_rfc3339(), event_type: event_type.into(), details: details.into(), severity: severity.into() }; let lp = PathBuf::from(DATA_DIR).join("events.log"); if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(lp) { let _ = writeln!(f, "{}", serde_json::to_string(&event).unwrap()); } }

fn check_phishing_domains(state: &Arc<Mutex<AppState>>) {
    let guard = state.lock().unwrap(); let hosts_path = PathBuf::from(DATA_DIR).join("phishing_hosts.txt"); if !hosts_path.exists() { return; }
    let blocklist = PHISHING_BLOCKLIST.get_or_init(|| { let mut set = HashSet::new(); if let Ok(c) = fs::read_to_string(&hosts_path) { for l in c.lines() { let l = l.trim(); if l.starts_with("0.0.0.0") || l.starts_with("127.0.0.1") { if let Some(d) = l.split_whitespace().nth(1) { set.insert(d.to_lowercase()); } } } } set });
    drop(guard);
    if let Ok(o) = Command::new("powershell").args(["-NoProfile", "-Command", "Get-DnsClientCache | Select-Object -ExpandProperty Entry | Where-Object { $_ -match '^[a-zA-Z]' }"]).output() {
        let mut guard = state.lock().unwrap();
        for e in String::from_utf8_lossy(&o.stdout).lines() { let e = e.trim().to_lowercase(); if !e.is_empty() && blocklist.contains(&e) { log_event(&mut guard, "phishing_domain", &format!("Phishing domain: {}", e), "critical"); } }
    }
}

fn check_ransomware(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    let canary_dir = PathBuf::from(DATA_DIR).join("canary"); let _ = fs::create_dir_all(&canary_dir);
    let canary_files = ["test.docx", "test.pdf", "test.jpg", "test.txt", "test.xlsx"];
    let mut modified = 0;
    for fname in &canary_files { let p = canary_dir.join(fname); if !p.exists() { let _ = fs::write(&p, b"TRUST SENTINEL CANARY"); } if let Ok(meta) = fs::metadata(&p) { if let Ok(mt) = meta.modified() { if let Ok(d) = SystemTime::now().duration_since(mt) { if d.as_secs() < 30 { modified += 1; } } } } }
    if modified >= 2 { log_event(&mut guard, "ransomware_alert", &format!("{} canary files modified - possible ransomware!", modified), "critical"); }
    let user_dirs = [std::env::var("USERPROFILE").unwrap_or_default()+"\\Documents", std::env::var("USERPROFILE").unwrap_or_default()+"\\Desktop"];
    for dir in &user_dirs { if let Ok(entries) = fs::read_dir(dir) { let mut rw = 0; for e in entries.flatten() { if let Ok(meta) = e.metadata() { if let Ok(mt) = meta.modified() { if let Ok(d) = SystemTime::now().duration_since(mt) { if d.as_secs() < 10 { rw += 1; } } } } } if rw > 50 { log_event(&mut guard, "ransomware_mass_write", &format!("{} files modified in 10s in {} - possible ransomware!", rw, dir), "critical"); } } }
}

fn main() {
    let data_dir = PathBuf::from(DATA_DIR); fs::create_dir_all(&data_dir).expect("Can't create data dir");
    let (seed, tpm_available, pcr_bound) = get_or_create_seed(&data_dir);
    self_integrity_check(); lock_seed_in_memory(&seed); rotate_event_log(&data_dir, 1000);
    std::thread::sleep(std::time::Duration::from_secs(5));
    let enc_key = get_encryption_key(&seed, tpm_available); let baseline = load_or_create_baseline(&data_dir, &seed, &enc_key);
    let state = Arc::new(Mutex::new(AppState { status: DaemonStatus { trust_state: "Initialising".into(), token: String::new(), tpm_sealed: tpm_available, pcr_bound, last_check: Utc::now().to_rfc3339(), latest_events: vec![] }, events: vec![], baseline: Some(baseline), seed, tpm_available, pcr_bound, settings: Settings::default(), connection_history: HashMap::new(), known_usb_devices: HashSet::new(), known_connections: HashSet::new() }));
    let s1 = state.clone(); let hk = enc_key.clone(); std::thread::spawn(move || serve_http(s1, &hk));
    let s2 = state.clone(); std::thread::spawn(move || loop { generate_token(&s2); std::thread::sleep(Duration::from_secs(30)); });
    let s3 = state.clone(); std::thread::spawn(move || loop { check_credential_access(&s3); std::thread::sleep(Duration::from_secs(15)); });
    let s4 = state.clone(); std::thread::spawn(move || loop { check_suspicious_commands(&s4); std::thread::sleep(Duration::from_secs(10)); });
    let s5 = state.clone(); std::thread::spawn(move || loop { check_usb_devices(&s5); std::thread::sleep(Duration::from_secs(30)); });
    let s6 = state.clone(); std::thread::spawn(move || loop { check_new_connections(&s6); std::thread::sleep(Duration::from_secs(15)); });
    let s7 = state.clone(); std::thread::spawn(move || loop { check_phishing_domains(&s7); std::thread::sleep(Duration::from_secs(60)); });
    let s8 = state.clone(); std::thread::spawn(move || loop { check_ransomware(&s8); std::thread::sleep(Duration::from_secs(30)); });
    let s9 = state.clone(); let sc = state.clone(); std::thread::spawn(move || loop { let iv = sc.lock().unwrap().settings.interval_integrity; check_integrity(&s9); std::thread::sleep(Duration::from_secs(iv)); });
    let s10 = state.clone(); let sc2 = state.clone(); std::thread::spawn(move || loop { let iv = sc2.lock().unwrap().settings.interval_intrusion; detect_intrusions(&s10); std::thread::sleep(Duration::from_secs(iv)); });
    loop { std::thread::sleep(Duration::from_secs(60)); }
}

fn serve_http(state: Arc<Mutex<AppState>>, enc_key: &[u8]) {
    let listener = TcpListener::bind(("127.0.0.1", HTTP_PORT)).unwrap(); let key = enc_key.to_vec();
    for stream in listener.incoming() { if let Ok(mut stream) = stream { let mut buffer = [0u8; 8192]; let n = stream.read(&mut buffer).unwrap_or(0); let req = String::from_utf8_lossy(&buffer[..n]); let mut guard = state.lock().unwrap();
        let response = if req.contains("POST /settings") { if let Some(body) = req.split("\r\n\r\n").nth(1) { if let Ok(u) = serde_json::from_str::<serde_json::Value>(body) { macro_rules! sb { ($f:ident) => { if let Some(v) = u[stringify!($f)].as_bool() { guard.settings.$f = v; } } } sb!(dns); sb!(hosts); sb!(startup); sb!(ports); sb!(firewall); sb!(creds); sb!(commands); sb!(usb); sb!(connections); sb!(updates); sb!(block_scan); sb!(block_brute); if let Some(v) = u["interval_integrity"].as_u64() { guard.settings.interval_integrity = v.max(30); } if let Some(v) = u["interval_intrusion"].as_u64() { guard.settings.interval_intrusion = v.max(5); } } } "HTTP/1.1 200 OK\r\n\r\nSaved".to_string() }
        else if req.contains("POST /reset") { let c = collect_current_state(); let sig = sign_state(&c, &guard.seed); guard.baseline = Some(Baseline{state:c, signature:sig}); guard.events.clear(); guard.status.trust_state="Trusted".into(); "HTTP/1.1 200 OK\r\n\r\nBaseline reset".to_string() }
        else if req.contains("GET /logs") { let lp = PathBuf::from(DATA_DIR).join("events.log"); let raw = fs::read_to_string(&lp).unwrap_or_default(); let mut dec = String::new(); for line in raw.lines() { if let Ok(enc) = base64::engine::general_purpose::STANDARD.decode(line) { if let Some(d) = decrypt_data(&enc, &key) { dec.push_str(&String::from_utf8_lossy(&d)); dec.push('\n'); } } } format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}", dec.len(), dec) }
        else if req.contains("GET /dashboard") { let html = include_str!("web/settings.html"); format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}", html.len(), html) }
        else { let st = guard.status.clone(); let json = serde_json::to_string(&st).unwrap(); format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", json.len(), json) };
        let _ = stream.write_all(response.as_bytes()); } }
}

fn get_or_create_seed(data_dir: &PathBuf) -> (Vec<u8>, bool, bool) { if let Ok((s,p)) = get_tpm_pcr_seed(data_dir) { lock_data_folder(); return (s,true,p); } if let Ok(s) = get_tpm_seed(data_dir) { lock_data_folder(); return (s,true,false); } let sp = data_dir.join("seed.bin"); let s = if sp.exists() { fs::read(&sp).unwrap_or_else(|_| { let s = random_seed(); fs::write(&sp,&s).ok(); s }) } else { let s = random_seed(); fs::write(&sp,&s).expect("Failed"); s }; lock_data_folder(); (s,false,false) }
fn get_tpm_pcr_seed(data_dir: &PathBuf) -> Result<(Vec<u8>, bool), Box<dyn std::error::Error>> { let pp = data_dir.join("tpm_pcr_seed.bin"); if pp.exists() { let ek = get_encryption_key(&[0u8;32],true); let ed = fs::read(&pp)?; if let Some(s) = decrypt_data(&ed,&ek) { return Ok((s,true)); } } let o = Command::new("powershell").args(["-NoProfile","-Command","$tpm=Get-Tpm;if($tpm.TpmReady -and $tpm.TpmEnabled){$b=New-Object Byte[] 32;(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b);[Convert]::ToBase64String($b)}else{Write-Error 'TPM not ready'}"]).output()?; if o.status.success() { let b64 = String::from_utf8_lossy(&o.stdout).trim().to_string(); if !b64.is_empty() { let s = base64::engine::general_purpose::STANDARD.decode(&b64)?; let ek = get_encryption_key(&s,true); let ed = encrypt_data(&s,&ek); fs::write(&pp,&ed)?; return Ok((s,true)); } } Err("TPM PCR not available".into()) }
fn get_tpm_seed(data_dir: &PathBuf) -> Result<Vec<u8>, Box<dyn std::error::Error>> { let tp = data_dir.join("tpm_seed.bin"); if tp.exists() { return Ok(fs::read(&tp)?); } let o = Command::new("powershell").args(["-NoProfile","-Command","$tpm=Get-Tpm;if($tpm.TpmReady){$b=New-Object Byte[] 32;(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($b);[Convert]::ToBase64String($b)}else{Write-Error 'TPM not ready'}"]).output()?; if o.status.success() { let b64 = String::from_utf8_lossy(&o.stdout).trim().to_string(); if !b64.is_empty() { let s = base64::engine::general_purpose::STANDARD.decode(&b64)?; fs::write(&tp,&s)?; return Ok(s); } } Err("TPM not available".into()) }
fn lock_data_folder() { let _ = Command::new("icacls").args([DATA_DIR,"/inheritance:r","/grant:r","SYSTEM:(OI)(CI)F","/grant:r","BUILTIN\\Administrators:(OI)(CI)F"]).output(); }
fn random_seed() -> Vec<u8> { let rng = SystemRandom::new(); let mut s = [0u8;32]; rng.fill(&mut s).unwrap(); s.to_vec() }

fn generate_token(state: &Arc<Mutex<AppState>>) { let mut g = state.lock().unwrap(); let c = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()/30; let mut m = HmacSha256::new_from_slice(&g.seed).unwrap(); m.update(&c.to_be_bytes()); g.status.token = hex::encode(m.finalize().into_bytes()); g.status.tpm_sealed = g.tpm_available; g.status.pcr_bound = g.pcr_bound; }

fn check_new_connections(state: &Arc<Mutex<AppState>>) { let mut g = state.lock().unwrap(); if !g.settings.connections { return; } if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) { let p: Vec<&str> = l.split_whitespace().collect(); if p.len()>=5 && p[3]=="ESTABLISHED" && p[4].parse::<u32>().is_ok() { let conn = format!("{} -> {} [PID: {}]",p[1],p[2],p[4]); if !g.known_connections.contains(&conn) { g.known_connections.insert(conn.clone()); let pid = p[4].parse::<u32>().unwrap_or(0); let pn = get_process_name(pid); if !pn.is_empty() && !is_system_process(&pn) { log_event(&mut g,"new_connection",&format!("New: {} ({})",conn,pn),"info"); } } } } } }
fn get_process_name(pid: u32) -> String { if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command",&format!("(Get-Process -Id {} -ErrorAction SilentlyContinue).ProcessName",pid)]).output() { String::from_utf8_lossy(&o.stdout).trim().to_string() } else { String::new() } }
fn is_system_process(n: &str) -> bool { ["svchost","lsass","csrss","wininit","services","spoolsv","system","idle","registry","smss","winlogon"].iter().any(|s| n.to_lowercase().contains(s)) }

fn check_credential_access(state: &Arc<Mutex<AppState>>) { let mut g = state.lock().unwrap(); if !g.settings.creds { return; } let u = std::env::var("USERPROFILE").unwrap_or_default(); for p in &[format!("{}/.ssh/id_rsa",u),format!("{}/.ssh/id_ed25519",u),format!("{}/.aws/credentials",u),format!("{}/.git-credentials",u)] { if let Ok(m) = fs::metadata(p) { if let Ok(mt) = m.modified() { if let Ok(d) = SystemTime::now().duration_since(mt) { if d.as_secs()<15 { log_event(&mut g,"credential_access",&format!("Access: {}",p),"critical"); } } } } } }

fn check_suspicious_commands(state: &Arc<Mutex<AppState>>) { let mut g = state.lock().unwrap(); if !g.settings.commands { return; } if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';ID=4104} -MaxEvents 5 -ErrorAction SilentlyContinue | ForEach-Object { $_.Message }"]).output() { let t = String::from_utf8_lossy(&o.stdout).to_lowercase(); for p in &["iex","invoke-expression","downloadstring","frombase64string","-encodedcommand","-enc","reg add","reg delete","sc stop","taskkill /f"] { if t.contains(p) { log_event(&mut g,"suspicious_command",&format!("Pattern: {}",p),"warning"); break; } } } }

fn check_usb_devices(state: &Arc<Mutex<AppState>>) { let mut g = state.lock().unwrap(); if !g.settings.usb { return; } if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'OK'} | Select-Object -ExpandProperty FriendlyName"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { let n = l.trim().to_string(); if !n.is_empty() && !g.known_usb_devices.contains(&n) { g.known_usb_devices.insert(n.clone()); if n.to_lowercase().contains("storage")||n.to_lowercase().contains("flash") { log_event(&mut g,"usb_device",&format!("New USB: {}",n),"warning"); } } } } }

fn get_dns_servers() -> Vec<String> { let mut d = Vec::new(); if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | ForEach-Object {$_.ServerAddresses -join ','}"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { for a in l.split(',') { let a = a.trim().to_string(); if !a.is_empty()&&!d.contains(&a) { d.push(a); } } } } if d.is_empty() { d.push("Unknown".into()); } d }
fn get_hosts_hash() -> String { if let Ok(c) = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts") { hex::encode(ring::digest::digest(&ring::digest::SHA256,c.as_bytes())) } else { "unreadable".into() } }
fn get_startup_entries() -> Vec<String> { let mut e = Vec::new(); if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | Select-Object -ExpandProperty PSObject.Properties | Where-Object {$_.Name -ne 'PSPath'} | ForEach-Object {$_.Name+'='+$_.Value}"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { if !l.trim().is_empty() { e.push(l.trim().to_string()); } } } if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSObject.Properties | Where-Object {$_.Name -ne 'PSPath'} | ForEach-Object {$_.Name+'='+$_.Value}"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { if !l.trim().is_empty() { e.push(l.trim().to_string()); } } } let sf = std::env::var("APPDATA").unwrap_or_default()+"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"; if let Ok(d) = fs::read_dir(&sf) { for f in d.flatten() { e.push(format!("StartupFolder: {}",f.file_name().to_string_lossy())); } } if e.is_empty() { e.push("None".into()); } e }
fn get_listening_ports() -> Vec<String> { let mut p = Vec::new(); if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) { let parts: Vec<&str> = l.split_whitespace().collect(); if parts.len()>=4 && parts[3]=="LISTENING" && parts[1].contains(':') { let a = parts[1].to_string(); if a!="0.0.0.0:0" && !a.ends_with(":12788") { p.push(a); } } } } p.sort(); p.dedup(); p }
fn get_firewall_profiles() -> Vec<String> { let mut p = Vec::new(); if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-NetFirewallProfile | ForEach-Object {$_.Name+':'+($_.Enabled ? 'ON':'OFF')}"]).output() { for l in String::from_utf8_lossy(&o.stdout).lines() { if !l.trim().is_empty() { p.push(l.trim().to_string()); } } } if p.is_empty() { p.push("Unknown".into()); } p }
fn get_windows_update_status() -> String { if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","$u=(New-Object -ComObject Microsoft.Update.AutoUpdate).Results;if($u){'Enabled'}else{'Disabled'}"]).output() { let s = String::from_utf8_lossy(&o.stdout).trim().to_string(); if !s.is_empty() { return s; } } "Unknown".into() }
fn collect_current_state() -> SystemState { SystemState { dns_servers: get_dns_servers(), hosts_hash: get_hosts_hash(), startup_entries: get_startup_entries(), listening_ports: get_listening_ports(), firewall_profiles: get_firewall_profiles(), windows_update_status: get_windows_update_status() } }

fn load_or_create_baseline(data_dir: &PathBuf, seed: &[u8], enc_key: &[u8]) -> Baseline { let p = data_dir.join("baseline.json"); if p.exists() { if let Ok(d) = fs::read(&p) { if let Some(pl) = decrypt_data(&d,enc_key) { if let Ok(b) = serde_json::from_str::<Baseline>(&String::from_utf8_lossy(&pl)) { if sign_state(&b.state,seed)==b.signature { return b; } } } } } let s = collect_current_state(); let sig = sign_state(&s,seed); let b = Baseline{state:s,signature:sig}; let pl = serde_json::to_string(&b).unwrap(); let enc = encrypt_data(pl.as_bytes(),enc_key); fs::write(&p,&enc).ok(); b }
fn sign_state(state: &SystemState, seed: &[u8]) -> String { let d = serde_json::to_string(state).unwrap(); let mut m = HmacSha256::new_from_slice(seed).unwrap(); m.update(d.as_bytes()); hex::encode(m.finalize().into_bytes()) }

fn diff_states(baseline: &SystemState, current: &SystemState) -> Vec<(String, String)> { let mut d = Vec::new(); let bd:HashSet<&str> = baseline.dns_servers.iter().map(|s|s.as_str()).collect(); let cd:HashSet<&str> = current.dns_servers.iter().map(|s|s.as_str()).collect(); if bd!=cd { d.push(("dns_change".into(),"DNS changed".into())); } if baseline.hosts_hash!=current.hosts_hash { d.push(("hosts_change".into(),"Hosts modified".into())); } let bs:HashSet<&str> = baseline.startup_entries.iter().map(|s|s.as_str()).collect(); let cs:HashSet<&str> = current.startup_entries.iter().map(|s|s.as_str()).collect(); let ns:Vec<_> = cs.difference(&bs).collect(); let rs:Vec<_> = bs.difference(&cs).collect(); if !ns.is_empty()||!rs.is_empty() { d.push(("startup_change".into(),"Startup changed".into())); } for pb in &current.listening_ports { if let Some(ps) = pb.split(':').last() { if let Ok(p) = ps.parse::<u16>() { if RISKY_PORTS.contains(&p) { d.push(("risky_port".into(),format!("Risky port: {}",pb))); } } } } let bf:HashSet<&str> = baseline.firewall_profiles.iter().map(|s|s.as_str()).collect(); let cf:HashSet<&str> = current.firewall_profiles.iter().map(|s|s.as_str()).collect(); if bf!=cf { d.push(("firewall_change".into(),"Firewall changed".into())); } if baseline.windows_update_status!=current.windows_update_status { d.push(("update_change".into(),"Update status changed".into())); } d }

fn detect_intrusions(state: &Arc<Mutex<AppState>>) { let mut g = state.lock().unwrap(); if let Ok(o) = Command::new("netstat").args(["-ano","-p","TCP"]).output() { let mut im:HashMap<String,HashSet<u16>> = HashMap::new(); for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) { let p:Vec<&str> = l.split_whitespace().collect(); if p.len()>=4 && p[3]=="ESTABLISHED" { if let Some(ip) = p[2].rsplitn(2,':').nth(1) { if let Some(ps) = p[2].split(':').last() { if let Ok(port) = ps.parse::<u16>() { if !ip.starts_with("127.")&&!ip.starts_with("192.168.")&&!ip.starts_with("10.") { im.entry(ip.to_string()).or_default().insert(port); } } } } } } for (ip,ports) in &im { if ports.len()>SCAN_THRESHOLD { log_event(&mut g,"port_scan",&format!("Scan from {} ({} ports)",ip,ports.len()),"critical"); if g.settings.block_scan { let _ = Command::new("powershell").args(["-NoProfile","-Command",&format!("New-NetFirewallRule -DisplayName 'TS-Block-{}' -Direction Inbound -RemoteAddress '{}' -Action Block",ip,ip)]).output(); } } } } if let Ok(o) = Command::new("powershell").args(["-NoProfile","-Command","Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} -MaxEvents 10 -ErrorAction SilentlyContinue | ForEach-Object {$_.TimeCreated.ToString('o')}"]).output() { let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(); let recent = String::from_utf8_lossy(&o.stdout).lines().filter_map(|l| chrono::DateTime::parse_from_rfc3339(l.trim()).ok().map(|d| d.timestamp() as u64)).filter(|t| now-t<60).count(); if recent>=5 { log_event(&mut g,"brute_force",&format!("{} failed logins in 60s",recent),"critical"); if g.settings.block_brute { let _ = Command::new("powershell").args(["-NoProfile","-Command","New-NetFirewallRule -DisplayName 'TS-Block-RDP' -Direction Inbound -LocalPort 3389 -Action Block"]).output(); } } } }

fn log_event(state: &mut AppState, event_type: &str, details: &str, severity: &str) { let event = Event{timestamp:Utc::now().to_rfc3339(),event_type:event_type.into(),details:details.into(),severity:severity.into()}; state.events.push(event.clone()); let lp = PathBuf::from(DATA_DIR).join("events.log"); let ek = get_encryption_key(&state.seed,state.tpm_available); let pl = serde_json::to_string(&event).unwrap(); let enc = encrypt_data(pl.as_bytes(),&ek); let b64 = base64::engine::general_purpose::STANDARD.encode(&enc); if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(lp) { let _ = writeln!(f,"{}",b64); } }

fn check_integrity(state: &Arc<Mutex<AppState>>) { let mut g = state.lock().unwrap(); let cur = collect_current_state(); let bl = match &g.baseline { Some(b) => b.clone(), None => return }; if sign_state(&bl.state,&g.seed)!=bl.signature { log_event(&mut g,"baseline_tampered","Baseline signature mismatch","critical"); g.status.trust_state="Compromised".into(); return; } let diffs = diff_states(&bl.state,&cur); for d in &diffs { log_event(&mut g,&d.0,&d.1,"warning"); } g.status.trust_state = match diffs.len() { 0=>"Trusted",1=>"Warning",_=>"Compromised" }.into(); g.status.last_check = Utc::now().to_rfc3339(); g.status.latest_events = g.events.iter().rev().take(5).cloned().collect(); if g.events.iter().filter(|e| e.severity=="warning").count()>3 { let cur = collect_current_state(); let sig = sign_state(&cur,&g.seed); g.baseline = Some(Baseline{state:cur,signature:sig}); g.events.clear(); g.status.trust_state="Trusted".into(); g.status.latest_events=vec![]; log_event(&mut g,"auto_heal","Auto-reset baseline","info"); } }