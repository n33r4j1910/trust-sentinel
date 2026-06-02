use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const DATA_DIR: &str = "C:\\ProgramData\\Trust Sentinel";
const HTTP_PORT: u16 = 12788;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SystemState {
    dns_servers: Vec<String>,
    hosts_hash: String,
    startup_entries: Vec<String>,
    services: Vec<String>,
    listening_ports: Vec<String>,
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
    last_check: String,
    latest_events: Vec<Event>,
}

struct AppState {
    status: DaemonStatus,
    events: Vec<Event>,
    baseline: Option<Baseline>,
    seed: Vec<u8>,
}

fn main() {
    let data_dir = PathBuf::from(DATA_DIR);
    fs::create_dir_all(&data_dir).expect("Can't create data dir");

    let seed = get_or_create_seed(&data_dir);
    // Wait for system to stabilize before taking baseline
    std::thread::sleep(std::time::Duration::from_secs(5));
    let baseline = load_or_create_baseline(&data_dir, &seed);

    let state = Arc::new(Mutex::new(AppState {
        status: DaemonStatus {
            trust_state: "Initialising".into(),
            token: String::new(),
            last_check: Utc::now().to_rfc3339(),
            latest_events: vec![],
        },
        events: vec![],
        baseline: Some(baseline),
        seed,
    }));

    // HTTP server
    let state_http = state.clone();
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", HTTP_PORT)).unwrap();
        for stream in listener.incoming() {
            if let Ok(mut stream) = stream {
                let mut buffer = [0; 512];
                let _ = stream.read(&mut buffer);
                let status = state_http.lock().unwrap().status.clone();
                let json = serde_json::to_string(&status).unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });

    // Token generator
    let state_token = state.clone();
    std::thread::spawn(move || loop {
        generate_token(&state_token);
        std::thread::sleep(Duration::from_secs(30));
    });

    // Integrity checker
    let state_integrity = state.clone();
    std::thread::spawn(move || loop {
        check_integrity(&state_integrity);
        std::thread::sleep(Duration::from_secs(300));
    });

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn get_or_create_seed(data_dir: &PathBuf) -> Vec<u8> {
    let seed_path = data_dir.join("seed.bin");
    if seed_path.exists() {
        fs::read(&seed_path).unwrap_or_else(|_| {
            let seed = random_seed();
            fs::write(&seed_path, &seed).ok();
            seed
        })
    } else {
        let seed = random_seed();
        fs::write(&seed_path, &seed).expect("Failed to write seed");
        seed
    }
}

fn random_seed() -> Vec<u8> {
    let rng = SystemRandom::new();
    let mut seed = [0u8; 32];
    rng.fill(&mut seed).unwrap();
    seed.to_vec()
}

fn generate_token(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    let seed = guard.seed.clone();
    let counter = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let mut mac = HmacSha256::new_from_slice(&seed).unwrap();
    mac.update(&counter.to_be_bytes());
    let token = hex::encode(mac.finalize().into_bytes());
    guard.status.token = token;
}

fn get_dns_servers() -> Vec<String> {
    let mut dns = Vec::new();
    if let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses.Count -gt 0 } | ForEach-Object { $_.ServerAddresses -join ',' }"
        ])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            for addr in line.split(',') {
                let addr = addr.trim();
                if !addr.is_empty() && !dns.contains(&addr.to_string()) {
                    dns.push(addr.to_string());
                }
            }
        }
    }
    if dns.is_empty() {
        dns.push("Unknown".into());
    }
    dns
}

fn get_hosts_hash() -> String {
    let path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
    if let Ok(content) = fs::read_to_string(path) {
        hex::encode(ring::digest::digest(&ring::digest::SHA256, content.as_bytes()))
    } else {
        "unreadable".into()
    }
}

fn get_startup_entries() -> Vec<String> {
    let mut entries = Vec::new();
    if let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' | Select-Object -ExpandProperty PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' } | ForEach-Object { $_.Name + '=' + $_.Value }"
        ])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if !line.trim().is_empty() {
                entries.push(line.trim().to_string());
            }
        }
    }
    if let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSObject.Properties | Where-Object { $_.Name -ne 'PSPath' -and $_.Name -ne 'PSParentPath' } | ForEach-Object { $_.Name + '=' + $_.Value }"
        ])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if !line.trim().is_empty() {
                entries.push(line.trim().to_string());
            }
        }
    }
    let startup = std::env::var("APPDATA").unwrap_or_default()
        + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    if let Ok(dir) = fs::read_dir(&startup) {
        for entry in dir.flatten() {
            entries.push(format!("StartupFolder: {}", entry.file_name().to_string_lossy()));
        }
    }
    if entries.is_empty() {
        entries.push("None".into());
    }
    entries
}

fn get_services() -> Vec<String> {
    let mut services = Vec::new();
    if let Ok(output) = Command::new("powershell")
        .args(["-NoProfile", "-Command",
            "Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name"
        ])
        .output()
    {
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            if !line.trim().is_empty() {
                services.push(line.trim().to_string());
            }
        }
    }
    services.sort();
    services.truncate(50);
    services
}

fn get_listening_ports() -> Vec<String> {
    let mut ports = Vec::new();
    if let Ok(output) = Command::new("netstat")
        .args(["-ano", "-p", "TCP"])
        .output()
    {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines().skip(4) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 && parts[1].contains(':') {
                let state = if parts.len() >= 4 { parts[3] } else { "" };
                if state == "LISTENING" {
                    let addr = parts[1].to_string();
                    if addr != "0.0.0.0:0" && addr != "[::]:0" && !addr.ends_with(":12788") {
                        ports.push(addr);
                    }
                }
            }
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

fn collect_current_state() -> SystemState {
    SystemState {
        dns_servers: get_dns_servers(),
        hosts_hash: get_hosts_hash(),
        startup_entries: get_startup_entries(),
        services: get_services(),
        listening_ports: get_listening_ports(),
    }
}

fn load_or_create_baseline(data_dir: &PathBuf, seed: &[u8]) -> Baseline {
    let path = data_dir.join("baseline.json");
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(baseline) = serde_json::from_str::<Baseline>(&data) {
                let expected = sign_state(&baseline.state, seed);
                if expected == baseline.signature {
                    return baseline;
                }
            }
        }
    }
    let state = collect_current_state();
    let sig = sign_state(&state, seed);
    let baseline = Baseline { state, signature: sig };
    fs::write(&path, serde_json::to_string_pretty(&baseline).unwrap()).ok();
    baseline
}

fn sign_state(state: &SystemState, seed: &[u8]) -> String {
    let data = serde_json::to_string(state).unwrap();
    let mut mac = HmacSha256::new_from_slice(seed).unwrap();
    mac.update(data.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn diff_states(baseline: &SystemState, current: &SystemState) -> Vec<(String, String)> {
    let mut diffs = Vec::new();

    let b_dns: HashSet<&str> = baseline.dns_servers.iter().map(|s| s.as_str()).collect();
    let c_dns: HashSet<&str> = current.dns_servers.iter().map(|s| s.as_str()).collect();
    if b_dns != c_dns {
        diffs.push(("dns_change".into(), format!("DNS changed: {:?} -> {:?}", baseline.dns_servers, current.dns_servers)));
    }

    if baseline.hosts_hash != current.hosts_hash {
        diffs.push(("hosts_change".into(), "Hosts file modified".into()));
    }

    let b_startup: HashSet<&str> = baseline.startup_entries.iter().map(|s| s.as_str()).collect();
    let c_startup: HashSet<&str> = current.startup_entries.iter().map(|s| s.as_str()).collect();
    let new_startup: Vec<_> = c_startup.difference(&b_startup).collect();
    let removed_startup: Vec<_> = b_startup.difference(&c_startup).collect();
    if !new_startup.is_empty() || !removed_startup.is_empty() {
        diffs.push(("startup_change".into(), format!("Startup: +{:?} -{:?}", new_startup, removed_startup)));
    }

    let b_svc: HashSet<&str> = baseline.services.iter().map(|s| s.as_str()).collect();
    let c_svc: HashSet<&str> = current.services.iter().map(|s| s.as_str()).collect();
    let new_svc: Vec<_> = c_svc.difference(&b_svc).collect();
    let removed_svc: Vec<_> = b_svc.difference(&c_svc).collect();
    if !new_svc.is_empty() || !removed_svc.is_empty() {
        diffs.push(("service_change".into(), format!("Services: +{:?} -{:?}", new_svc, removed_svc)));
    }

    diffs
}

fn log_event(state: &mut AppState, event_type: &str, details: &str, severity: &str) {
    let event = Event {
        timestamp: Utc::now().to_rfc3339(),
        event_type: event_type.into(),
        details: details.into(),
        severity: severity.into(),
    };
    state.events.push(event.clone());
    let log_path = PathBuf::from(DATA_DIR).join("events.log");
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(log_path) {
        let _ = writeln!(file, "{}", serde_json::to_string(&event).unwrap());
    }
}

fn check_integrity(state: &Arc<Mutex<AppState>>) {
    let mut guard = state.lock().unwrap();
    let current = collect_current_state();
    let baseline = match &guard.baseline {
        Some(b) => b.clone(),
        None => return,
    };
    let expected_sig = sign_state(&baseline.state, &guard.seed);
    if expected_sig != baseline.signature {
        log_event(&mut guard, "baseline_tampered", "Baseline signature mismatch", "critical");
        guard.status.trust_state = "Compromised".into();
        return;
    }
    let diffs = diff_states(&baseline.state, &current);
    for diff in &diffs {
        log_event(&mut guard, &diff.0, &diff.1, "warning");
    }
    guard.status.trust_state = match diffs.len() {
        0 => "Trusted",
        1 => "Warning",
        _ => "Compromised",
    }
    .into();
    guard.status.last_check = Utc::now().to_rfc3339();
    guard.status.latest_events = guard.events.iter().rev().take(5).cloned().collect();
}