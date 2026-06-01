use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::net::TcpListener;
use std::io::Read;

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

#[derive(Debug, Serialize, Deserialize)]
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
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n\r\n{}",
                    json.len(), json
                );
                let _ = stream.write_all(response.as_bytes());
            }
        }
    });

    let state_token = state.clone();
    std::thread::spawn(move || loop {
        generate_token(&state_token);
        std::thread::sleep(Duration::from_secs(30));
    });

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

fn collect_current_state() -> SystemState {
    let hosts = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts").unwrap_or_default();
    SystemState {
        dns_servers: vec!["192.168.1.1".to_string()],
        hosts_hash: hex::encode(ring::digest::digest(&ring::digest::SHA256, hosts.as_bytes())),
        startup_entries: vec!["OneDrive".to_string()],
        services: vec!["Dhcp".to_string(), "Dnscache".to_string()],
        listening_ports: vec!["0.0.0.0:445".to_string()],
    }
}

fn load_or_create_baseline(data_dir: &PathBuf, seed: &[u8]) -> Baseline {
    let path = data_dir.join("baseline.json");
    if path.exists() {
        let data = fs::read_to_string(&path).unwrap();
        let baseline: Baseline = serde_json::from_str(&data).unwrap();
        let expected = sign_state(&baseline.state, seed);
        if expected == baseline.signature {
            return baseline;
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
    if baseline.dns_servers != current.dns_servers {
        diffs.push(("dns_change".into(), "DNS servers changed".into()));
    }
    if baseline.hosts_hash != current.hosts_hash {
        diffs.push(("hosts_change".into(), "Hosts file modified".into()));
    }
    if baseline.startup_entries != current.startup_entries {
        diffs.push(("startup_change".into(), "Startup entries changed".into()));
    }
    if baseline.services != current.services {
        diffs.push(("service_change".into(), "New or removed services".into()));
    }
    if baseline.listening_ports != current.listening_ports {
        diffs.push(("port_change".into(), "Listening ports changed".into()));
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
    let mut file = fs::OpenOptions::new().create(true).append(true).open(log_path).unwrap();
    writeln!(file, "{}", serde_json::to_string(&event).unwrap()).ok();
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
    }.into();
    guard.status.last_check = Utc::now().to_rfc3339();
    guard.status.latest_events = guard.events.iter().rev().take(5).cloned().collect();
}