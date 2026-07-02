use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const HTTP_PORT: u16 = 12789;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct SystemState { hosts_hash: String, listening_ports: Vec<String> }

#[derive(Debug, Serialize, Clone)]
struct DaemonStatus { trust_state: String, token: String, last_check: String }

fn main() {
    let seed = random_seed();
    let baseline = Arc::new(Mutex::new(collect_state()));
    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let b1 = baseline.clone(); let e1 = events.clone(); let s1 = seed.clone();
    std::thread::spawn(move || {
        let listener = TcpListener::bind(("127.0.0.1", HTTP_PORT)).unwrap();
        println!("Trust Sentinel on http://127.0.0.1:{}", HTTP_PORT);
        for stream in listener.incoming() {
            if let Ok(mut s) = stream {
                let _ = s.read(&mut [0u8; 1024]);
                let cur = collect_state();
                let bl = b1.lock().unwrap();
                let ev = e1.lock().unwrap();
                let diffs = diff(&bl, &cur);
                let state = if diffs.is_empty() { "Trusted" } else if diffs.len()==1 { "Warning" } else { "Compromised" };
                let token = token_str(&s1);
                let st = DaemonStatus { trust_state: state.into(), token, last_check: chrono::Utc::now().to_rfc3339() };
                let json = serde_json::to_string(&st).unwrap();
                let r = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}", json.len(), json);
                let _ = s.write_all(r.as_bytes());
            }
        }
    });

    // Check for changes every 5 min
    let b2 = baseline.clone(); let e2 = events.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(300));
        let cur = collect_state();
        let bl = b2.lock().unwrap();
        let diffs = diff(&bl, &cur);
        if !diffs.is_empty() {
            let mut ev = e2.lock().unwrap();
            for d in &diffs { ev.push(format!("{}: {}", d.0, d.1)); }
        }
    });

    loop { std::thread::sleep(Duration::from_secs(60)); }
}

fn random_seed() -> Vec<u8> { let r = SystemRandom::new(); let mut s = [0u8;32]; r.fill(&mut s).unwrap(); s.to_vec() }
fn token_str(seed: &[u8]) -> String { let c = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()/30; let mut m = HmacSha256::new_from_slice(seed).unwrap(); m.update(&c.to_be_bytes()); hex::encode(m.finalize().into_bytes()) }

fn collect_state() -> SystemState {
    let hosts = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts").unwrap_or_default();
    let hosts_hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, hosts.as_bytes()));
    SystemState { hosts_hash, listening_ports: vec![] }
}

fn diff(a: &SystemState, b: &SystemState) -> Vec<(String, String)> {
    let mut d = Vec::new();
    if a.hosts_hash != b.hosts_hash { d.push(("hosts_change".into(), "Hosts modified".into())); }
    d
}