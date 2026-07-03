use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use hmac::{Hmac, Mac};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const HTTP_PORT: u16 = 12789;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct SystemState {
    dns_servers: Vec<String>,
    hosts_hash: String,
    startup_entries: Vec<String>,
    listening_ports: Vec<String>,
    firewall_profiles: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
struct DaemonStatus {
    trust_state: String,
    token: String,
    last_check: String,
    latest_events: Vec<String>,
}

fn main() {
    let _ = fs::create_dir_all("C:\\ProgramData\\Trust Sentinel");
    let seed = random_seed();
    let baseline = Arc::new(Mutex::new(collect_state()));
    let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let b1 = baseline.clone();
    let e1 = events.clone();
    let s1 = seed.clone();
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
                let state = if diffs.is_empty() {
                    "Trusted"
                } else if diffs.len() == 1 {
                    "Warning"
                } else {
                    "Compromised"
                };
                let token = token_str(&s1);
                let st = DaemonStatus {
                    trust_state: state.into(),
                    token,
                    last_check: Utc::now().to_rfc3339(),
                    latest_events: ev.iter().rev().take(5).cloned().collect(),
                };
                let json = serde_json::to_string(&st).unwrap();
                let r = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\n\r\n{}",
                    json.len(),
                    json
                );
                let _ = s.write_all(r.as_bytes());
            }
        }
    });

    // Check for changes every 5 min
    let b2 = baseline.clone();
    let e2 = events.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(300));
        let cur = collect_state();
        let bl = b2.lock().unwrap();
        let diffs = diff(&bl, &cur);
        if !diffs.is_empty() {
            let mut ev = e2.lock().unwrap();
            for d in &diffs {
                ev.push(format!("{}: {}", d.0, d.1));
            }
        }
    });

    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}

fn random_seed() -> Vec<u8> {
    let r = SystemRandom::new();
    let mut s = [0u8; 32];
    r.fill(&mut s).unwrap();
    s.to_vec()
}

fn token_str(seed: &[u8]) -> String {
    let c = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 30;
    let mut m = HmacSha256::new_from_slice(seed).unwrap();
    m.update(&c.to_be_bytes());
    hex::encode(m.finalize().into_bytes())
}

fn collect_state() -> SystemState {
    SystemState {
        dns_servers: get_dns(),
        hosts_hash: get_hosts_hash(),
        startup_entries: get_startup(),
        listening_ports: get_ports(),
        firewall_profiles: get_firewall(),
    }
}

fn get_dns() -> Vec<String> {
    let mut d = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object {$_.ServerAddresses.Count -gt 0} | ForEach-Object {$_.ServerAddresses -join ','}"])
        .output()
    {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            for a in l.split(',') {
                let a = a.trim().to_string();
                if !a.is_empty() && !d.contains(&a) {
                    d.push(a);
                }
            }
        }
    }
    if d.is_empty() {
        d.push("Unknown".into());
    }
    d
}

fn get_hosts_hash() -> String {
    if let Ok(c) = fs::read_to_string("C:\\Windows\\System32\\drivers\\etc\\hosts") {
        hex::encode(ring::digest::digest(&ring::digest::SHA256, c.as_bytes()))
    } else {
        "unreadable".into()
    }
}

fn get_startup() -> Vec<String> {
    let mut e = Vec::new();
    let sf = std::env::var("APPDATA").unwrap_or_default()
        + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup";
    if let Ok(d) = fs::read_dir(&sf) {
        for f in d.flatten() {
            e.push(f.file_name().to_string_lossy().to_string());
        }
    }
    // Check registry Run keys
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "(Get-ItemProperty 'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run').PSObject.Properties | Where-Object {$_.Name -ne 'PSPath'} | Select-Object -ExpandProperty Name"])
        .output()
    {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let l = l.trim().to_string();
            if !l.is_empty() {
                e.push(l);
            }
        }
    }
    if e.is_empty() {
        e.push("None".into());
    }
    e
}

fn get_ports() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("netstat").args(["-ano", "-p", "TCP"]).output() {
        for l in String::from_utf8_lossy(&o.stdout).lines().skip(4) {
            let parts: Vec<&str> = l.split_whitespace().collect();
            if parts.len() >= 4 && parts[3] == "LISTENING" {
                let a = parts[1].to_string();
                if a != "0.0.0.0:0" && !a.ends_with(&format!(":{}", HTTP_PORT)) {
                    p.push(a);
                }
            }
        }
    }
    p.sort();
    p.dedup();
    p
}

fn get_firewall() -> Vec<String> {
    let mut p = Vec::new();
    if let Ok(o) = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-NetFirewallProfile | ForEach-Object {$_.Name+':'+($_.Enabled ? 'ON':'OFF')}"])
        .output()
    {
        for l in String::from_utf8_lossy(&o.stdout).lines() {
            let l = l.trim().to_string();
            if !l.is_empty() {
                p.push(l);
            }
        }
    }
    if p.is_empty() {
        p.push("Unknown".into());
    }
    p
}

fn diff(a: &SystemState, b: &SystemState) -> Vec<(String, String)> {
    let mut d = Vec::new();
    
    let ad: HashSet<&str> = a.dns_servers.iter().map(|s| s.as_str()).collect();
    let bd: HashSet<&str> = b.dns_servers.iter().map(|s| s.as_str()).collect();
    if ad != bd {
        d.push(("dns_change".into(), "DNS servers changed".into()));
    }
    
    if a.hosts_hash != b.hosts_hash {
        d.push(("hosts_change".into(), "Hosts file modified".into()));
    }
    
    let ae: HashSet<&str> = a.startup_entries.iter().map(|s| s.as_str()).collect();
    let be: HashSet<&str> = b.startup_entries.iter().map(|s| s.as_str()).collect();
    if ae != be {
        d.push(("startup_change".into(), "Startup entries changed".into()));
    }
    
    let ap: HashSet<&str> = a.listening_ports.iter().map(|s| s.as_str()).collect();
    let bp: HashSet<&str> = b.listening_ports.iter().map(|s| s.as_str()).collect();
    if ap != bp {
        d.push(("port_change".into(), "Listening ports changed".into()));
    }
    
    let af: HashSet<&str> = a.firewall_profiles.iter().map(|s| s.as_str()).collect();
    let bf: HashSet<&str> = b.firewall_profiles.iter().map(|s| s.as_str()).collect();
    if af != bf {
        d.push(("firewall_change".into(), "Firewall profiles changed".into()));
    }
    
    d
}