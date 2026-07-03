use reqwest::blocking::Client;
use serde::Deserialize;
use std::{thread, time::Duration};
use tray_icon::TrayIconBuilder;

#[derive(Debug, Deserialize)]
struct DaemonStatus {
    trust_state: String,
    token: String,
    last_check: String,
    latest_events: Vec<String>,
}

fn make_icon(r: u8, g: u8, b: u8) -> tray_icon::Icon {
    let size = 16;
    let mut rgba = Vec::new();
    let center = size as f32 / 2.0;
    let radius = size as f32 / 2.0 - 1.0;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 + 0.5 - center;
            let dy = y as f32 + 0.5 - center;
            if (dx * dx + dy * dy).sqrt() <= radius {
                rgba.push(r); rgba.push(g); rgba.push(b); rgba.push(255);
            } else {
                rgba.push(0); rgba.push(0); rgba.push(0); rgba.push(0);
            }
        }
    }
    tray_icon::Icon::from_rgba(rgba, size as u32, size as u32).unwrap()
}

fn main() {
    let client = Client::new();
    let icon_green = make_icon(0, 255, 0);
    let icon_yellow = make_icon(255, 255, 0);
    let icon_red = make_icon(255, 0, 0);
    let icon_gray = make_icon(128, 128, 128);

    let mut tray = TrayIconBuilder::new()
        .with_icon(icon_gray.clone())
        .with_tooltip("Trust Sentinel - Starting...")
        .build()
        .unwrap();

    loop {
        if let Ok(resp) = client.get("http://127.0.0.1:12789").send() {
            if let Ok(status) = resp.json::<DaemonStatus>() {
                let events_text: String = status.latest_events.iter()
                    .map(|e| format!("  - {}", e))
                    .collect::<Vec<_>>()
                    .join("\n");
                
                let (icon, tooltip): (tray_icon::Icon, String) = match status.trust_state.as_str() {
                    "Trusted" => (
                        icon_green.clone(),
                        "🟢 Trust Sentinel - All Good\nYour device is safe. No unauthorized changes detected.\n\nOpen http://127.0.0.1:12789 for details".to_string()
                    ),
                    "Warning" => (
                        icon_yellow.clone(),
                        format!("🟡 Trust Sentinel - Warning!\nSomething changed on your system.\n\nRecent changes:\n{}\n\nWhat to do:\n1. Open http://127.0.0.1:12789\n2. If the change was you, it's safe\n3. If unexpected, investigate immediately", events_text)
                    ),
                    "Compromised" => (
                        icon_red.clone(),
                        format!("🔴 Trust Sentinel - COMPROMISED!\nMultiple unauthorized changes detected!\n\nRecent:\n{}\n\nWhat to do:\n1. DISCONNECT from network\n2. Open http://127.0.0.1:12789\n3. Run antivirus scan\n4. Check hosts file and DNS", events_text)
                    ),
                    _ => (icon_gray.clone(), "Trust Sentinel - Checking...".to_string()),
                };
                tray.set_icon(Some(icon)).ok();
                tray.set_tooltip(Some(tooltip)).ok();
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}