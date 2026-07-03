use reqwest::blocking::Client;
use serde::Deserialize;
use std::{thread, time::Duration};
use tray_icon::TrayIconBuilder;

#[derive(Debug, Deserialize)]
struct DaemonStatus {
    trust_state: String,
    token: String,
    last_check: String,
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
                let (icon, tooltip) = match status.trust_state.as_str() {
                    "Trusted" => (
                        icon_green.clone(),
                        "🟢 Trust Sentinel - Device is safe\nAll checks passed. No unauthorized changes detected."
                    ),
                    "Warning" => (
                        icon_yellow.clone(),
                        "🟡 Trust Sentinel - Warning\nA change was detected.\n\nWhat to do:\n• Open http://127.0.0.1:12789 to check details\n• If the change was you, click Reset Baseline"
                    ),
                    "Compromised" => (
                        icon_red.clone(),
                        "🔴 Trust Sentinel - Compromised\nMultiple unauthorized changes detected.\n\nWhat to do:\n• Disconnect from network immediately\n• Open http://127.0.0.1:12789 to review events\n• Run antivirus scan\n• Restore from backup if needed"
                    ),
                    _ => (
                        icon_gray.clone(),
                        "Trust Sentinel - Checking..."
                    ),
                };
                tray.set_icon(Some(icon)).ok();
                tray.set_tooltip(Some(tooltip)).ok();
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}