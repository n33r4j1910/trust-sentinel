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
    let mut rgba = Vec::new();
    for _ in 0..(16 * 16) {
        rgba.push(r);
        rgba.push(g);
        rgba.push(b);
        rgba.push(255);
    }
    tray_icon::Icon::from_rgba(rgba, 16, 16).unwrap()
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
        if let Ok(resp) = client.get("http://127.0.0.1:12788").send() {
            if let Ok(status) = resp.json::<DaemonStatus>() {
                let (icon, tooltip): (tray_icon::Icon, String) = match status.trust_state.as_str() {
                    "Trusted" => (icon_green.clone(), "Trust Sentinel - Trusted".to_string()),
                    "Warning" => (icon_yellow.clone(), "Trust Sentinel - Warning".to_string()),
                    "Compromised" => (icon_red.clone(), "Trust Sentinel - Compromised".to_string()),
                    _ => (icon_gray.clone(), format!("Trust Sentinel - {}", status.trust_state)),
                };
                tray.set_icon(Some(icon)).ok();
                tray.set_tooltip(Some(tooltip.as_str())).ok();
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}