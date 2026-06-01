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

fn main() {
    let client = Client::new();

    let icon_green = tray_icon::Icon::from_path("src/green.ico", None).unwrap();
    let icon_yellow = tray_icon::Icon::from_path("src/yellow.ico", None).unwrap();
    let icon_red = tray_icon::Icon::from_path("src/red.ico", None).unwrap();
    let icon_gray = tray_icon::Icon::from_path("src/gray.ico", None).unwrap();

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