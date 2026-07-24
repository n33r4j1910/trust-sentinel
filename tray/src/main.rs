use reqwest::blocking::Client;
use serde::Deserialize;
use std::process::Command as Cmd;
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
    println!("Starting Trust Sentinel tray...");
    let client = Client::new();
    let icon_green = make_icon(0, 255, 0);
    let icon_yellow = make_icon(255, 255, 0);
    let icon_red = make_icon(255, 0, 0);
    let icon_gray = make_icon(128, 128, 128);
    let icon_orange = make_icon(255, 140, 0);

    let mut tray = TrayIconBuilder::new()
        .with_icon(icon_gray.clone())
        .with_tooltip("Trust Sentinel - Starting...")
        .build()
        .unwrap();
    println!("Tray created");

    let mut last_state = String::new();

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
                        "Trust Sentinel - All Good\nYour device is safe.".to_string()
                    ),
                    "Stealth" => (
                        icon_orange.clone(),
                        "Trust Sentinel - Stealth Mode\nYour device is hidden on this network.".to_string()
                    ),
                    "Visible" => (
                        icon_green.clone(),
                        "Trust Sentinel - Visible\nStealth deactivated. Device is visible.".to_string()
                    ),
                    "Warning" => (
                        icon_yellow.clone(),
                        format!("Trust Sentinel - Warning!\n\nChanges detected:\n{}\n\nA details window will open automatically.", events_text)
                    ),
                    "Compromised" => (
                        icon_red.clone(),
                        format!("Trust Sentinel - COMPROMISED!\n\n{}\n\nA repair window will open automatically.", events_text)
                    ),
                    _ => (icon_gray.clone(), "Trust Sentinel - Checking...".to_string()),
                };
                tray.set_icon(Some(icon)).ok();
                tray.set_tooltip(Some(tooltip)).ok();

                // Show popup + open browser on Warning or Compromised
                                if (status.trust_state == "Warning" || status.trust_state == "Compromised") && last_state != status.trust_state {
                    let msg = if status.trust_state == "Warning" {
                        "Trust Sentinel: Warning - Changes detected! Opening details..."
                    } else {
                        "Trust Sentinel: COMPROMISED! Opening repair panel..."
                    };
                    let _ = Cmd::new("powershell")
                        .args(["-NoProfile", "-Command", 
                            &format!("Add-Type -AssemblyName System.Windows.Forms; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Warning; $n.Visible = $true; $n.ShowBalloonTip(10000, 'Trust Sentinel', '{}', 'Warning'); Start-Sleep 10; $n.Dispose()", msg)
                        ])
                        .spawn();
                    let _ = Cmd::new("cmd").args(["/c", "start", "http://127.0.0.1:12789"]).spawn();
                }
                last_state = status.trust_state;
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}