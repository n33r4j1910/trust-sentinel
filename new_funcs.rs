fn download_phishing_list() { 
    let path = std::path::PathBuf::from(DATA_DIR).join("phishing_hosts.txt"); 
    if !path.exists() { 
            let _ = Command::new("powershell").args(["-NoProfile","-Command","Invoke-WebRequest -Uri 'https://someonewhocares.org/hosts/zero/hosts' -OutFile 'C:\\ProgramData\\Trust Sentinel\\phishing_hosts.txt' -ErrorAction SilentlyContinue"]).output(); 
        }); 
    } 
} 
 
fn setup_startup() { 
    let link = std::path::PathBuf::from(std::env::var("APPDATA").unwrap_or_default()).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup\\TrustSentinel.lnk"); 
    if !link.exists() { 
        let _ = Command::new("powershell").args(["-NoProfile","-Command","$ws = New-Object -ComObject WScript.Shell; $sc = $ws.CreateShortcut($env:APPDATA + '\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\TrustSentinel.lnk'); $sc.TargetPath = 'wscript.exe'; $sc.Arguments = $env:ProgramData + '\\Trust Sentinel\\start_silent.vbs'; $sc.WindowStyle = 7; $sc.Save()"]).output(); 
    } 
} 
