# Trust Sentinel 
 
**Lightweight Device Integrity Guardian** 
 
## Features 
- Rotating HMAC-SHA256 trust token every 30 seconds 
- System baseline monitoring (DNS, hosts, startup, services, ports) 
- Trust states: Trusted / Warning / Compromised 
- 100%% offline - no cloud, no API keys 
- Ultra-lightweight: <0.1%% CPU, ~25MB RAM 
 
## Quick Start 
``` 
git clone https://github.com/n33r4j1910/trust-sentinel.git 
cd trust-sentinel 
cargo build --release 
target\release\trust-sentinel-daemon.exe 
``` 
Then open http://127.0.0.1:12788 
 
## License 
MIT 
