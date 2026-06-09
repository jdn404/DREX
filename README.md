
```
  ██████╗ ██████╗ ███████╗██╗  ██╗
  ██╔══██╗██╔══██╗██╔════╝╚██╗██╔╝
  ██║  ██║██████╔╝█████╗   ╚███╔╝ 
  ██║  ██║██╔══██╗██╔══╝   ██╔██╗ 
  ██████╔╝██║  ██║███████╗██╔╝ ██╗
  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

**DREX v0.0.1 — Network Intelligence Scanner**

Real SNI bug discovery and proxy hunting for African mobile networks.  
Single Go binary. Termux · Linux · Windows · macOS.

---

## Install — Termux

```bash
pkg update && pkg upgrade -y
pkg install golang git -y
git clone https://github.com/jdn404/DREX.git
cd DREX
go mod tidy
go build -o drex .
./drex scan econet
```

## Install — Linux

```bash
sudo apt install golang git -y
git clone https://github.com/jdn404/DREX.git
cd DREX
go mod tidy
go build -o drex .
./drex scan econet
```

## Cross-compile for Android (from PC)

```bash
GOOS=android GOARCH=arm64 go build -o drex .
```

---

## Commands

```
drex scan econet                  Full scan — balanced mode
drex scan econet --mode turbo     Max speed — 2000 goroutines
drex scan econet --mode stealth   Slow + thorough
drex scan 1                       Carrier by number (1 = econet)
drex scan all                     Scan all 14 carriers
drex results                      Show last saved results
drex export econet                Export all config formats
drex export econet --format v2ray Export specific format
drex validate 41.57.96.45:8080   Test a specific proxy
drex snicheck 41.57.96.45 econet.co.zw  Test SNI bug
drex list                         List all carriers
drex version                      Show version
```

## Modes

| Mode       | Goroutines | Timeout | Use case              |
|------------|-----------|---------|----------------------|
| turbo      | 2000      | 3s      | Max speed            |
| aggressive | 1000      | 5s      | Fast + reliable      |
| balanced   | 200       | 8s      | Default              |
| stealth    | 30        | 15s     | Slow, thorough       |

## Supported Carriers

Econet ZW · NetOne ZW · Telecel ZW · MTN ZA · Airtel NG · Glo NG  
Zamtel ZM · Vodacom ZA · Safaricom KE · Orange SN · Telkom KE  
MTN Ghana · Tigo TZ · Halotel TZ

## Export Formats

- HTTP Injector `.conf`
- V2Ray vmess `.json`
- NapsternetV `.json`
- HTTP Custom `.hc`
- V2Ray subscription `.txt`
- Raw proxy list `.txt`
- CSV `.csv`

All exports saved to `drex_exports/`  
Results saved to `drex_results.json`

## How SNI discovery works

DREX connects directly to each IP in the carrier's IP ranges and initiates a TLS handshake with the `ServerName` field set to known zero-rated or CDN domains. If the IP responds with a valid HTTP status code, that IP is a real working SNI bug host — not hardcoded, genuinely discovered on the network.

Every hit is then verified with a second independent connection to confirm it actually works.
