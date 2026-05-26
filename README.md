
<div align="center">

```
  █████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗
 ██╔══██╗██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝
 ███████║██║  ██║██╔██╗ ██║█████╗   ╚███╔╝ 
 ██╔══██║██║  ██║██║╚██╗██║██╔══╝   ██╔██╗ 
 ██║  ██║██████╔╝██║ ╚████║███████╗██╔╝ ██╗
 ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

**Network Intelligence Scanner**

![Version](https://img.shields.io/badge/version-v2.0.0-brightgreen?style=flat-square)
![Python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/platform-Termux%20%7C%20Linux-black?style=flat-square)
![Developer](https://img.shields.io/badge/dev-Jaden%20Afrix-ff2d78?style=flat-square)
![Country](https://img.shields.io/badge/origin-Zimbabwe-green?style=flat-square)

> Async SNI bug hunter + proxy host scanner built for African mobile networks.  
> Finds working hosts, exports ready-to-use configs for HTTP Injector, V2Ray, NapsternetV & HTTP Custom.

</div>

---

## Table of Contents

- [Requirements](#requirements)
- [Installation — Termux](#installation--termux)
- [Installation — Linux / Kali](#installation--linux--kali)
- [Running ADNEX](#running-adnex)
- [Scan Commands](#scan-commands)
- [Export Commands](#export-commands)
- [Utility Commands](#utility-commands)
- [Scan Strategies](#scan-strategies)
- [Supported Carriers](#supported-carriers)
- [Output Files](#output-files)
- [Config](#config)
- [Developer](#developer)

---

## Requirements

- Python 3.8+
- pip
- Internet connection (for initial install only)
- Termux (Android) or any Linux terminal

**Python packages:**
```
rich>=13.0.0
aiohttp>=3.9.0
requests>=2.31.0
psutil>=5.9.0
```

---

## Installation — Termux

> Full setup from scratch. Run these one by one.

**Step 1 — Update Termux packages**
```bash
pkg update -y && pkg upgrade -y
```

**Step 2 — Install Python and Git**
```bash
pkg install python git -y
```

**Step 3 — Clone the repo**
```bash
git clone https://github.com/jdn404/ADNEX.git
```

**Step 4 — Enter the directory**
```bash
cd ADNEX
```

**Step 5 — Install dependencies**
```bash
pip install -r requirements.txt --break-system-packages
```

**Step 6 — Make the script executable**
```bash
chmod +x adnex.py
```

**Step 7 — Run ADNEX**
```bash
python adnex.py
```

---

### Termux One-Liner Install

Copy and paste this entire block:

```bash
pkg update -y && pkg upgrade -y && pkg install python git -y && git clone https://github.com/jdn404/ADNEX.git && cd ADNEX && pip install -r requirements.txt --break-system-packages && python adnex.py
```

---

### Running Again After First Install

Every time you want to run ADNEX after the first install:

```bash
cd ADNEX
python adnex.py
```

If you closed Termux and need to navigate back:
```bash
ls
cd ADNEX
python adnex.py
```

---

## Installation — Linux / Kali

**Step 1 — Update system**
```bash
sudo apt update && sudo apt upgrade -y
```

**Step 2 — Install Python and Git**
```bash
sudo apt install python3 python3-pip git -y
```

**Step 3 — Clone the repo**
```bash
git clone https://github.com/jdn404/ADNEX.git
```

**Step 4 — Enter directory**
```bash
cd ADNEX
```

**Step 5 — Install dependencies**
```bash
pip3 install -r requirements.txt
```

**Step 6 — Make executable**
```bash
chmod +x adnex.py
```

**Step 7 — Run**
```bash
python3 adnex.py
```

---

### Run as executable (optional)

```bash
chmod +x adnex.py
./adnex.py
```

---

### Update ADNEX to latest version

```bash
cd ADNEX
git pull origin main
python adnex.py
```

---

## Running ADNEX

Once inside the tool you'll see the live dashboard with:
- System stats (CPU, RAM, Disk)
- Scan status panel
- Real-time log output
- Proxy hits table
- SNI bugs table
- Carrier list
- Command panel

Type commands at the prompt:
```
adnex@jadenafrix~$
```

---

## Scan Commands

| Command | Description |
|---|---|
| `scan <carrier>` | Full scan — proxy + SNI + payload injection |
| `turbo <carrier>` | Turbo mode — 2000 threads, 3s timeout, max aggression |
| `aggressive <carrier>` | Aggressive mode — 1000 threads, 5s timeout |
| `ultra <carrier> <strategy>` | Ultra engine with custom strategy |
| `stealth <carrier>` | Stealth scan — rotating user-agents + header injection |
| `deepsni <carrier>` | Deep SNI-only TLS probe on multiple ports |
| `inject <carrier>` | Payload injection scan — 10 payload types |
| `wscan <carrier>` | WebSocket endpoint scanner |
| `anonscan <carrier>` | Anonymity detection — transparent / anonymous / elite |
| `commonsni` | Scan 30+ common CDN/global SNI bug candidates |
| `massport <carrier> <port>` | Mass-check one port across entire carrier IP range |
| `portscan <ip>` | Async port scan on a single IP |
| `scanrange <cidr> <ports>` | Scan custom IP range with custom ports |
| `scanip <ip>` | Deep scan a single IP (all proxy types) |
| `multiscan <c1,c2,c3>` | Scan multiple carriers at once |
| `autoscan` | Auto-detect your carrier via GeoIP and scan it |
| `watch <carrier> <seconds>` | Auto-repeat scan loop every N seconds |
| `fullport <ip>` | Full port range scan — 120+ ports |
| `discover <domain>` | Smart IP discovery — resolve domain → map subnet → scan |
| `cfsweep` | Cloudflare SNI sweep across all edge domains |
| `stop` | Stop active scan |

**Examples:**
```bash
scan econet
turbo mtn
ultra airtel turbo
stealth vodacom
deepsni econet
massport econet 8080
scanrange 41.57.96.0/19 80,8080,3128
multiscan econet,mtn,airtel
watch econet 60
discover econet.co.zw
```

---

## Export Commands

| Command | Description |
|---|---|
| `exportall <carrier>` | Export all formats at once |
| `bestexport <carrier>` | Export only top-ranked results |
| `hiexport <carrier>` | HTTP Injector full JSON config |
| `sub` | Generate V2Ray subscription link file |
| `export <carrier>` | Basic export |
| `report` | Full session report (.txt) |
| `summary` | Session summary JSON |

**Export formats generated:**
- `HTTP Injector (.conf)` — proxy + bug host config
- `V2Ray vmess (.json)` — v2rayNG ready
- `NapsternetV (.json)` — NapsternetV ready
- `HTTP Custom (.hc)` — HTTP Custom app ready
- `V2Ray Subscription (.txt)` — paste into any V2Ray client
- `Raw proxy list (.txt)` — plain `ip:port` list
- `CSV (.csv)` — spreadsheet format
- `Payload config (.json)` — combined config

All exports saved to `adnex_results/exports/`

---

## Utility Commands

| Command | Description |
|---|---|
| `results` | Show in-memory scan results |
| `top <n>` | Show top N quality proxies sorted by score |
| `viewresults` | Full results screen |
| `stats` | Detailed scan statistics + latency distribution |
| `chart` | Latency distribution bar chart |
| `scansum` | Quick scan summary |
| `geo <ip>` | GeoIP lookup for any IP |
| `geobatch` | GeoIP lookup for all found proxies |
| `validate <ip:port>` | Triple-validate a proxy (3-round check) |
| `autovalidate <seconds>` | Start background proxy re-validator |
| `resolve <carrier>` | Resolve carrier zero-rated domains to IPs |
| `loadfile <path>` | Load and validate proxies from a text file |
| `list` | List all carriers |
| `allcarriers` | Full carrier table with IP counts |
| `carrierstats` | IP count stats per carrier |
| `carrier <name>` | Detailed info on one carrier |
| `netinfo` | Show network interfaces + public IP |
| `status` | Current scan status |
| `config` | View config.json settings |
| `benchmark` | Test async engine speed |
| `history` | Show previously saved scan files |
| `saved` | Browse saved result files |
| `flush` | Wipe all results from memory |
| `clear` | Clear the terminal screen |
| `tips` | Usage tips |
| `quickstart` | Step-by-step guide |
| `scanmenu` | All scan modes menu |
| `exportmenu` | All export options menu |
| `help` | Full command reference |
| `about` | Tool info and developer |
| `exit` | Quit ADNEX |

---

## Scan Strategies

Pass a strategy name to `ultra` command:

| Strategy | Threads | Timeout | Use Case |
|---|---|---|---|
| `turbo` | 2000 | 3s | Maximum speed, less accuracy |
| `aggressive` | 1000 | 5s | Fast + reliable |
| `balanced` | 500 | 8s | Default — speed + accuracy |
| `stealth` | 100 | 12s | Slow, thorough, hard to detect |

```bash
ultra econet turbo
ultra mtn balanced
ultra airtel stealth
```

---

## Supported Carriers

| Key | Carrier | Country |
|---|---|---|
| `econet` | Econet Zimbabwe | ZW |
| `netone` | NetOne Zimbabwe | ZW |
| `telecel` | Telecel Zimbabwe | ZW |
| `mtn` | MTN | ZA |
| `airtel` | Airtel Africa | NG |
| `glo` | Glo Mobile | NG |
| `zamtel` | Zamtel Zambia | ZM |
| `vodacom` | Vodacom | ZA |
| `safaricom` | Safaricom Kenya | KE |
| `orange` | Orange Africa | SN |
| `telkom` | Telkom Kenya | KE |
| `mtn_gh` | MTN Ghana | GH |
| `tigo` | Tigo Africa | TZ |
| `halotel` | Halotel Tanzania | TZ |

---

## Output Files

All results auto-saved to `adnex_results/`:

```
adnex_results/
├── proxies/
│   └── econet_20250526_143022.txt
├── sni/
│   └── econet_20250526_143022.txt
└── exports/
    ├── BEST_HI_econet_20250526_143022.conf
    ├── BEST_V2Ray_econet_20250526_143022.json
    ├── BEST_NapsternetV_econet_20250526_143022.json
    ├── hi_full_econet_20250526_143022.json
    ├── v2ray_econet_20250526_143022.json
    ├── napsternetv_econet_20250526_143022.json
    ├── httpcustom_econet_20250526_143022.hc
    ├── subscription_20250526_143022.txt
    ├── raw_proxies_econet_20250526_143022.txt
    ├── proxies_econet_20250526_143022.csv
    ├── session_report_20250526_143022.txt
    └── summary_20250526_143022.json
```

---

## Config

Edit `config.json` to customize behavior:

```json
{
  "concurrency": 500,
  "timeout": 8,
  "retry": 3,
  "validate_rounds": 2,
  "save_auto": true,
  "theme": "green"
}
```

| Key | Default | Description |
|---|---|---|
| `concurrency` | 500 | Async connections at once |
| `timeout` | 8 | Seconds per connection |
| `retry` | 3 | Retry attempts per host |
| `validate_rounds` | 2 | Rounds for proxy validation |
| `save_auto` | true | Auto-save results after scan |

Higher concurrency = faster but uses more RAM. On low-end devices keep at 200-300.

---

## Troubleshooting

**`ModuleNotFoundError`**
```bash
pip install -r requirements.txt --break-system-packages
```

**`Permission denied`**
```bash
chmod +x adnex.py
```

**`python: command not found`** (Linux)
```bash
python3 adnex.py
```

**`git: command not found`** (Termux)
```bash
pkg install git -y
```

**Scan too slow**
Edit `config.json` and increase `concurrency` to `1000` or use `turbo` mode.

**No hits found**
Try `commonsni` or `cfsweep` — these don't need carrier-specific IPs.

---

## Developer

```
Name    : Jaden Afrix
Country : Zimbabwe
Age     : 19
GitHub  : github.com/jdn404
Tool    : ADNEX v2.0.0
Brand   : CYBIX TECH
```

---

<div align="center">

**ADNEX v2.0.0** — Built by **Jaden Afrix** | Zimbabwe  
CYBIX TECH © 2025

</div>
