import requests
import socket
import ssl
import time
import argparse
import urllib.parse
import base64
import json
import hashlib
import ipaddress
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich import print as rprint

TIMEOUT = 4
socket.setdefaulttimeout(TIMEOUT)

SOURCES = [
    "https://raw.githubusercontent.com/barry-far/V2ray-Config/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/Epodonios/v2ray-configs/main/All_Configs_Sub.txt",
    "https://raw.githubusercontent.com/SoliSpirit/v2ray-configs/main/all_configs.txt",
]

@lru_cache(maxsize=2048)
def resolve_ip(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except:
        return ""

def is_ip(address: str) -> bool:
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def fetch_all_configs():
    console = Console()
    all_links = set()
    with Progress() as progress:
        task = progress.add_task("[cyan]دانلود از منابع معتبر...", total=len(SOURCES))
        for url in SOURCES:
            try:
                r = requests.get(url, timeout=15)
                r.raise_for_status()
                for line in r.text.splitlines():
                    line = line.strip()
                    if line.startswith(('vless://', 'vmess://', 'trojan://')):
                        all_links.add(line)
                progress.update(task, advance=1)
                rprint(f"[green]✓[/green] {url.split('/')[-1][:30]}... → پیدا شد")
            except:
                rprint(f"[red]✗[/red] {url.split('/')[-1][:30]}... رد شد")
                progress.update(task, advance=1)
    return list(all_links)

def get_hash(link: str) -> str:
    return hashlib.md5(link.encode('utf-8')).hexdigest()

def parse_vless(link: str):
    try:
        parsed = urllib.parse.urlparse(link)
        netloc = parsed.netloc or parsed.path.split('?')[0]
        uuid, addr_port = netloc.split('@') if '@' in netloc else ('', netloc)
        address, port = addr_port.rsplit(':', 1) if ':' in addr_port else (addr_port, 443)
        query = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment)[:40] if parsed.fragment else address
        sni = query.get('sni', [address])[0]
        security = query.get('security', ['tls'])[0]
        return {'type': 'vless', 'address': address, 'port': int(port), 'remark': remark,
                'sni': sni, 'security': security, 'full_link': link.strip(), 'hash': get_hash(link)}
    except:
        return None

def parse_vmess(link: str):
    try:
        b64 = link[8:].split('#')[0].strip()
        b64 += '=' * (-len(b64) % 4)
        data = json.loads(base64.b64decode(b64).decode('utf-8', errors='ignore'))
        address = data.get('add') or data.get('address')
        port = int(data.get('port', 443))
        remark = (link.split('#')[-1] if '#' in link else data.get('ps', 'VMess'))[:40]
        sni = data.get('sni') or data.get('host') or address
        security = data.get('tls', 'none')
        return {'type': 'vmess', 'address': address, 'port': port, 'remark': remark,
                'sni': sni, 'security': security, 'full_link': link.strip(), 'hash': get_hash(link)}
    except:
        return None

def parse_trojan(link: str):
    try:
        link = link[9:]
        if '#' in link:
            link, remark = link.split('#', 1)
            remark = urllib.parse.unquote(remark)[:40]
        else:
            remark = 'Trojan'
        addr_port = link.split('@')[-1] if '@' in link else link
        address, port = addr_port.rsplit(':', 1) if ':' in addr_port else (addr_port, 443)
        return {'type': 'trojan', 'address': address, 'port': int(port), 'remark': remark,
                'sni': address, 'security': 'tls', 'full_link': f"trojan://{link}#{remark}", 'hash': get_hash(link)}
    except:
        return None

def test_config(config):
    host = config['address']
    port = config['port']
    sni = config.get('sni', host)
    security = config.get('security', 'tls')
    
    ip = host if is_ip(host) else resolve_ip(host)
    if not ip:
        return False, 9999, "❌ DNS Fail"

    start = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        
        if security in ['tls', 'reality', 'xtls']:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            host_name = sni if sni and not is_ip(sni) else None
            ssl_sock = ctx.wrap_socket(sock, server_hostname=host_name)
            ssl_sock.close()
        else:
            sock.close()
            
        latency = round((time.time() - start) * 1000, 1)
        return True, latency, "✅ سالم (TLS)" if security in ['tls', 'reality', 'xtls'] else "✅ سالم (TCP)"
    except Exception:
        return False, 9999, "❌ Timeout/Dead"

def main():
    parser = argparse.ArgumentParser(description="🚀 V2Ray Master Scraper & Tester")
    parser.add_argument("-t", "--threads", type=int, default=50, help="تعداد ترد (پیش‌فرض ۵۰)")
    parser.add_argument("-m", "--max-latency", type=int, default=500, help="حداکثر پینگ مجاز (میلی‌ثانیه)")
    parser.add_argument("-l", "--limit", type=int, default=1000, help="تعداد کانفیگ برای تست")
    parser.add_argument("--all", action="store_true", help="تست کل کانفیگ‌ها")
    args = parser.parse_args()

    console = Console()
    console.print("[bold magenta]🔥 V2Ray Master Pro 2026 — Auto Updater[/bold magenta]")

    links = fetch_all_configs()
    rprint(f"[bold cyan]📦 {len(links)} کانفیگ خام استخراج شد[/bold cyan]")

    configs = []
    seen = set()
    for link in links:
        for parse_func in [parse_vless, parse_vmess, parse_trojan]:
            cfg = parse_func(link)
            if cfg and cfg['hash'] not in seen:
                seen.add(cfg['hash'])
                configs.append(cfg)
                break

    if not args.all:
        configs = configs[:args.limit]
        rprint(f"[yellow]⚡ در حال تست روی {len(configs)} کانفیگ...[/yellow]")

    results = []
    good_links = []
    
    with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(), TextColumn("[progress.percentage]{task.percentage:>3.0f}%"), TimeRemainingColumn()) as progress:
        task = progress.add_task("[green]در حال اتک و تست پورت‌ها...", total=len(configs))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_cfg = {executor.submit(test_config, cfg): cfg for cfg in configs}
            for future in as_completed(future_to_cfg):
                cfg = future_to_cfg[future]
                try:
                    success, lat, status = future.result()
                    results.append({'remark': cfg['remark'], 'proto': cfg['type'].upper(), 'addr': f"{cfg['address']}:{cfg['port']}", 'lat': lat, 'status': status})
                    if success and lat <= args.max_latency:
                        good_links.append(cfg['full_link'])
                except:
                    pass
                progress.update(task, advance=1)

    if good_links:
        with open("good_configs.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(good_links))
        
        b64_content = base64.b64encode("\n".join(good_links).encode('utf-8')).decode('utf-8')
        with open("sub.txt", "w", encoding="utf-8") as f:
            f.write(b64_content)
            
        rprint("\n[bold green]🎉 عملیات با موفقیت تمام شد![/bold green]")
        rprint("[bold yellow]فایل‌های sub.txt و good_configs.txt بروزرسانی شدند.[/bold yellow]")
    else:
        rprint("[red]هیچ کانفیگ سالمی پیدا نشد![/red]")

if __name__ == "__main__":
    main()
