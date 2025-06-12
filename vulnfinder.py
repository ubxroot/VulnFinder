#!/usr/bin/env python3

import argparse
import requests
import socket
import re
from urllib.parse import urlparse

RED = "\033[91m"
RESET = "\033[0m"

BANNER = RED + r"""
 _    _ _ ____  __     __ ____  ____  _____ ____  _____ 
| |  | | |  _ \ \ \   / /|  _ \|  _ \| ____|  _ \| ____|
| |  | | | |_) | \ \ / / | |_) | | | |  _| | |_) |  _|  
| |__| | |  _ <   \ V /  |  _ <| |_| | |___|  _ <| |___ 
 \____/|_|_| \_\   \_/   |_| \_\____/|_____|_| \_\_____|
                                               
""" + RESET

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]

def check_url_headers(target):
    try:
        response = requests.get(target, timeout=5)
        print(f"\n[+] Target: {target}")
        print("[+] HTTP Headers:")
        for k, v in response.headers.items():
            print(f"    {k}: {v}")

        server = response.headers.get("Server", "")
        if server:
            print(f"[!] Server info found: {server}")
            if re.search(r'apache/2\.2|nginx/1\.1', server.lower()):
                print("[!] Potentially outdated server version.")
        
        if "Index of /" in response.text:
            print("[!] Directory listing is enabled.")
        
        for sensitive_path in ['/.git/', '/phpinfo.php', '/.env']:
            check_sensitive_path(target, sensitive_path)

    except requests.exceptions.RequestException as e:
        print(f"[!] Could not connect to {target}: {e}")

def check_sensitive_path(base_url, path):
    try:
        url = base_url.rstrip('/') + path
        res = requests.get(url, timeout=3)
        if res.status_code == 200:
            print(f"[!] Exposed resource found: {url}")
    except:
        pass

def port_scan(ip):
    print(f"\n[+] Starting port scan on {ip}")
    open_ports = []
    for port in COMMON_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            try:
                s.connect((ip, port))
                print(f"[+] Port {port} is open.")
                open_ports.append(port)
            except:
                continue
    if not open_ports:
        print("[+] No common ports open.")
    return open_ports

def extract_ip_or_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    except:
        return url

def main():
    parser = argparse.ArgumentParser(description="VulnFinder - Lightweight Vulnerability Assessment Tool")
    parser.add_argument("target", help="Target URL or IP address")
    args = parser.parse_args()

    print(BANNER)

    target = args.target
    if not target.startswith("http"):
        target = "http://" + target

    domain = extract_ip_or_domain(target)
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"[!] Could not resolve {domain}")
        return

    check_url_headers(target)
    port_scan(ip)

if __name__ == "__main__":
    main()
