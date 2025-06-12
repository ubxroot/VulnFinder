#!/usr/bin/env python3

import argparse
import requests
import socket
import re
import threading
from urllib.parse import urlparse

RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

BANNER = RED + r"""
 _    _ _ ____  __     __ ____  ____  _____ ____  _____ 
| |  | | |  _ \ \ \   / /|  _ \|  _ \| ____|  _ \| ____|
| |  | | | |_) | \ \ / / | |_) | | | |  _| | |_) |  _|  
| |__| | |  _ <   \ V /  |  _ <| |_| | |___|  _ <| |___ 
 \____/|_|_| \_\   \_/   |_| \_\____/|_____|_| \_\_____|
                                               
""" + RESET

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]
COMMON_PATHS = ['/admin', '/login', '/config', '/setup', '/server-status', '/phpinfo.php', '/.env', '/robots.txt']

def check_url_headers(target):
    try:
        print(f"\n{CYAN}[+] Checking HTTP headers...{RESET}")
        response = requests.get(target, timeout=5)
        for k, v in response.headers.items():
            print(f"    {k}: {v}")

        server = response.headers.get("Server", "")
        if server:
            print(f"{GREEN}[!] Server Info: {server}{RESET}")
            if re.search(r'apache/2\.2|nginx/1\.1', server.lower()):
                print(f"{RED}[!] Potentially outdated server version.{RESET}")
        
        if "Index of /" in response.text:
            print(f"{RED}[!] Directory listing is enabled.{RESET}")

        for sensitive_path in ['/.git/', '/phpinfo.php', '/.env']:
            check_sensitive_path(target, sensitive_path)

    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] Connection Error: {e}{RESET}")

def check_sensitive_path(base_url, path):
    try:
        url = base_url.rstrip('/') + path
        res = requests.get(url, timeout=3)
        if res.status_code == 200 and "Index of" in res.text:
            print(f"{RED}[!] Exposed Directory Found: {url}{RESET}")
        elif res.status_code == 200:
            print(f"{RED}[!] Sensitive File Found: {url}{RESET}")
    except:
        pass

def scan_common_paths(base_url):
    print(f"\n{CYAN}[+] Scanning common URL paths...{RESET}")
    for path in COMMON_PATHS:
        full_url = base_url.rstrip("/") + path
        try:
            res = requests.get(full_url, timeout=3)
            if res.status_code == 200:
                print(f"{RED}[!] Possible sensitive endpoint: {full_url}{RESET}")
        except:
            continue

def port_scan(ip):
    print(f"\n{CYAN}[+] Scanning ports on {ip}...{RESET}")
    open_ports = []

    def scan(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            try:
                s.connect((ip, port))
                print(f"{GREEN}[+] Port {port} is open.{RESET}")
                open_ports.append(port)
            except:
                pass

    threads = []
    for port in COMMON_PORTS:
        t = threading.Thread(target=scan, args=(port,))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not open_ports:
        print("[+] No common ports open.")
    return open_ports

def extract_domain(url):
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

    domain = extract_domain(target)
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"{RED}[!] Could not resolve {domain}{RESET}")
        return

    check_url_headers(target)
    scan_common_paths(target)
    port_scan(ip)

if __name__ == "__main__":
    main()
