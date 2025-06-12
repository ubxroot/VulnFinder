#!/usr/bin/env python3

import argparse
import requests
import socket
import re
import threading
from urllib.parse import urlparse
import pyfiglet # New import for the custom banner

# ANSI escape codes for colors
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m" # Resets color to default

# --- Custom Banner Definition ---
# Generates "UBXROOT" in a 'slant' font.
# The entire banner text is wrapped in RED for consistent coloring.
UBXROOT_PART = pyfiglet.figlet_format("UBXROOT", font="slant")

# The full banner including the dynamic UBXROOT part, tool name, and description.
# Note: The leading RED color ensures the entire multi-line string is red.
BANNER = f"""{RED}{UBXROOT_PART}
VulnFinder - Lightweight Vulnerability Assessment Tool
github python3 scripted
{RESET}""" # RESET at the end to ensure subsequent output isn't red unless intended

# --- Common data for scans ---
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]
COMMON_PATHS = ['/admin', '/login', '/config', '/setup', '/server-status', '/phpinfo.php', '/.env', '/robots.txt']

def check_url_headers(target):
    """
    Checks HTTP headers of the target URL for common security-related information
    and potential misconfigurations (e.g., directory listing, outdated server).
    """
    try:
        print(f"\n{CYAN}[+] Checking HTTP headers...{RESET}")
        response = requests.get(target, timeout=5)
        for k, v in response.headers.items():
            print(f"    {k}: {v}")

        server = response.headers.get("Server", "")
        if server:
            print(f"{GREEN}[!] Server Info: {server}{RESET}")
            # Regex to detect potentially outdated server versions (example: Apache 2.2, Nginx 1.x)
            if re.search(r'apache/2\.2|nginx/1\.1', server.lower()):
                print(f"{RED}[!] Potentially outdated server version.{RESET}")
        
        # Check if directory listing is enabled based on response text
        if "Index of /" in response.text:
            print(f"{RED}[!] Directory listing is enabled.{RESET}")

        # Check for sensitive paths that might not be in COMMON_PATHS but are common findings
        for sensitive_path in ['/.git/', '/phpinfo.php', '/.env']:
            check_sensitive_path(target, sensitive_path)

    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] Connection Error: {e}{RESET}")
    except Exception as e:
        print(f"{RED}[!] An unexpected error occurred during header check: {e}{RESET}")


def check_sensitive_path(base_url, path):
    """
    Attempts to access a specific sensitive path under the base URL
    and reports if it's found and potentially exposed.
    """
    try:
        url = base_url.rstrip('/') + path
        res = requests.get(url, timeout=3)
        if res.status_code == 200:
            if "Index of" in res.text:
                print(f"{RED}[!] Exposed Directory Found: {url}{RESET}")
            else:
                print(f"{RED}[!] Sensitive File Found (Status 200): {url}{RESET}")
    except requests.exceptions.RequestException:
        # Silently pass if there's a connection error or timeout for sensitive paths
        pass
    except Exception as e:
        print(f"{RED}[!] Error checking sensitive path {url}: {e}{RESET}")


def scan_common_paths(base_url):
    """
    Scans the target URL for common administrative or sensitive web paths.
    """
    print(f"\n{CYAN}[+] Scanning common URL paths...{RESET}")
    found_any = False
    for path in COMMON_PATHS:
        full_url = base_url.rstrip("/") + path
        try:
            res = requests.get(full_url, timeout=3)
            if res.status_code == 200:
                print(f"{RED}[!] Possible sensitive endpoint: {full_url}{RESET}")
                found_any = True
        except requests.exceptions.RequestException:
            # Ignore connection errors for common path scans
            continue
        except Exception as e:
            print(f"{RED}[!] Error scanning path {full_url}: {e}{RESET}")
    if not found_any:
        print(f"{GREEN}[+] No common sensitive paths found (or they returned non-200 status).{RESET}")


def port_scan(ip):
    """
    Performs a multi-threaded port scan on a list of common ports for the target IP address.
    """
    print(f"\n{CYAN}[+] Scanning common ports on {ip}...{RESET}")
    open_ports = []
    print_lock = threading.Lock() # To prevent messy output from concurrent threads

    def scan_single_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5) # Shorter timeout for faster scanning
            try:
                s.connect((ip, port))
                with print_lock: # Use lock to ensure clean printing
                    print(f"{GREEN}[+] Port {port} is open.{RESET}")
                open_ports.append(port)
            except (socket.timeout, ConnectionRefusedError, OSError):
                # These are expected errors for closed/filtered ports, so no print
                pass
            except Exception as e:
                with print_lock:
                    print(f"{RED}[!] Error scanning port {port}: {e}{RESET}")

    threads = []
    for port in COMMON_PORTS:
        t = threading.Thread(target=scan_single_port, args=(port,))
        threads.append(t)
        t.start() # Start the thread

    for t in threads:
        t.join() # Wait for all threads to complete

    if not open_ports:
        print("[+] No common ports open.")
    else:
        print(f"\n{GREEN}[+] Found {len(open_ports)} open common ports: {sorted(open_ports)}{RESET}")
    return open_ports


def extract_domain(url):
    """
    Extracts the network location (domain or IP) from a given URL.
    Handles cases where the URL might just be an IP address or hostname.
    """
    try:
        parsed = urlparse(url)
        # Returns netloc (e.g., example.com, 192.168.1.1) or path if no scheme/netloc (e.g., just "localhost")
        return parsed.netloc or parsed.path
    except:
        return url # Return original if parsing fails


def main():
    """
    Main function to parse command-line arguments and orchestrate the vulnerability assessment.
    """
    parser = argparse.ArgumentParser(description="VulnFinder - Lightweight Vulnerability Assessment Tool")
    parser.add_argument("target", help="Target URL (e.g., http://example.com) or IP address (e.g., 192.168.1.1)")
    args = parser.parse_args()

    # Display the custom banner at the very beginning of the script's execution
    print(BANNER)

    target = args.target
    # Ensure the target URL has a scheme for requests.get to work correctly
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    domain_or_ip = extract_domain(target)
    
    # Resolve domain to IP for port scanning (if it's a domain)
    try:
        ip_address = socket.gethostbyname(domain_or_ip)
        print(f"{CYAN}[+] Target IP resolved: {ip_address}{RESET}")
    except socket.gaierror:
        print(f"{RED}[!] Could not resolve domain or IP: {domain_or_ip}. Please ensure it's correct and reachable.{RESET}")
        return
    except Exception as e:
        print(f"{RED}[!] An unexpected error occurred during domain resolution: {e}{RESET}")
        return

    # --- Execute the vulnerability checks ---
    check_url_headers(target)
    scan_common_paths(target)
    port_scan(ip_address)

    print(f"\n{GREEN}[+] VulnFinder scan complete.{RESET}")


if __name__ == "__main__":
    main()

