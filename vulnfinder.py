#!/usr/bin/env python3

import argparse # This import is technically not needed anymore but kept for minimal change
import requests
import socket
import re
import threading
from urllib.parse import urlparse, quote_plus
from queue import Queue # For managing tasks in threads
import json # For handling JSON responses from APIs
import sys # For platform specific handling (e.g. crt.sh API)

import pyfiglet
from rich.console import Console
from rich.table import Table
from rich.text import Text

# Initialize the Typer application and Console for rich output
# This line is placed at the top to ensure 'app' is defined globally
app = typer.Typer(help="VulnFinder - Comprehensive Web Vulnerability & Reconnaissance Tool")
console = Console()

# ANSI escape codes for colors
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# --- Custom Banner Definition ---
UBXROOT_PART = pyfiglet.figlet_format("UBXROOT", font="slant")
BANNER = f"""{RED}{UBXROOT_PART}
VulnFinder - Comprehensive Web Vulnerability & Reconnaissance Tool
github python3 scripted
{RESET}"""

# --- Common data for scans ---
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]
# Expanded list of common/sensitive paths
COMMON_PATHS = [
    '/admin', '/login', '/config', '/setup', '/dashboard', '/panel',
    '/phpmyadmin', '/wp-admin', '/user', '/backup', '/.git/config',
    '/phpinfo.php', '/.env', '/robots.txt', '/sitemap.xml', '/crossdomain.xml'
]

# --- Global lists for findings and tasks ---
all_findings = []
http_check_queue = Queue()
port_scan_results = []
findings_lock = threading.Lock() # Lock to safely add findings from multiple threads

# --- Vulnerability Check Definitions ---
# Each check is a dictionary defining its type, severity, description, and remediation.
VULNERABILITY_CHECKS = [
    # HTTP Header Checks
    {"type": "security_header_missing_hsts", "severity": "Medium", "description": "Missing Strict-Transport-Security (HSTS) header. HTTPS might not be enforced.", "remediation": "Implement HSTS header to enforce HTTPS-only connections: `Strict-Transport-Security: max-age=31536000; includeSubDomains`."},
    {"type": "security_header_missing_xfo", "severity": "Medium", "description": "Missing X-Frame-Options header. Site might be vulnerable to Clickjacking.", "remediation": "Implement X-Frame-Options header to prevent embedding: `X-Frame-Options: DENY` or `SAMEORIGIN`."},
    {"type": "security_header_missing_xcto", "severity": "Medium", "description": "Missing X-Content-Type-Options header. Browser might perform MIME sniffing, leading to XSS.", "remediation": "Implement X-Content-Type-Options header: `X-Content-Type-Options: nosniff`."},
    {"type": "security_header_missing_csp", "severity": "High", "description": "Missing Content-Security-Policy (CSP) header. Site might be vulnerable to various attacks like XSS, data injection.", "remediation": "Implement a strong Content-Security-Policy header to restrict content sources."},
    {"type": "server_info_disclosure", "severity": "Low", "description": "Server header discloses detailed server software and version, aiding attackers.", "remediation": "Configure web server to suppress or generalize the 'Server' header information."},
    {"type": "directory_listing_enabled", "severity": "Medium", "description": "Directory listing is enabled, potentially exposing sensitive files.", "remediation": "Disable directory listing on the web server (e.g., Options -Indexes in Apache)."},
    {"type": "sensitive_file_exposure", "severity": "High", "description": "Sensitive configuration or info file (e.g., .git, phpinfo.php, .env) is exposed.", "remediation": "Remove or properly restrict access to sensitive files and directories."},

    # Web Application Checks
    {"type": "reflected_xss_potential", "severity": "High", "description": "Potential reflected XSS detected. Input from URL parameter is echoed without proper sanitization.", "remediation": "Implement rigorous input validation and output encoding for all user-supplied data."},
    {"type": "open_redirect_potential", "severity": "Medium", "description": "Potential open redirect vulnerability. User input can redirect to arbitrary URLs.", "remediation": "Validate and whitelist all redirection targets. Avoid using untrusted input in redirection logic."},
    {"type": "robots_txt_disallowed_paths", "severity": "Low", "description": "Robots.txt lists disallowed paths, potentially indicating sensitive directories.", "remediation": "Review sensitive disallowed paths. Ensure they are properly secured and not publicly accessible."},
]

# --- Core Scanner Functions ---

def fetch_url(url, timeout=5):
    """Helper to fetch a URL and return response or None on error."""
    try:
        return requests.get(url, timeout=timeout, allow_redirects=False) # allow_redirects=False for open redirect check
    except requests.exceptions.RequestException:
        return None

def check_security_headers(target, response):
    """Checks for common missing security headers."""
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    # HSTS
    if "strict-transport-security" not in headers:
        with findings_lock:
            all_findings.append({
                "type": "security_header_missing_hsts",
                "severity": "Medium",
                "target_url": target,
                "description": "Missing Strict-Transport-Security (HSTS) header. HTTPS might not be enforced.",
                "remediation": "Implement HSTS header to enforce HTTPS-only connections: `Strict-Transport-Security: max-age=31536000; includeSubDomains`."
            })
    
    # X-Frame-Options
    if "x-frame-options" not in headers:
        with findings_lock:
            all_findings.append({
                "type": "security_header_missing_xfo",
                "severity": "Medium",
                "target_url": target,
                "description": "Missing X-Frame-Options header. Site might be vulnerable to Clickjacking.",
                "remediation": "Implement X-Frame-Options header to prevent embedding: `X-Frame-Options: DENY` or `SAMEORIGIN`."
            })
            
    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        with findings_lock:
            all_findings.append({
                "type": "security_header_missing_xcto",
                "severity": "Medium",
                "target_url": target,
                "description": "Missing X-Content-Type-Options header. Browser might perform MIME sniffing, leading to XSS.",
                "remediation": "Implement X-Content-Type-Options header: `X-Content-Type-Options: nosniff`."
            })

    # Content-Security-Policy
    if "content-security-policy" not in headers:
        with findings_lock:
            all_findings.append({
                "type": "security_header_missing_csp",
                "severity": "High",
                "target_url": target,
                "description": "Missing Content-Security-Policy (CSP) header. Site might be vulnerable to various attacks like XSS, data injection.",
                "remediation": "Implement a strong Content-Security-Policy header to restrict content sources."
            })

    # Server Information Disclosure
    server = headers.get("server", "")
    if server:
        with findings_lock:
            all_findings.append({
                "type": "server_info_disclosure",
                "severity": "Low",
                "target_url": target,
                "description": f"Server header discloses detailed server software and version: {server}",
                "remediation": "Configure web server to suppress or generalize the 'Server' header information."
            })

    # Directory Listing
    if "Index of /" in response.text and response.status_code == 200:
        with findings_lock:
            all_findings.append({
                "type": "directory_listing_enabled",
                "severity": "Medium",
                "target_url": target,
                "description": "Directory listing is enabled on the root, potentially exposing sensitive files.",
                "remediation": "Disable directory listing on the web server (e.g., Options -Indexes in Apache, autoindex off in Nginx)."
            })

def check_sensitive_paths_scan(base_url):
    """Scans for commonly exposed sensitive paths."""
    for path in COMMON_PATHS:
        full_url = base_url.rstrip("/") + path
        response = fetch_url(full_url)
        if response and response.status_code == 200:
            description = f"Path '{path}' found."
            if "Index of" in response.text:
                description = f"Exposed directory '{path}' found."
            
            with findings_lock:
                all_findings.append({
                    "type": "sensitive_file_exposure",
                    "severity": "High",
                    "target_url": full_url,
                    "description": description,
                    "remediation": "Remove or properly restrict access to sensitive files and directories."
                })

def check_robots_txt(base_url):
    """Fetches and parses robots.txt for disallowed paths."""
    robots_url = base_url.rstrip('/') + '/robots.txt'
    response = fetch_url(robots_url)
    if response and response.status_code == 200:
        disallowed_paths = re.findall(r"Disallow:\s*(.*)", response.text, re.IGNORECASE)
        for path in disallowed_paths:
            if path.strip() and path.strip() != '/': # Ignore empty paths and root disallow
                full_path_url = base_url.rstrip('/') + path.strip()
                with findings_lock:
                    all_findings.append({
                        "type": "robots_txt_disallowed_paths",
                        "severity": "Low",
                        "target_url": full_path_url,
                        "description": f"Robots.txt indicates disallowed path: '{path.strip()}'. This might be a sensitive area.",
                        "remediation": "Ensure all disallowed paths are properly secured and not publicly accessible. Use robots.txt for crawl control, not security."
                    })

def check_reflected_xss(base_url):
    """A very basic check for reflected XSS in URL parameters."""
    test_payload = "<script>alert(1)</script>"
    # Try injecting into a common parameter if available, or just append
    test_url = f"{base_url}?q={quote_plus(test_payload)}" # Example with 'q' param
    
    response = fetch_url(test_url)
    if response and test_payload in response.text:
        # A more robust check would verify if the script actually executes in a headless browser.
        # This is a simple string reflection check.
        with findings_lock:
            all_findings.append({
                "type": "reflected_xss_potential",
                "severity": "High",
                "target_url": test_url,
                "description": f"Potential reflected XSS detected. Payload '{test_payload}' reflected in response.",
                "remediation": "Implement rigorous input validation and output encoding for all user-supplied data (e.g., HTML entity encoding, URL encoding)."
            })

def check_open_redirect(base_url):
    """A basic check for open redirect vulnerability."""
    redirect_target = "http://evil.com/"
    # Common redirect parameters
    redirect_params = ["next", "redirect", "url", "continue", "target", "dest"]
    
    for param in redirect_params:
        test_url = f"{base_url}?{param}={quote_plus(redirect_target)}"
        response = fetch_url(test_url)
        # Check if the response actually redirects to the external site
        if response and response.status_code in [301, 302, 303, 307, 308] and \
           response.headers.get("Location") and redirect_target in response.headers["Location"]:
            with findings_lock:
                all_findings.append({
                    "type": "open_redirect_potential",
                    "severity": "Medium",
                    "target_url": test_url,
                    "description": f"Potential Open Redirect vulnerability detected via parameter '{param}'. Redirects to {redirect_target}.",
                    "remediation": "Validate and whitelist all redirection targets. Avoid using untrusted input in redirection logic. Use safe redirect mechanisms."
                })
            return # Only need to find one


def passive_subdomain_discovery(domain_or_ip):
    """
    Performs passive subdomain discovery using crt.sh certificate transparency logs.
    Note: Requires an internet connection and direct access to crt.sh API.
    """
    console.print(f"\n{CYAN}[+] Performing passive subdomain discovery for {domain_or_ip}...{RESET}")
    # crt.sh API for certificate transparency logs
    crtsh_url = f"https://crt.sh/?q=%25.{domain_or_ip}&output=json"
    
    try:
        response = requests.get(crtsh_url, timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors
        certs = response.json()
        
        found_subdomains = set()
        for entry in certs:
            # Common Name (CN)
            if 'common_name' in entry:
                found_subdomains.add(entry['common_name'].lower())
            # Subject Alternative Names (SANs)
            if 'name_value' in entry:
                # name_value can be a comma-separated list
                for name in entry['name_value'].split(','):
                    name = name.strip()
                    # Only add if it's a subdomain of the target or the target itself
                    if name.endswith(domain_or_ip) and name != domain_or_ip:
                         found_subdomains.add(name.lower())
        
        if found_subdomains:
            console.print(f"{GREEN}[+] Found {len(found_subdomains)} potential subdomains:{RESET}")
            for sd in sorted(list(found_subdomains)):
                console.print(f"    - {sd}")
        else:
            console.print("[+] No additional subdomains found via crt.sh for this target.", style="green")

    except requests.exceptions.RequestException as e:
        console.print(f"{RED}[!] Error during subdomain discovery (crt.sh): {e}{RESET}")
    except json.JSONDecodeError:
        console.print(f"{RED}[!] Error parsing crt.sh response. Invalid JSON received.{RESET}")
    except Exception as e:
        console.print(f"{RED}[!] An unexpected error occurred during subdomain discovery: {e}{RESET}")

# --- Threading / Worker Functions ---

def http_worker(task_queue):
    """Worker function for executing HTTP-based checks from the queue."""
    while True:
        task = task_queue.get()
        if task is None: # Sentinel value to signal termination
            break
        
        check_type, args, kwargs = task
        try:
            if check_type == "headers":
                target_url, response = args
                check_security_headers(target_url, response)
            elif check_type == "common_paths":
                base_url, = args
                check_sensitive_paths_scan(base_url)
            elif check_type == "robots.txt":
                base_url, = args
                check_robots_txt(base_url)
            elif check_type == "xss":
                base_url, = args
                check_reflected_xss(base_url)
            elif check_type == "open_redirect":
                base_url, = args
                check_open_redirect(base_url)
            # Add more check types as needed
        except Exception as e:
            console.print(f"{RED}[!] Error executing HTTP check {check_type}: {e}{RESET}")
        finally:
            task_queue.task_done()

def port_scan_single_port(ip, port):
    """Scans a single port and adds to global results if open."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            with findings_lock: # Use lock to safely append to shared list
                port_scan_results.append(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            # These are expected errors for closed/filtered ports, so no print or error handling
            pass
        except Exception as e:
            # Catch unexpected errors during port scan
            sys.stderr.write(f"{RED}[!] Error scanning port {port}: {e}{RESET}\n")


# --- Main execution flow ---
def extract_domain_from_url(url):
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


@app.command() # Decorate main to make it a Typer command
def main(target: str = typer.Argument(..., help="Target URL (e.g., http://example.com) or IP address (e.g., 192.168.1.1)")):
    """
    Main function to parse command-line arguments and orchestrate the vulnerability assessment.
    """
    # Display the custom banner at the very beginning of the script's execution
    print(BANNER)

    target_url_input = target # Use the target argument directly from Typer
    # Ensure the target URL has a scheme for requests.get to work correctly
    if not target_url_input.startswith("http://") and not target_url_input.startswith("https://"):
        target_url = "http://" + target_url_input
    else:
        target_url = target_url_input

    domain_or_ip = extract_domain_from_url(target_url)
    
    # Resolve domain to IP for port scanning (if it's a domain)
    ip_address = None
    try:
        ip_address = socket.gethostbyname(domain_or_ip)
        console.print(f"{CYAN}[+] Target resolved: Domain=[/][white]{domain_or_ip}[/][CYAN], IP=[/][white]{ip_address}{RESET}")
    except socket.gaierror:
        console.print(f"{RED}[!] Could not resolve {domain_or_ip}. Please ensure it's correct and reachable.{RESET}")
        return
    except Exception as e:
        console.print(f"{RED}[!] An unexpected error occurred during domain resolution: {e}{RESET}")
        return

    # --- HTTP-based Checks (threaded) ---
    console.print(f"\n{CYAN}[+] Starting HTTP-based vulnerability checks...{RESET}")
    num_worker_threads = 5 # Number of concurrent threads for HTTP checks
    
    # Create worker threads
    workers = []
    for _ in range(num_worker_threads):
        worker = threading.Thread(target=http_worker, args=(http_check_queue,))
        worker.daemon = True # Allows main program to exit even if threads are blocked
        worker.start()
        workers.append(worker)

    # Initial HTTP GET to get response for header checks and potential redirects
    initial_response = fetch_url(target_url)
    if initial_response:
        http_check_queue.put(("headers", (target_url, initial_response), {}))
    else:
        console.print(f"{RED}[!] Could not get initial HTTP response from {target_url}. Skipping HTTP checks.{RESET}")
        # Put sentinels to terminate workers if initial fetch failed
        for _ in range(num_worker_threads):
            http_check_queue.put(None)
        for worker in workers:
            worker.join()
        # No need for the "pass" here, as the return handles the exit
        return # Exit if initial HTTP response failed

    # Add other HTTP-based tasks to the queue
    http_check_queue.put(("common_paths", (target_url,), {}))
    http_check_queue.put(("robots.txt", (target_url,), {}))
    http_check_queue.put(("xss", (target_url,), {}))
    http_check_queue.put(("open_redirect", (target_url,), {}))
    
    # Wait for all HTTP checks to complete
    http_check_queue.join()
    # Signal workers to terminate
    for _ in range(num_worker_threads):
        http_check_queue.put(None)
    for worker in workers:
        worker.join()


    # --- Port Scan (threaded) ---
    console.print(f"\n{CYAN}[+] Starting port scan on {ip_address}...{RESET}")
    port_scan_threads = []
    for port in COMMON_PORTS:
        t = threading.Thread(target=port_scan_single_port, args=(ip_address, port))
        t.start()
        port_scan_threads.append(t)

    for t in port_scan_threads:
        t.join() # Wait for all port scan threads to complete

    if port_scan_results:
        console.print(f"{GREEN}[+] Found {len(port_scan_results)} open common ports: {sorted(port_scan_results)}{RESET}")
    else:
        console.print("[+] No common ports open.", style="green")

    # --- Passive Reconnaissance ---
    passive_subdomain_discovery(domain_or_ip)


    # --- Display All Findings in a Table ---
    console.print(f"\n{YELLOW}--- Consolidated Scan Results ---{RESET}")
    if all_findings:
        table = Table(title="Vulnerability Findings", show_header=True, header_style="bold magenta")
        table.add_column("Type", style="bold green", min_width=15)
        table.add_column("Severity", style="bold blue", min_width=10)
        table.add_column("Target/URL", style="cyan", min_width=20)
        table.add_column("Description", style="white", min_width=30)
        table.add_column("Remediation", style="yellow", min_width=40)

        # Sort findings by severity (High > Medium > Low)
        severity_order = {"High": 3, "Medium": 2, "Low": 1}
        sorted_findings = sorted(all_findings, key=lambda x: severity_order.get(x.get("severity"), 0), reverse=True)

        for finding in sorted_findings:
            table.add_row(
                finding.get("type", "N/A").replace('_', ' ').title(),
                finding.get("severity", "N/A"),
                finding.get("target_url", "N/A"),
                finding.get("description", "N/A"),
                finding.get("remediation", "No specific remedy provided.")
            )
        console.print(table)
    else:
        console.print(f"\n{GREEN}[+] No specific web vulnerabilities or sensitive paths identified. Good job!{RESET}")

    console.print(f"\n{GREEN}[+] VulnFinder scan complete. Review results above.{RESET}")


if __name__ == "__main__":
    app()

