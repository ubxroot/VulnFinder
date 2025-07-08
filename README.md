# VulnFinder

**Created by [UBXROOT](https://github.com/ubxroot)**

---

VulnFinder is a powerful, open-source Python-based vulnerability assessment tool designed for both offensive and defensive cybersecurity operations. Built for professionals, researchers, and enthusiasts, VulnFinder provides comprehensive scanning, threat intelligence enrichment, and actionable reporting—all using only free APIs and open-source resources.

## 🚀 Features
- **Local Vulnerability Scanning**: Detects OS, kernel, and package vulnerabilities; SUID binaries; misconfigurations.
- **Binary Analysis**: Extracts hashes, checks against NVD CVEs, VirusTotal (free tier), and YARA rules.
- **Web & IP Scanning**: Scans websites for common vulnerabilities (headers, XSS, open redirect, sensitive files, subdomains) and IPs for open ports, services, and OS fingerprinting.
- **Threat Intelligence**: Enriches findings with CVE/NVD, ExploitDB, and custom threat feeds.
- **Reporting Engine**: Generates reports in JSON, table, markdown, CSV, and PDF formats.
- **Compliance Checks**: Maps findings to standards like OWASP Top 10, PCI-DSS, and HIPAA.
- **Performance & Automation**: Multi-threaded, scriptable, and ready for CI/CD and SIEM/SOAR integration.
- **User-Friendly CLI**: Intuitive, colorful, and fully documented command-line interface.

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ubxroot/vulnfinder.git
   cd vulnfinder
   ```
2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
3. **(Optional) Install YARA and nmap for advanced features:**
   - Linux: `sudo apt install yara nmap`
   - macOS: `brew install yara nmap`
   - Windows: Download binaries from official sites.

## 🛠️ Usage

Run the main tool from the `vulnfinder` directory:
```bash
python vulnfinder.py --help
```

### Example Commands
- Local system scan:
  ```bash
  python vulnfinder.py local-scan
  ```
- Binary analysis:
  ```bash
  python vulnfinder.py binary-scan /path/to/binary
  ```
- Web scan:
  ```bash
  python vulnfinder.py web-scan https://example.com
  ```
- IP scan:
  ```bash
  python vulnfinder.py ip-scan 192.168.1.1
  ```
- Threat intelligence enrichment:
  ```bash
  python vulnfinder.py threat-intel indicator_value
  ```
- Generate a report:
  ```bash
  python vulnfinder.py report --format markdown
  ```

## 🤝 Contributing
Contributions are welcome! Please open issues or pull requests for new features, bug fixes, or improvements. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License
This project is licensed under the [MIT License](LICENSE).

---

> VulnFinder is developed and maintained by **UBXROOT**. For professional services, custom integrations, or support, contact [UBXROOT on GitHub](https://github.com/ubxroot). 
