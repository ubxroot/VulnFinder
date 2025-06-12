# VulnFinder

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-yellow.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/ubxroot/vulnfinder)

**VulnFinder** is a powerful Python-based vulnerability assessment tool developed for offensive and defensive cybersecurity operations. It performs local system and binary scans, cross-checks known CVEs, and produces actionable reports.

---

## 🛡️ Features

### 🔍 Local Vulnerability Scanning
* Scans installed packages and software for known CVEs.
* OS fingerprinting and kernel version check.
* Cross-platform support: Linux, Windows, macOS.

### ⚙️ Binary Vulnerability Analysis
* Extracts hashes (MD5, SHA1, SHA256) of executables.
* Checks binaries against:
  * NVD CVE feeds
  * VirusTotal (optional API key)
  * YARA rules and heuristics

### 📦 Software Inventory & Misconfigurations
* Detects weak permissions, outdated packages, open services.
* Checks for dangerous SUID binaries on Linux.

### 🧠 Threat Intelligence Enrichment
* Enriches detected indicators using:
  * CVE NVD database (offline/online)
  * ExploitDB search
  * Custom threat feeds

### 📊 Reporting Engine
* Generates detailed reports in JSON, table, or markdown format.
* Severity classification for findings.
* Export to CSV or PDF (optional CLI flag).

---

## 🚀 Installation

```bash
git clone https://github.com/ubxroot/vulnfinder.git
cd vulnfinder
pip install -r requirements.txt
```

## ⚙️ Usage
# 📌 Examples

```bash
python3 vulnfinder.py https://example.com
python3 vulnfinder.py 192.168.1.1
python3 vulnfinder.py targetsite.com
```

## 📁 Configuration
# Customize the config.yaml file for:
* Threat intelligence APIs
* Output format and location
* CVE feed preferences

## 📝 License
MIT License.
