# 🛡️ iSeeWaves - Unified DAST & Binary Analysis Scanner

A multi-platform security testing tool designed to meet **National CERT SSDLC** advisory requirements. Automatically classifies inputs, routes them to specialized analysis pipelines, and enforces strict **Zero-Trust** artifact cleanup.

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)

---

## 🚀 Features

- **Multi-Platform Support**: Scan Web URLs, Mobile Apps (.apk/.ipa), Windows Executables (.exe), and Linux Packages (.deb)
- **Automated Classification**: Detects input type and routes to appropriate security engines
- **Industry-Standard Tools**: Integrates OWASP ZAP, Nikto, apktool, pefile, checksec, YARA, and LIEF
- **Zero-Trust Cleanup**: Securely deletes all temporary artifacts after analysis
- **No Hardcoded Secrets**: All credentials loaded via environment variables
- **Professional Reports**: Generates PDF reports with CWE, CVSS, and remediation guidance
- **Web Interface**: User-friendly Flask-based dashboard
- **CI/CD Ready**: Webhook support for automated pipelines

---

## 📋 Supported Analysis Pipelines

### 1. **Web/API Scanning** (URLs)
   - **Engines**: OWASP ZAP → Nikto
   - **Detects**: XSS, SQL Injection, Misconfigurations, Outdated Software

### 2. **Mobile App Analysis** (.apk/.ipa)
   - **Engines**: Apktool → Grep Analysis
   - **Detects**: Insecure Data Storage, Hardcoded Secrets, Missing Certificate Pinning

### 3. **Windows Executable Analysis** (.exe)
   - **Engines**: PEFile → Manalyze → YARA
   - **Detects**: Missing ASLR/DEP, Suspicious Imports, Malware Signatures

### 4. **Linux Package Analysis** (.deb)
   - **Engines**: dpkg-deb → LIEF → checksec → YARA
   - **Detects**: World-Writable Files, Missing PIE/RELRO, Binary Vulnerabilities

---

## ⚙️ Prerequisites

### System Requirements
- **Operating System**: Kali Linux (recommended) or any Debian-based distro
- **Python**: 3.10 or higher
- **Disk Space**: 2GB minimum
- **RAM**: 4GB recommended

### Required System Tools
```bash
# Update package list
sudo apt update

# Install security scanning tools
sudo apt install -y nikto zaproxy apktool checksec yara dpkg

# Optional: Install Manalyze for deep PE analysis
git clone https://github.com/rprater/Manalyze.git
cd Manalyze
cmake .
make
sudo make install

Python Dependencies
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt

📦 Installation
Quick Start (First-Time Setup)

# 1. Clone the repository
git clone https://github.com/famia-1q/DAST-Tool.git
cd DAST-Tool

# 2. Install system dependencies
sudo apt update
sudo apt install -y nikto zaproxy apktool checksec yara dpkg

# 3. Set up Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Run the application
python3 app.py

Access the Web Interface
Open your browser and navigate to:

http://localhost:5000

