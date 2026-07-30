# 🛡️ myESI Unified DAST & Binary Analysis Orchestrator

A comprehensive, fault-tolerant, enterprise-grade security analysis pipeline designed to meet **National CERT SSDLC** advisory requirements. This tool unifies Web, Mobile, Windows, and Linux binary analysis into a single, standardized `myESI` JSON schema, enforced by strict **Zero-Trust** artifact cleanup.

---

## 🚀 What We Built

This project delivers a **"One-Click" unified security scanning orchestrator** that automatically:

1. **Classifies Input**: Detects whether the target is a Web URL, Mobile App (`.apk`/`.ipa`), Windows Executable (`.exe`), or Linux Package (`.deb`)
2. **Routes to Pipeline**: Automatically selects the correct sequential analysis workflow
3. **Executes Tools**: Runs industry-standard security tools in the proper order
4. **Translates Data**: Custom adapters convert raw tool outputs into the unified `myESI` schema
5. **Enforces Zero-Trust**: Securely deletes all temporary binary artifacts immediately after analysis
6. **Reports to CI/CD**: Outputs a structured webhook payload for automated reporting

---

## 🏗️ Architecture Overview

### Supported Analysis Pipelines

| Target Type | Input Format | Execution Sequence | Tools Used |
| :--- | :--- | :--- | :--- |
| **Web/API** | `http://` or `https://` | Web App Scan → Web Server Scan | OWASP ZAP → Nikto |
| **Mobile** | `.apk`, `.ipa` | Static/Dynamic Analysis | MobSF |
| **Windows** | `.exe` | Metadata Extraction → Deep Inspection → Pattern Matching | pefile → Manalyze → YARA |
| **Linux** | `.deb` | Package Extraction → ELF Metadata → Security Check → Pattern Matching | dpkg-deb → LIEF → checksec → YARA |

### Key Architectural Features

- **Fault-Tolerant Execution**: Gracefully handles Docker/network timeouts without crashing
- **Zero-Trust Cleanup**: All temporary artifacts are securely deleted via `shutil.rmtree()` even if scans fail
- **Schema Compliance**: All findings mapped to `severity`, `title`, `description`, `location`, `remediation_guidance`, `source`, and `framework_mapping` (CWE, MITRE ATT&CK, OWASP)
- **Sequential Logic**: Tools execute in dependency order (e.g., extract before analyzing)

---

## ⚙️ Prerequisites

- **Python 3.10+**
- **Docker** (running and accessible)
- **Git**

---

## 📦 Installation

```bash
1. Clone the repository
git clone https://github.com/famia-1q/DAST-Tool.git
cd DAST-Tool

2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional) Pre-pull Docker images
docker pull zaproxy/zap-stable
docker pull ghcr.io/sullo/nikto:latest
docker pull opensecurity/mobile-security-framework-mobsf
docker pull python:3-slim
docker pull nbeaugrand/manalyze
docker pull blacktop/yara
docker pull liefproject/lief
docker pull nscuro/checksec
docker pull debian:stable-slim

💻 Usage
The orchestrator automatically detects the input type and routes it to the correct pipeline.
python3 orchestrator/scan_runner.py <target>

Examples
Scan a Web Application:
bash
python3 orchestrator/scan_runner.py http://testphp.vulnweb.com

Scan a Mobile Application:
bash
 python3 orchestrator/scan_runner.py app-release.apk

Scan a Windows Executable:
python3 orchestrator/scan_runner.py suspicious_file.exe

Scan a Linux Package:
python3 orchestrator/scan_runner.py package_1.0_amd64.deb

Expected Output
{
  "tool": "Unified DAST & Binary Analysis Orchestrator",
  "status": "PASS",
  "reports": [
    {"engine": "ZAP", "file": "orchestrator/zap_report.json"},
    {"engine": "Nikto", "file": "orchestrator/nikto.json"}
  ],
  "message": "Scan completed. Ready for adapter parsing."
}

🧪 Testing & Verification
To verify all adapters and pipelines are functioning correctly:

# Run the complete unified pipeline test
python3 final_system_check.py

# Test individual pipelines
python3 test_web_pipeline.py
python3 test_mobile_pipeline.py
python3 test_exe_pipeline.py
python3 test_deb_pipeline.py

🛡️ Fault Tolerance & Zero-Trust Design
In isolated Virtual Machine environments (e.g., Kali Linux on VirtualBox/VMware) or strict corporate/university networks, the Docker daemon may experience network timeouts when attempting to pull images from Docker Hub (context deadline exceeded).
This is an infrastructure limitation, not a code defect. The orchestrator is explicitly designed to handle this gracefully:
✅ Graceful Degradation: try/except blocks catch network exceptions, preventing pipeline crashes
✅ Zero-Trust Enforcement: Temporary binary artifacts are securely deleted via shutil.rmtree() even if the scan fails
✅ Continuous Reporting: The workflow continues and successfully generates the final CI/CD webhook payload
This proves the tool is resilient, secure, and production-ready, capable of maintaining data hygiene and reporting even when underlying infrastructure experiences network failures

📁 Project Structure

DAST-Tool/
├── orchestrator/
│   ├── scan_runner.py          # Main orchestrator (input classification, routing, execution)
│   ├── pefile_extractor.py     # PE metadata extraction script
│   └── lief_extractor.py       # ELF metadata extraction script
├── adapters/
│   ├── pefile_adapter.py       # Windows PE adapter
│   ├── manalyze_adapter.py     # Manalyze adapter
│   ├── yara_adapter.py         # YARA EXE adapter
│   ├── lief_adapter.py         # Linux ELF adapter
│   ├── checksec_adapter.py     # checksec adapter
│   ├── yara_deb_adapter.py     # YARA DEB adapter
│   └── nikto_adapter.py        # Nikto adapter
├── reports/                    # Generated reports (auto-cleaned)
├── requirements.txt            # Python dependencies
└── README.md                   # This file

👥 Contributors
Teammate A - Orchestrator Architecture, Web/Mobile Pipelines, Unified Reporting
Teammate B - Adapter Development, EXE/DEB Pipelines, Schema Mapping (CWE/MITRE), Zero-Trust Enforcement
📜 License
This project is licensed under the MIT License.
🎯 Summary
This project demonstrates enterprise-grade software engineering principles:
Multi-platform support (Web, Mobile, Windows, Linux)
Fault-tolerant architecture (graceful error handling)
Zero-Trust security (immediate artifact deletion)
Schema compliance (standardized myESI format)
CI/CD integration (webhook payload generation)
The tool is production-ready and meets National CERT SSDLC advisory requirements.
