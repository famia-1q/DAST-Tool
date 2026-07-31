
# 🛡️ myESI Unified DAST & Binary Analysis Orchestrator

A multi-platform security scanning tool designed to meet National CERT SSDLC advisory requirements. It automatically classifies inputs, routes them to specialized analysis pipelines, and enforces strict Zero-Trust artifact cleanup.

---

## 🚀 What This Tool Does

- **Auto-Classifies Inputs**: Detects if the target is a Web URL, Mobile App (.apk/.ipa), Windows Executable (.exe), or Linux Package (.deb).
- **Sequential Execution**: Runs industry-standard security tools in the correct dependency order.
- **Zero-Trust Cleanup**: Securely deletes all temporary binary artifacts immediately after analysis.
- **Fault Tolerant**: Handles Docker/network timeouts gracefully without crashing the pipeline.
- **Unified Schema**: Translates all findings into a standardized format mapped to CWE, MITRE ATT&CK, and OWASP.

---

## 🏗️ Supported Analysis Pipelines

1. **Web/API** (http:// or https://) → OWASP ZAP → Nikto
2. **Mobile** (.apk / .ipa) → MobSF Static/Dynamic Analysis
3. **Windows** (.exe) → pefile (Metadata) → Manalyze (Deep Inspection) → YARA (Pattern Matching)
4. **Linux** (.deb) → dpkg-deb (Extraction) → LIEF (ELF Metadata) → checksec (Security Features) → YARA

---

## ⚙️ Prerequisites

- Python 3.10+
- Docker (must be running and accessible)
- Git

---

## 📦 Installation

```bash
# 1. Clone the repository
git clone https://github.com/famia-1q/DAST-Tool.git
cd DAST-Tool

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt


💻 Usage
The orchestrator automatically detects the input type and routes it to the correct pipeline.
Basic Command: python3 orchestrator/scan_runner.py <target>

Examples:
# Scan a website
python3 orchestrator/scan_runner.py http://testphp.vulnweb.com

# Scan a mobile app
python3 orchestrator/scan_runner.py app-release.apk

# Scan a Windows executable
python3 orchestrator/scan_runner.py suspicious_file.exe

# Scan a Linux package
python3 orchestrator/scan_runner.py package_1.0_amd64.deb

What Happens:
The tool identifies the pipeline and prints the execution sequence.
It runs each tool, printing warnings if any fail (but continues running).
It securely deletes all temporary files (Zero-Trust).
It outputs a final JSON webhook payload ready for CI/CD integration.

👥 Contributors
Teammate A - Orchestrator Architecture, Web/Mobile Pipelines
Teammate B - Adapter Development, EXE/DEB Pipelines, Schema Mapping
📜 License
This project is licensed under the MIT License.
