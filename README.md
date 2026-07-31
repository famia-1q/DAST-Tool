# myESI Unified DAST & Binary Analysis Orchestrator
A multi-platform security scanning tool designed to meet **National CERT SSDLC** advisory requirements. It automatically classifies inputs, routes them to specialized analysis pipelines, and enforces strict **Zero-Trust** artifact cleanup.

---

## 🚀 What This Tool Does

- **Auto-Classifies Inputs**: Detects if the target is a Web URL, Mobile App (.apk/.ipa), Windows Executable (.exe), or Linux Package (.deb).
- **Sequential Execution**: Runs industry-standard security tools in the correct dependency order.
- **Zero-Trust Cleanup**: Securely deletes all temporary binary artifacts immediately after analysis.
- **Fault Tolerant**: Handles Docker/network timeouts gracefully without crashing the pipeline.
- **Unified Schema**: Translates all findings into a standardized format mapped to CWE, MITRE ATT&CK, and OWASP.

---

## 🏗️ Supported Analysis Pipelines

1. **Web/API** (http:// or https://) -> OWASP ZAP -> Nikto
2. **Mobile** (.apk / .ipa) -> MobSF Static/Dynamic Analysis
3. **Windows** (.exe) -> pefile (Metadata) -> Manalyze (Deep Inspection) -> YARA (Pattern Matching)
4. **Linux** (.deb) -> dpkg-deb (Extraction) -> LIEF (ELF Metadata) -> checksec (Security Features) -> YARA

---

## ⚙️ Prerequisites

- Python 3.10+
- Docker (must be running and accessible)
- Git

---

## 📦 Installation

```bash
git clone https://github.com/famia-1q/DAST-Tool.git
cd DAST-Tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

💻 Usage
The orchestrator automatically detects the input type and routes it to the correct pipeline.
Basic Command:  python3 orchestrator/scan_runner.py <target>

Examples:  python3 orchestrator/scan_runner.py http://testphp.vulnweb.com
python3 orchestrator/scan_runner.py demo_app.apk
python3 orchestrator/scan_runner.py suspicious_file.exe
python3 orchestrator/scan_runner.py package_1.0_amd64.deb

👥 Contributors
Teammate A - Orchestrator Architecture, Web/Mobile Pipelines
Teammate B - Adapter Development, EXE/DEB Pipelines, Schema Mapping
📜 License
This project is licensed under the MIT License.

