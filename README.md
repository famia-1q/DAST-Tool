# 🛡️ myESI Unified DAST & Binary Analysis Orchestrator

## What This Tool Does

This is a **multi-platform security scanner** that automatically:
- Detects what type of target you're scanning (Web URL, Mobile App, Windows EXE, or Linux DEB)
- Routes it to the correct analysis pipeline
- Runs multiple security tools in sequence
- Cleans up all temporary files securely (Zero-Trust)
- Outputs a unified report for CI/CD integration

## What We Built

### 4 Analysis Pipelines:

1. **Web/API** → Runs OWASP ZAP, then Nikto
2. **Mobile (.apk/.ipa)** → Runs MobSF
3. **Windows (.exe)** → Runs pefile, Manalyze, then YARA
4. **Linux (.deb)** → Extracts with dpkg-deb, runs LIEF, checksec, then YARA

### Key Features:
- **Automatic Input Classification** - Just give it a URL or file, it figures out what to do
- **Sequential Execution** - Tools run in the right order (extract → analyze → pattern match)
- **Zero-Trust Cleanup** - All temp files deleted immediately after scanning
- **Fault Tolerant** - Handles Docker/network errors gracefully without crashing
- **Unified Schema** - All findings mapped to CWE, MITRE ATT&CK, OWASP standards

## How to Use This Tool

### Installation:
bash
git clone https://github.com/famia-1q/DAST-Tool.git
cd DAST-Tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Basic Command:
python3 orchestrator/scan_runner.py <your-target>

Examples:
Scan a website: python3 orchestrator/scan_runner.py http://example.com

Scan a mobile app: python3 orchestrator/scan_runner.py app.apk

Scan a Windows executable: python3 orchestrator/scan_runner.py malware.exe

Scan a Linux package: python3 orchestrator/scan_runner.py package.deb

What Happens:
The tool will:
Show you which pipeline it's running
Execute each tool in sequence
Print warnings if any tool fails (but keeps going)
Delete all temp files
Output a JSON webhook payload with the results

Testing: python3 final_system_check.py

Requirements
Python 3.10+
Docker (must be running)
Git
Contributors
Teammate A - Orchestrator, Web/Mobile pipelines
Teammate B - Adapters, EXE/DEB pipelines, schema mapping


