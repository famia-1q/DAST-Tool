# 🛡️ Unified DAST & Binary Analysis Tool (myESI)

A comprehensive, "One Hood, One Click" security scanning orchestrator designed to meet **National CERT SSDLC Advisory** requirements for runtime and binary-level security validation.

## 🚀 What It Does
This tool automatically classifies your input and runs the appropriate enterprise-grade security engines sequentially, ensuring layered security coverage without manual intervention.

- **Web Applications (URLs):** Runs **OWASP ZAP** (App layer) → **Nikto** (Server layer).
- **Mobile Apps (.apk / .ipa):** Runs **MobSF** (Mobile Security Framework).
- **Windows Executables (.exe):** Runs **pefile** (Metadata) → **Manalyze** (Deep Inspection) → **YARA** (Pattern Matching).
- **Linux Packages (.deb):** Runs **dpkg-deb** (Extraction) → **LIEF** (ELF Analysis) → **checksec** (Security Features) → **YARA**.

## 🔒 Zero-Trust Privacy Guarantee
To protect proprietary code and comply with strict data privacy mandates, **all submitted binaries are immediately and permanently deleted** from the scanning environment the moment the analysis is complete. No binary data is ever persisted.

## 🛠️ Prerequisites
- Linux Environment (e.g., Kali Linux, Ubuntu)
- Docker installed and running
- Python 3.x

## 💻 How to Use (One-Click Execution)

1. Clone the repository:
   ```bash
   git clone https://github.com/famia-1q/DAST-Tool.git
   cd DAST-Tool
