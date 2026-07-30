
# 🛡️ myESI Unified DAST & Binary Analysis Tool

A professional, automated, "One Hood, One Click" security scanning pipeline designed to meet National CERT SSDLC compliance requirements. This tool seamlessly integrates web, API, and mobile binary scanning into a single, unified workflow with standardized reporting.

---

## 🚀 Core Objectives
- Unified Input: Accepts either a Web/API URL or a Mobile Binary (.apk/.ipa) and automatically routes it to the correct engine.
- Layered Security Coverage: Sequentially scans web targets with both OWASP ZAP (Application Logic) and Nikto (Server Configuration).
- Zero-Trust Privacy: Enforces strict data hygiene by using ephemeral Docker containers (--rm) and automatically deleting temporary binary files post-scan.
- Standardized Reporting: Translates heterogeneous tool outputs into a strict myESI Unified Schema, complete with source attribution and OWASP framework mapping.

---

## 🛠️ Architecture & Components

### 🧠 1. The Orchestrator (Engine & Infrastructure)
- Input Classification: Intelligently routes URLs to web scanners and .apk/.ipa files to mobile scanners.
- Sequential Execution: Runs OWASP ZAP first, followed immediately by Nikto, ensuring a clean, chronological audit trail.
- Docker Management: Spins up isolated, ephemeral containers for zaproxy/zap-stable, ghcr.io/sullo/nikto:latest, and opensecurity/mobile-security-framework-mobsf.
- Zero-Trust Cleanup: Utilizes shutil.rmtree() to securely wipe temporary mobile binaries from the host system immediately after analysis.

### 🛠️ 2. The Adapters (Translation & Schema Mapping)
- Unified Parsing: Custom Python adapters (parser.py, nikto_adapter.py) extract raw JSON and map it to the myESI schema (severity, title, description, location, remediation_guidance).
- Severity Normalization: Translates tool-specific scales (e.g., Nikto's 0-3 scale) into standard Low, Medium, High, and Critical ratings.
- Source Attribution: Hardcodes "Source" tags ("Source: OWASP ZAP", "Source: Nikto", "Source: MobSF") to every finding for full audit transparency.
- Framework Mapping: Web/API findings map to OWASP ASVS and CIS Benchmarks. Mobile findings map to OWASP MASVS.

### 📄 3. One-Click Reporting
- Utilizes the reportlab library to generate a professional, formatted PDF Audit Report containing an Executive Summary and a Detailed Findings Table.

---

##  Prerequisites
- OS: Linux (Kali Linux recommended) or macOS/Windows with WSL2.
- Docker: Installed and running.
- Python: Version 3.8 or higher.

---

## ⚙️ Installation & Setup

1. Clone the repository:
   git clone https://github.com/famia-1q/DAST-Tool.git
   cd DAST-Tool

2. Set up a Python Virtual Environment (Recommended):
   python3 -m venv venv
   source venv/bin/activate

3. Install required dependencies:
   pip install reportlab

4. Pull required Docker images:
   docker pull zaproxy/zap-stable
   docker pull ghcr.io/sullo/nikto:latest
   docker pull opensecurity/mobile-security-framework-mobsf

---

##  Usage & Testing

### 🌐 Test 1: Full Web/API Layered Scan (ZAP + Nikto)
Run the end-to-end merged pipeline test against a sample URL:
python3 test_final_merged.py
(This will sequentially run ZAP, then Nikto, combine the findings, and generate reports/FINAL_NATIONAL_CERT_REPORT.pdf)

### 📱 Test 2: Mobile Binary Scan (MobSF)
Run the dedicated mobile pipeline test:
python3 test_apk_pipeline.py
(This will simulate an .apk scan, enforce Zero-Trust deletion, and generate reports/MOBILE_AUDIT_REPORT.pdf)

---

## 📂 Project Structure

DAST-Tool/
├── adapters/
│   ├── parser.py              (ZAP & MobSF schema mapping)
│   ├── nikto_adapter.py       (Nikto schema mapping & severity normalization)
│   └── report_generator.py    (PDF generation logic)
├── orchestrator/
│   └── scan_runner.py         (Input classification, Docker execution, Zero-Trust cleanup)
├── reports/
│   ├── FINAL_NATIONAL_CERT_REPORT.pdf  (Generated web/server report)
│   └── MOBILE_AUDIT_REPORT.pdf         (Generated mobile report)
├── test_final_merged.py       (End-to-end Web/API pipeline test)
├── test_apk_pipeline.py       (End-to-end Mobile pipeline test)
└── README.md                  (This file)

---

## 🔮 Future Work (Deferred)
- Desktop Binary Analysis (.exe / .deb): Currently deferred to maintain pipeline stability. Future iterations will integrate open-source, JSON-capable tools like ClamAV (signature-based malware scanning) or Trivy (CVE vulnerability matching) to handle compiled desktop artifacts without requiring source code.

---

##  Contributors
- Teammate A: Orchestrator, Docker Infrastructure, Zero-Trust Enforcement.
- Teammate B: Adapter Development, Unified Schema Mapping, Framework Compliance, PDF Reporting, and End-to-End Pipeline Testing.

---
Built in compliance with National CERT SSDLC mandates and OWASP security standards.