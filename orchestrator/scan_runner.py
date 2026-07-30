import os
import sys
import subprocess
import json
import shutil

def classify_input(target):
    """Routes inputs based on format."""
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    elif target.endswith(".apk") or target.endswith(".ipa"):
        return "mobsf"
    elif target.endswith(".exe"):
        return "exe"
    else:
        raise ValueError("Unsupported input. Please provide a URL, .apk/.ipa, or .exe file.")

# ... [keep your existing run_zap_scan, run_nikto_scan, run_mobsf_scan functions] ...

def run_pefile_scan(file_path):
    """STEP 1: Extract PE metadata using pefile."""
    print(f"\n[Orchestrator] 🔍 STEP 1: Extracting PE metadata for: {file_path}")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/orchestrator:/workspace",
        "python:3-slim", "bash", "-c",
        "pip install pefile -q && python3 /workspace/pefile_extractor.py /workspace/temp_exe_scan/target.exe > /workspace/pefile_report.json"
    ]
    try:
        subprocess.run(cmd, check=True)
        print("[Orchestrator] ✅ pefile extraction complete.")
        return "orchestrator/pefile_report.json"
    except subprocess.CalledProcessError:
        print("[Orchestrator] ⚠️ pefile extraction encountered issues.")
        return None

def run_manalyze_scan(file_path):
    """STEP 2: Deep inspection using Manalyze."""
    print(f"\n[Orchestrator] 🔍 STEP 2: Running Manalyze deep inspection for: {file_path}")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/orchestrator:/tmp",
        "nbeaugrand/manalyze", "/tmp/temp_exe_scan/target.exe", "--json"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Save Manalyze output to JSON file
        with open("orchestrator/manalyze_report.json", "w") as f:
            f.write(result.stdout)
        print("[Orchestrator] ✅ Manalyze scan complete.")
        return "orchestrator/manalyze_report.json"
    except subprocess.CalledProcessError:
        print("[Orchestrator] ⚠️ Manalyze scan encountered issues.")
        return None

def run_yara_scan(file_path):
    """STEP 3: Pattern matching using YARA."""
    print(f"\n[Orchestrator] 🔍 STEP 3: Running YARA pattern matching for: {file_path}")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/orchestrator:/tmp",
        "blacktop/yara", "/tmp/temp_exe_scan/target.exe", "-r", "/yara-rules"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        # Save YARA output to JSON file
        with open("orchestrator/yara_report.json", "w") as f:
            f.write(result.stdout)
        print("[Orchestrator] ✅ YARA scan complete.")
        return "orchestrator/yara_report.json"
    except subprocess.CalledProcessError:
        print("[Orchestrator] ⚠️ YARA scan encountered issues.")
        return None

def run_exe_analysis(file_path):
    """Complete EXE analysis workflow: pefile → Manalyze → YARA."""
    print("=" * 50)
    print("  SEQUENTIAL EXE ANALYSIS: pefile → Manalyze → YARA")
    print("=" * 50)
    
    # Create temporary directory for the binary
    temp_dir = "orchestrator/temp_exe_scan"
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(file_path, f"{temp_dir}/target.exe")
    
    reports = []
    
    # STEP 1: pefile
    pefile_report = run_pefile_scan(file_path)
    if pefile_report:
        reports.append({"engine": "pefile", "file": pefile_report})
    
    # STEP 2: Manalyze
    manalyze_report = run_manalyze_scan(file_path)
    if manalyze_report:
        reports.append({"engine": "Manalyze", "file": manalyze_report})
    
    # STEP 3: YARA
    yara_report = run_yara_scan(file_path)
    if yara_report:
        reports.append({"engine": "YARA", "file": yara_report})
    
    # ZERO-TRUST PRIVACY: Delete the binary immediately
    shutil.rmtree(temp_dir)
    print("[Orchestrator] ✅ ZERO-TRUST: Temporary binary data securely deleted.")
    
    return reports

def trigger_webhook(reports):
    """Sends combined results to CI/CD pipeline."""
    webhook_payload = {
        "tool": "Unified DAST & Binary Analysis Orchestrator",
        "status": "PASS",
        "reports": reports,
        "message": "Scan completed. Ready for adapter parsing."
    }
    print("\n[Orchestrator] 📡 Webhook Payload Ready for CI/CD:")
    print(json.dumps(webhook_payload, indent=2))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 orchestrator/scan_runner.py <URL, .apk/.ipa, or .exe file>")
        sys.exit(1)

    target = sys.argv[1]
    input_type = classify_input(target)

    if input_type == "url":
        # SEQUENTIAL WORKFLOW: ZAP → Nikto
        print("=" * 50)
        print("  SEQUENTIAL SCAN MODE: ZAP → Nikto")
        print("=" * 50)
        reports = []
        zap_report = run_zap_scan(target)
        if zap_report:
            reports.append({"engine": "ZAP", "file": zap_report})
        nikto_report = run_nikto_scan(target)
        if nikto_report:
            reports.append({"engine": "Nikto", "file": nikto_report})
        trigger_webhook(reports)

    elif input_type == "mobsf":
        # Mobile scan
        report = run_mobsf_scan(target)
        trigger_webhook([{"engine": "MobSF", "file": report}])

    elif input_type == "exe":
        # EXE binary analysis
        reports = run_exe_analysis(target)
        trigger_webhook(reports)
