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
    elif target.endswith(".deb"):
        return "deb"
    else:
        raise ValueError("Unsupported input. Please provide a URL, .apk/.ipa, .exe, or .deb file.")

# ... [keep all your existing functions: run_zap_scan, run_nikto_scan, run_mobsf_scan, run_pefile_scan, run_manalyze_scan, run_yara_scan, run_exe_analysis] ...

def run_dpkg_deb_extract(deb_path):
    """STEP 1: Extract .deb package structure."""
    print(f"\n[Orchestrator] 📦 STEP 1: Extracting .deb package for: {deb_path}")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/orchestrator:/workspace",
        "debian:stable-slim", "bash", "-c",
        "apt-get update -qq && apt-get install -qq -y dpkg && dpkg-deb -x /workspace/temp_deb_scan/target.deb /workspace/temp_deb_scan/extracted/"
    ]
    try:
        subprocess.run(cmd, check=True)
        print("[Orchestrator] ✅ .deb extraction complete.")
        return True
    except subprocess.CalledProcessError:
        print("[Orchestrator] ⚠️ .deb extraction encountered issues.")
        return False

def run_lief_scan(binary_path):
    """STEP 2: Extract ELF metadata using LIEF."""
    print(f"\n[Orchestrator] 🔍 STEP 2: Extracting ELF metadata for: {binary_path}")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/orchestrator:/workspace",
        "liefproject/lief", "python3", "/workspace/lief_extractor.py", binary_path
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open("orchestrator/lief_report.json", "w") as f:
            f.write(result.stdout)
        print("[Orchestrator] ✅ LIEF extraction complete.")
        return "orchestrator/lief_report.json"
    except subprocess.CalledProcessError:
        print("[Orchestrator] ⚠️ LIEF extraction encountered issues.")
        return None

def run_checksec_scan(binary_path):
    """STEP 3: Check binary security features."""
    print(f"\n[Orchestrator] 🛡️ STEP 3: Checking security features for: {binary_path}")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/orchestrator:/workspace",
        "nscuro/checksec", "--file", binary_path, "--output=json"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open("orchestrator/checksec_report.json", "w") as f:
            f.write(result.stdout)
        print("[Orchestrator] ✅ checksec scan complete.")
        return "orchestrator/checksec_report.json"
    except subprocess.CalledProcessError:
        print("[Orchestrator] ⚠️ checksec scan encountered issues.")
        return None

def run_yara_deb_scan(extracted_path):
    """STEP 4: Pattern matching using YARA on all extracted files."""
    print(f"\n[Orchestrator] 🔍 STEP 4: Running YARA pattern matching on extracted files")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.getcwd()}/orchestrator:/workspace",
        "blacktop/yara", "/workspace/temp_deb_scan/extracted", "-r", "/yara-rules"
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        with open("orchestrator/yara_deb_report.json", "w") as f:
            f.write(result.stdout)
        print("[Orchestrator] ✅ YARA scan complete.")
        return "orchestrator/yara_deb_report.json"
    except subprocess.CalledProcessError:
        print("[Orchestrator] ⚠️ YARA scan encountered issues.")
        return None

def run_deb_analysis(deb_path):
    """Complete DEB analysis workflow: dpkg-deb → LIEF → checksec → YARA."""
    print("=" * 50)
    print("  SEQUENTIAL DEB ANALYSIS: dpkg-deb → LIEF → checksec → YARA")
    print("=" * 50)
    
    # Create temporary directory for the package
    temp_dir = "orchestrator/temp_deb_scan"
    os.makedirs(temp_dir, exist_ok=True)
    shutil.copy(deb_path, f"{temp_dir}/target.deb")
    
    reports = []
    
    # STEP 1: dpkg-deb extraction
    if run_dpkg_deb_extract(deb_path):
        # Find the main binary (usually in /usr/bin or /usr/sbin)
        extracted_path = f"{temp_dir}/extracted"
        binary_path = None
        
        # Look for ELF binaries
        for root, dirs, files in os.walk(extracted_path):
            for file in files:
                file_path = os.path.join(root, file)
                if os.access(file_path, os.X_OK):  # Check if executable
                    binary_path = file_path
                    break
            if binary_path:
                break
        
        if binary_path:
            # STEP 2: LIEF
            lief_report = run_lief_scan(binary_path)
            if lief_report:
                reports.append({"engine": "LIEF", "file": lief_report})
            
            # STEP 3: checksec
            checksec_report = run_checksec_scan(binary_path)
            if checksec_report:
                reports.append({"engine": "checksec", "file": checksec_report})
        
        # STEP 4: YARA (scan all extracted files)
        yara_report = run_yara_deb_scan(extracted_path)
        if yara_report:
            reports.append({"engine": "YARA", "file": yara_report})
    
    # ZERO-TRUST PRIVACY: Delete the package immediately
    shutil.rmtree(temp_dir)
    print("[Orchestrator] ✅ ZERO-TRUST: Temporary package data securely deleted.")
    
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
        print("Usage: python3 orchestrator/scan_runner.py <URL, .apk/.ipa, .exe, or .deb file>")
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

    elif input_type == "deb":
        # DEB package analysis
        reports = run_deb_analysis(target)
        trigger_webhook(reports)
