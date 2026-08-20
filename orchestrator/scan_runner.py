#!/usr/bin/env python3
import os
import sys
import json
import shutil
import tempfile
import requests # Make sure 'requests' is in requirements.txt

MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB limit to prevent DoS

def classify_input(target):
    if target.startswith("http://") or target.startswith("https://"):
        return "url"
    elif target.endswith(".apk") or target.endswith(".ipa"):
        return "mobsf"
    elif target.endswith(".exe"):
        return "exe"
    elif target.endswith(".deb"):
        return "deb"
    else:
        raise ValueError("Unsupported input. Provide a URL, .apk/.ipa, .exe, or .deb file.")

# ... [Keep all the run_zap_scan, run_nikto_scan, run_mobsf_scan, run_pefile_scan, etc. functions exactly as they were in your original file] ...
# NOTE: Since I am providing the webhook fix, just replace the trigger_webhook function at the bottom:

def trigger_webhook(reports):
    # ✅ FIX: Load webhook URL from environment variable (No hardcoded URLs!)
    webhook_url = os.environ.get('WEBHOOK_URL')
    
    if not webhook_url:
        print("\n[Orchestrator] ️ No WEBHOOK_URL environment variable set. Skipping webhook dispatch.")
        # Still print payload for local debugging
        status = "PASS" if reports else "PARTIAL_FAIL"
        message = "Scan completed. Ready for adapter parsing." if reports else "Scan completed with warnings."
        webhook_payload = {
            "tool": "Unified DAST & Binary Analysis Orchestrator",
            "status": status,
            "reports": reports,
            "message": message
        }
        print(json.dumps(webhook_payload, indent=2))
        return

    status = "PASS" if reports else "PARTIAL_FAIL"
    message = "Scan completed. Ready for adapter parsing." if reports else "Scan completed with warnings."
    
    webhook_payload = {
        "tool": "Unified DAST & Binary Analysis Orchestrator",
        "status": status,
        "reports": reports,
        "message": message
    }
    
    try:
        # ✅ REAL FLOW: Actually send the HTTP POST request
        print(f"\n[Orchestrator] 📡 Sending webhook to: {webhook_url}")
        response = requests.post(webhook_url, json=webhook_payload, timeout=10)
        if response.status_code in [200, 201]:
            print(f"[Orchestrator] ✅ Webhook sent successfully to CI/CD pipeline.")
        else:
            print(f"[Orchestrator] ⚠️ Webhook failed with status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[Orchestrator] ❌ Webhook dispatch error: {str(e)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 orchestrator/scan_runner.py <URL, .apk/.ipa, .exe, or .deb file>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        input_type = classify_input(target)
    except ValueError as e:
        print(f"[Orchestrator] ❌ {e}")
        sys.exit(1)

    reports = []
    # Note: For CLI usage, you would call the specific run functions here based on input_type.
    # Since the Flask app (app.py) is your main UI, this CLI script is mostly for direct testing.
    trigger_webhook(reports)
