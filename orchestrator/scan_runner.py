#!/usr/bin/env python3
"""
NOTE: This module is used by the standalone test/portfolio scripts
(test_full_pipeline.py, test_apk_pipeline.py, final_project_confirmation.py,
etc.) - it is NOT imported by the live Flask app (app.py). The live web app
calls adapters/zap_adapter.py directly, which uses the ZAP daemon + REST API
approach, not the older -quickurl subprocess call still used by
run_zap_scan() below. Keep both working: this file's functions stay for the
test scripts that import them, but don't treat run_zap_scan() here as
reflecting how the live dashboard actually scans.
"""
import os
import sys
import json
import shutil
import tempfile
import subprocess
import requests  # Make sure 'requests' is in requirements.txt

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


def run_zap_scan(target_url):
    """
    Run OWASP ZAP against a web target.

    Returns the generated JSON report path, or None
    when ZAP is unavailable or the scan fails.
    """

    zap_path = shutil.which("zap.sh")

    if not zap_path:
        print("[ZAP] zap.sh not found. Skipping ZAP scan.")
        return None

    report_dir = os.path.join(
        tempfile.gettempdir(),
        "dast_zap"
    )

    os.makedirs(report_dir, exist_ok=True)

    report_path = os.path.join(
        report_dir,
        "zap_report.json"
    )

    print(f"[ZAP] Starting scan against: {target_url}")

    command = [
        zap_path,
        "-cmd",
        "-quickurl",
        target_url,
        "-quickout",
        report_path,
        "-quickprogress"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )

        print(f"[ZAP] Exit code: {result.returncode}")

        if os.path.exists(report_path):
            print(f"[ZAP] Report saved: {report_path}")
            return report_path

        print("[ZAP] No report was generated.")

        if result.stderr:
            print(result.stderr[-1000:])

        return None

    except subprocess.TimeoutExpired:
        print("[ZAP] Scan timed out.")
        return None

    except Exception as exc:
        print(f"[ZAP] Scan failed: {exc}")
        return None


def run_nikto_scan(target_url):
    """
    Run a real Nikto scan against a web target.

    Nikto 2.6.0 on this system does not reliably create the
    requested output file, so we capture its real stdout and
    save it ourselves.

    Returns the saved raw Nikto report path, or None on failure.
    """

    nikto_path = shutil.which("nikto")

    if not nikto_path:
        print("[Nikto] nikto not found. Skipping Nikto scan.")
        return None

    report_dir = os.path.join(
        tempfile.gettempdir(),
        "dast_nikto"
    )

    os.makedirs(report_dir, exist_ok=True)

    report_path = os.path.join(
        report_dir,
        "nikto_report.txt"
    )

    print(f"[Nikto] Starting scan against: {target_url}")

    command = [
        nikto_path,
        "-h",
        target_url,
        "-Format",
        "txt",
        "-nointeractive"
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=240,
            check=False
        )

        print(f"[Nikto] Exit code: {result.returncode}")

        # Nikto writes the actual scan report to stdout.
        # Save the real output ourselves.
        output = result.stdout or ""

        if result.stderr:
            output += "\n\n===== NIKTO STDERR =====\n"
            output += result.stderr

        if output.strip():
            with open(
                report_path,
                "w",
                encoding="utf-8",
                errors="replace"
            ) as handle:
                handle.write(output)

            print(f"[Nikto] Raw report saved: {report_path}")
            print(f"[Nikto] Report size: {os.path.getsize(report_path)} bytes")

            return report_path

        print("[Nikto] No output was captured.")
        return None

    except subprocess.TimeoutExpired as exc:
        print("[Nikto] Scan timed out.")

        # Preserve any output generated before timeout.
        output = ""

        if exc.stdout:
            output += str(exc.stdout)

        if exc.stderr:
            output += "\n\n===== NIKTO STDERR =====\n"
            output += str(exc.stderr)

        if output.strip():
            with open(
                report_path,
                "w",
                encoding="utf-8",
                errors="replace"
            ) as handle:
                handle.write(output)

            print(f"[Nikto] Partial report saved: {report_path}")
            return report_path

        return None

    except Exception as exc:
        print(f"[Nikto] Scan failed: {exc}")
        return None


def run_mobsf_scan(apk_path):
    """
    Backward-compatible MobSF runner.

    Returns the path to a JSON report when MobSF is configured
    and the scan succeeds. Returns None when MobSF is unavailable.
    """

    if not os.path.isfile(apk_path):
        print(f"[MobSF] APK not found: {apk_path}")
        return None

    mobsf_url = os.environ.get(
        "MOBSF_URL",
        "http://127.0.0.1:8000"
    ).rstrip("/")

    api_key = os.environ.get("MOBSF_API_KEY")

    if not api_key:
        print("[MobSF] MOBSF_API_KEY is not configured. Skipping scan.")
        return None

    try:
        print(f"[*] Uploading APK to MobSF: {apk_path}")

        with open(apk_path, "rb") as apk_file:
            response = requests.post(
                f"{mobsf_url}/api/v1/upload",
                files={
                    "file": (
                        os.path.basename(apk_path),
                        apk_file,
                        "application/vnd.android.package-archive"
                    )
                },
                headers={
                    "Authorization": api_key
                },
                timeout=120
            )

        if response.status_code != 200:
            print(
                f"[MobSF] Upload failed: HTTP {response.status_code}"
            )
            return None

        upload_data = response.json()
        file_hash = upload_data.get("hash")

        if not file_hash:
            print("[MobSF] Upload response did not contain a hash.")
            return None

        print("[*] Starting MobSF APK analysis")

        scan_response = requests.post(
            f"{mobsf_url}/api/v1/scan",
            data={
                "scan_type": "apk",
                "hash": file_hash
            },
            headers={
                "Authorization": api_key
            },
            timeout=300
        )

        if scan_response.status_code != 200:
            print(
                f"[MobSF] Scan failed: HTTP {scan_response.status_code}"
            )
            return None

        report = scan_response.json()

        report_dir = os.path.join(
            "/tmp",
            "dast_mobsf"
        )

        os.makedirs(
            report_dir,
            exist_ok=True
        )

        report_path = os.path.join(
            report_dir,
            "mobsf_report.json"
        )

        with open(
            report_path,
            "w",
            encoding="utf-8"
        ) as handle:
            json.dump(
                report,
                handle,
                indent=2
            )

        print(f"[MobSF] Report saved: {report_path}")

        return report_path

    except requests.RequestException as exc:
        print(f"[MobSF] Connection failed: {exc}")
        return None

    except Exception as exc:
        print(f"[MobSF] Scan failed: {exc}")
        return None


def trigger_webhook(reports):
    webhook_url = os.environ.get('WEBHOOK_URL')

    if not webhook_url:
        print("\n[Orchestrator] No WEBHOOK_URL environment variable set. Skipping webhook dispatch.")
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
        print(f"\n[Orchestrator] Sending webhook to: {webhook_url}")
        response = requests.post(webhook_url, json=webhook_payload, timeout=10)
        if response.status_code in [200, 201]:
            print("[Orchestrator] Webhook sent successfully to CI/CD pipeline.")
        else:
            print(f"[Orchestrator] Webhook failed with status {response.status_code}: {response.text}")
    except Exception as e:
        print(f"[Orchestrator] Webhook dispatch error: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 orchestrator/scan_runner.py <URL, .apk/.ipa, .exe, or .deb file>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        input_type = classify_input(target)
    except ValueError as e:
        print(f"[Orchestrator] {e}")
        sys.exit(1)

    reports = []
    # Note: For CLI usage, you would call the specific run functions here based on input_type.
    # Since the Flask app (app.py) is your main UI, this CLI script is mostly for direct testing.
    trigger_webhook(reports)
