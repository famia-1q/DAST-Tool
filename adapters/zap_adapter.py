#!/usr/bin/env python3

import json
import os
import shutil
import subprocess
import tempfile


def _finding(
    tool,
    severity,
    finding,
    cwe="N/A",
    details="",
    remediation="N/A"
):
    return {
        "tool": tool,
        "severity": severity,
        "finding": finding,
        "cwe": cwe,
        "details": details,
        "remediation": remediation
    }


def _severity_from_risk(risk):
    risk = str(risk).lower().strip()

    mapping = {
        "informational": "Info",
        "info": "Info",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical"
    }

    return mapping.get(
        risk,
        "Low"
    )


def _parse_zap_json(path):
    findings = []

    if not os.path.exists(path):
        return findings

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as handle:
            data = json.load(handle)

    except Exception:
        return findings

    alerts = []

    if isinstance(data, dict):
        alerts = data.get("alerts", [])

        if not alerts:
            site_list = data.get("site", [])

            if isinstance(site_list, list):
                for site in site_list:
                    if isinstance(site, dict):
                        alerts.extend(
                            site.get("alerts", [])
                        )

    elif isinstance(data, list):
        alerts = data

    for alert in alerts[:100]:

        if not isinstance(alert, dict):
            continue

        name = (
            alert.get("name")
            or alert.get("alert")
            or "ZAP Alert"
        )

        risk = (
            alert.get("risk")
            or alert.get("riskcode")
            or "Informational"
        )

        severity = _severity_from_risk(risk)

        url = (
            alert.get("url")
            or alert.get("uri")
            or ""
        )

        description = (
            alert.get("description")
            or alert.get("desc")
            or ""
        )

        solution = (
            alert.get("solution")
            or "Review and remediate the identified issue."
        )

        cwe = (
            alert.get("cweid")
            or "N/A"
        )

        # Avoid meaningless ZAP informational alerts if desired,
        # but retain them so the report shows what was tested.
        findings.append(
            _finding(
                "OWASP ZAP",
                severity,
                str(name)[:150],
                cwe=f"CWE-{cwe}"
                if str(cwe).isdigit()
                else str(cwe),
                details=(
                    f"URL: {url}\n"
                    f"{description[:600]}"
                ),
                remediation=str(solution)[:600]
            )
        )

    return findings


def scan_web_target_with_zap(
    target_url: str,
    timeout=120
) -> list:
    """
    Runs OWASP ZAP quick scan.

    The adapter attempts to export machine-readable JSON and
    returns individual ZAP alerts rather than one generic finding.
    """

    findings = []

    if not target_url.startswith(
        ("http://", "https://")
    ):
        return [
            _finding(
                "OWASP ZAP",
                "Error",
                "Invalid URL format",
                details="Target must begin with http:// or https://.",
                remediation="Provide a valid HTTP/HTTPS target."
            )
        ]

    zap_path = (
        shutil.which("zaproxy")
        or shutil.which("zap")
    )

    if not zap_path:
        return [
            _finding(
                "OWASP ZAP",
                "Warning",
                "ZAP not installed",
                details="OWASP ZAP executable was not found in PATH.",
                remediation="Install OWASP ZAP and make it available in PATH."
            )
        ]

    print(
        f"[*] Starting OWASP ZAP scan against: {target_url}"
    )

    report_file = tempfile.mktemp(
        prefix="zap_report_",
        suffix=".json"
    )

    try:

        command = [
            zap_path,
            "-cmd",
            "-quickurl",
            target_url,
            "-quickout",
            report_file,
            "-quickprogress"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        print(
            f"[*] ZAP exit code: {result.returncode}"
        )

        # ------------------------------------------------------
        # Parse exported report
        # ------------------------------------------------------

        findings.extend(
            _parse_zap_json(report_file)
        )

        # ------------------------------------------------------
        # If report has alerts, return them.
        # ------------------------------------------------------

        if findings:
            return findings[:100]

        # ------------------------------------------------------
        # ZAP completed but no alerts
        # ------------------------------------------------------

        if result.returncode == 0:
            return [
                _finding(
                    "OWASP ZAP",
                    "Info",
                    "ZAP scan completed",
                    details=(
                        "ZAP completed the requested scan without "
                        "producing parsed security alerts."
                    ),
                    remediation="N/A"
                )
            ]

        # ------------------------------------------------------
        # ZAP failed
        # ------------------------------------------------------

        combined = (
            stdout + "\n" + stderr
        ).strip()

        return [
            _finding(
                "OWASP ZAP",
                "Warning",
                "ZAP scan completed with errors",
                details=combined[:1000],
                remediation=(
                    "Verify ZAP installation, target accessibility, "
                    "and ZAP command-line configuration."
                )
            )
        ]

    except subprocess.TimeoutExpired:
        return [
            _finding(
                "OWASP ZAP",
                "Warning",
                "ZAP scan timed out",
                details=(
                    f"ZAP exceeded the configured {timeout}-second timeout."
                ),
                remediation=(
                    "Verify target accessibility and consider "
                    "increasing the scan timeout for larger applications."
                )
            )
        ]

    except Exception as exc:
        return [
            _finding(
                "OWASP ZAP",
                "Error",
                "ZAP scan failed",
                details=str(exc),
                remediation="Verify the ZAP installation."
            )
        ]

    finally:
        try:
            if os.path.exists(report_file):
                os.remove(report_file)
        except Exception:
            pass
