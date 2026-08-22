#!/usr/bin/env python3
"""
OWASP ZAP adapter - daemon + REST API version.

Why this replaces the old subprocess/-quickurl approach:
  - The old code ran `zaproxy -cmd -quickurl ... -quickout ...` and killed
    it with subprocess.run(timeout=120). A real spider + active scan
    almost never finishes in 120s, so it always hit TimeoutExpired.
  - This version starts ZAP once in daemon mode, drives it through its
    REST API (spider -> active scan -> alerts), and polls for progress
    instead of blocking on one big subprocess call. No more silent kill.
"""

import os
import shutil
import subprocess
import time

import requests

ZAP_HOST = "127.0.0.1"
ZAP_PORT = 8090
ZAP_BASE = f"http://{ZAP_HOST}:{ZAP_PORT}"

# How long we're willing to wait for each phase. Tune per target size.
ZAP_STARTUP_TIMEOUT = 60          # seconds to wait for the daemon to come up
ZAP_SPIDER_TIMEOUT = 300          # seconds to wait for spider to finish
ZAP_ACTIVE_SCAN_TIMEOUT = 900     # seconds to wait for active scan to finish
POLL_INTERVAL = 2                 # seconds between status checks

_zap_process = None  # keeps a handle if we started the daemon ourselves


def _finding(tool, severity, finding, cwe="N/A", details="", remediation="N/A"):
    return {
        "tool": tool,
        "severity": severity,
        "finding": finding,
        "cwe": cwe,
        "details": details,
        "remediation": remediation,
    }


def _severity_from_risk(risk):
    risk = str(risk).lower().strip()
    mapping = {
        "informational": "Info",
        "info": "Info",
        "low": "Low",
        "medium": "Medium",
        "high": "High",
        "critical": "Critical",
    }
    return mapping.get(risk, "Low")


def _is_zap_running():
    try:
        r = requests.get(f"{ZAP_BASE}/JSON/core/view/version/", timeout=3)
        return r.status_code == 200
    except requests.exceptions.RequestException:
        return False


def _api_actually_usable():
    """
    Liveness (_is_zap_running) only proves *something* answers on the
    port - it doesn't prove the API key/config matches what we need.
    Action-tier endpoints enforce the API key even when view-tier ones
    sometimes don't, so we probe one that has no destructive side
    effects. A 403 here means a stale/misconfigured daemon is squatting
    on our port and must be killed rather than reused.
    """
    try:
        r = requests.get(
            f"{ZAP_BASE}/JSON/spider/action/setOptionMaxDepth/",
            params={"Integer": "5"},
            timeout=5,
        )
        return r.status_code == 200
    except requests.exceptions.RequestException:
        return False


def _kill_stale_daemon():
    print("[ZAP] Existing daemon on this port is misconfigured (API check failed). Killing it.")
    try:
        subprocess.run(["pkill", "-9", "-f", f"port {ZAP_PORT}"], check=False)
    except Exception:
        pass
    time.sleep(2)


def start_zap_daemon():
    """
    Starts ZAP in headless daemon mode if it isn't already running,
    and waits until its API responds.

    Returns True if ZAP is up (whether we started it or it was already
    running), False if it never came up within ZAP_STARTUP_TIMEOUT.
    """
    global _zap_process

    if _is_zap_running():
        if _api_actually_usable():
            print("[ZAP] Daemon already running and API confirmed usable, reusing it.")
            return True
        _kill_stale_daemon()

    zap_path = shutil.which("zaproxy") or shutil.which("zap.sh") or shutil.which("owasp-zap")

    if not zap_path:
        print("[ZAP] zaproxy executable not found in PATH.")
        return False

    print(f"[ZAP] Starting daemon: {zap_path} -daemon -port {ZAP_PORT}")

    command = [
        zap_path,
        "-daemon",
        "-host", ZAP_HOST,
        "-port", str(ZAP_PORT),
        "-config", "api.disablekey=true",
        "-config", "api.addrs.addr.name=.*",
        "-config", "api.addrs.addr.regex=true",
        "-config", "start.checkForUpdates=false",   # skip slow update check
    ]

    # Detached background process - we do NOT wait on this with a timeout,
    # because a daemon is meant to keep running.
    _zap_process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    start = time.time()
    while time.time() - start < ZAP_STARTUP_TIMEOUT:
        if _is_zap_running():
            elapsed = round(time.time() - start, 1)
            print(f"[ZAP] Daemon is up after {elapsed}s.")
            return True
        time.sleep(1)

    print(f"[ZAP] Daemon did not respond within {ZAP_STARTUP_TIMEOUT}s.")
    return False


def stop_zap_daemon():
    """Call this if you want to shut ZAP down after a scan (optional)."""
    try:
        requests.get(f"{ZAP_BASE}/JSON/core/action/shutdown/", timeout=5)
        print("[ZAP] Shutdown requested.")
    except requests.exceptions.RequestException:
        if _zap_process:
            _zap_process.terminate()
            print("[ZAP] Daemon process terminated locally.")


def _run_spider(target_url):
    print(f"[ZAP] Starting spider on: {target_url}")
    r = requests.get(
        f"{ZAP_BASE}/JSON/spider/action/scan/",
        params={"url": target_url, "recurse": "true"},
        timeout=15,
    )
    r.raise_for_status()
    scan_id = r.json()["scan"]

    start = time.time()
    while time.time() - start < ZAP_SPIDER_TIMEOUT:
        status = requests.get(
            f"{ZAP_BASE}/JSON/spider/view/status/",
            params={"scanId": scan_id},
            timeout=10,
        ).json()["status"]
        print(f"[ZAP] Spider progress: {status}%")

        if int(status) >= 100:
            print("[ZAP] Spider complete.")
            return True

        time.sleep(POLL_INTERVAL)

    print(f"[ZAP] Spider did not finish within {ZAP_SPIDER_TIMEOUT}s, moving on with partial results.")
    return False


def _run_active_scan(target_url):
    print(f"[ZAP] Starting active scan on: {target_url}")
    r = requests.get(
        f"{ZAP_BASE}/JSON/ascan/action/scan/",
        params={"url": target_url, "recurse": "true"},
        timeout=15,
    )
    r.raise_for_status()
    scan_id = r.json()["scan"]

    start = time.time()
    while time.time() - start < ZAP_ACTIVE_SCAN_TIMEOUT:
        status = requests.get(
            f"{ZAP_BASE}/JSON/ascan/view/status/",
            params={"scanId": scan_id},
            timeout=10,
        ).json()["status"]
        print(f"[ZAP] Active scan progress: {status}%")

        if int(status) >= 100:
            print("[ZAP] Active scan complete.")
            return True

        time.sleep(POLL_INTERVAL)

    print(f"[ZAP] Active scan did not finish within {ZAP_ACTIVE_SCAN_TIMEOUT}s, moving on with partial results.")
    return False


def _get_alerts(target_url):
    r = requests.get(
        f"{ZAP_BASE}/JSON/core/view/alerts/",
        params={"baseurl": target_url},
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("alerts", [])


def _alerts_to_findings(alerts):
    """
    ZAP raises one alert entry per URL where an issue is found, so a
    single missing-header issue on 6 pages shows up as 6 near-identical
    rows. For a client-facing report that's noise: group by (name, risk)
    and merge the affected URLs into one finding with one details block.
    """
    groups = {}   # (name, risk) -> {"urls": [...], "description":..., "solution":..., "cweid":...}
    order = []    # preserves first-seen order for stable output

    for alert in alerts:
        name = str(alert.get("alert") or alert.get("name") or "ZAP Alert")[:150]
        risk = alert.get("risk") or "Informational"
        url = alert.get("url", "")
        key = (name, risk)

        if key not in groups:
            groups[key] = {
                "urls": [],
                "description": alert.get("description", ""),
                "solution": alert.get("solution") or "Review and remediate the identified issue.",
                "cweid": alert.get("cweid", "N/A"),
            }
            order.append(key)

        if url and url not in groups[key]["urls"]:
            groups[key]["urls"].append(url)

    findings = []

    for name, risk in order[:100]:
        g = groups[(name, risk)]
        severity = _severity_from_risk(risk)
        cwe = g["cweid"]

        urls = g["urls"]
        url_count = len(urls)
        shown_urls = urls[:10]
        url_block = "\n".join(f"  - {u}" for u in shown_urls)
        if url_count > len(shown_urls):
            url_block += f"\n  ...and {url_count - len(shown_urls)} more URL(s)"

        affected = f"Affected URLs ({url_count}):\n{url_block}" if urls else "URL: N/A"

        findings.append(
            _finding(
                "OWASP ZAP",
                severity,
                name,
                cwe=f"CWE-{cwe}" if str(cwe).isdigit() else str(cwe),
                details=f"{affected}\n\n{str(g['description'])[:600]}",
                remediation=str(g["solution"])[:600],
            )
        )

    return findings


def scan_web_target_with_zap(target_url: str, shutdown_after=False) -> list:
    """
    Full daemon + REST API ZAP scan: start daemon -> spider -> active scan
    -> pull alerts -> convert to findings. Replaces the old blocking
    `-quickurl` subprocess call that was timing out at 120s.
    """

    if not target_url.startswith(("http://", "https://")):
        return [
            _finding(
                "OWASP ZAP",
                "Error",
                "Invalid URL format",
                details="Target must begin with http:// or https://.",
                remediation="Provide a valid HTTP/HTTPS target.",
            )
        ]

    if not start_zap_daemon():
        return [
            _finding(
                "OWASP ZAP",
                "Warning",
                "ZAP daemon unavailable",
                details=(
                    "ZAP was not found in PATH, or the daemon did not "
                    f"come up within {ZAP_STARTUP_TIMEOUT}s."
                ),
                remediation="Install ZAP (`sudo apt install zaproxy`) and verify it starts manually.",
            )
        ]

    try:
        _run_spider(target_url)
        _run_active_scan(target_url)
        alerts = _get_alerts(target_url)

        if alerts:
            return _alerts_to_findings(alerts)

        return [
            _finding(
                "OWASP ZAP",
                "Info",
                "ZAP scan completed",
                details="ZAP completed spidering and active scanning with no alerts raised.",
                remediation="N/A",
            )
        ]

    except requests.exceptions.RequestException as exc:
        return [
            _finding(
                "OWASP ZAP",
                "Error",
                "ZAP API call failed",
                details=str(exc),
                remediation="Verify the ZAP daemon is reachable at "
                f"{ZAP_BASE} and its API is enabled.",
            )
        ]

    finally:
        if shutdown_after:
            stop_zap_daemon()
