#!/usr/bin/env python3

import json
import os
import re
import shutil
import subprocess


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


def _is_non_finding(line):
    """
    Ignore Nikto informational/status lines that should not become
    security findings.
    """

    text = line.strip().lower()

    if not text:
        return True

    ignored_prefixes = (
        "+ target ip:",
        "+ target hostname:",
        "+ target port:",
        "+ ssl info:",
        "subject:",
        "cn:",
        "san:",
        "ciphers:",
        "issuer:",
        "+ platform:",
        "+ start time:",
        "+ end time:",
        "+ server:",
        "+ multiple ips found:",
        "+ no cgi directories found",
        "+ 1 host(s) tested",
        "+ 0 host(s) tested",
        "+ scan terminated:",
        "+ end time:",
        "+ start time:"
    )

    if text.startswith(ignored_prefixes):
        return True

    # Nikto operational errors/status messages.
    ignored_contains = (
        "failed to check for updates",
        "host maximum execution time",
        "scan terminated",
        "no cgi directories found"
    )

    if any(item in text for item in ignored_contains):
        return True

    return False


def _severity_from_text(text):
    """
    Conservative severity mapping.

    Nikto itself does not provide a reliable severity value for every
    text-mode result, so severity is inferred only from clearly
    security-relevant indicators.
    """

    lower = text.lower()

    critical_keywords = (
        "remote code execution",
        "rce",
        "command execution",
        "arbitrary code execution"
    )

    high_keywords = (
        "sql injection",
        "sql-injection",
        "cross-site scripting",
        "xss",
        "command injection",
        "path traversal",
        "directory traversal",
        "remote file inclusion",
        "local file inclusion",
        "arbitrary file",
        "authentication bypass",
        "privilege escalation"
    )

    medium_keywords = (
        "default password",
        "default credential",
        "backup file",
        "backup directory",
        "configuration file",
        "config file",
        "password file",
        "credential",
        "directory listing",
        "index of",
        "admin panel",
        "admin interface",
        "sensitive information",
        "information disclosure",
        "phpinfo",
        "debug"
    )

    low_keywords = (
        "cookie",
        "httponly",
        "secure flag",
        "security header",
        "missing header",
        "clickjacking",
        "content-security-policy",
        "x-frame-options",
        "server version",
        "outdated",
        "deprecated",
        "allowed http method"
    )

    if any(keyword in lower for keyword in critical_keywords):
        return "Critical"

    if any(keyword in lower for keyword in high_keywords):
        return "High"

    if any(keyword in lower for keyword in medium_keywords):
        return "Medium"

    if any(keyword in lower for keyword in low_keywords):
        return "Low"

    return None


def _extract_nikto_id(line):
    match = re.search(r"\[\s*(\d{6,})\s*\]", line)

    if match:
        return match.group(1)

    return "N/A"


def _extract_uri(line):
    match = re.search(
        r"\+\s*(/[^\s:]*)\s*:",
        line
    )

    if match:
        return match.group(1)

    return "/"


def _parse_nikto_json(output):
    findings = []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return findings

    if isinstance(data, list):
        vulnerabilities = data

    elif isinstance(data, dict):

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            vulnerabilities = data.get("findings", [])

        if not vulnerabilities and "msg" in data:
            vulnerabilities = [data]

    else:
        vulnerabilities = []

    for vuln in vulnerabilities[:100]:

        if not isinstance(vuln, dict):
            continue

        msg = (
            vuln.get("msg")
            or vuln.get("message")
            or vuln.get("description")
            or ""
        ).strip()

        if not msg:
            continue

        if _is_non_finding(msg):
            continue

        if "no vulnerabilities" in msg.lower():
            continue

        raw_severity = str(
            vuln.get("severity", "")
        ).strip()

        severity_map = {
            "0": "Info",
            "1": "Low",
            "2": "Medium",
            "3": "High",
            "4": "Critical"
        }

        severity = severity_map.get(raw_severity)

        if not severity:
            severity = _severity_from_text(msg)

        if not severity:
            # Do not promote generic Nikto observations to vulnerabilities.
            severity = "Info"

        cwe = vuln.get(
            "cweid",
            "N/A"
        )

        uri = vuln.get(
            "uri",
            "/"
        )

        description = vuln.get(
            "description",
            msg
        )

        findings.append(
            _finding(
                "Nikto",
                severity,
                f"Nikto Detection: {msg[:150]}",
                cwe=cwe,
                details=(
                    f"URI: {uri}\n"
                    f"{description[:500]}"
                ),
                remediation=(
                    "Review the affected endpoint and apply the "
                    "recommended security controls."
                )
            )
        )

    return findings


def parse_nikto_text(output):
    """
    Parse real Nikto text-mode output into normalized findings.

    Nikto 2.x commonly emits findings such as:

        + [013587] /: Suggested security header missing: ...
        + [006609] /.git/HEAD: Git HEAD file found.
        + [001825] /reports/: This might be interesting.

    Only actual Nikto result lines are converted into findings.
    Operational/status lines are ignored.
    """

    findings = []
    seen = set()

    for raw_line in output.splitlines():
        line = raw_line.strip()

        if not line or not line.startswith("+"):
            continue

        if _is_non_finding(line):
            continue

        clean_line = line[1:].strip()

        # Ignore scan metadata and operational messages.
        if _is_non_finding("+ " + clean_line):
            continue

        nikto_id = _extract_nikto_id(line)

        # Only process actual Nikto plugin/result lines.
        if nikto_id == "N/A":
            continue

        # Remove the plugin ID so we can extract URI and message cleanly.
        without_id = re.sub(
            r"^\[\s*\d{6,}\s*\]\s*",
            "",
            clean_line
        ).strip()

        # Expected form:
        # /path: message
        uri_match = re.match(
            r"^(\/[^:]*):\s*(.+)$",
            without_id
        )

        if uri_match:
            uri = uri_match.group(1).strip()
            message = uri_match.group(2).strip()
        else:
            uri = "/"
            message = without_id

        if not message:
            continue

        # Avoid duplicate observations.
        key = f"{nikto_id}:{uri}:{message}".lower()

        if key in seen:
            continue

        seen.add(key)

        severity = _severity_from_text(message)

        # Explicit mappings for common Nikto observations.
        lower = message.lower()

        if severity is None:
            if any(
                phrase in lower
                for phrase in (
                    "git head file found",
                    "git config file found",
                    "git index",
                    "directory listing",
                    "open directory browsing",
                    "source code",
                    "password file",
                    "credential",
                    "configuration file",
                    "config file"
                )
            ):
                severity = "Medium"

            elif any(
                phrase in lower
                for phrase in (
                    "security header missing",
                    "x-content-type-options is not set",
                    "x-frame-options",
                    "referrer-policy",
                    "permissions-policy",
                    "content-security-policy",
                    "strict-transport-security",
                    "appears to be outdated",
                    "outdated",
                    "deprecated"
                )
            ):
                severity = "Low"

            else:
                # A real Nikto plugin result is still a real observation.
                # Do not manufacture a vulnerability severity.
                severity = "Info"

        # CWE mapping is intentionally conservative.
        if "directory listing" in lower or "directory browsing" in lower:
            cwe = "CWE-548"

        elif "git head" in lower or "git config" in lower or "git index" in lower:
            cwe = "CWE-538"

        elif "security header" in lower or "x-content-type-options" in lower:
            cwe = "CWE-693"

        elif "information disclosure" in lower:
            cwe = "CWE-200"

        else:
            cwe = "N/A"

        # Human-readable title.
        title = f"Nikto [{nikto_id}]: {message}"

        if severity == "Critical":
            remediation = (
                "Immediately investigate the affected endpoint and "
                "remove or remediate the identified critical exposure."
            )

        elif severity == "High":
            remediation = (
                "Investigate the affected endpoint and apply appropriate "
                "security controls as soon as possible."
            )

        elif severity == "Medium":
            remediation = (
                "Review the exposed resource or configuration and restrict "
                "unnecessary access or information disclosure."
            )

        elif severity == "Low":
            remediation = (
                "Apply appropriate web-server security hardening and "
                "configure the recommended security controls."
            )

        else:
            remediation = (
                "Review the Nikto observation and determine whether any "
                "additional security hardening is required."
            )

        findings.append(
            _finding(
                "Nikto",
                severity,
                title[:200],
                cwe=cwe,
                details=(
                    f"URI: {uri}\n"
                    f"Nikto Plugin ID: {nikto_id}\n"
                    f"{message[:1000]}"
                ),
                remediation=remediation
            )
        )

    return findings[:100]

def _network_failure_finding(
    target_url,
    stdout,
    stderr,
    returncode
):
    """
    Convert common Nikto connectivity failures into useful findings.
    """

    combined = (
        (stdout or "")
        + "\n"
        + (stderr or "")
    ).lower()

    if any(
        phrase in combined
        for phrase in [
            "could not connect",
            "connection refused",
            "connection timed out",
            "failed to connect",
            "unable to connect",
            "no route to host",
            "couldn't connect",
            "connection reset"
        ]
    ):
        return _finding(
            "Nikto",
            "Warning",
            "Target connectivity issue",
            cwe="N/A",
            details=(
                f"Nikto could not reliably communicate with "
                f"{target_url}.\n"
                f"Exit code: {returncode}"
            ),
            remediation=(
                "Verify that the target is reachable and that "
                "the supplied URL, port, TLS configuration and "
                "network access are correct."
            )
        )

    return None


def scan_web_target(target_url):
    """
    Run Nikto against a web target.

    Returns the unified finding format expected by app.py.
    """

    findings = []

    if not target_url:
        return [
            _finding(
                "Nikto",
                "Error",
                "Invalid target",
                details="No target URL was supplied.",
                remediation="Provide a valid HTTP or HTTPS URL."
            )
        ]

    nikto_path = shutil.which("nikto")

    if not nikto_path:
        return [
            _finding(
                "Nikto",
                "Error",
                "Nikto not installed",
                details="The Nikto executable was not found in PATH.",
                remediation="Install Nikto with: sudo apt install nikto"
            )
        ]

    print(
        f"[*] Starting Nikto scan against: {target_url}"
    )

    command = [
        nikto_path,
        "-h",
        target_url,
        "-timeout",
        "15",
        "-maxtime",
        "180",
        "-Tuning",
        "123456789x"
    ]

    print(
        "[*] Nikto command: "
        + " ".join(command)
    )

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=240,
            check=False
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""

        print(
            f"[*] Nikto exit code: {result.returncode}"
        )

        print(
            f"[*] Nikto stdout length: {len(stdout)}"
        )

        print(
            f"[*] Nikto stderr length: {len(stderr)}"
        )

        # ----------------------------------------------------------
        # JSON
        # ----------------------------------------------------------

        if stdout.strip().startswith(("{", "[")):

            findings.extend(
                _parse_nikto_json(stdout)
            )

        # ----------------------------------------------------------
        # TEXT
        # ----------------------------------------------------------

        if not findings:

            findings.extend(
                parse_nikto_text(
                    stdout + "\n" + stderr
                )
            )

        # ----------------------------------------------------------
        # CONNECTIVITY
        # ----------------------------------------------------------

        if not findings:

            network_finding = (
                _network_failure_finding(
                    target_url,
                    stdout,
                    stderr,
                    result.returncode
                )
            )

            if network_finding:
                findings.append(
                    network_finding
                )

        # ----------------------------------------------------------
        # SUCCESSFUL EMPTY SCAN
        # ----------------------------------------------------------

        if not findings:

            findings.append(
                _finding(
                    "Nikto",
                    "Info",
                    "No actionable Nikto findings",
                    cwe="N/A",
                    details=(
                        "Nikto completed the scan but did not "
                        "identify any actionable security findings "
                        "in the returned output."
                    ),
                    remediation="N/A"
                )
            )

        print(
            f"[*] Nikto findings returned: {len(findings)}"
        )

        return findings[:50]

    except subprocess.TimeoutExpired:

        return [
            _finding(
                "Nikto",
                "Warning",
                "Scan timed out",
                details=(
                    "Nikto exceeded the 240-second execution "
                    "limit or the target did not respond in time."
                ),
                remediation=(
                    "Verify target accessibility and WAF behavior. "
                    "Consider reducing the scan scope."
                )
            )
        ]

    except Exception as exc:

        return [
            _finding(
                "Nikto",
                "Error",
                "Nikto scan failed",
                details=str(exc),
                remediation=(
                    "Verify the Nikto installation and target URL."
                )
            )
        ]


def parse_nikto_report(raw_report_path):
    """
    Parse a Nikto report from either JSON or plain-text format.

    Supports:
      - Nikto JSON
      - Nikto text output
      - legacy {"nikto": {"scandetails": [...]}} JSON
    """

    if not os.path.exists(raw_report_path):
        return []

    try:
        with open(
            raw_report_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as handle:
            content = handle.read()
    except Exception:
        return []

    if not content.strip():
        return []

    # ----------------------------------------------------------
    # JSON
    # ----------------------------------------------------------
    try:
        data = json.loads(content)

        # Legacy Nikto structure
        if isinstance(data, dict):
            nikto = data.get("nikto")

            if isinstance(nikto, dict):
                scan_details = nikto.get("scandetails", [])

                findings = []

                for item in scan_details[:50]:
                    if not isinstance(item, dict):
                        continue

                    description = (
                        item.get("description")
                        or item.get("msg")
                        or "Nikto finding"
                    )

                    severity = item.get("severity", "Info")

                    severity_map = {
                        "0": "Info",
                        "1": "Low",
                        "2": "Medium",
                        "3": "High",
                        "4": "Critical"
                    }

                    severity = severity_map.get(
                        str(severity),
                        str(severity).capitalize()
                    )

                    findings.append(
                        _finding(
                            "Nikto",
                            severity,
                            description[:150],
                            cwe="N/A",
                            details=(
                                f"Method: {item.get('method', 'N/A')}\n"
                                f"URL: {item.get('url', '/')}\n"
                                f"OSVDB: {item.get('OSVDB', 'N/A')}\n"
                                f"{description[:500]}"
                            ),
                            remediation=(
                                "Review the affected endpoint and "
                                "apply the appropriate security controls."
                            )
                        )
                    )

                return findings

        # Current Nikto JSON
        if isinstance(data, list):
            raw_items = data
        elif isinstance(data, dict):
            raw_items = data.get("vulnerabilities", [])

            if not raw_items:
                raw_items = data.get("findings", [])

            if not raw_items and "msg" in data:
                raw_items = [data]
        else:
            raw_items = []

        findings = []

        for item in raw_items[:50]:
            if not isinstance(item, dict):
                continue

            msg = (
                item.get("msg")
                or item.get("message")
                or item.get("description")
                or ""
            ).strip()

            if not msg:
                continue

            severity = str(
                item.get("severity", "")
            ).strip()

            severity_map = {
                "0": "Info",
                "1": "Low",
                "2": "Medium",
                "3": "High",
                "4": "Critical"
            }

            severity = severity_map.get(
                severity,
                _severity_from_text(msg) or "Info"
            )

            findings.append(
                _finding(
                    "Nikto",
                    severity,
                    msg[:150],
                    cwe=item.get("cweid", "N/A"),
                    details=msg[:500],
                    remediation=(
                        "Review the affected endpoint and "
                        "apply appropriate remediation."
                    )
                )
            )

        return findings[:50]

    except json.JSONDecodeError:
        pass

    # ----------------------------------------------------------
    # TEXT
    # ----------------------------------------------------------

    return parse_nikto_text(content)
