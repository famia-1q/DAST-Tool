#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import tempfile


MAX_APK_SIZE = 500 * 1024 * 1024
DECOMPILE_TIMEOUT = 180


def _finding(tool, severity, finding, cwe="N/A", details="", remediation="N/A"):
    return {
        "tool": tool,
        "severity": severity,
        "finding": finding,
        "cwe": cwe,
        "details": details,
        "remediation": remediation,
    }


def scan_apk_target(file_path):
    """
    Static Android APK analysis.

    Pipeline:
      1. Validate APK
      2. Decompile with apktool
      3. Inspect AndroidManifest.xml
      4. Search for potentially hardcoded secrets
      5. Search for insecure storage indicators
      6. Check network security configuration
      7. Return findings
    """

    findings = []

    if not file_path:
        return [_finding(
            "APK Analyzer",
            "Error",
            "No APK file supplied",
            details="No file path was provided.",
            remediation="Provide a valid APK file."
        )]

    file_path = os.path.abspath(os.path.expanduser(file_path))

    if not os.path.exists(file_path):
        return [_finding(
            "APK Analyzer",
            "Error",
            "File not found",
            details=f"Path: {file_path}",
            remediation="Ensure the APK path is correct."
        )]

    if not os.path.isfile(file_path):
        return [_finding(
            "APK Analyzer",
            "Error",
            "Path is not a file",
            details=f"Path: {file_path}",
            remediation="Provide an APK file rather than a directory."
        )]

    file_size = os.path.getsize(file_path)

    if file_size == 0:
        return [_finding(
            "APK Analyzer",
            "Error",
            "Invalid APK: file is empty",
            cwe="N/A",
            details="The supplied APK is 0 bytes and cannot be decompiled.",
            remediation="Upload/provide a valid, non-empty APK."
        )]

    if file_size > MAX_APK_SIZE:
        return [_finding(
            "APK Analyzer",
            "Error",
            "File too large",
            details=f"APK size {file_size} bytes exceeds the 500 MB limit.",
            remediation="Scan an APK smaller than 500 MB."
        )]

    apktool_path = shutil.which("apktool")

    if not apktool_path:
        return [_finding(
            "apktool",
            "Error",
            "apktool not installed",
            details="apktool was not found in PATH.",
            remediation="Install apktool with: sudo apt install apktool"
        )]

    # Verify that the APK is actually a ZIP/APK before invoking apktool.
    try:
        zip_test = subprocess.run(
            ["unzip", "-t", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        if zip_test.returncode != 0:
            return [_finding(
                "APK Analyzer",
                "Error",
                "Invalid or corrupted APK",
                details=(
                    "The supplied file is not a valid ZIP/APK archive. "
                    f"{(zip_test.stderr or zip_test.stdout).strip()[:500]}"
                ),
                remediation="Provide a valid Android APK file."
            )]

    except FileNotFoundError:
        # unzip is optional; apktool will perform the actual validation.
        pass
    except subprocess.TimeoutExpired:
        return [_finding(
            "APK Analyzer",
            "Error",
            "APK validation timed out",
            details="Archive validation exceeded 30 seconds.",
            remediation="Try a smaller or valid APK."
        )]

    decompile_dir = tempfile.mkdtemp(prefix="dast_apk_")

    try:
        print(f"[*] Decompiling APK: {file_path}")
        print(f"[*] Output directory: {decompile_dir}")

        try:
            result = subprocess.run(
                [
                    apktool_path,
                    "d",
                    file_path,
                    "-o",
                    decompile_dir,
                    "-f",
                    "--no-assets"
                ],
                capture_output=True,
                text=True,
                timeout=DECOMPILE_TIMEOUT
            )

        except subprocess.TimeoutExpired:
            return [_finding(
                "apktool",
                "Error",
                "Decompilation timed out",
                details=f"APK decompilation exceeded {DECOMPILE_TIMEOUT} seconds.",
                remediation="Try a smaller APK or increase the configured timeout."
            )]

        if result.returncode != 0:
            error_output = (result.stderr or result.stdout or "").strip()

            return [_finding(
                "apktool",
                "Error",
                "APK decompilation failed",
                details=error_output[:1000] or "apktool returned a non-zero exit code.",
                remediation="Ensure the file is a valid APK and compatible with apktool."
            )]

        print("[*] APK decompiled successfully")

        # ------------------------------------------------------------
        # 1. AndroidManifest.xml analysis
        # ------------------------------------------------------------

        manifest_path = os.path.join(
            decompile_dir,
            "AndroidManifest.xml"
        )

        if not os.path.exists(manifest_path):
            findings.append(_finding(
                "apktool",
                "Warning",
                "AndroidManifest.xml not found",
                details="Manifest was not found after APK decompilation.",
                remediation="Verify that the supplied APK is valid."
            ))
        else:
            try:
                with open(
                    manifest_path,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as f:
                    manifest = f.read()

                # Debuggable application
                if re.search(
                    r'android:debuggable\s*=\s*["\']true["\']',
                    manifest,
                    re.IGNORECASE
                ):
                    findings.append(_finding(
                        "apktool",
                        "High",
                        "Application Debugging Enabled",
                        "CWE-489",
                        "AndroidManifest.xml explicitly enables android:debuggable.",
                        "Disable debugging in production builds."
                    ))

                # Cleartext traffic
                if re.search(
                    r'android:usesCleartextTraffic\s*=\s*["\']true["\']',
                    manifest,
                    re.IGNORECASE
                ):
                    findings.append(_finding(
                        "apktool",
                        "Medium",
                        "Cleartext Network Traffic Allowed",
                        "CWE-319",
                        "The application explicitly allows cleartext HTTP traffic.",
                        "Disable cleartext traffic and use HTTPS."
                    ))

                # Exported components
                exported_components = re.findall(
                    r'<(activity|service|receiver|provider)\b[^>]*'
                    r'android:exported\s*=\s*["\']true["\']',
                    manifest,
                    re.IGNORECASE
                )

                if exported_components:
                    findings.append(_finding(
                        "apktool",
                        "Medium",
                        "Exported Android Components Detected",
                        "CWE-926",
                        (
                            f"{len(exported_components)} exported component(s) "
                            "were identified in AndroidManifest.xml."
                        ),
                        "Review exported components and restrict them unless externally accessible."
                    ))

                # Network security configuration
                has_network_config = (
                    "android:networkSecurityConfig" in manifest
                )

                if not has_network_config:
                    findings.append(_finding(
                        "apktool",
                        "Low",
                        "No Network Security Configuration Declared",
                        "CWE-295",
                        "No android:networkSecurityConfig attribute was found.",
                        "Define an appropriate Network Security Config and enforce secure transport."
                    ))

            except OSError as e:
                findings.append(_finding(
                    "apktool",
                    "Warning",
                    "Manifest analysis failed",
                    details=str(e),
                    remediation="Verify manifest accessibility."
                ))

        # ------------------------------------------------------------
        # 2. Source/code analysis
        # ------------------------------------------------------------

        text_extensions = {
            ".xml",
            ".smali",
            ".java",
            ".kt",
            ".json",
            ".properties",
            ".txt",
            ".gradle",
            ".js",
            ".html",
            ".xml"
        }

        files_scanned = 0
        secret_matches = []
        insecure_storage_matches = []
        http_matches = []

        secret_pattern = re.compile(
            r'(?i)(api[_-]?key|apikey|secret[_-]?key|password|passwd|'
            r'access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret)'
        )

        storage_pattern = re.compile(
            r'(?i)(SharedPreferences|MODE_WORLD_READABLE|'
            r'MODE_WORLD_WRITEABLE|SQLiteDatabase|'
            r'getSharedPreferences)'
        )

        http_pattern = re.compile(
            r'(?i)http://'
        )

        for root, dirs, files in os.walk(decompile_dir):

            # Avoid unnecessarily scanning huge generated/build folders.
            dirs[:] = [
                d for d in dirs
                if d not in {
                    "__pycache__",
                    ".git",
                    "build"
                }
            ]

            for filename in files:

                full_path = os.path.join(root, filename)

                if not os.path.isfile(full_path):
                    continue

                if os.path.splitext(filename)[1].lower() not in text_extensions:
                    continue

                try:
                    if os.path.getsize(full_path) > 5 * 1024 * 1024:
                        continue

                    with open(
                        full_path,
                        "r",
                        encoding="utf-8",
                        errors="ignore"
                    ) as f:
                        content = f.read()

                    files_scanned += 1

                    for line in content.splitlines():

                        clean_line = line.strip()

                        if not clean_line:
                            continue

                        # Avoid flagging the scanner's own generic words
                        # in Android resource descriptions.
                        if secret_pattern.search(clean_line):
                            if not re.search(
                                r'(?i)(example|placeholder|sample|dummy)',
                                clean_line
                            ):
                                secret_matches.append(
                                    f"{filename}: {clean_line[:180]}"
                                )

                        if storage_pattern.search(clean_line):
                            insecure_storage_matches.append(
                                f"{filename}: {clean_line[:180]}"
                            )

                        if http_pattern.search(clean_line):
                            http_matches.append(
                                f"{filename}: {clean_line[:180]}"
                            )

                except (OSError, UnicodeError):
                    continue

        # ------------------------------------------------------------
        # 3. Hardcoded secrets
        # ------------------------------------------------------------

        if secret_matches:
            findings.append(_finding(
                "apktool/grep",
                "High",
                "Potential Hardcoded Secrets Detected",
                "CWE-798",
                (
                    f"Potential secret-related strings were found in "
                    f"{len(secret_matches)} location(s). Example: "
                    f"{secret_matches[0]}"
                ),
                "Remove secrets from the APK and store sensitive credentials securely on a backend or protected keystore."
            ))

        # ------------------------------------------------------------
        # 4. Insecure storage
        # ------------------------------------------------------------

        if insecure_storage_matches:
            findings.append(_finding(
                "apktool/grep",
                "Medium",
                "Potential Insecure Data Storage",
                "CWE-312",
                (
                    f"Potential insecure storage APIs were found in "
                    f"{len(insecure_storage_matches)} location(s). Example: "
                    f"{insecure_storage_matches[0]}"
                ),
                "Use Android Keystore or encrypted storage for sensitive information."
            ))

        # ------------------------------------------------------------
        # 5. HTTP URLs
        # ------------------------------------------------------------

        if http_matches:
            findings.append(_finding(
                "apktool/grep",
                "Medium",
                "HTTP URLs Detected",
                "CWE-319",
                (
                    f"Potential cleartext HTTP references were found in "
                    f"{len(http_matches)} location(s). Example: "
                    f"{http_matches[0]}"
                ),
                "Use HTTPS for application network communication."
            ))

        # ------------------------------------------------------------
        # 6. Successful scan summary
        # ------------------------------------------------------------

        findings.append(_finding(
            "APK Analyzer",
            "Info",
            "APK static analysis completed",
            details=(
                f"Successfully decompiled and inspected the APK. "
                f"Text/code files scanned: {files_scanned}. "
                f"Security checks completed: manifest, secrets, storage, "
                f"and cleartext HTTP indicators."
            ),
            remediation="Review all reported findings and validate potential false positives."
        ))

    finally:
        if os.path.exists(decompile_dir):
            try:
                shutil.rmtree(decompile_dir)
            except OSError:
                pass

    return findings


def parse_yara_report(report_path):
    """
    Backward-compatible YARA report parser.

    Accepts JSON reports generated by the adapter and returns
    normalized findings compatible with the unified pipeline.
    """
    import json
    import os

    findings = []

    if not report_path or not os.path.exists(report_path):
        return findings

    try:
        with open(
            report_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as handle:
            data = json.load(handle)
    except Exception:
        return findings

    if isinstance(data, dict):
        raw_findings = data.get("findings", [])

        if not raw_findings and isinstance(data.get("results"), list):
            raw_findings = data["results"]

    elif isinstance(data, list):
        raw_findings = data

    else:
        raw_findings = []

    for item in raw_findings:
        if not isinstance(item, dict):
            continue

        findings.append({
            "tool": item.get("tool", "yara"),
            "severity": item.get("severity", "Info"),
            "finding": item.get(
                "finding",
                item.get("rule", "YARA finding")
            ),
            "cwe": item.get("cwe", "N/A"),
            "details": item.get("details", ""),
            "remediation": item.get(
                "remediation",
                "Review the YARA match and investigate the affected file."
            )
        })

    return findings


