#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
import tempfile
import hashlib
import zipfile


MAX_APK_SIZE = 500 * 1024 * 1024
DECOMPILE_TIMEOUT = 600           # was 180 - too short for real-world APKs;
                                   # full resource+smali decompile of a normal
                                   # sized app routinely takes several minutes
DECOMPILE_TIMEOUT_NO_RES = 240    # fallback pass, resources skipped, much faster

# ------------------------------------------------------------------
# In-memory record of every APK hash this process has scanned.
# This is what lets us tell you, on the dashboard, whether "two
# different scans returned the same result" because:
#   (a) you actually uploaded the exact same file twice, or
#   (b) two genuinely different files just happen to have identical
#       manifest/code findings (common with template apps whose
#       differences live only in assets/resources).
# NOTE: this resets when the Flask process restarts. If you need it
# to survive restarts, swap this dict for a small SQLite table.
# ------------------------------------------------------------------
_SEEN_APK_HASHES = {}


def _finding(tool, severity, finding, cwe="N/A", details="", remediation="N/A"):
    return {
        "tool": tool,
        "severity": severity,
        "finding": finding,
        "cwe": cwe,
        "details": details,
        "remediation": remediation,
    }


def _sha256_of_file(file_path, chunk_size=1024 * 1024):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _zip_structure_fingerprint(file_path):
    """
    Fingerprint the APK's internal file listing (names + sizes),
    independent of any --no-assets / --no-src flags used later during
    decompilation. Two APKs with genuinely different content (even if
    just different images/resources) will get different fingerprints
    here, which is useful for confirming the adapter really is looking
    at two distinct files.

    Returns (entry_count, fingerprint_hash) or (0, None) on failure.
    """
    try:
        with zipfile.ZipFile(file_path) as zf:
            entries = sorted(
                f"{info.filename}:{info.file_size}"
                for info in zf.infolist()
            )
        fingerprint = hashlib.sha256(
            "\n".join(entries).encode("utf-8", errors="ignore")
        ).hexdigest()
        return len(entries), fingerprint
    except Exception:
        return 0, None


def _apktool_version(apktool_path):
    try:
        result = subprocess.run(
            [apktool_path, "--version"],
            capture_output=True,
            text=True,
            timeout=15
        )
        return (result.stdout or result.stderr or "").strip() or "unknown"
    except Exception:
        return "unknown"


def scan_apk_target(file_path):
    """
    Static Android APK analysis.

    Pipeline:
      1. Validate APK
      2. Hash + fingerprint the file (proves which file was actually scanned,
         and flags exact duplicate uploads)
      3. Decompile with apktool
      4. Inspect AndroidManifest.xml (package/version/permissions + risk flags)
      5. Search for potentially hardcoded secrets
      6. Search for insecure storage indicators
      7. Check network security configuration
      8. Return findings
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

    # ------------------------------------------------------------
    # Identity check: hash + zip fingerprint FIRST, before anything
    # else can fail. This is the single most important addition for
    # debugging "two different APKs gave the same result" -- it puts
    # the proof of *which file was scanned* directly in the report.
    # ------------------------------------------------------------
    file_hash = _sha256_of_file(file_path)
    entry_count, zip_fingerprint = _zip_structure_fingerprint(file_path)

    duplicate_of = _SEEN_APK_HASHES.get(file_hash)
    _SEEN_APK_HASHES[file_hash] = os.path.basename(file_path)

    if duplicate_of:
        findings.append(_finding(
            "APK Analyzer",
            "Warning",
            "Duplicate APK detected (identical SHA-256)",
            details=(
                f"This upload is byte-for-byte identical to a previously "
                f"scanned file ('{duplicate_of}'). If you expected a "
                f"different app, double-check the file you're uploading -- "
                f"the adapter is correctly reporting identical findings "
                f"because it is, in fact, the same file."
            ),
            remediation="Confirm you're selecting the intended APK before scanning."
        ))

    findings.append(_finding(
        "APK Analyzer",
        "Info",
        "Scanned File Identity",
        details=(
            f"Filename: {os.path.basename(file_path)} | "
            f"Size: {file_size} bytes | "
            f"SHA-256: {file_hash} | "
            f"Zip entries: {entry_count} | "
            f"Structure fingerprint: {zip_fingerprint}"
        ),
        remediation="N/A -- informational, use this to confirm which file was analyzed."
    ))

    apktool_path = shutil.which("apktool")

    if not apktool_path:
        findings.append(_finding(
            "apktool",
            "Error",
            "apktool not installed",
            details="apktool was not found in PATH. All apktool-dependent checks below were skipped.",
            remediation="Install apktool with: sudo apt install apktool"
        ))
        return findings

    apktool_version = _apktool_version(apktool_path)

    # Verify that the APK is actually a ZIP/APK before invoking apktool.
    try:
        zip_test = subprocess.run(
            ["unzip", "-t", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        if zip_test.returncode != 0:
            findings.append(_finding(
                "APK Analyzer",
                "Error",
                "Invalid or corrupted APK",
                details=(
                    "The supplied file is not a valid ZIP/APK archive. "
                    f"{(zip_test.stderr or zip_test.stdout).strip()[:500]}"
                ),
                remediation="Provide a valid Android APK file."
            ))
            return findings

    except FileNotFoundError:
        # unzip is optional; apktool will perform the actual validation.
        pass
    except subprocess.TimeoutExpired:
        findings.append(_finding(
            "APK Analyzer",
            "Error",
            "APK validation timed out",
            details="Archive validation exceeded 30 seconds.",
            remediation="Try a smaller or valid APK."
        ))
        return findings

    # Unique per-invocation decompile dir (tied to the file hash too,
    # so it's trivially traceable in logs which run produced which dir).
    decompile_dir = tempfile.mkdtemp(prefix=f"dast_apk_{file_hash[:12]}_")

    try:
        print(f"[*] Decompiling APK: {file_path}")
        print(f"[*] SHA-256: {file_hash}")
        print(f"[*] apktool version: {apktool_version}")
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
            # Full decode (resources + smali) timed out. Retry with -r
            # (skip resource decoding) - much faster, and still gives us
            # AndroidManifest.xml + smali for the permission/secret/cert
            # pinning checks below, instead of returning nothing at all.
            print(f"[*] Full decode exceeded {DECOMPILE_TIMEOUT}s, retrying without resources...")
            shutil.rmtree(decompile_dir, ignore_errors=True)
            os.makedirs(decompile_dir, exist_ok=True)

            try:
                result = subprocess.run(
                    [
                        apktool_path,
                        "d",
                        file_path,
                        "-o",
                        decompile_dir,
                        "-f",
                        "-r",              # skip resource decoding
                        "--no-assets"
                    ],
                    capture_output=True,
                    text=True,
                    timeout=DECOMPILE_TIMEOUT_NO_RES
                )
                findings.append(_finding(
                    "apktool",
                    "Info",
                    "Partial decompilation (resources skipped)",
                    details=(
                        f"Full decompilation exceeded {DECOMPILE_TIMEOUT}s, so resource "
                        "decoding was skipped to finish in time. Manifest and smali-based "
                        "findings below are still valid; resource/strings.xml-based checks "
                        "were not performed on this run."
                    ),
                    remediation="Re-run with a longer DECOMPILE_TIMEOUT if full resource analysis is needed."
                ))
            except subprocess.TimeoutExpired:
                findings.append(_finding(
                    "apktool",
                    "Error",
                    "Decompilation timed out",
                    details=(
                        f"APK decompilation exceeded {DECOMPILE_TIMEOUT}s (full) and "
                        f"{DECOMPILE_TIMEOUT_NO_RES}s (resources skipped, retry). "
                        "This APK is unusually large or apktool is struggling with it."
                    ),
                    remediation="Try a smaller APK, or increase DECOMPILE_TIMEOUT / DECOMPILE_TIMEOUT_NO_RES."
                ))
                return findings

        if result.returncode != 0:
            error_output = (result.stderr or result.stdout or "").strip()

            findings.append(_finding(
                "apktool",
                "Error",
                "APK decompilation failed",
                details=(
                    f"apktool {apktool_version} failed on this specific file "
                    f"(SHA-256 {file_hash[:16]}...). Raw output: "
                    f"{error_output[:1000] or 'apktool returned a non-zero exit code.'}"
                ),
                remediation=(
                    "This is often caused by an outdated apktool that doesn't "
                    "recognize newer AAPT2 resource formats. Try: "
                    "'apktool empty-framework-dir --force' then update apktool, "
                    "or run 'apktool d <file> -o <dir> -f' manually to see the "
                    "full traceback."
                )
            ))
            return findings

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

                # Package identity -- shown so you can visually confirm
                # on the dashboard that two scans really are two different apps.
                package_match = re.search(r'package\s*=\s*"([^"]+)"', manifest)
                version_name_match = re.search(r'android:versionName\s*=\s*"([^"]+)"', manifest)
                version_code_match = re.search(r'android:versionCode\s*=\s*"([^"]+)"', manifest)
                permissions = re.findall(
                    r'<uses-permission[^>]*android:name\s*=\s*"([^"]+)"',
                    manifest,
                    re.IGNORECASE
                )

                findings.append(_finding(
                    "apktool",
                    "Info",
                    "Application Identity",
                    details=(
                        f"Package: {package_match.group(1) if package_match else 'unknown'} | "
                        f"Version name: {version_name_match.group(1) if version_name_match else 'unknown'} | "
                        f"Version code: {version_code_match.group(1) if version_code_match else 'unknown'} | "
                        f"Declared permissions: {len(permissions)}"
                    ),
                    remediation="N/A -- informational."
                ))

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
