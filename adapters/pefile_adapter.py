#!/usr/bin/env python3

import os
import re
import json
import shutil
import hashlib
import subprocess

try:
    import pefile
except ImportError:
    pefile = None


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


def _run_command(command, timeout=60):
    """
    Safely execute an external command.
    """
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False
    )


_SEEN_EXE_HASHES = {}


def _sha256_of_file(file_path, chunk_size=1024 * 1024):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _validate_file(file_path):
    if not file_path:
        return False, "No file path supplied."

    if not os.path.exists(file_path):
        return False, f"File does not exist: {file_path}"

    if not os.path.isfile(file_path):
        return False, f"Path is not a regular file: {file_path}"

    try:
        if os.path.getsize(file_path) == 0:
            return False, "File is empty (0 bytes)."
    except OSError as exc:
        return False, f"Unable to read file size: {exc}"

    return True, ""


def _scan_pe_security(pe, file_name):
    findings = []

    try:
        dll_characteristics = pe.OPTIONAL_HEADER.DllCharacteristics

        # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
        aslr_enabled = bool(dll_characteristics & 0x0040)

        # IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
        dep_enabled = bool(dll_characteristics & 0x0100)

        # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
        high_entropy_aslr = bool(dll_characteristics & 0x0020)

        # IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
        cfg_enabled = bool(dll_characteristics & 0x4000)

        if aslr_enabled:
            findings.append(
                _finding(
                    "pefile",
                    "Info",
                    "ASLR Enabled",
                    details=f"'{file_name}' has Address Space Layout Randomization enabled.",
                    remediation="N/A"
                )
            )
        else:
            findings.append(
                _finding(
                    "pefile",
                    "Medium",
                    "ASLR Not Enabled",
                    cwe="CWE-120",
                    details=f"'{file_name}' does not have ASLR enabled.",
                    remediation="Recompile the application with ASLR enabled."
                )
            )

        if dep_enabled:
            findings.append(
                _finding(
                    "pefile",
                    "Info",
                    "DEP/NX Enabled",
                    details=f"'{file_name}' has DEP/NX enabled.",
                    remediation="N/A"
                )
            )
        else:
            findings.append(
                _finding(
                    "pefile",
                    "Medium",
                    "DEP/NX Not Enabled",
                    cwe="CWE-693",
                    details=f"'{file_name}' does not have DEP/NX enabled.",
                    remediation="Enable DEP/NX compatibility during compilation."
                )
            )

        if high_entropy_aslr:
            findings.append(
                _finding(
                    "pefile",
                    "Info",
                    "High Entropy ASLR Enabled",
                    details="High Entropy ASLR is enabled.",
                    remediation="N/A"
                )
            )

        if cfg_enabled:
            findings.append(
                _finding(
                    "pefile",
                    "Info",
                    "Control Flow Guard Enabled",
                    details="Control Flow Guard is enabled.",
                    remediation="N/A"
                )
            )

        if aslr_enabled and dep_enabled:
            findings.append(
                _finding(
                    "pefile",
                    "Info",
                    "Security Mitigations Enabled",
                    details=f"'{file_name}' has ASLR and DEP enabled.",
                    remediation="N/A"
                )
            )

    except Exception as exc:
        findings.append(
            _finding(
                "pefile",
                "Warning",
                "PE security analysis incomplete",
                details=str(exc),
                remediation="Ensure the executable is a valid PE file."
            )
        )

    return findings


def _scan_manalyze(file_path):
    findings = []

    manalyze_path = shutil.which("manalyze")

    if not manalyze_path:
        findings.append(
            _finding(
                "manalyze",
                "Warning",
                "Manalyze not installed",
                details="Manalyze executable was not found in PATH.",
                remediation="Install Manalyze and make sure it is available through PATH."
            )
        )
        return findings

    try:
        print(f"[*] Running Manalyze: {manalyze_path}")

        result = _run_command(
            [manalyze_path, file_path],
            timeout=90
        )

        output = (result.stdout or "") + "\n" + (result.stderr or "")

        if not output.strip():
            findings.append(
                _finding(
                    "manalyze",
                    "Warning",
                    "Manalyze returned no output",
                    details=f"Manalyze exited with code {result.returncode}.",
                    remediation="Verify the executable and Manalyze installation."
                )
            )
            return findings

        lower_output = output.lower()

        # Suspicious APIs
        suspicious_apis = [
            "virtualalloc",
            "virtualallocex",
            "writeprocessmemory",
            "createremotethread",
            "ntwritevirtualmemory",
            "winexec",
            "shellexecute",
            "shellexecuteex",
            "createprocess",
            "urlmon",
            "internetopen",
            "internetopenurl"
        ]

        detected_apis = [
            api for api in suspicious_apis
            if api.lower() in lower_output
        ]

        if detected_apis:
            findings.append(
                _finding(
                    "manalyze",
                    "Medium",
                    "Suspicious API Imports Detected",
                    cwe="CWE-94",
                    details=(
                        "Manalyze identified potentially security-sensitive APIs: "
                        + ", ".join(detected_apis)
                    ),
                    remediation=(
                        "Review the use of these APIs and verify that they are "
                        "required and safely implemented."
                    )
                )
            )

        # Packing
        packing_terms = [
            "packed",
            "upx",
            "packer",
            "protector",
            "obfuscator"
        ]

        detected_packing = [
            term for term in packing_terms
            if term in lower_output
        ]

        if detected_packing:
            findings.append(
                _finding(
                    "manalyze",
                    "Medium",
                    "Possible Packing or Obfuscation Detected",
                    cwe="CWE-656",
                    details=(
                        "Manalyze output contains indicators associated with "
                        "packing or obfuscation: "
                        + ", ".join(sorted(set(detected_packing)))
                    ),
                    remediation=(
                        "Determine whether packing is legitimate. "
                        "If unexpected, perform additional malware analysis."
                    )
                )
            )

        # Anti-debugging indicators
        anti_debug_terms = [
            "isdebuggerpresent",
            "checkremotedebuggerpresent",
            "outputdebugstring",
            "ntqueryinformationprocess"
        ]

        detected_debug = [
            term for term in anti_debug_terms
            if term in lower_output
        ]

        if detected_debug:
            findings.append(
                _finding(
                    "manalyze",
                    "Low",
                    "Potential Anti-Debugging Indicators",
                    details=(
                        "Potential anti-debugging APIs were identified: "
                        + ", ".join(detected_debug)
                    ),
                    remediation=(
                        "Review these APIs to determine whether their use "
                        "is legitimate."
                    )
                )
            )

        # If Manalyze successfully executed but found nothing our parser
        # considers suspicious, report informational completion.
        if not any(f["tool"] == "manalyze" for f in findings):
            findings.append(
                _finding(
                    "manalyze",
                    "Info",
                    "Manalyze scan completed",
                    details="Manalyze completed without matching configured suspicious indicators.",
                    remediation="N/A"
                )
            )

    except subprocess.TimeoutExpired:
        findings.append(
            _finding(
                "manalyze",
                "Warning",
                "Manalyze scan timed out",
                details="Manalyze exceeded the 90-second execution limit.",
                remediation="Retry with a smaller executable or increase the timeout."
            )
        )

    except Exception as exc:
        findings.append(
            _finding(
                "manalyze",
                "Warning",
                "Manalyze scan failed",
                details=str(exc),
                remediation="Verify the Manalyze installation and PE file."
            )
        )

    return findings


def _scan_yara(file_path):
    findings = []

    yara_path = shutil.which("yara")

    if not yara_path:
        findings.append(
            _finding(
                "yara",
                "Warning",
                "YARA not installed",
                details="YARA executable was not found in PATH.",
                remediation="Install YARA using the system package manager."
            )
        )
        return findings

    try:
        rules_dir = None

        # Project rules
        project_rules = os.path.abspath("rules")

        if os.path.isdir(project_rules):
            rules_dir = project_rules

        # System rules
        elif os.path.isdir("/usr/share/yara/rules"):
            rules_dir = "/usr/share/yara/rules"

        if not rules_dir:
            findings.append(
                _finding(
                    "yara",
                    "Info",
                    "YARA scan skipped",
                    details="No YARA rules directory was found.",
                    remediation="Add YARA rules under the project's rules/ directory."
                )
            )
            return findings

        print(f"[*] Running YARA using rules: {rules_dir}")

        result = _run_command(
            [yara_path, "-r", rules_dir, file_path],
            timeout=90
        )

        output = (result.stdout or "").strip()
        error = (result.stderr or "").strip()

        if result.returncode not in (0, 1):
            findings.append(
                _finding(
                    "yara",
                    "Warning",
                    "YARA scan failed",
                    details=error[:500] if error else output[:500],
                    remediation="Check the YARA rules and binary."
                )
            )
            return findings

        if output:
            matches = output.splitlines()

            for match in matches[:30]:
                findings.append(
                    _finding(
                        "yara",
                        "High",
                        "YARA Rule Match Detected",
                        cwe="N/A",
                        details=match[:500],
                        remediation=(
                            "Investigate the matched YARA rule and "
                            "determine whether the executable is malicious."
                        )
                    )
                )
        else:
            findings.append(
                _finding(
                    "yara",
                    "Info",
                    "YARA scan completed with no matches",
                    details="No configured YARA rules matched the binary.",
                    remediation="N/A"
                )
            )

    except subprocess.TimeoutExpired:
        findings.append(
            _finding(
                "yara",
                "Warning",
                "YARA scan timed out",
                details="YARA exceeded the 90-second execution limit.",
                remediation="Reduce the scan scope or optimize the YARA rules."
            )
        )

    except Exception as exc:
        findings.append(
            _finding(
                "yara",
                "Warning",
                "YARA scan failed",
                details=str(exc),
                remediation="Check the YARA installation and rules."
            )
        )

    return findings


def scan_exe_target(file_path):
    """
    Complete PE/EXE analysis.

    Engines:
        - pefile
        - Manalyze
        - YARA
    """

    findings = []

    valid, error = _validate_file(file_path)

    if not valid:
        return [
            _finding(
                "pefile",
                "Error",
                "Invalid PE input",
                details=error,
                remediation="Provide a valid non-empty Windows PE executable."
            )
        ]

    file_name = os.path.basename(file_path)

    # ==========================================================
    # 0. IDENTITY (hash + duplicate-upload detection)
    # ==========================================================

    try:
        file_size = os.path.getsize(file_path)
        file_hash = _sha256_of_file(file_path)

        duplicate_of = _SEEN_EXE_HASHES.get(file_hash)
        _SEEN_EXE_HASHES[file_hash] = file_name

        if duplicate_of:
            findings.append(
                _finding(
                    "PE Analyzer",
                    "Warning",
                    "Duplicate Executable Detected (identical SHA-256)",
                    details=(
                        f"This upload is byte-for-byte identical to a "
                        f"previously scanned file ('{duplicate_of}'). If you "
                        f"expected a different binary, double-check the file "
                        f"you're uploading."
                    ),
                    remediation="Confirm you're selecting the intended executable before scanning."
                )
            )

        findings.append(
            _finding(
                "PE Analyzer",
                "Info",
                "Scanned File Identity",
                details=(
                    f"Filename: {file_name} | "
                    f"Size: {file_size} bytes | "
                    f"SHA-256: {file_hash}"
                ),
                remediation="N/A -- informational, use this to confirm which file was analyzed."
            )
        )
    except OSError as exc:
        findings.append(
            _finding(
                "PE Analyzer",
                "Warning",
                "Could not hash file",
                details=str(exc),
                remediation="Verify file permissions and disk access."
            )
        )

    # ==========================================================
    # 1. PEFILE
    # ==========================================================

    if pefile is None:
        findings.append(
            _finding(
                "pefile",
                "Error",
                "PEFile library not installed",
                details="Python pefile package is unavailable.",
                remediation="Install with: pip install pefile"
            )
        )
    else:
        try:
            print(f"[*] Running PE analysis: {file_path}")

            pe = pefile.PE(file_path)

            findings.extend(
                _scan_pe_security(pe, file_name)
            )

            pe.close()

        except pefile.PEFormatError as exc:
            findings.append(
                _finding(
                    "pefile",
                    "Error",
                    "Invalid PE executable",
                    details=str(exc),
                    remediation="Provide a valid Windows PE executable."
                )
            )

        except Exception as exc:
            findings.append(
                _finding(
                    "pefile",
                    "Error",
                    "PE analysis failed",
                    details=str(exc),
                    remediation="Ensure the file is a valid PE executable."
                )
            )

    # ==========================================================
    # 2. MANALYZE
    # ==========================================================

    findings.extend(
        _scan_manalyze(file_path)
    )

    # ==========================================================
    # 3. YARA
    # ==========================================================

    findings.extend(
        _scan_yara(file_path)
    )

    return findings


def parse_pefile_report(raw_report_path):
    """
    Backward-compatible parser for legacy pefile JSON reports.
    """
    findings = []

    if not os.path.exists(raw_report_path):
        return findings

    try:
        with open(
            raw_report_path,
            "r",
            encoding="utf-8",
            errors="replace"
        ) as handle:
            data = json.load(handle)
    except Exception:
        return findings

    if not isinstance(data, dict):
        return findings

    file_name = data.get(
        "file_name",
        os.path.basename(raw_report_path)
    )

    if data.get("is_packed"):
        findings.append(
            {
                "tool": "pefile",
                "severity": "Medium",
                "finding": "Packed Executable",
                "cwe": "N/A",
                "details": (
                    f"'{file_name}' is marked as packed."
                ),
                "remediation": (
                    "Investigate the packing mechanism and "
                    "validate the executable's origin."
                )
            }
        )

    if data.get("is_suspicious"):
        findings.append(
            {
                "tool": "pefile",
                "severity": "High",
                "finding": "Suspicious Executable Indicators",
                "cwe": "N/A",
                "details": (
                    f"'{file_name}' contains suspicious "
                    "indicators according to the supplied metadata."
                ),
                "remediation": (
                    "Perform deeper static analysis and "
                    "validate suspicious imports, sections, "
                    "and executable behavior."
                )
            }
        )

    if not findings:
        findings.append(
            {
                "tool": "pefile",
                "severity": "Info",
                "finding": "PE metadata parsed",
                "cwe": "N/A",
                "details": (
                    f"Successfully parsed metadata for '{file_name}'."
                ),
                "remediation": "N/A"
            }
        )

    return findings
