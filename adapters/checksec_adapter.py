#!/usr/bin/env python3
import json

import os
import shutil
import stat
import subprocess
import tempfile


MAX_DEB_SIZE = 500 * 1024 * 1024


def _finding(tool, severity, finding, cwe="N/A", details="", remediation="N/A"):
    return {
        "tool": tool,
        "severity": severity,
        "finding": finding,
        "cwe": cwe,
        "details": details,
        "remediation": remediation,
    }


def scan_deb_target(file_path):
    """
    Analyze a Debian package.

    Checks:
      - DEB validity
      - world-writable files
      - executable binaries
      - checksec mitigations
      - LIEF ELF metadata
      - YARA rules
    """

    findings = []

    if not file_path:
        return [_finding(
            "DEB Analyzer",
            "Error",
            "No DEB file supplied",
            details="No file path was provided.",
            remediation="Provide a valid .deb package."
        )]

    file_path = os.path.abspath(os.path.expanduser(file_path))

    if not os.path.exists(file_path):
        return [_finding(
            "DEB Analyzer",
            "Error",
            "File not found",
            details=f"Path: {file_path}",
            remediation="Ensure the DEB file exists."
        )]

    if not os.path.isfile(file_path):
        return [_finding(
            "DEB Analyzer",
            "Error",
            "Path is not a file",
            details=f"Path: {file_path}",
            remediation="Provide a DEB package file."
        )]

    file_size = os.path.getsize(file_path)

    if file_size == 0:
        return [_finding(
            "DEB Analyzer",
            "Error",
            "Invalid DEB: file is empty",
            details="The supplied package is 0 bytes.",
            remediation="Provide a valid Debian package."
        )]

    if file_size > MAX_DEB_SIZE:
        return [_finding(
            "DEB Analyzer",
            "Error",
            "File too large",
            details=f"Package size is {file_size} bytes.",
            remediation="Scan a DEB package smaller than 500 MB."
        )]

    dpkg_path = shutil.which("dpkg-deb")

    if not dpkg_path:
        return [_finding(
            "dpkg-deb",
            "Error",
            "dpkg-deb not installed",
            details="dpkg-deb was not found in PATH.",
            remediation="Install dpkg with: sudo apt install dpkg"
        )]

    extract_dir = tempfile.mkdtemp(prefix="dast_deb_")

    try:
        # ------------------------------------------------------------
        # 1. Validate DEB
        # ------------------------------------------------------------

        info_result = subprocess.run(
            [dpkg_path, "--info", file_path],
            capture_output=True,
            text=True,
            timeout=30
        )

        if info_result.returncode != 0:
            return [_finding(
                "dpkg-deb",
                "Error",
                "Invalid DEB package",
                details=(info_result.stderr or info_result.stdout).strip()[:1000],
                remediation="Provide a valid Debian .deb package."
            )]

        # ------------------------------------------------------------
        # 2. Extract package
        # ------------------------------------------------------------

        subprocess.run(
            [dpkg_path, "-x", file_path, extract_dir],
            check=True,
            capture_output=True,
            text=True,
            timeout=120
        )

        print(f"[*] DEB extracted to {extract_dir}")

        # ------------------------------------------------------------
        # 3. World-writable files
        # ------------------------------------------------------------

        world_writable = []

        for root, dirs, files in os.walk(extract_dir):

            for name in files:

                full_path = os.path.join(root, name)

                try:
                    mode = os.stat(full_path).st_mode

                    if mode & stat.S_IWOTH:
                        world_writable.append(full_path)

                except OSError:
                    continue

        if world_writable:
            findings.append(_finding(
                "dpkg-deb",
                "High",
                "World-Writable Files Detected",
                "CWE-732",
                (
                    f"{len(world_writable)} world-writable file(s) found. "
                    f"Example: {world_writable[0]}"
                ),
                "Remove unnecessary world-write permissions using chmod and package permission controls."
            ))
        else:
            findings.append(_finding(
                "dpkg-deb",
                "Info",
                "No World-Writable Files Detected",
                details="No extracted package files were writable by everyone.",
                remediation="N/A"
            ))

        # ------------------------------------------------------------
        # 4. Find executable files
        # ------------------------------------------------------------

        executable_files = []

        for root, dirs, files in os.walk(extract_dir):

            for name in files:

                full_path = os.path.join(root, name)

                try:
                    if os.access(full_path, os.X_OK):
                        executable_files.append(full_path)
                except OSError:
                    continue

        # ------------------------------------------------------------
        # 5. checksec
        # ------------------------------------------------------------

        checksec_path = shutil.which("checksec")

        if not checksec_path:
            findings.append(_finding(
                "checksec",
                "Warning",
                "checksec not installed",
                details="checksec was not found in PATH.",
                remediation="Install checksec with: sudo apt install checksec"
            ))

        elif executable_files:

            checked_binaries = 0
            missing_pie = 0
            missing_relro = 0
            missing_nx = 0
            missing_canary = 0

            for binary in executable_files[:100]:

                try:
                    result = subprocess.run(
                        [checksec_path, "--file", binary],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    output = (
                        result.stdout + "\n" + result.stderr
                    ).lower()

                    checked_binaries += 1

                    if "no pie" in output or "pie: no" in output:
                        missing_pie += 1

                    if "no relro" in output or "relro: no" in output:
                        missing_relro += 1

                    if "nx: no" in output or "nx disabled" in output:
                        missing_nx += 1

                    if "canary: no" in output:
                        missing_canary += 1

                except (subprocess.TimeoutExpired, OSError):
                    continue

            if missing_pie:
                findings.append(_finding(
                    "checksec",
                    "Medium",
                    "Missing PIE Protection",
                    "CWE-693",
                    f"{missing_pie} executable(s) appear to lack PIE.",
                    "Compile position-independent executables using -fPIE -pie."
                ))

            if missing_relro:
                findings.append(_finding(
                    "checksec",
                    "Medium",
                    "Missing RELRO Protection",
                    "CWE-693",
                    f"{missing_relro} executable(s) appear to lack RELRO.",
                    "Use appropriate linker flags such as -Wl,-z,relro,-z,now."
                ))

            if missing_nx:
                findings.append(_finding(
                    "checksec",
                    "Medium",
                    "NX/DEP Protection Missing",
                    "CWE-693",
                    f"{missing_nx} executable(s) appear to lack NX protection.",
                    "Enable non-executable memory protections during compilation/linking."
                ))

            if missing_canary:
                findings.append(_finding(
                    "checksec",
                    "Low",
                    "Stack Canary Protection Missing",
                    "CWE-693",
                    f"{missing_canary} executable(s) appear to lack stack canaries.",
                    "Consider compiling with stack-protector protections."
                ))

            findings.append(_finding(
                "checksec",
                "Info",
                "checksec analysis completed",
                details=f"Analyzed {checked_binaries} executable file(s) from the package.",
                remediation="Review mitigation findings above."
            ))

        else:
            findings.append(_finding(
                "checksec",
                "Info",
                "No executable binaries found",
                details="No executable files were identified in the extracted package.",
                remediation="N/A"
            ))

        # ------------------------------------------------------------
        # 6. LIEF analysis
        # ------------------------------------------------------------

        try:
            import lief

            elf_count = 0

            for binary_path in executable_files[:100]:

                try:
                    binary = lief.parse(binary_path)

                    if binary is None:
                        continue

                    elf_count += 1

                    # Modern LIEF objects expose sections through .sections.
                    for section in getattr(binary, "sections", []):

                        name = getattr(section, "name", "")

                        flags = getattr(section, "flags", 0)

                        # ELF SHF_WRITE is 0x1.
                        if name == ".text" and isinstance(flags, int):
                            if flags & 0x1:
                                findings.append(_finding(
                                    "lief",
                                    "High",
                                    "Writable .text Section",
                                    "CWE-732",
                                    f"Executable section .text is writable in {binary_path}.",
                                    "Remove write permission from executable code sections."
                                ))

                except Exception:
                    continue

            findings.append(_finding(
                "lief",
                "Info",
                "LIEF analysis completed",
                details=f"Successfully parsed {elf_count} binary file(s).",
                remediation="Review any LIEF security findings."
            ))

        except ImportError:
            findings.append(_finding(
                "lief",
                "Warning",
                "LIEF library not installed",
                details="Python LIEF package is unavailable.",
                remediation="Install LIEF with: pip install lief"
            ))

        # ------------------------------------------------------------
        # 7. YARA
        # ------------------------------------------------------------

        yara_path = shutil.which("yara")

        if not yara_path:
            findings.append(_finding(
                "yara",
                "Warning",
                "YARA not installed",
                details="YARA executable was not found in PATH.",
                remediation="Install YARA with: sudo apt install yara"
            ))

        else:

            project_root = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..")
            )

            rules_dir = os.path.join(project_root, "rules")

            if not os.path.isdir(rules_dir):
                findings.append(_finding(
                    "yara",
                    "Info",
                    "YARA scan skipped",
                    details="No rules directory was found.",
                    remediation="Add YARA rules under the project's rules/ directory."
                ))

            else:

                rule_files = []

                for root, dirs, files in os.walk(rules_dir):
                    for name in files:
                        if name.endswith((".yar", ".yara")):
                            rule_files.append(os.path.join(root, name))

                if not rule_files:

                    findings.append(_finding(
                        "yara",
                        "Info",
                        "YARA scan skipped",
                        details="The rules directory contains no .yar or .yara files.",
                        remediation="Add YARA rules to the project's rules/ directory."
                    ))

                else:

                    matched = False

                    for rule_file in rule_files:

                        try:
                            result = subprocess.run(
                                [yara_path, "-r", rule_file, extract_dir],
                                capture_output=True,
                                text=True,
                                timeout=120
                            )

                            for line in result.stdout.splitlines():

                                if not line.strip():
                                    continue

                                matched = True
                                parts = line.split(maxsplit=1)
                                rule_name = parts[0]

                                findings.append(_finding(
                                    "yara",
                                    "High",
                                    f"YARA Rule Match: {rule_name}",
                                    "CWE-506",
                                    f"YARA rule matched package content: {line[:500]}",
                                    "Investigate the matched content and determine whether it is malicious or unauthorized."
                                ))

                        except subprocess.TimeoutExpired:
                            findings.append(_finding(
                                "yara",
                                "Warning",
                                "YARA scan timed out",
                                details=f"Rule scan exceeded 120 seconds: {rule_file}",
                                remediation="Review the YARA rules and scan package contents separately."
                            ))

                    if not matched:
                        findings.append(_finding(
                            "yara",
                            "Info",
                            "YARA scan completed with no matches",
                            details=f"Scanned using {len(rule_files)} YARA rule file(s).",
                            remediation="N/A"
                        ))

    except subprocess.TimeoutExpired:
        findings.append(_finding(
            "DEB Analyzer",
            "Error",
            "DEB analysis timed out",
            details="Package processing exceeded the configured timeout.",
            remediation="Try a smaller or less complex package."
        ))

    except subprocess.CalledProcessError as e:
        findings.append(_finding(
            "DEB Analyzer",
            "Error",
            "DEB extraction failed",
            details=(e.stderr or str(e))[:1000],
            remediation="Ensure the file is a valid Debian package."
        ))

    except Exception as e:
        findings.append(_finding(
            "DEB Analyzer",
            "Error",
            "Analysis failed",
            details=str(e),
            remediation="Ensure the DEB package and analysis dependencies are valid."
        ))

    finally:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir, ignore_errors=True)

    return findings


def parse_checksec_report(raw_report_path):
    """
    Backward-compatible parser for legacy checksec JSON reports.
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

    file_name = data.get("file", "unknown")

    relro = str(data.get("relro", "")).lower()
    canary = str(data.get("canary", "")).lower()
    nx = str(data.get("nx", "")).lower()
    pie = str(data.get("pie", "")).lower()

    if relro in {"no", "none", "disabled"}:
        findings.append(
            _finding(
                "checksec",
                "Medium",
                "RELRO Disabled",
                cwe="CWE-693",
                details=f"'{file_name}' does not have RELRO enabled.",
                remediation=(
                    "Compile/link with appropriate RELRO options, "
                    "such as -Wl,-z,relro,-z,now."
                )
            )
        )

    elif relro == "partial":
        findings.append(
            _finding(
                "checksec",
                "Low",
                "Partial RELRO",
                cwe="CWE-693",
                details=f"'{file_name}' has only Partial RELRO.",
                remediation=(
                    "Prefer Full RELRO using "
                    "-Wl,-z,relro,-z,now."
                )
            )
        )

    if canary in {"no", "disabled", "none"}:
        findings.append(
            _finding(
                "checksec",
                "Medium",
                "Stack Canary Disabled",
                cwe="CWE-693",
                details=f"'{file_name}' does not use a stack canary.",
                remediation=(
                    "Recompile with stack protector support, "
                    "for example -fstack-protector-strong."
                )
            )
        )

    if nx in {"no", "disabled"}:
        findings.append(
            _finding(
                "checksec",
                "Medium",
                "NX Disabled",
                cwe="CWE-693",
                details=f"'{file_name}' does not have NX enabled.",
                remediation=(
                    "Enable non-executable memory protections "
                    "during compilation/linking."
                )
            )
        )

    if pie in {"no", "disabled"}:
        findings.append(
            _finding(
                "checksec",
                "Medium",
                "PIE Disabled",
                cwe="CWE-693",
                details=f"'{file_name}' is not compiled as PIE.",
                remediation="Recompile using -fPIE -pie."
            )
        )

    if not findings:
        findings.append(
            _finding(
                "checksec",
                "Info",
                "checksec metadata parsed",
                details=(
                    f"Security metadata for '{file_name}' "
                    "was parsed successfully."
                ),
                remediation="N/A"
            )
        )

    return findings
