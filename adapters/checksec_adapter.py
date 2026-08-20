#!/usr/bin/env python3
import subprocess
import os
import shutil

def scan_deb_target(file_path):
    """
    Analyzes Linux DEB packages using dpkg-deb, LIEF, checksec, and YARA.
    """
    findings = []
    extract_dir = "/tmp/deb_extracted_dynamic"

    if not os.path.exists(file_path):
        return [{
            "tool": "checksec",
            "severity": "Error",
            "finding": "File not found",
            "cwe": "N/A",
            "details": f"Path: {file_path}",
            "remediation": "Ensure file exists."
        }]

    file_size = os.path.getsize(file_path)
    if file_size > 500 * 1024 * 1024:  # 500MB limit
        return [{
            "tool": "checksec",
            "severity": "Error",
            "finding": "File too large",
            "cwe": "N/A",
            "details": f"File size {file_size} exceeds 500MB limit",
            "remediation": "Scan smaller files only"
        }]

    try:
        # === 1. EXTRACT DEB WITH dpkg-deb ===
        dpkg_path = shutil.which('dpkg-deb')
        if not dpkg_path:
            return [{
                "tool": "dpkg-deb",
                "severity": "Error",
                "finding": "dpkg-deb not installed",
                "cwe": "N/A",
                "details": "dpkg-deb tool not found",
                "remediation": "Install dpkg: sudo apt install dpkg"
            }]

        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir)
        
        subprocess.run(
            ['dpkg-deb', '-x', file_path, extract_dir],
            check=True,
            capture_output=True
        )
        print(f"[*] DEB extracted to {extract_dir}")

        # === 2. CHECK FOR WORLD-WRITABLE FILES ===
        find_result = subprocess.run(
            ['find', extract_dir, '-type', 'f', '-perm', '-002'],
            capture_output=True,
            text=True
        )
        
        if find_result.stdout.strip():
            findings.append({
                "tool": "dpkg-deb/find",
                "severity": "High",
                "finding": "World-Writable Files Detected",
                "cwe": "CWE-732",
                "details": f"Files: {find_result.stdout.strip().splitlines()[0]}",
                "remediation": "Fix permissions with chmod o-w <file>"
            })

        # === 3. RUN CHECKSEC ===
        checksec_path = shutil.which('checksec')
        if checksec_path:
            checksec_result = subprocess.run(
                [checksec_path, '--dir', extract_dir],
                capture_output=True,
                text=True
            )
            
            output = checksec_result.stdout + "\n" + checksec_result.stderr
            
            if "No PIE" in output or "pie: no" in output.lower() or "pie: disabled" in output.lower():
                findings.append({
                    "tool": "checksec",
                    "severity": "Medium",
                    "finding": "Missing PIE (Position Independent Executable)",
                    "cwe": "CWE-121",
                    "details": "Binaries not compiled with PIE",
                    "remediation": "Recompile with -fPIE -pie flags"
                })
                
            if "No RELRO" in output or "relro: no" in output.lower():
                findings.append({
                    "tool": "checksec",
                    "severity": "Medium",
                    "finding": "Missing RELRO",
                    "cwe": "CWE-121",
                    "details": "Binaries missing RELRO protection",
                    "remediation": "Recompile with -Wl,-z,relro,-z,now"
                })
                
            if not findings:
                findings.append({
                    "tool": "checksec",
                    "severity": "Info",
                    "finding": "Package passed basic security checks",
                    "cwe": "N/A",
                    "details": "No critical issues detected by checksec",
                    "remediation": "N/A"
                })
        else:
            findings.append({
                "tool": "checksec",
                "severity": "Warning",
                "finding": "checksec not installed",
                "cwe": "N/A",
                "details": "checksec tool not found in PATH",
                "remediation": "Install checksec: sudo apt install checksec"
            })

        # === 4. RUN LIEF ===
        try:
            import lief
            binaries_found = 0
            
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path_full = os.path.join(root, file)
                    if os.path.isfile(file_path_full) and os.access(file_path_full, os.X_OK):
                        try:
                            binary = lief.parse(file_path_full)
                            if binary:
                                binaries_found += 1
                                
                                # Check for suspicious sections
                                if binary.has_section('.text'):
                                    section = binary.get_section('.text')
                                    if section.flags & lief.ELF.Section.FLAGS.SHF_WRITE:
                                        findings.append({
                                            "tool": "lief",
                                            "severity": "High",
                                            "finding": "Executable Section is Writable",
                                            "cwe": "CWE-693",
                                            "details": f"Section .text has write permissions in {file}",
                                            "remediation": "Remove write permissions from executable sections"
                                        })
                        except Exception as e:
                            pass  # Not a valid ELF file
                            
            if binaries_found == 0:
                findings.append({
                    "tool": "lief",
                    "severity": "Info",
                    "finding": "No executable binaries found in package",
                    "cwe": "N/A",
                    "details": "Package may contain only scripts or data files",
                    "remediation": "N/A"
                })
                
        except ImportError:
            findings.append({
                "tool": "lief",
                "severity": "Warning",
                "finding": "LIEF library not installed",
                "cwe": "N/A",
                "details": "Python LIEF library is missing",
                "remediation": "Install with: pip3 install lief"
            })
        except Exception as e:
            findings.append({
                "tool": "lief",
                "severity": "Warning",
                "finding": "LIEF analysis failed",
                "cwe": "N/A",
                "details": f"Error: {str(e)}",
                "remediation": "Ensure LIEF is properly installed"
            })

        # === 5. RUN YARA ===
        try:
            yara_path = shutil.which('yara')
            if yara_path:
                yara_rules = "rules/" if os.path.exists("rules/") else None
                
                if yara_rules:
                    result = subprocess.run(
                        [yara_path, '-r', yara_rules, extract_dir],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                else:
                    result = subprocess.run(
                        [yara_path, '-r', '/usr/share/yara/rules/', extract_dir],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                
                if result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        if line and not line.startswith('warning'):
                            parts = line.split()
                            if len(parts) >= 2:
                                rule_name = parts[0]
                                findings.append({
                                    "tool": "yara",
                                    "severity": "High",
                                    "finding": f"YARA Rule Match: {rule_name}",
                                    "cwe": "CWE-506",
                                    "details": f"DEB package content matches YARA rule '{rule_name}'",
                                    "remediation": "Investigate the matched rule for potential malicious content"
                                })
            else:
                findings.append({
                    "tool": "yara",
                    "severity": "Warning",
                    "finding": "YARA not installed",
                    "cwe": "N/A",
                    "details": "YARA tool not found in PATH",
                    "remediation": "Install YARA: sudo apt install yara"
                })
        except subprocess.TimeoutExpired:
            findings.append({
                "tool": "yara",
                "severity": "Warning",
                "finding": "YARA scan timed out",
                "cwe": "N/A",
                "details": "Scan exceeded 120 second timeout",
                "remediation": "Try scanning a smaller package"
            })
        except Exception as e:
            findings.append({
                "tool": "yara",
                "severity": "Warning",
                "finding": "YARA scan failed",
                "cwe": "N/A",
                "details": f"Error: {str(e)}",
                "remediation": "Ensure YARA is properly installed"
            })

    except subprocess.CalledProcessError as e:
        findings.append({
            "tool": "DEB Analyzer",
            "severity": "Error",
            "finding": "DEB extraction failed",
            "cwe": "N/A",
            "details": f"dpkg-deb error: {e.stderr.decode() if e.stderr else str(e)}",
            "remediation": "Ensure file is a valid DEB package"
        })
    except Exception as e:
        findings.append({
            "tool": "DEB Analyzer",
            "severity": "Error",
            "finding": "Analysis failed",
            "cwe": "N/A",
            "details": str(e),
            "remediation": "Ensure file is a valid DEB package"
        })
    finally:
        if os.path.exists(extract_dir):
            try:
                shutil.rmtree(extract_dir)
            except:
                pass

    return findings
