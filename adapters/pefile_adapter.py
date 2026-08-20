#!/usr/bin/env python3
import subprocess
import os
import shutil

def scan_exe_target(file_path):
    """
    Analyzes Windows EXE files using pefile, Manalyze, and YARA.
    """
    findings = []

    if not os.path.exists(file_path):
        return [{
            "tool": "pefile",
            "severity": "Error",
            "finding": "File not found",
            "cwe": "N/A",
            "details": f"Path: {file_path}",
            "remediation": "Ensure the file was uploaded correctly."
        }]

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return [{
            "tool": "pefile",
            "severity": "Error",
            "finding": "File is empty",
            "cwe": "N/A",
            "details": "Uploaded file has 0 bytes",
            "remediation": "Re-upload the file."
        }]

    if file_size > 500 * 1024 * 1024:  # 500MB limit
        return [{
            "tool": "pefile",
            "severity": "Error",
            "finding": "File too large",
            "cwe": "N/A",
            "details": f"File size {file_size} exceeds 500MB limit",
            "remediation": "Scan smaller files only"
        }]

    # === 1. RUN PEFILE ===
    try:
        import pefile
        pe = pefile.PE(file_path)
        file_name = os.path.basename(file_path)
        
        is_aslr = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 
                      pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE'])
        is_dep = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 
                     pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_NX_COMPAT'])

        if not is_aslr:
            findings.append({
                "tool": "pefile",
                "severity": "High",
                "finding": "Missing Security Mitigation: ASLR Disabled",
                "cwe": "CWE-121",
                "details": f"'{file_name}' compiled without ASLR",
                "remediation": "Recompile with /DYNAMICBASE flag"
            })
        
        if not is_dep:
            findings.append({
                "tool": "pefile",
                "severity": "High",
                "finding": "Missing Security Mitigation: DEP Disabled",
                "cwe": "CWE-121",
                "details": f"'{file_name}' compiled without DEP/NX",
                "remediation": "Recompile with /NXCOMPAT flag"
            })

        if is_aslr and is_dep and not findings:
            findings.append({
                "tool": "pefile",
                "severity": "Info",
                "finding": "Security Mitigations Enabled",
                "cwe": "N/A",
                "details": f"'{file_name}' has ASLR and DEP enabled",
                "remediation": "N/A"
            })

    except ImportError:
        findings.append({
            "tool": "pefile",
            "severity": "Error",
            "finding": "PEFile library not installed",
            "cwe": "N/A",
            "details": "Python pefile library is missing",
            "remediation": "Install with: pip3 install pefile"
        })
    except Exception as e:
        findings.append({
            "tool": "pefile",
            "severity": "Error",
            "finding": f"PE analysis failed",
            "cwe": "N/A",
            "details": str(e),
            "remediation": "Ensure file is a valid PE executable"
        })

    # === 2. RUN MANALYZE ===
    try:
        manalyze_path = shutil.which('manalyze')
        if manalyze_path:
            result = subprocess.run(
                [manalyze_path, file_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout:
                # Parse Manalyze output for suspicious imports
                if 'VirtualAlloc' in result.stdout or 'WriteProcessMemory' in result.stdout:
                    findings.append({
                        "tool": "manalyze",
                        "severity": "High",
                        "finding": "Suspicious API Imports Detected",
                        "cwe": "CWE-78",
                        "details": "Binary imports memory manipulation APIs commonly used in code injection",
                        "remediation": "Review why these APIs are needed and verify they are not misused"
                    })
                
                # Check for packing detection
                if 'packed' in result.stdout.lower() or 'upx' in result.stdout.lower():
                    findings.append({
                        "tool": "manalyze",
                        "severity": "Medium",
                        "finding": "Binary Appears to be Packed",
                        "cwe": "CWE-656",
                        "details": "Executable shows signs of packing/obfuscation",
                        "remediation": "Review the packing tool used and investigate for hidden payloads"
                    })
            elif result.stderr:
                findings.append({
                    "tool": "manalyze",
                    "severity": "Warning",
                    "finding": "Manalyze scan returned errors",
                    "cwe": "N/A",
                    "details": result.stderr[:300],
                    "remediation": "Check if file is a valid PE executable"
                })
        else:
            findings.append({
                "tool": "manalyze",
                "severity": "Warning",
                "finding": "Manalyze not installed",
                "cwe": "N/A",
                "details": "Manalyze tool not found in PATH",
                "remediation": "Install Manalyze from https://github.com/rprater/Manalyze"
            })
            
    except subprocess.TimeoutExpired:
        findings.append({
            "tool": "manalyze",
            "severity": "Warning",
            "finding": "Manalyze scan timed out",
            "cwe": "N/A",
            "details": "Scan exceeded 60 second timeout",
            "remediation": "Try scanning a smaller file"
        })
    except Exception as e:
        findings.append({
            "tool": "manalyze",
            "severity": "Warning",
            "finding": "Manalyze scan failed",
            "cwe": "N/A",
            "details": f"Error: {str(e)}",
            "remediation": "Ensure Manalyze is properly installed"
        })

    # === 3. RUN YARA ===
    try:
        yara_path = shutil.which('yara')
        if yara_path:
            # Check for custom YARA rules
            yara_rules = "rules/" if os.path.exists("rules/") else None
            
            if yara_rules:
                result = subprocess.run(
                    [yara_path, '-r', yara_rules, file_path],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
            else:
                # Try system YARA rules
                result = subprocess.run(
                    [yara_path, '-r', '/usr/share/yara/rules/', file_path],
                    capture_output=True,
                    text=True,
                    timeout=60
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
                                "details": f"Binary matches YARA rule '{rule_name}'",
                                "remediation": "Investigate the matched rule for potential malware or suspicious patterns"
                            })
            elif result.stderr and 'warning' not in result.stderr.lower():
                findings.append({
                    "tool": "yara",
                    "severity": "Warning",
                    "finding": "YARA scan completed with no matches",
                    "cwe": "N/A",
                    "details": "No YARA rules matched the binary",
                    "remediation": "N/A"
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
            "details": "Scan exceeded 60 second timeout",
            "remediation": "Try scanning a smaller file"
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

    return findings
