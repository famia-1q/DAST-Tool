import subprocess
import os

def scan_exe_target(file_path):
    findings = []

    if not os.path.exists(file_path):
        return [{"tool": "pefile", "severity": "Error", "finding": "File not found", "cwe": "N/A", "details": f"Path: {file_path}", "remediation": "Ensure the file was uploaded correctly."}]

    file_size = os.path.getsize(file_path)
    if file_size == 0:
        return [{"tool": "pefile", "severity": "Error", "finding": "File is empty", "cwe": "N/A", "details": "Uploaded file has 0 bytes", "remediation": "Re-upload the file."}]

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
                "tool": "pefile", "severity": "High", "finding": "Missing Security Mitigation: ASLR Disabled",
                "cwe": "CWE-121", "details": f"'{file_name}' compiled without ASLR", "remediation": "Recompile with /DYNAMICBASE flag"
            })
        
        if not is_dep:
            findings.append({
                "tool": "pefile", "severity": "High", "finding": "Missing Security Mitigation: DEP Disabled",
                "cwe": "CWE-121", "details": f"'{file_name}' compiled without DEP/NX", "remediation": "Recompile with /NXCOMPAT flag"
            })

        if is_aslr and is_dep and not findings:
            findings.append({
                "tool": "pefile", "severity": "Info", "finding": "Security Mitigations Enabled",
                "cwe": "N/A", "details": f"'{file_name}' has ASLR and DEP enabled", "remediation": "N/A"
            })

    except Exception as e:
        findings.append({"tool": "pefile", "severity": "Error", "finding": f"PE analysis failed", "cwe": "N/A", "details": str(e), "remediation": "Ensure file is a valid PE executable"})

    # === 2. RUN MANALYZE (if available) ===
    try:
        result = subprocess.run(['manalyze', file_path], capture_output=True, text=True, timeout=60)
        if result.returncode == 0 and result.stdout:
            # Parse Manalyze output for suspicious imports
            if 'VirtualAlloc' in result.stdout or 'WriteProcessMemory' in result.stdout:
                findings.append({
                    "tool": "manalyze", "severity": "High", "finding": "Suspicious API Imports Detected",
                    "cwe": "CWE-78", "details": "Binary imports memory manipulation APIs commonly used in code injection",
                    "remediation": "Review why these APIs are needed and verify they are not misused"
                })
            
            # Check for packing detection
            if 'packed' in result.stdout.lower() or 'upx' in result.stdout.lower():
                findings.append({
                    "tool": "manalyze", "severity": "Medium", "finding": "Binary Appears to be Packed",
                    "cwe": "CWE-656", "details": "Executable shows signs of packing/obfuscation",
                    "remediation": "Review the packing tool used and investigate for hidden payloads"
                })
    except Exception as e:
        pass  # Manalyze might not be installed, silently continue

    # === 3. RUN YARA (if available) ===
    try:
        # Check if you have custom YARA rules, otherwise use generic scan
        yara_rules = "rules/" if os.path.exists("rules/") else None
        
        if yara_rules:
            result = subprocess.run(['yara', '-r', yara_rules, file_path], capture_output=True, text=True, timeout=60)
        else:
            # Generic YARA scan without specific rules
            result = subprocess.run(['yara', '-r', '/usr/share/yara/rules/', file_path], capture_output=True, text=True, timeout=60)
        
        if result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                if line and not line.startswith('warning'):
                    parts = line.split()
                    if len(parts) >= 2:
                        rule_name = parts[0]
                        findings.append({
                            "tool": "yara", "severity": "High", "finding": f"YARA Rule Match: {rule_name}",
                            "cwe": "CWE-506", "details": f"Binary matches YARA rule '{rule_name}'",
                            "remediation": "Investigate the matched rule for potential malware or suspicious patterns"
                        })
    except Exception as e:
        pass  # YARA might not be installed or no rules found

    return findings
