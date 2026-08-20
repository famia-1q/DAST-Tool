import os

def scan_exe_target(file_path):
    findings = []

    # Check if file exists
    if not os.path.exists(file_path):
        return [{
            "tool": "pefile", 
            "severity": "Error", 
            "finding": "File not found", 
            "cwe": "N/A", 
            "details": f"Path: {file_path}", 
            "remediation": "Ensure the file was uploaded correctly."
        }]

    # Check file size
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

    try:
        import pefile
        
        print(f"[*] Analyzing: {file_path} (Size: {file_size} bytes)")
        pe = pefile.PE(file_path)
        file_name = os.path.basename(file_path)
        
        # Check ASLR
        is_aslr = bool(pe.OPTIONAL_HEADER.DllCharacteristics & 
                      pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE'])
        
        # Check DEP
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

        if is_aslr and is_dep:
            findings.append({
                "tool": "pefile",
                "severity": "Info",
                "finding": "Security Mitigations Enabled",
                "cwe": "N/A",
                "details": f"'{file_name}' has ASLR and DEP enabled",
                "remediation": "N/A"
            })

    except ImportError:
        return [{
            "tool": "pefile", 
            "severity": "Error", 
            "finding": "pefile library not installed", 
            "cwe": "N/A", 
            "details": "Run: pip install pefile", 
            "remediation": "Install pefile library"
        }]
    except Exception as e:
        error_msg = str(e)
        return [{
            "tool": "pefile", 
            "severity": "Error", 
            "finding": f"Analysis failed: {error_msg[:50]}", 
            "cwe": "N/A", 
            "details": f"Error: {error_msg}", 
            "remediation": "Ensure file is a valid Windows PE executable (.exe or .dll)"
        }]

    return findings