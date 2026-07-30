import json
import os

def parse_lief_report(report_path):
    """Parse LIEF JSON output into myESI unified schema."""
    findings = []
    
    # Check if file exists to prevent crashes
    if not os.path.exists(report_path):
        print(f"[Adapter] ⚠️ LIEF report not found at {report_path}")
        return findings

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[Adapter] ⚠️ Failed to parse JSON from {report_path}")
        return findings

    file_name = data.get("file_name", "Unknown File")
    
    # Check 1: Is PIE (Position Independent Executable) disabled?
    if not data.get("is_pie", True): # Default to True if missing to avoid false positives
        findings.append({
            "severity": "Medium",
            "title": "Binary is Not Position Independent (No PIE)",
            "description": "The binary is not compiled as position-independent, making it more vulnerable to memory corruption exploitation.",
            "location": f"File: {file_name}",
            "remediation_guidance": "Recompile the binary with -fPIE -pie flags to enable ASLR protection.",
            "source": "LIEF",
            "framework_mapping": ["CWE-693", "OWASP Binary Analysis"]
        })
    
    # Check 2: Is NX (No-Execute) disabled?
    if not data.get("has_nx", True):
        findings.append({
            "severity": "High",
            "title": "Binary Does Not Have NX (No-Execute) Protection",
            "description": "The binary allows execution of data segments, making it highly vulnerable to buffer overflow and shellcode injection attacks.",
            "location": f"File: {file_name}",
            "remediation_guidance": "Recompile with -z noexecstack flag to enable NX protection.",
            "source": "LIEF",
            "framework_mapping": ["CWE-693", "CWE-78"]
        })
    
    # Check 3: High entropy sections (potential packing/obfuscation)
    for section in data.get("sections", []):
        if section.get("entropy", 0) > 7.0:
            findings.append({
                "severity": "Medium",
                "title": f"High Entropy Section Detected: {section.get('name')}",
                "description": f"Section '{section.get('name')}' has high entropy ({section.get('entropy'):.2f}), indicating potential packing, compression, or obfuscation.",
                "location": f"File: {file_name}, Section: {section.get('name')}",
                "remediation_guidance": "Investigate the section contents. High entropy may indicate packing or embedded encrypted data.",
                "source": "LIEF",
                "framework_mapping": ["CWE-656", "MITRE ATT&CK T1027"]
            })
    
    return findings
