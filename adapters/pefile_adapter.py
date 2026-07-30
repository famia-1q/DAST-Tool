import json
import os

def parse_pefile_report(report_path):
    """Parse pefile JSON output into myESI unified schema."""
    findings = []
    
    # Check if file exists to prevent crashes
    if not os.path.exists(report_path):
        print(f"[Adapter] ⚠️ pefile report not found at {report_path}")
        return findings

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[Adapter] ⚠️ Failed to parse JSON from {report_path}")
        return findings

    file_name = data.get("file_name", "Unknown File")
    
    # Check 1: Is the file packed/obfuscated?
    if data.get("is_packed"):
        findings.append({
            "severity": "Medium",
            "title": "PE File Appears to be Packed or Obfuscated",
            "description": "The executable shows signs of packing (high entropy sections detected). This can hide malicious code or intellectual property.",
            "location": f"File: {file_name}",
            "remediation_guidance": "Review the packing tool used. If this is a legitimate protector, document it. Otherwise, investigate for hidden payloads.",
            "source": "pefile",
            "framework_mapping": ["CWE-656", "MITRE ATT&CK T1027"]
        })
    
    # Check 2: Are there suspicious API imports?
    if data.get("is_suspicious"):
        findings.append({
            "severity": "High",
            "title": "Suspicious API Imports Detected",
            "description": "The executable imports APIs commonly used in malicious activities (e.g., VirtualAlloc, WriteProcessMemory, CreateRemoteThread).",
            "location": f"File: {file_name}",
            "remediation_guidance": "Investigate why these memory-manipulation APIs are needed. Verify they are not being misused for code injection.",
            "source": "pefile",
            "framework_mapping": ["CWE-78", "MITRE ATT&CK T1055"]
        })

    return findings
