import json
import os

def parse_yara_deb_report(report_path):
    """Parse YARA output for DEB files into myESI unified schema."""
    findings = []
    
    # Check if file exists to prevent crashes
    if not os.path.exists(report_path):
        print(f"[Adapter] ⚠️ YARA DEB report not found at {report_path}")
        return findings

    try:
        with open(report_path, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"[Adapter] ⚠️ Failed to read YARA report: {e}")
        return findings

    # YARA standard text output format: "RuleName FilePath"
    lines = content.strip().split('\n')
    
    for line in lines:
        line = line.strip()
        # Ignore empty lines or warnings
        if not line or line.lower().startswith('warning'):
            continue
            
        parts = line.split()
        if len(parts) >= 2:
            rule_name = parts[0]
            file_path = parts[1]
            
            findings.append({
                "severity": "High", # YARA matches are usually treated as high severity indicators
                "title": f"YARA Rule Match: {rule_name}",
                "description": f"The extracted file '{file_path}' matches the YARA rule '{rule_name}'. This indicates a known malware family, suspicious pattern, or specific packer.",
                "location": f"File: {file_path}",
                "remediation_guidance": "Investigate the matched rule. If this is a known malicious pattern, isolate the package and perform deep dynamic analysis.",
                "source": "YARA",
                "framework_mapping": ["MITRE ATT&CK", "CWE-506"]
            })

    return findings

