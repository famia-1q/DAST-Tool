import json
import os

def parse_checksec_report(report_path):
    """Parse checksec JSON output into myESI unified schema."""
    findings = []
    
    # Check if file exists to prevent crashes
    if not os.path.exists(report_path):
        print(f"[Adapter] ⚠️ checksec report not found at {report_path}")
        return findings

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[Adapter] ⚠️ Failed to parse JSON from {report_path}")
        return findings

    file_name = data.get("file", "Unknown File")
    
    # Map checksec features to human-readable names and severity
    security_features = {
        "relro": {"name": "RELRO (Relocation Read-Only)", "severity": "Medium"},
        "canary": {"name": "Stack Canary", "severity": "High"},
        "nx": {"name": "NX (No-Execute)", "severity": "High"},
        "pie": {"name": "PIE (Position Independent Executable)", "severity": "Medium"}
    }
    
    for feature, details in security_features.items():
        # checksec might output "No", "Disabled", or False for missing protections
        status = data.get(feature, "").lower()
        if status in ["no", "disabled", "false", False]:
            findings.append({
                "severity": details["severity"],
                "title": f"{details['name']} is Disabled",
                "description": f"The binary does not have {details['name']} protection enabled, making it more vulnerable to memory corruption exploitation.",
                "location": f"File: {file_name}",
                "remediation_guidance": f"Enable {details['name']} during compilation (e.g., using GCC/Clang flags) to improve binary security.",
                "source": "checksec",
                "framework_mapping": ["CWE-693", "OWASP Binary Analysis"]
            })
    
    return findings
