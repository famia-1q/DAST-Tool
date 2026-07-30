import json
import os

def parse_manalyze_report(report_path):
    """Parse Manalyze JSON output into myESI unified schema."""
    findings = []
    
    # Check if file exists to prevent crashes
    if not os.path.exists(report_path):
        print(f"[Adapter] ⚠️ Manalyze report not found at {report_path}")
        return findings

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[Adapter] ⚠️ Failed to parse JSON from {report_path}")
        return findings

    # Manalyze output can be a list of findings or a dict with a 'results' key
    # We handle both formats to be safe
    manalyze_results = []
    if isinstance(data, list):
        manalyze_results = data
    elif isinstance(data, dict) and "results" in data:
        manalyze_results = data["results"]
    elif isinstance(data, dict) and "plugins" in data:
        # Sometimes findings are nested under plugins
        for plugin_name, plugin_data in data["plugins"].items():
            if isinstance(plugin_data, list):
                manalyze_results.extend(plugin_data)

    file_name = data.get("file_name", "Unknown File") if isinstance(data, dict) else "Unknown File"

    # Process each finding
    for item in manalyze_results:
        if isinstance(item, dict):
            # Map Manalyze's fields to myESI schema
            severity = item.get("severity", "Medium").capitalize()
            # Normalize severity to match myESI standards
            if severity not in ["Low", "Medium", "High", "Critical"]:
                severity = "Medium"
                
            findings.append({
                "severity": severity,
                "title": item.get("name", "Manalyze Security Finding"),
                "description": item.get("description", "A security issue was detected by Manalyze."),
                "location": f"File: {file_name}",
                "remediation_guidance": item.get("remediation", "Review the Manalyze documentation and address the identified security issue."),
                "source": "Manalyze",
                "framework_mapping": ["CWE-693", "OWASP Binary Analysis"]
            })

    return findings
