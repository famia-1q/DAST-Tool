import json
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def parse_zap_report(raw_json_path: str) -> list:
    """Maps OWASP ZAP output to myESI unified schema."""
    try:
        with open(raw_json_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error(f"ZAP report not found at {raw_json_path}")
        return []

    unified_findings = []
    for site in data.get("site", []):
        location = site.get("@name", "Unknown URL")
        for alert in site.get("alerts", []):
            unified_findings.append({
                "severity": alert.get("risk", "INFO").upper(),
                "title": alert.get("alert", "Unknown Title"),
                "description": alert.get("desc", "No description provided."),
                "location": location,
                "remediation_guidance": alert.get("solution", "No remediation provided."),
                "source": "OWASP ZAP",
                "framework_mapping": ["OWASP ASVS", "OWASP API Security Top 10"]
            })
    return unified_findings

def parse_mobsf_report(raw_json_path: str) -> list:
    """Maps MobSF output to myESI unified schema."""
    try:
        with open(raw_json_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error(f"MobSF report not found at {raw_json_path}")
        return []

    unified_findings = []
    issues = data.get("security_issues", []) + data.get("misc_issues", [])
    
    for finding in issues:
        unified_findings.append({
            "severity": finding.get("severity", "INFO").upper(),
            "title": finding.get("title", "Unknown Title"),
            "description": finding.get("description", "No description provided."),
            "location": finding.get("file", finding.get("section", "Unknown")),
            "remediation_guidance": finding.get("remediation", "No remediation provided."),
            "source": "MobSF",
            "framework_mapping": ["OWASP MASVS"]
        })
    return unified_findings

def generate_unified_report(raw_report_path: str, engine: str) -> dict:
    """Main adapter router."""
    if engine.lower() == "zap":
        findings = parse_zap_report(raw_report_path)
    elif engine.lower() == "mobsf":
        findings = parse_mobsf_report(raw_report_path)
    else:
        raise ValueError(f"Unknown engine: {engine}. Supported: 'zap', 'mobsf'")
    
    return {
        "myESI_version": "1.0",
        "engine_used": engine.upper(),
        "total_findings": len(findings),
        "findings": findings
    }