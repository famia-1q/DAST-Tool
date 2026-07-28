import json
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def parse_nikto_report(raw_json_path: str) -> list:
    """
    Translates Nikto’s server-level findings into the myESI unified schema.
    """
    try:
        with open(raw_json_path, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        logging.error(f"Nikto report not found at {raw_json_path}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in Nikto report at {raw_json_path}")
        return []

    unified_findings = []
    scan_details = data.get("nikto", {}).get("scandetails", [])
    
    for scan in scan_details:
        target_host = scan.get("targethostname", "Unknown Host")
        vulnerabilities = scan.get("vulnerabilities", [])
        
        for vuln in vulnerabilities:
            raw_severity = str(vuln.get("severity", "1")) 
            if raw_severity == "0":
                severity = "LOW"
            elif raw_severity == "1":
                severity = "MEDIUM"
            elif raw_severity == "2":
                severity = "HIGH"
            elif raw_severity == "3":
                severity = "CRITICAL"
            else:
                severity = "MEDIUM"

            finding_id = vuln.get("id", "N/A")
            title = f"Server Misconfiguration (ID: {finding_id})"
            description = vuln.get("msg", "No description provided by Nikto.")
            uri = vuln.get("uri", "/")
            location = f"{target_host}{uri}"
            source = "Nikto"
            framework_mapping = ["OWASP ASVS V14: Configuration", "CIS Benchmarks"]

            unified_findings.append({
                "severity": severity,
                "title": title,
                "description": description,
                "location": location,
                "remediation_guidance": "Review server configuration, check referenced OSVDB/CVE IDs, and apply latest security patches.",
                "source": source,
                "framework_mapping": framework_mapping
            })
            
    return unified_findings

if __name__ == "__main__":
    print("✅ Nikto Adapter module loaded successfully. Ready for integration.")
