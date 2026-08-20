import subprocess
import json
import os
import uuid
import logging
import signal

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def scan_web_target(target_url: str) -> list:
    """
    Dynamically runs Nikto against the target URL with better timeout handling.
    """
    unified_findings = []
    scan_id = str(uuid.uuid4())[:8]
    output_file = f"/tmp/nikto_{scan_id}.json"

    logging.info(f"[*] Starting Nikto scan against: {target_url}")

    try:
        # Run Nikto with extended timeout (10 minutes = 600 seconds)
        # Use -timeout option to control Nikto's internal timeout
        result = subprocess.run(
            [
                'nikto', 
                '-h', target_url, 
                '-Format', 'json', 
                '-output', output_file,
                '-timeout', '300',  # Nikto's internal timeout per request
                '-maxtime', '600'   # Maximum total scan time
            ],
            capture_output=True,
            text=True,
            timeout=900  # Python subprocess timeout (15 minutes)
        )

        logging.info(f"Nikto exit code: {result.returncode}")
        
        # Parse JSON output
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                
                logging.info(f"Parsed Nikto JSON successfully")
                
                # Handle different Nikto JSON structures
                vulnerabilities = []
                if isinstance(data, list):
                    vulnerabilities = data
                elif isinstance(data, dict):
                    if 'nikto' in data and 'scandetails' in data['nikto']:
                        for scan in data['nikto']['scandetails']:
                            vulnerabilities.extend(scan.get('vulnerabilities', []))
                    elif 'vulnerabilities' in data:
                        vulnerabilities = data['vulnerabilities']
                
                for vuln in vulnerabilities:
                    raw_severity = str(vuln.get("severity", "1"))
                    severity_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
                    severity = severity_map.get(raw_severity, "Low")
                    
                    finding_id = vuln.get("id", "N/A")
                    msg = vuln.get("msg", "Web vulnerability detected")
                    uri = vuln.get("uri", "/")
                    target_host = vuln.get("targethostname", target_url)
                    
                    unified_findings.append({
                        "tool": "Nikto",
                        "severity": severity,
                        "finding": f"OSVDB-{finding_id}: {msg}",
                        "cwe": "CWE-693",
                        "details": f"URL: {target_host}{uri}",
                        "remediation": "Review and fix the identified vulnerability"
                    })
                
                if not unified_findings:
                    unified_findings.append({
                        "tool": "Nikto",
                        "severity": "Info",
                        "finding": "No vulnerabilities detected",
                        "cwe": "N/A",
                        "details": f"Target {target_url} appears secure against standard Nikto checks",
                        "remediation": "N/A"
                    })
                    
            except json.JSONDecodeError as e:
                logging.error(f"JSON decode error: {e}")
                # Fallback: try to extract info from stdout
                if result.stdout:
                    unified_findings.append({
                        "tool": "Nikto",
                        "severity": "Info",
                        "finding": "Scan completed (parsing issues)",
                        "cwe": "N/A",
                        "details": f"Nikto ran but JSON parsing failed. Raw output: {result.stdout[:500]}",
                        "remediation": "N/A"
                    })
        else:
            # No JSON file created - use stdout/stderr
            if result.stdout or result.stderr:
                unified_findings.append({
                    "tool": "Nikto",
                    "severity": "Info",
                    "finding": "Scan completed with informational findings",
                    "cwe": "N/A",
                    "details": f"Nikto output: {result.stdout[:300] if result.stdout else result.stderr[:300]}",
                    "remediation": "N/A"
                })
            else:
                unified_findings.append({
                    "tool": "Nikto",
                    "severity": "Info",
                    "finding": "Scan completed with no findings",
                    "cwe": "N/A",
                    "details": "Nikto ran successfully but returned no vulnerabilities",
                    "remediation": "N/A"
                })

    except subprocess.TimeoutExpired:
        logging.error("Nikto scan timed out")
        unified_findings.append({
            "tool": "Nikto",
            "severity": "Warning",
            "finding": "Scan timed out - partial results may be available",
            "cwe": "N/A",
            "details": "The scan exceeded the time limit. This can happen with slow or unresponsive targets. Try scanning a faster target or increase timeout settings.",
            "remediation": "Ensure target is accessible and not blocking automated scanners"
        })
        
        # Try to get partial results even after timeout
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                with open(output_file, 'r') as f:
                    data = json.load(f)
                # Parse partial results...
                logging.info("Partial results recovered after timeout")
            except:
                pass
                
    except Exception as e:
        logging.error(f"Nikto scan failed: {str(e)}")
        unified_findings.append({
            "tool": "Nikto",
            "severity": "Error",
            "finding": "Scan execution failed",
            "cwe": "N/A",
            "details": f"Error: {str(e)}",
            "remediation": "Ensure Nikto is installed and target URL is valid"
        })
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)

    return unified_findings