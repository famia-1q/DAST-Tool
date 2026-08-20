#!/usr/bin/env python3
import subprocess
import json
import os
import uuid
import shutil
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def scan_web_target(target_url: str) -> list:
    """
    Nikto scanner - captures output directly to memory for reliability.
    """
    unified_findings = []

    if not target_url.startswith(('http://', 'https://')):
        return [{
            "tool": "Nikto",
            "severity": "Error",
            "finding": "Invalid URL format",
            "cwe": "N/A",
            "details": "URL must start with http:// or https://",
            "remediation": "Provide a valid URL with protocol"
        }]

    print(f"[*] Starting Nikto scan against: {target_url}")

    # Check if Nikto is available
    nikto_path = shutil.which('nikto')
    if not nikto_path:
        return [{
            "tool": "Nikto",
            "severity": "Error",
            "finding": "Nikto not found in PATH",
            "cwe": "N/A",
            "details": "Searched PATH",
            "remediation": "Install Nikto: sudo apt install nikto"
        }]

    try:
        # ✅ FIX: Run Nikto and capture stdout directly (no file writing)
        result = subprocess.run(
            [
                'nikto',
                '-h', target_url,
                '-Format', 'json',
                '-timeout', '60',
                '-maxtime', '120'
            ],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        print(f"[*] Nikto exit code: {result.returncode}")
        
        # Try to parse the stdout as JSON
        raw_output = result.stdout.strip()
        
        if raw_output:
            try:
                # Nikto sometimes outputs a list of JSON objects, sometimes a single object
                # We try to parse it directly first
                data = json.loads(raw_output)
                
                vulnerabilities = []
                if isinstance(data, list):
                    vulnerabilities = data
                elif isinstance(data, dict):
                    if 'vulnerabilities' in data:
                        vulnerabilities = data['vulnerabilities']
                    else:
                        vulnerabilities = [data]
                
                print(f"[*] Found {len(vulnerabilities)} vulnerabilities in JSON")
                
                for idx, vuln in enumerate(vulnerabilities[:20], 1):
                    if not vuln:
                        continue
                    
                    severity = "Low"
                    if isinstance(vuln, dict):
                        sev = str(vuln.get("severity", "1"))
                        severity_map = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
                        severity = severity_map.get(sev, "Low")
                        
                        msg = vuln.get("msg", vuln.get("message", "Vulnerability found"))
                        uri = vuln.get("uri", vuln.get("url", "/"))
                        finding_id = vuln.get("id", f"OSVDB-{idx}")
                        
                        unified_findings.append({
                            "tool": "Nikto",
                            "severity": severity,
                            "finding": f"{finding_id}: {msg[:100]}",
                            "cwe": vuln.get("cweid", "CWE-693"),
                            "details": f"URL: {uri}",
                            "remediation": "Review and fix the vulnerability"
                        })
                
            except json.JSONDecodeError:
                # If JSON parsing fails, it might be plain text output
                print("[!] JSON parsing failed, treating as text output")
                unified_findings.append({
                    "tool": "Nikto",
                    "severity": "Info",
                    "finding": "Nikto scan completed (text output)",
                    "cwe": "N/A",
                    "details": raw_output[:500],
                    "remediation": "N/A"
                })
        else:
            # If stdout is empty, check stderr
            if result.stderr:
                unified_findings.append({
                    "tool": "Nikto",
                    "severity": "Error",
                    "finding": "Nikto returned errors",
                    "cwe": "N/A",
                    "details": result.stderr[:500],
                    "remediation": "Check target URL or Nikto installation"
                })
            else:
                unified_findings.append({
                    "tool": "Nikto",
                    "severity": "Info",
                    "finding": "No vulnerabilities detected",
                    "cwe": "N/A",
                    "details": "Nikto found no issues",
                    "remediation": "N/A"
                })

    except subprocess.TimeoutExpired:
        print("[!] Nikto scan timed out")
        unified_findings.append({
            "tool": "Nikto",
            "severity": "Warning",
            "finding": "Nikto scan timed out",
            "cwe": "N/A",
            "details": "Scan exceeded 5 minute timeout",
            "remediation": "Target may be slow or blocking scans"
        })
        
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        unified_findings.append({
            "tool": "Nikto",
            "severity": "Error",
            "finding": "Unexpected error during scan",
            "cwe": "N/A",
            "details": f"Error: {str(e)}",
            "remediation": "Check logs and installation"
        })

    return unified_findings
