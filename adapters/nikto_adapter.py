#!/usr/bin/env python3
import subprocess
import json
import os
import uuid
import shutil
import re

def scan_web_target(target_url: str) -> list:
    """
    Enhanced Nikto scanner with better vulnerability detection.
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

    nikto_path = shutil.which('nikto')
    if not nikto_path:
        return [{
            "tool": "Nikto",
            "severity": "Error",
            "finding": "Nikto not found",
            "cwe": "N/A",
            "details": "Install Nikto: sudo apt install nikto",
            "remediation": "Install Nikto"
        }]

    try:
        result = subprocess.run([
            'nikto',
            '-h', target_url,
            '-Format', 'json',
            '-timeout', '120',
            '-maxtime', '180',
            '-Tuning', '123456789x'
        ], capture_output=True, text=True, timeout=300)
        
        print(f"[*] Nikto exit code: {result.returncode}")
        print(f"[*] Nikto stdout length: {len(result.stdout)}")
        
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                vulnerabilities = []
                
                if isinstance(data, list):
                    vulnerabilities = data
                elif isinstance(data, dict):
                    vulnerabilities = data.get('vulnerabilities', [data])
                
                print(f"[*] Parsed {len(vulnerabilities)} vulnerabilities from JSON")
                
                for idx, vuln in enumerate(vulnerabilities[:30], 1):
                    if not vuln or not isinstance(vuln, dict):
                        continue
                    
                    msg = vuln.get("msg", "")
                    if not msg or "no vulnerabilities" in msg.lower():
                        continue
                    
                    severity = vuln.get("severity", "1")
                    severity_map = {
                        "0": "Info", "1": "Low", "2": "Medium", 
                        "3": "High", "4": "Critical"
                    }
                    sev = severity_map.get(str(severity), "Low")
                    
                    vuln_keywords = ['sql injection', 'xss', 'traversal', 
                                   'overflow', 'exec', 'upload', 'password']
                    is_vuln = any(keyword in msg.lower() for keyword in vuln_keywords)
                    
                    if is_vuln:
                        sev = "High" if sev in ["Info", "Low"] else sev
                    
                    unified_findings.append({
                        "tool": "Nikto",
                        "severity": sev,
                        "finding": f"{vuln.get('id', 'OSVDB-' + str(idx))}: {msg[:100]}",
                        "cwe": vuln.get("cweid", "CWE-693"),
                        "details": f"URL: {vuln.get('uri', '/')}\n{vuln.get('description', '')[:300]}",
                        "remediation": "Review and fix the identified vulnerability"
                    })
                    
            except json.JSONDecodeError as e:
                print(f"[!] JSON parse failed: {e}")
                unified_findings.extend(parse_nikto_text(result.stdout + result.stderr))
        
        if not unified_findings:
            if "Unable to connect" in result.stdout or result.returncode != 0:
                unified_findings.append({
                    "tool": "Nikto",
                    "severity": "Warning",
                    "finding": "Target unreachable or blocking scans",
                    "cwe": "N/A",
                    "details": f"Stderr: {result.stderr[:300]}",
                    "remediation": "Check if target is accessible"
                })
            else:
                unified_findings.append({
                    "tool": "Nikto",
                    "severity": "Info",
                    "finding": "No vulnerabilities detected",
                    "cwe": "N/A",
                    "details": "Target appears secure",
                    "remediation": "N/A"
                })

    except subprocess.TimeoutExpired:
        unified_findings.append({
            "tool": "Nikto",
            "severity": "Warning",
            "finding": "Scan timed out",
            "cwe": "N/A",
            "details": "Scan exceeded 5 minute timeout",
            "remediation": "Target may be slow or blocking scans"
        })
    except Exception as e:
        unified_findings.append({
            "tool": "Nikto",
            "severity": "Error",
            "finding": "Scan failed",
            "cwe": "N/A",
            "details": f"Error: {str(e)}",
            "remediation": "Check Nikto installation"
        })

    return unified_findings


def parse_nikto_text(output: str) -> list:
    """Parse Nikto text output for vulnerabilities."""
    findings = []
    
    patterns = [
        (r'\+ (\d{6,}): (.+?) - (.+)', 'High'),
        (r'\+ Server: (.+)', 'Low'),
        (r'\+ Retrieved .+ headers: (.+)', 'Medium'),
        (r'\+ .*(?:admin|backup|config|password|secret).+', 'Medium'),
        (r'\+ (?:OSVDB-\d+): (.+)', 'Medium'),
        (r'\+ HTTP method may allow (.+)', 'Medium'),
    ]
    
    for line in output.split('\n'):
        for pattern, default_sev in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                groups = match.groups()
                finding_title = groups[1] if len(groups) > 1 else groups[0]
                
                severity = default_sev
                if any(kw in finding_title.lower() for kw in ['sql', 'xss', 'injection', 'traversal']):
                    severity = 'High'
                elif any(kw in finding_title.lower() for kw in ['password', 'admin', 'backup', 'config']):
                    severity = 'Medium'
                
                findings.append({
                    "tool": "Nikto",
                    "severity": severity,
                    "finding": f"Nikto Detection: {finding_title[:100]}",
                    "cwe": "CWE-693",
                    "details": line[:300],
                    "remediation": "Review and remediate the finding"
                })
                break
    
    return findings
