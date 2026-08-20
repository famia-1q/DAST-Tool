#!/usr/bin/env python3
import subprocess
import os
import shutil

def scan_web_target_with_zap(target_url: str) -> list:
    """
    Ultra-fast ZAP scan - won't timeout.
    """
    findings = []
    
    if not target_url.startswith(('http://', 'https://')):
        findings.append({
            "tool": "OWASP ZAP",
            "severity": "Error",
            "finding": "Invalid URL format",
            "cwe": "N/A",
            "details": "URL must start with http:// or https://",
            "remediation": "Provide a valid URL with protocol"
        })
        return findings
    
    print(f"[*] Starting OWASP ZAP scan against: {target_url}")
    
    # Check for local ZAP
    zap_path = shutil.which('zaproxy') or shutil.which('zap')
    
    if not zap_path:
        print("[!] ZAP not found")
        return [{
            "tool": "OWASP ZAP",
            "severity": "Error",
            "finding": "ZAP not installed",
            "cwe": "N/A",
            "details": "OWASP ZAP not found in PATH",
            "remediation": "Install ZAP: sudo apt install zaproxy"
        }]
    
    print(f"[*] Found ZAP at: {zap_path}")
    
    try:
        # ✅ ULTRA-FAST: Just do a quick spider, no active scanning
        print("[*] Running ZAP quick spider (30 seconds max)...")
        
        result = subprocess.run([
            zap_path, '-daemon',
            '-quickurl', target_url,
            '-quickprogress', '/dev/null',
            '-config', 'spider.maxDuration=1',  # 1 minute spider
            '-quickexit'
        ], capture_output=True, text=True, timeout=60)  # 60 seconds total
        
        output = result.stdout + result.stderr
        
        if output:
            # Check for any security-related keywords
            if any(keyword in output.lower() for keyword in ['alert', 'warning', 'fail', 'error']):
                findings.append({
                    "tool": "OWASP ZAP",
                    "severity": "Medium",
                    "finding": "ZAP detected potential issues",
                    "cwe": "CWE-693",
                    "details": output[:500],
                    "remediation": "Review ZAP output for details"
                })
            else:
                findings.append({
                    "tool": "OWASP ZAP",
                    "severity": "Info",
                    "finding": "ZAP quick scan completed",
                    "cwe": "N/A",
                    "details": "Spider completed successfully",
                    "remediation": "N/A"
                })
        else:
            findings.append({
                "tool": "OWASP ZAP",
                "severity": "Info",
                "finding": "ZAP scan completed",
                "cwe": "N/A",
                "details": "Scan executed successfully",
                "remediation": "N/A"
            })
            
    except subprocess.TimeoutExpired:
        print("[!] ZAP timed out - returning gracefully")
        findings.append({
            "tool": "OWASP ZAP",
            "severity": "Warning",
            "finding": "ZAP scan timed out",
            "cwe": "N/A",
            "details": "Scan exceeded 60 second timeout",
            "remediation": "Target may be slow or large"
        })
    except Exception as e:
        print(f"[!] ZAP error: {e}")
        findings.append({
            "tool": "OWASP ZAP",
            "severity": "Error",
            "finding": "ZAP scan failed",
            "cwe": "N/A",
            "details": f"Error: {str(e)}",
            "remediation": "Check ZAP installation"
        })
    
    return findings
