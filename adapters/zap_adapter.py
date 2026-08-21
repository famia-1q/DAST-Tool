#!/usr/bin/env python3
import subprocess
import os
import shutil
import threading
import time

def scan_web_target_with_zap(target_url: str) -> list:
    """
    Runs OWASP ZAP scan - non-blocking with smart timeout.
    Returns immediately if ZAP takes too long.
    """
    findings = []
    
    if not target_url.startswith(('http://', 'https://')):
        return findings  # Return empty, don't block
    
    print(f"[*] Starting OWASP ZAP scan against: {target_url}")
    
    # Check for local ZAP
    zap_path = shutil.which('zaproxy') or shutil.which('zap')
    
    if not zap_path:
        print("[!] ZAP not installed - skipping (this is OK)")
        return []  # Don't fail the scan, just skip ZAP
    
    print(f"[*] Found ZAP at: {zap_path}")
    
    # Run ZAP in a separate thread with timeout
    zap_result = [None]  # Use list to allow modification in thread
    zap_error = [None]
    
    def run_zap_scan():
        try:
            # Ultra-minimal ZAP scan - just spider, no active scan
            result = subprocess.run([
                zap_path, '-cmd',
                '-quickurl', target_url,
                '-quickprogress', '/dev/null'
            ], capture_output=True, text=True, timeout=120)
            
            zap_result[0] = result
        except Exception as e:
            zap_error[0] = str(e)
    
    # Start ZAP in background
    zap_thread = threading.Thread(target=run_zap_scan)
    zap_thread.start()
    
    # Wait max 90 seconds
    zap_thread.join(timeout=90)
    
    if zap_thread.is_alive():
        print("[!] ZAP still running after 90 seconds - skipping (Nikto will handle it)")
        return []  # Just skip ZAP, don't fail
    
    if zap_error[0]:
        print(f"[!] ZAP error: {zap_error[0]} - continuing with Nikto only")
        return []
    
    if zap_result[0]:
        result = zap_result[0]
        output = result.stdout + result.stderr
        
        if output and any(keyword in output.lower() for keyword in ['alert', 'warning', 'fail']):
            findings.append({
                "tool": "OWASP ZAP",
                "severity": "Medium",
                "finding": "ZAP detected potential issues",
                "cwe": "CWE-693",
                "details": output[:500],
                "remediation": "Review ZAP output"
            })
        else:
            findings.append({
                "tool": "OWASP ZAP",
                "severity": "Info",
                "finding": "ZAP scan completed",
                "cwe": "N/A",
                "details": "No critical issues found",
                "remediation": "N/A"
            })
    
    return findings
