import subprocess
import os
import shutil

def scan_deb_target(file_path):
    findings = []
    extract_dir = "/tmp/deb_extracted_dynamic"

    if not os.path.exists(file_path):
        return [{"tool": "checksec", "severity": "Error", "finding": "File not found", "cwe": "N/A", "details": f"Path: {file_path}", "remediation": "Ensure file exists."}]

    try:
        # Extract DEB
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir)
        
        print(f"[*] Extracting DEB: {file_path}")
        subprocess.run(['dpkg-deb', '-x', file_path, extract_dir], check=True, capture_output=True)

        # Check for World-Writable Files
        print("[*] Checking for world-writable files...")
        find_result = subprocess.run(
            ['find', extract_dir, '-type', 'f', '-perm', '-002'],
            capture_output=True, text=True
        )
        
        if find_result.stdout.strip():
            findings.append({
                "tool": "dpkg-deb/find",
                "severity": "High",
                "finding": "World-Writable Files Detected",
                "cwe": "CWE-732",
                "details": f"Files: {find_result.stdout.strip().splitlines()[0]}",
                "remediation": "Fix permissions with chmod"
            })

        # Run Checksec
        print("[*] Running checksec...")
        checksec_result = subprocess.run(
            ['checksec', '--dir', extract_dir],
            capture_output=True, text=True
        )
        
        output = checksec_result.stdout + "\n" + checksec_result.stderr
        print(f"[*] Checksec output:\n{output[:500]}")  # Debug print
        
        # Check for various missing mitigations
        if "No PIE" in output or "pie: no" in output.lower() or "pie: disabled" in output.lower():
            findings.append({
                "tool": "checksec",
                "severity": "Medium",
                "finding": "Missing PIE (Position Independent Executable)",
                "cwe": "CWE-121",
                "details": "Binaries not compiled with PIE",
                "remediation": "Recompile with -fPIE -pie flags"
            })
            
        if "No RELRO" in output or "relro: no" in output.lower():
            findings.append({
                "tool": "checksec",
                "severity": "Medium",
                "finding": "Missing RELRO",
                "cwe": "CWE-121",
                "details": "Binaries missing RELRO protection",
                "remediation": "Recompile with -Wl,-z,relro,-z,now"
            })
            
        if "No canary" in output or "canary: no" in output.lower():
            findings.append({
                "tool": "checksec",
                "severity": "High",
                "finding": "Missing Stack Canary",
                "cwe": "CWE-121",
                "details": "Binaries lack stack canaries",
                "remediation": "Recompile with -fstack-protector-strong"
            })

        if not findings:
            findings.append({
                "tool": "checksec",
                "severity": "Info",
                "finding": "Package passed basic security checks",
                "cwe": "N/A",
                "details": "No critical issues detected in this package",
                "remediation": "N/A"
            })

    except Exception as e:
        findings.append({
            "tool": "DEB Analyzer",
            "severity": "Error",
            "finding": f"Analysis failed: {str(e)[:50]}",
            "cwe": "N/A",
            "details": str(e),
            "remediation": "Ensure file is a valid DEB package"
        })
    finally:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)

    return findings