import subprocess
import os
import shutil

def scan_apk_target(file_path):
    """
    Dynamically analyzes an Android APK by decompiling it with apktool 
    and scanning for insecure storage, hardcoded secrets, and missing cert pinning.
    """
    findings = []
    decompile_dir = "/tmp/apk_decompiled_dynamic"

    if not os.path.exists(file_path):
        return [{"tool": "apktool", "severity": "Error", "finding": "File not found", "cwe": "N/A", "details": f"Path: {file_path}", "remediation": "Ensure the file path is correct."}]

    try:
        # 1. Decompile the APK dynamically
        if os.path.exists(decompile_dir):
            shutil.rmtree(decompile_dir)
        os.makedirs(decompile_dir)
        
        subprocess.run(['apktool', 'd', file_path, '-o', decompile_dir, '-f'], 
                       check=True, capture_output=True, timeout=120)

        # 2. Check for Insecure Data Storage (SharedPreferences) - CWE-312
        grep_shared = subprocess.run(
            ['grep', '-r', 'SharedPreferences', decompile_dir],
            capture_output=True, text=True
        )
        if grep_shared.stdout.strip():
            findings.append({
                "tool": "apktool/grep",
                "severity": "High",
                "finding": "Insecure Data Storage (SharedPreferences)",
                "cwe": "CWE-312",
                "details": "Application uses SharedPreferences which may store sensitive data in plaintext.",
                "remediation": "Use EncryptedSharedPreferences or Android Keystore for sensitive data."
            })

        # 3. Check for Hardcoded Secrets - CWE-798
        grep_secrets = subprocess.run(
            ['grep', '-rE', 'api_key|password|secret|token', decompile_dir],
            capture_output=True, text=True
        )
        # Filter out false positives (like standard Android library strings)
        real_secrets = [line for line in grep_secrets.stdout.splitlines() if 'res/values' not in line and len(line) > 20]
        
        if real_secrets:
            findings.append({
                "tool": "apktool/grep",
                "severity": "Medium",
                "finding": "Hardcoded API Keys or Secrets Detected",
                "cwe": "CWE-798",
                "details": f"Potential secret found: {real_secrets[0][:100]}",
                "remediation": "Move secrets to a secure backend or use Android Keystore."
            })

        # 4. Check for Missing Certificate Pinning - CWE-295
        manifest_path = os.path.join(decompile_dir, 'AndroidManifest.xml')
        if os.path.exists(manifest_path):
            with open(manifest_path, 'r') as f:
                manifest_content = f.read()
            
            if 'networkSecurityConfig' not in manifest_content:
                findings.append({
                    "tool": "apktool",
                    "severity": "Low",
                    "finding": "Missing SSL/TLS Certificate Pinning",
                    "cwe": "CWE-295",
                    "details": "No network security configuration found in AndroidManifest.xml.",
                    "remediation": "Implement certificate pinning using Network Security Config."
                })

        if not findings:
            findings.append({
                "tool": "APK Analyzer",
                "severity": "Info",
                "finding": "No critical mobile vulnerabilities found",
                "cwe": "N/A",
                "details": "APK passed basic static analysis checks.",
                "remediation": "N/A"
            })

    except subprocess.TimeoutExpired:
        findings.append({"tool": "apktool", "severity": "Error", "finding": "Decompilation timed out", "cwe": "N/A", "details": "APK decompilation took too long.", "remediation": "Try a smaller APK or increase timeout."})
    except Exception as e:
        findings.append({"tool": "APK Analyzer", "severity": "Error", "finding": "Analysis failed", "cwe": "N/A", "details": str(e), "remediation": "Ensure the file is a valid APK and apktool is installed."})
    finally:
        if os.path.exists(decompile_dir):
            shutil.rmtree(decompile_dir)

    return findings