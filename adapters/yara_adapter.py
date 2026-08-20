#!/usr/bin/env python3
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
        return [{
            "tool": "apktool",
            "severity": "Error",
            "finding": "File not found",
            "cwe": "N/A",
            "details": f"Path: {file_path}",
            "remediation": "Ensure the file path is correct."
        }]

    file_size = os.path.getsize(file_path)
    if file_size > 500 * 1024 * 1024:  # 500MB limit
        return [{
            "tool": "apktool",
            "severity": "Error",
            "finding": "File too large",
            "cwe": "N/A",
            "details": f"APK size {file_size} exceeds 500MB limit",
            "remediation": "Scan smaller APK files only"
        }]

    try:
        # 1. Check if apktool is installed
        apktool_path = shutil.which('apktool')
        if not apktool_path:
            return [{
                "tool": "apktool",
                "severity": "Error",
                "finding": "apktool not installed",
                "cwe": "N/A",
                "details": "apktool not found in PATH",
                "remediation": "Install apktool: sudo apt install apktool"
            }]

        # 2. Decompile the APK
        if os.path.exists(decompile_dir):
            shutil.rmtree(decompile_dir)
        os.makedirs(decompile_dir)
        
        print(f"[*] Decompiling APK to {decompile_dir}...")
        subprocess.run(
            [apktool_path, 'd', file_path, '-o', decompile_dir, '-f'],
            check=True,
            capture_output=True,
            timeout=120
        )
        print("[*] APK decompiled successfully")

        # 3. Check for Insecure Data Storage (SharedPreferences) - CWE-312
        grep_shared = subprocess.run(
            ['grep', '-r', 'SharedPreferences', decompile_dir],
            capture_output=True,
            text=True
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

        # 4. Check for Hardcoded Secrets - CWE-798
        grep_secrets = subprocess.run(
            ['grep', '-rE', 'api_key|password|secret|token', decompile_dir],
            capture_output=True,
            text=True
        )
        # Filter out false positives (like standard Android library strings)
        real_secrets = [
            line for line in grep_secrets.stdout.splitlines() 
            if 'res/values' not in line and len(line) > 20
        ]
        
        if real_secrets:
            findings.append({
                "tool": "apktool/grep",
                "severity": "Medium",
                "finding": "Hardcoded API Keys or Secrets Detected",
                "cwe": "CWE-798",
                "details": f"Potential secret found: {real_secrets[0][:100]}",
                "remediation": "Move secrets to a secure backend or use Android Keystore."
            })

        # 5. Check for Missing Certificate Pinning - CWE-295
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
        else:
            findings.append({
                "tool": "apktool",
                "severity": "Warning",
                "finding": "AndroidManifest.xml not found",
                "cwe": "N/A",
                "details": "Could not find AndroidManifest.xml in decompiled APK",
                "remediation": "Ensure APK is valid and not corrupted"
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
        findings.append({
            "tool": "apktool",
            "severity": "Error",
            "finding": "Decompilation timed out",
            "cwe": "N/A",
            "details": "APK decompilation took too long.",
            "remediation": "Try a smaller APK or increase timeout."
        })
    except subprocess.CalledProcessError as e:
        findings.append({
            "tool": "apktool",
            "severity": "Error",
            "finding": "APK decompilation failed",
            "cwe": "N/A",
            "details": f"apktool error: {e.stderr.decode() if e.stderr else str(e)}",
            "remediation": "Ensure the file is a valid APK and apktool is installed."
        })
    except Exception as e:
        findings.append({
            "tool": "APK Analyzer",
            "severity": "Error",
            "finding": "Analysis failed",
            "cwe": "N/A",
            "details": str(e),
            "remediation": "Ensure the file is a valid APK and apktool is installed."
        })
    finally:
        if os.path.exists(decompile_dir):
            try:
                shutil.rmtree(decompile_dir)
            except:
                pass

    return findings
