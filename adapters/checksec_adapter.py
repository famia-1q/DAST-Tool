import subprocess
import os
import shutil

def scan_deb_target(file_path):
    findings = []
    extract_dir = "/tmp/deb_extracted_dynamic"

    if not os.path.exists(file_path):
        return [{"tool": "checksec", "severity": "Error", "finding": "File not found", "cwe": "N/A", "details": f"Path: {file_path}", "remediation": "Ensure file exists."}]

    try:
        # === 1. EXTRACT DEB WITH dpkg-deb ===
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)
        os.makedirs(extract_dir)
        
        subprocess.run(['dpkg-deb', '-x', file_path, extract_dir], check=True, capture_output=True)

        # === 2. CHECK FOR WORLD-WRITABLE FILES ===
        find_result = subprocess.run(
            ['find', extract_dir, '-type', 'f', '-perm', '-002'],
            capture_output=True, text=True
        )
        
        if find_result.stdout.strip():
            findings.append({
                "tool": "dpkg-deb/find", "severity": "High", "finding": "World-Writable Files Detected",
                "cwe": "CWE-732", "details": f"Files: {find_result.stdout.strip().splitlines()[0]}",
                "remediation": "Fix permissions with chmod"
            })

        # === 3. RUN CHECKSEC ===
        checksec_result = subprocess.run(
            ['checksec', '--dir', extract_dir],
            capture_output=True, text=True
        )
        
        output = checksec_result.stdout + "\n" + checksec_result.stderr
        
        if "No PIE" in output or "pie: no" in output.lower() or "pie: disabled" in output.lower():
            findings.append({
                "tool": "checksec", "severity": "Medium", "finding": "Missing PIE (Position Independent Executable)",
                "cwe": "CWE-121", "details": "Binaries not compiled with PIE", "remediation": "Recompile with -fPIE -pie flags"
            })
            
        if "No RELRO" in output or "relro: no" in output.lower():
            findings.append({
                "tool": "checksec", "severity": "Medium", "finding": "Missing RELRO",
                "cwe": "CWE-121", "details": "Binaries missing RELRO protection",
                "remediation": "Recompile with -Wl,-z,relro,-z,now"
            })

        # === 4. RUN LIEF (if available) ===
        try:
            import lief
            binaries = []
            for root, dirs, files in os.walk(extract_dir):
                for file in files:
                    file_path_full = os.path.join(root, file)
                    if os.path.isfile(file_path_full) and os.access(file_path_full, os.X_OK):
                        try:
                            binary = lief.parse(file_path_full)
                            if binary:
                                binaries.append(binary)
                                
                                # Check for suspicious sections
                                if binary.has_section('.text'):
                                    section = binary.get_section('.text')
                                    if section.flags & lief.ELF.Section.FLAGS.SHF_WRITE:
                                        findings.append({
                                            "tool": "lief", "severity": "High", "finding": "Executable Section is Writable",
                                            "cwe": "CWE-693", "details": f"Section .text has write permissions in {file}",
                                            "remediation": "Remove write permissions from executable sections"
                                        })
                        except:
                            pass
        except ImportError:
            pass  # LIEF not installed

        # === 5. RUN YARA (if available) ===
        try:
            yara_rules = "rules/" if os.path.exists("rules/") else None
            if yara_rules:
                result = subprocess.run(['yara', '-r', yara_rules, extract_dir], capture_output=True, text=True, timeout=120)
                if result.stdout.strip():
                    for line in result.stdout.strip().split('\n'):
                        if line and not line.startswith('warning'):
                            parts = line.split()
                            if len(parts) >= 2:
                                rule_name = parts[0]
                                findings.append({
                                    "tool": "yara", "severity": "High", "finding": f"YARA Rule Match: {rule_name}",
                                    "cwe": "CWE-506", "details": f"DEB package content matches YARA rule '{rule_name}'",
                                    "remediation": "Investigate the matched rule for potential malicious content"
                                })
        except Exception as e:
            pass

        if not findings:
            findings.append({
                "tool": "checksec", "severity": "Info", "finding": "Package passed basic security checks",
                "cwe": "N/A", "details": "No critical issues detected in this package", "remediation": "N/A"
            })

    except Exception as e:
        findings.append({
            "tool": "DEB Analyzer", "severity": "Error", "finding": f"Analysis failed",
            "cwe": "N/A", "details": str(e), "remediation": "Ensure file is a valid DEB package"
        })
    finally:
        if os.path.exists(extract_dir):
            shutil.rmtree(extract_dir)

    return findings
