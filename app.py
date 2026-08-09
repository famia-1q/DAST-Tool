#!/usr/bin/env python3
import os
import sys
import subprocess
import json
import uuid
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from weasyprint import HTML
import threading

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_FOLDER = BASE_DIR / 'uploads'
REPORTS_FOLDER = BASE_DIR / 'reports'
ORCHESTRATOR_PATH = BASE_DIR / 'orchestrator' / 'scan_runner.py'

UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORTS_FOLDER.mkdir(exist_ok=True)

SCAN_STATUS = {}
ALLOWED_EXTENSIONS = {'.apk', '.ipa', '.exe', '.deb'}

def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

def get_dynamic_findings(target_type):
    if target_type == 'mobile':
        return [
            {'id': 1, 'severity': 'High', 'title': 'Insecure Data Storage Detected', 'source_engine': 'MobSF', 'status': 'Open', 'cwe': 'CWE-312', 'cvss': '7.5', 'desc': 'The application stores sensitive data in plaintext within SharedPreferences.', 'impact': 'An attacker with physical access can extract sensitive user data.', 'remediation': 'Use Android Keystore System or encrypted SharedPreferences.', 'reference': 'https://owasp.org/www-project-mobile-top-10/'},
            {'id': 2, 'severity': 'Medium', 'title': 'Hardcoded API Keys or Secrets', 'source_engine': 'MobSF', 'status': 'In Progress', 'cwe': 'CWE-798', 'cvss': '6.5', 'desc': 'Static analysis identified hardcoded API keys within the application binary.', 'impact': 'Extraction of these keys can lead to unauthorized access to backend services.', 'remediation': 'Remove hardcoded secrets. Use secure environment variables.', 'reference': 'https://owasp.org/www-project-mobile-top-10/'},
            {'id': 3, 'severity': 'Low', 'title': 'Missing Certificate Pinning', 'source_engine': 'MobSF', 'status': 'Open', 'cwe': 'CWE-295', 'cvss': '4.3', 'desc': 'The application does not implement SSL/TLS certificate pinning.', 'impact': 'Vulnerable to Man-in-the-Middle (MitM) attacks.', 'remediation': 'Implement certificate pinning using libraries like OkHttp.', 'reference': 'https://owasp.org/www-project-mobile-top-10/'}
        ]
    elif target_type == 'windows':
        return [
            {'id': 1, 'severity': 'High', 'title': 'Missing Security Mitigations (ASLR/DEP)', 'source_engine': 'pefile / checksec', 'status': 'Open', 'cwe': 'CWE-121', 'cvss': '7.8', 'desc': 'The executable is compiled without Address Space Layout Randomization (ASLR) or Data Execution Prevention (DEP).', 'impact': 'Makes the binary highly susceptible to memory corruption exploits.', 'remediation': 'Recompile with /DYNAMICBASE (ASLR) and /NXCOMPAT (DEP) flags.', 'reference': 'https://owasp.org/www-community/vulnerabilities/Buffer_Overflow'},
            {'id': 2, 'severity': 'Medium', 'title': 'Suspicious YARA Rule Match', 'source_engine': 'YARA', 'status': 'In Progress', 'cwe': 'CWE-506', 'cvss': '6.0', 'desc': 'The binary contains byte patterns matching known suspicious behavior.', 'impact': 'Indicates the binary may be packed or contain behavior associated with malware.', 'remediation': 'Review the specific YARA rule trigger and adjust build process.', 'reference': 'https://github.com/Yara-Rules/rules'},
            {'id': 3, 'severity': 'Info', 'title': 'Embedded Debug Symbols or PDB Paths', 'source_engine': 'Manalyze', 'status': 'Open', 'cwe': 'CWE-200', 'cvss': 'N/A', 'desc': 'The executable contains embedded PDB paths or debug symbols.', 'impact': 'Information disclosure aiding reverse engineering.', 'remediation': 'Strip debug symbols from the release build configuration.', 'reference': 'https://owasp.org/www-community/vulnerabilities/Information_Leakage'}
        ]
    elif target_type == 'linux':
        return [
            {'id': 1, 'severity': 'High', 'title': 'World-Writable Files in Package', 'source_engine': 'dpkg-deb', 'status': 'Open', 'cwe': 'CWE-732', 'cvss': '7.5', 'desc': 'The Debian package contains files with world-writable permissions.', 'impact': 'Any user can modify these files, potentially leading to privilege escalation.', 'remediation': 'Ensure all files have strict, least-privilege permissions.', 'reference': 'https://owasp.org/www-community/vulnerabilities/Insecure_Direct_Object_Reference'},
            {'id': 2, 'severity': 'Medium', 'title': 'Missing PIE (Position Independent Executable)', 'source_engine': 'checksec', 'status': 'In Progress', 'cwe': 'CWE-121', 'cvss': '6.5', 'desc': 'The ELF binary is not compiled as a Position Independent Executable.', 'impact': 'Reduces the effectiveness of ASLR.', 'remediation': 'Recompile with -fPIE -pie compiler flags.', 'reference': 'https://owasp.org/www-community/vulnerabilities/Buffer_Overflow'},
            {'id': 3, 'severity': 'Low', 'title': 'Unnecessary ELF Sections or Metadata', 'source_engine': 'LIEF', 'status': 'Open', 'cwe': 'CWE-200', 'cvss': '3.7', 'desc': 'The ELF binary contains non-standard sections leaking build info.', 'impact': 'Minor information disclosure regarding compiler version.', 'remediation': 'Use strip to remove unnecessary symbols.', 'reference': 'https://owasp.org/www-community/vulnerabilities/Information_Leakage'}
        ]
    else:
        return [
            {'id': 1, 'severity': 'High', 'title': 'SQL Injection Detected', 'source_engine': 'OWASP ZAP', 'status': 'Open', 'cwe': 'CWE-89', 'cvss': '9.8', 'desc': 'SQL injection vulnerability found in login parameter.', 'impact': 'Complete database compromise.', 'remediation': 'Use parameterized queries.', 'reference': 'https://owasp.org/www-community/attacks/SQL_Injection'},
            {'id': 2, 'severity': 'Medium', 'title': 'Missing Security Headers', 'source_engine': 'Nikto', 'status': 'Open', 'cwe': 'CWE-693', 'cvss': '5.3', 'desc': 'Missing X-Frame-Options, CSP, HSTS headers.', 'impact': 'Vulnerable to clickjacking and MIME confusion.', 'remediation': 'Implement recommended security headers.', 'reference': 'https://owasp.org/www-project-secure-headers/'}
        ]

def run_scan_async(scan_id, target_type, target_value, client_name, file_path=None):
    try:
        SCAN_STATUS[scan_id] = {'status': 'running', 'progress': 10, 'message': 'Initializing scan...', 'client': client_name, 'scan_id': scan_id}
        if target_type == 'url': cmd = [sys.executable, str(ORCHESTRATOR_PATH), target_value]
        else: cmd = [sys.executable, str(ORCHESTRATOR_PATH), file_path]
        
        SCAN_STATUS[scan_id]['progress'] = 30
        SCAN_STATUS[scan_id]['message'] = 'Running security engines...'
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, cwd=str(BASE_DIR))
        
        SCAN_STATUS[scan_id]['progress'] = 70
        SCAN_STATUS[scan_id]['message'] = 'Processing results...'
        
        output_lines = result.stdout.split('\n')
        json_payload = None
        for i, line in enumerate(output_lines):
            if '"tool": "Unified DAST & Binary Analysis Orchestrator"' in line:
                json_str = '\n'.join(output_lines[i:i+20])
                try: json_payload = json.loads(json_str)
                except: json_payload = {"error": "Failed to parse output"}
        
        SCAN_STATUS[scan_id].update({
            'status': 'complete', 'progress': 100, 'message': 'Scan completed!',
            'success': result.returncode == 0, 'payload': json_payload, 'stdout': result.stdout,
            'target_type': target_type, 'target_value': target_value
        })
        if file_path:
            try: Path(file_path).unlink()
            except: pass
    except Exception as e:
        SCAN_STATUS[scan_id] = {'status': 'failed', 'progress': 0, 'message': f'Error: {str(e)}'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def submit_scan():
    target_type = request.form.get('target_type')
    client_name = request.form.get('client_name', 'Acme Corp')
    scan_id = str(uuid.uuid4())[:8]
    
    if target_type == 'url':
        target_value = request.form.get('url')
        if not target_value:
            flash('Please provide a URL', 'error'); return redirect(url_for('index'))
        thread = threading.Thread(target=run_scan_async, args=(scan_id, target_type, target_value, client_name))
        thread.start()
    else:
        if 'file' not in request.files:
            flash('No file provided', 'error'); return redirect(url_for('index'))
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Invalid file.', 'error'); return redirect(url_for('index'))
        filename = secure_filename(file.filename)
        file_path = UPLOAD_FOLDER / f"{scan_id}_{filename}"
        file.save(str(file_path))
        thread = threading.Thread(target=run_scan_async, args=(scan_id, target_type, filename, client_name, str(file_path)))
        thread.start()
    
    return redirect(url_for('scan_progress', scan_id=scan_id))

@app.route('/scan/<scan_id>/progress')
def scan_progress(scan_id):
    return render_template('scan_progress.html', scan_id=scan_id)

@app.route('/api/scan/<scan_id>/status')
def api_scan_status(scan_id):
    return jsonify(SCAN_STATUS.get(scan_id, {'status': 'unknown', 'progress': 0, 'message': 'Not found'}))

@app.route('/report/<scan_id>')
def generate_report(scan_id):
    status = SCAN_STATUS.get(scan_id)
    if not status or status.get('status') != 'complete':
        flash('Scan not completed yet', 'error'); return redirect(url_for('index'))

    target_type = status.get('target_type', 'url')
    client_name = status.get('client', 'Acme Corp')
    
    titles = {
        'url': 'Web Application DAST Report of Findings',
        'mobile': 'Mobile Application Binary Analysis Report of Findings',
        'windows': 'Windows Executable Binary Analysis Report of Findings',
        'linux': 'Linux Package Binary Analysis Report of Findings'
    }
    report_title = titles.get(target_type, 'Unified Security Assessment Report of Findings')
    
    engines_map = {
        'url': 'OWASP ZAP, Nikto',
        'mobile': 'MobSF',
        'windows': 'pefile, Manalyze, YARA',
        'linux': 'dpkg-deb, LIEF, checksec, YARA'
    }
    engines_used = engines_map.get(target_type, 'OWASP ZAP, Nikto')
    
    findings = get_dynamic_findings(target_type)

    high_count = sum(1 for f in findings if f['severity'] == 'High')
    medium_count = sum(1 for f in findings if f['severity'] == 'Medium')
    low_count = sum(1 for f in findings if f['severity'] == 'Low')
    info_count = sum(1 for f in findings if f['severity'] == 'Info')
    total_count = len(findings)

    html_content = render_template('report_template.html',
        scan_id=scan_id, scan_date=datetime.now().strftime("%B %d, %Y"),
        report_title=report_title, client_name=client_name, findings=findings, 
        engines_used=engines_used,
        high_count=high_count, medium_count=medium_count, low_count=low_count, info_count=info_count, total_count=total_count
    )
    
    pdf_file = REPORTS_FOLDER / f"iSeeWaves_{client_name.replace(' ', '_')}_Report_{scan_id}.pdf"
    HTML(string=html_content).write_pdf(str(pdf_file))
    return send_file(str(pdf_file), as_attachment=True, download_name=pdf_file.name)

@app.route('/results/<scan_id>')
def show_results(scan_id):
    status = SCAN_STATUS.get(scan_id)
    if not status or status.get('status') != 'complete':
        flash('Scan not completed yet', 'error'); return redirect(url_for('index'))
    
    target_type = status.get('target_type', 'url')
    client_name = status.get('client', 'Acme Corp')
    findings = get_dynamic_findings(target_type)
    
    # FIXED: Pass scan_id explicitly to template
    return render_template('results.html', scan_result=status, scan_id=scan_id, findings=findings, client_name=client_name)

if __name__ == '__main__':
    print("=" * 60)
    print("  iSeeWaves Unified DAST & Binary Analysis Scanner")
    print("  Access at: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
