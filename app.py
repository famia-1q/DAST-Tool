#!/usr/bin/env python3
import os
import sys
import json
import uuid
import secrets
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for, jsonify
from werkzeug.utils import secure_filename
from weasyprint import HTML
import threading

# Import the REAL dynamic adapters
from adapters.nikto_adapter import scan_web_target
from adapters.zap_adapter import scan_web_target_with_zap
from adapters.pefile_adapter import scan_exe_target
from adapters.checksec_adapter import scan_deb_target
from adapters.yara_adapter import scan_apk_target

app = Flask(__name__)

# ✅ FIX 1: Secure Secret Key (No hardcoded secrets)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Optional: Force failure if deployed in production without a real key
if os.environ.get('FLASK_ENV') == 'production' and not os.environ.get('FLASK_SECRET_KEY'):
    raise ValueError("CRITICAL: FLASK_SECRET_KEY environment variable must be set in production!")

app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_FOLDER = BASE_DIR / 'uploads'
REPORTS_FOLDER = BASE_DIR / 'reports'

UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORTS_FOLDER.mkdir(exist_ok=True)

SCAN_STATUS = {}
ALLOWED_EXTENSIONS = {'.apk', '.ipa', '.exe', '.deb'}

def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

def run_scan_async(scan_id, target_type, target_value, client_name, file_path=None):
    try:
        SCAN_STATUS[scan_id] = {
            'status': 'running', 
            'progress': 10, 
            'message': 'Initializing scan...', 
            'client': client_name, 
            'scan_id': scan_id,
            'target_type': target_type,
            'target_value': target_value
        }
        
        SCAN_STATUS[scan_id]['progress'] = 30
        SCAN_STATUS[scan_id]['message'] = 'Running security engines...'
        
        # 1. CALL THE REAL DYNAMIC ADAPTERS BASED ON TARGET TYPE
        findings = []
        if target_type == 'url':
            # ✅ FIX 2: Run BOTH ZAP and Nikto for real URL scanning
            zap_findings = scan_web_target_with_zap(target_value)
            nikto_findings = scan_web_target(target_value)
            findings = zap_findings + nikto_findings
            
        elif target_type in ['windows', 'exe']:
            findings = scan_exe_target(file_path)
        elif target_type in ['linux', 'deb']:
            findings = scan_deb_target(file_path)
        elif target_type in ['mobile', 'apk']:
            findings = scan_apk_target(file_path)
        else:
            findings = [{'severity': 'Error', 'finding': 'Unknown Target Type', 'details': 'Invalid scan type provided.'}]
        
        SCAN_STATUS[scan_id]['progress'] = 70
        SCAN_STATUS[scan_id]['message'] = 'Processing results...'
        
        # 2. Format findings to match the HTML report template expectations
        formatted_findings = []
        for idx, f in enumerate(findings, 1):
            formatted_findings.append({
                'id': idx,
                'severity': f.get('severity', 'Info').capitalize(),
                'title': f.get('finding', f.get('title', 'Security Finding Detected')),
                'source_engine': f.get('tool', 'Unknown Engine'),
                'status': 'Open',
                'cwe': f.get('cwe', 'N/A'),
                'cvss': f.get('cvss', 'N/A'),
                'desc': f.get('details', f.get('description', 'No details provided.')),
                'impact': 'Potential security risk identified during dynamic analysis.',
                'remediation': f.get('remediation', 'Review and remediate the identified issue.'),
                'reference': 'https://cwe.mitre.org/'
            })
        
        # 3. Update scan status with REAL findings
        SCAN_STATUS[scan_id].update({
            'status': 'complete', 
            'progress': 100, 
            'message': 'Scan completed!',
            'success': True, 
            'findings': formatted_findings
        })
        
        # Cleanup uploaded file after scanning
        if file_path:
            try: 
                Path(file_path).unlink()
            except Exception: 
                pass
                
    except Exception as e:
        SCAN_STATUS[scan_id] = {
            'status': 'failed', 
            'progress': 0, 
            'message': f'Error: {str(e)}'
        }

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
            flash('Please provide a URL', 'error')
            return redirect(url_for('index'))
        thread = threading.Thread(target=run_scan_async, args=(scan_id, target_type, target_value, client_name))
        thread.start()
    else:
        if 'file' not in request.files:
            flash('No file provided', 'error')
            return redirect(url_for('index'))
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Invalid file.', 'error')
            return redirect(url_for('index'))
        
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
        flash('Scan not completed yet', 'error')
        return redirect(url_for('index'))

    target_type = status.get('target_type', 'url')
    client_name = status.get('client', 'Acme Corp')
    findings = status.get('findings', [])

    titles = {
        'url': 'Web Application DAST Report of Findings',
        'mobile': 'Mobile Application Binary Analysis Report of Findings',
        'windows': 'Windows Executable Binary Analysis Report of Findings',
        'linux': 'Linux Package Binary Analysis Report of Findings'
    }
    report_title = titles.get(target_type, 'Unified Security Assessment Report of Findings')
    
    engines_map = {
        'url': 'OWASP ZAP + Nikto (Dynamic CLI)',
        'mobile': 'Apktool + Grep (Dynamic Analysis)',
        'windows': 'pefile + Manalyze + YARA (Dynamic Analysis)',
        'linux': 'dpkg-deb + checksec + LIEF + YARA (Dynamic Analysis)'
    }
    engines_used = engines_map.get(target_type, 'Dynamic Security Engines')
    
    high_count = sum(1 for f in findings if f['severity'] == 'High')
    medium_count = sum(1 for f in findings if f['severity'] == 'Medium')
    low_count = sum(1 for f in findings if f['severity'] == 'Low')
    info_count = sum(1 for f in findings if f['severity'] == 'Info')
    total_count = len(findings)

    html_content = render_template('report_template.html',
        scan_id=scan_id, 
        scan_date=datetime.now().strftime("%B %d, %Y"),
        report_title=report_title, 
        client_name=client_name, 
        findings=findings, 
        engines_used=engines_used,
        high_count=high_count, 
        medium_count=medium_count, 
        low_count=low_count, 
        info_count=info_count, 
        total_count=total_count
    )
    
    # ✅ FIX 3: Prevent Path Traversal in PDF generation
    safe_client_name = secure_filename(client_name) or "Unknown_Client"
    pdf_file = REPORTS_FOLDER / f"iSeeWaves_{safe_client_name}_Report_{scan_id}.pdf"
    
    pdf_file.parent.mkdir(parents=True, exist_ok=True)
    
    HTML(string=html_content).write_pdf(str(pdf_file))
    return send_file(str(pdf_file), as_attachment=True, download_name=pdf_file.name)

@app.route('/results/<scan_id>')
def show_results(scan_id):
    status = SCAN_STATUS.get(scan_id)
    if not status or status.get('status') != 'complete':
        flash('Scan not completed yet', 'error')
        return redirect(url_for('index'))
    
    client_name = status.get('client', 'Acme Corp')
    findings = status.get('findings', [])
    
    return render_template('results.html', scan_result=status, scan_id=scan_id, findings=findings, client_name=client_name)

if __name__ == '__main__':
    print("=" * 60)
    print("  iSeeWaves Unified DAST & Binary Analysis Scanner")
    print("  Access at: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
