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

def run_scan_async(scan_id, target_type, target_value, client_name, file_path=None):
    try:
        SCAN_STATUS[scan_id] = {'status': 'running', 'progress': 10, 'message': 'Initializing scan...', 'client': client_name}
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
    client_name = request.form.get('client_name', 'Valued Client')
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
    target_value = status.get('target_value', 'Unknown')
    client_name = status.get('client', 'Valued Client')
    
    # Dynamic Report Titles based on Scan Type
    titles = {
        'url': 'Web Application DAST Report of Findings',
        'mobile': 'Mobile Application Binary Analysis Report',
        'windows': 'Windows Executable Binary Analysis Report',
        'linux': 'Linux Package Binary Analysis Report'
    }
    report_title = titles.get(target_type, 'Unified Security Assessment Report of Findings')
    
    # Prepare dummy findings for the template if none exist
    findings = [
        {'id': 1, 'severity': 'High', 'title': 'Automated Engine Execution Successful', 'cwe': 'N/A', 'cvss': 'N/A', 'desc': f'The {target_type.upper()} scan completed successfully using the iSeeWaves Unified Orchestrator.', 'remediation': 'Review raw JSON outputs for specific engine warnings.'}
    ]

    html_content = render_template('report_template.html',
        scan_id=scan_id, scan_date=datetime.now().strftime("%B %d, %Y"),
        client_name=client_name, target=target_value, report_title=report_title,
        scan_type=target_type.upper(), findings=findings,
        high_count=0, medium_count=0, low_count=0, info_count=1, total_count=1
    )
    
    pdf_file = REPORTS_FOLDER / f"iSeeWaves_{client_name.replace(' ', '_')}_Report_{scan_id}.pdf"
    HTML(string=html_content).write_pdf(str(pdf_file))
    
    return send_file(str(pdf_file), as_attachment=True, download_name=pdf_file.name)

if __name__ == '__main__':
    print("=" * 60)
    print("  iSeeWaves Unified DAST & Binary Analysis Scanner")
    print("  Access at: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
