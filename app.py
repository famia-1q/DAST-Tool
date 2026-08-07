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
import time

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-in-production'
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024

BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_FOLDER = BASE_DIR / 'uploads'
REPORTS_FOLDER = BASE_DIR / 'reports'
ORCHESTRATOR_PATH = BASE_DIR / 'orchestrator' / 'scan_runner.py'

UPLOAD_FOLDER.mkdir(exist_ok=True)
REPORTS_FOLDER.mkdir(exist_ok=True)

# Scan status storage
SCAN_STATUS = {}

ALLOWED_EXTENSIONS = {'.apk', '.ipa', '.exe', '.deb'}

def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

def run_scan_async(scan_id, target_type, target_value, file_path=None):
    """Run scan in background with progress updates"""
    try:
        SCAN_STATUS[scan_id] = {
            'status': 'running',
            'progress': 10,
            'message': 'Initializing scan...',
            'stage': 'starting'
        }
        
        if target_type == 'url':
            cmd = [sys.executable, str(ORCHESTRATOR_PATH), target_value]
        else:
            cmd = [sys.executable, str(ORCHESTRATOR_PATH), file_path]
        
        SCAN_STATUS[scan_id] = {
            'status': 'running',
            'progress': 30,
            'message': 'Running security engines...',
            'stage': 'scanning'
        }
        
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=3600, 
            cwd=str(BASE_DIR)
        )
        
        SCAN_STATUS[scan_id] = {
            'status': 'running',
            'progress': 70,
            'message': 'Processing results...',
            'stage': 'processing'
        }
        
        # Parse output
        output_lines = result.stdout.split('\n')
        json_payload = None
        for i, line in enumerate(output_lines):
            if '"tool": "Unified DAST & Binary Analysis Orchestrator"' in line:
                json_str = '\n'.join(output_lines[i:i+20])
                try:
                    json_payload = json.loads(json_str)
                except:
                    json_payload = {"error": "Failed to parse output"}
        
        SCAN_STATUS[scan_id] = {
            'status': 'complete',
            'progress': 100,
            'message': 'Scan completed!',
            'stage': 'complete',
            'success': result.returncode == 0,
            'payload': json_payload,
            'stdout': result.stdout
        }
        
        # Clean up uploaded file
        if file_path:
            try:
                Path(file_path).unlink()
            except:
                pass
                
    except Exception as e:
        SCAN_STATUS[scan_id] = {
            'status': 'failed',
            'progress': 0,
            'message': f'Error: {str(e)}',
            'stage': 'failed'
        }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def submit_scan():
    target_type = request.form.get('target_type')
    scan_id = str(uuid.uuid4())[:8]
    
    if target_type == 'url':
        target_value = request.form.get('url')
        if not target_value:
            flash('Please provide a URL', 'error')
            return redirect(url_for('index'))
        thread = threading.Thread(target=run_scan_async, args=(scan_id, 'url', target_value))
        thread.start()
    else:
        if 'file' not in request.files:
            flash('No file provided', 'error')
            return redirect(url_for('index'))
        
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Invalid file. Allowed: .apk, .ipa, .exe, .deb', 'error')
            return redirect(url_for('index'))
        
        filename = secure_filename(file.filename)
        file_path = UPLOAD_FOLDER / f"{scan_id}_{filename}"
        file.save(str(file_path))
        
        thread = threading.Thread(target=run_scan_async, args=(scan_id, 'file', filename, str(file_path)))
        thread.start()
    
    return redirect(url_for('scan_progress', scan_id=scan_id))

@app.route('/scan/<scan_id>/progress')
def scan_progress(scan_id):
    return render_template('scan_progress.html', scan_id=scan_id)

@app.route('/api/scan/<scan_id>/status')
def api_scan_status(scan_id):
    status = SCAN_STATUS.get(scan_id, {'status': 'unknown', 'progress': 0, 'message': 'Not found'})
    return jsonify(status)

@app.route('/report/<scan_id>')
def generate_report(scan_id):
    status = SCAN_STATUS.get(scan_id)
    if not status or status.get('status') != 'complete':
        flash('Scan not completed yet', 'error')
        return redirect(url_for('index'))
    
    html_content = render_template('report_template.html', 
                                   scan_id=scan_id,
                                   company_name="iSeeWaves Client",
                                   scan_date=datetime.now().strftime("%B %d, %Y"))
    
    pdf_file = REPORTS_FOLDER / f"iSeeWaves_Report_{scan_id}.pdf"
    HTML(string=html_content).write_pdf(str(pdf_file))
    
    return send_file(str(pdf_file), 
                     as_attachment=True, 
                     download_name=f"iSeeWaves_Security_Report_{scan_id}.pdf")

if __name__ == '__main__':
    print("=" * 60)
    print("  iSeeWaves Unified DAST & Binary Analysis Scanner")
    print("  Access at: http://localhost:5000")
    print("=" * 60)
    app.run(host='0.0.0.0', port=5000, debug=True)
