import os
import json
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

def generate_pdf_report(unified_data: dict, output_pdf_path: str):
    """Generates a One-Click Audit PDF Report from unified myESI data."""
    os.makedirs(os.path.dirname(output_pdf_path), exist_ok=True)
    
    doc = SimpleDocTemplate(output_pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("myESI Unified Security Audit Report", styles['Title']))
    elements.append(Spacer(1, 12))
    
    exec_summary = (
        f"<b>Scan Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>"
        f"<b>Engine Used:</b> {unified_data.get('engine_used', 'Unknown')}<br/>"
        f"<b>Total Findings:</b> {unified_data.get('total_findings', 0)}<br/>"
        f"<b>Compliance Frameworks:</b> {', '.join(unified_data['findings'][0]['framework_mapping']) if unified_data['findings'] else 'N/A'}"
    )
    elements.append(Paragraph("Executive Summary", styles['Heading2']))
    elements.append(Paragraph(exec_summary, styles['Normal']))
    elements.append(Spacer(1, 20))

    elements.append(Paragraph("Detailed Findings", styles['Heading2']))
    elements.append(Spacer(1, 10))

    data = [["Severity", "Source", "Title", "Location", "Remediation"]]
    
    for finding in unified_data.get("findings", []):
        data.append([
            finding.get("severity", "INFO"),
            finding.get("source", "Unknown"),
            finding.get("title", "N/A")[:40] + "...",
            finding.get("location", "N/A")[:30] + "...",
            finding.get("remediation_guidance", "N/A")[:50] + "..."
        ])

    table = Table(data, colWidths=[60, 60, 150, 120, 150])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('WORDWRAP', (0, 0), (-1, -1), True)
    ]))

    elements.append(table)
    doc.build(elements)
    print(f"✅ PDF Report successfully generated: {output_pdf_path}")
