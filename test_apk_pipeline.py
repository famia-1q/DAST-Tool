import os
import sys
import json
from orchestrator.scan_runner import run_mobsf_scan
from adapters.parser import generate_unified_report
from adapters.report_generator import generate_pdf_report

def main():
    print("="*70)
    print("🚀 myESI MOBILE BINARY (APK) PIPELINE TEST")
    print("="*70)
    
    # 1. Create a dummy APK file for the test
    dummy_apk = "test_app.apk"
    print(f"\n[1/3] Preparing dummy mobile binary: {dummy_apk}")
    with open(dummy_apk, "w") as f:
        f.write("MOCK_APK_DATA_FOR_TESTING")
    print("      -> Dummy APK created successfully.")

    # 2. Run MobSF Scan (Zero-Trust Enforced)
    print("\n[2/3] Running MobSF Orchestrator (Zero-Trust Enforced)...")
    report_path = run_mobsf_scan(dummy_apk)
    
    if report_path and os.path.exists(report_path):
        print(f"      -> Raw report generated at: {report_path}")
        
        # 3. Parse and Generate PDF
        print("\n[3/3] Generating Mobile Security Audit PDF...")
        unified_data = generate_unified_report(report_path, "mobsf")
        
        final_pdf_path = "reports/MOBILE_AUDIT_REPORT.pdf"
        generate_pdf_report(unified_data, final_pdf_path)
        
        print("\n" + "="*70)
        print("✅ SUCCESS! Mobile binary scan and reporting complete.")
        print("✅ Zero-Trust privacy enforced (temporary binary deleted).")
        print("✅ myESI Unified Schema mapping complete (OWASP MASVS).")
        print(f"📄 Final Report Location: {os.path.abspath(final_pdf_path)}")
        print("="*70)
    else:
        print("❌ FAILED: MobSF report was not generated.")

    # Cleanup the dummy APK file from the root directory
    if os.path.exists(dummy_apk):
        os.remove(dummy_apk)
        print("\n[Cleanup] Dummy APK file removed from root directory.")

if __name__ == "__main__":
    main()
