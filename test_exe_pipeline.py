import json
import os
from adapters.pefile_adapter import parse_pefile_report
from adapters.manalyze_adapter import parse_manalyze_report
from adapters.yara_adapter import parse_yara_report

print("=" * 70)
print(" 🔧 TESTING WINDOWS EXE PIPELINE")
print("=" * 70)

with open("mock_pefile.json", "w") as f:
    json.dump({"file_name": "malware.exe", "is_packed": True, "is_suspicious": True}, f)

with open("mock_manalyze.json", "w") as f:
    json.dump([{"severity": "high", "name": "Suspicious Import", 
                "description": "Found bad API", "remediation": "Review"}], f)

with open("mock_yara_exe.txt", "w") as f:
    f.write("Malware_Family_X malware.exe\n")

print("\n[1/3] Testing pefile Adapter...")
pefile_findings = parse_pefile_report("mock_pefile.json")
print(f"   ✅ pefile adapter processed. Found {len(pefile_findings)} issues.")

print("\n[2/3] Testing Manalyze Adapter...")
manalyze_findings = parse_manalyze_report("mock_manalyze.json")
print(f"   ✅ Manalyze adapter processed. Found {len(manalyze_findings)} issues.")

print("\n[3/3] Testing YARA Adapter...")
yara_findings = parse_yara_report("mock_yara_exe.txt")
print(f"   ✅ YARA adapter processed. Found {len(yara_findings)} issues.")

print("\n" + "=" * 70)
print(" 📄 EXE PIPELINE RESULTS")
print("=" * 70)
all_findings = pefile_findings + manalyze_findings + yara_findings
print(json.dumps(all_findings, indent=2))

for file in ["mock_pefile.json", "mock_manalyze.json", "mock_yara_exe.txt"]:
    if os.path.exists(file):
        os.remove(file)

print("\n✅ EXE PIPELINE TEST COMPLETE!")
