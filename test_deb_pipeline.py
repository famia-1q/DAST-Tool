import json
import os
from adapters.lief_adapter import parse_lief_report
from adapters.checksec_adapter import parse_checksec_report
from adapters.yara_deb_adapter import parse_yara_deb_report

print("=" * 70)
print(" 🐧 TESTING LINUX DEB PIPELINE")
print("=" * 70)

with open("mock_lief.json", "w") as f:
    json.dump({"file_name": "htop", "is_pie": False, "has_nx": True, 
               "sections": [{"name": ".text", "entropy": 7.5}]}, f)

with open("mock_checksec.json", "w") as f:
    json.dump({"file": "htop", "relro": "Partial", "canary": "No", 
               "nx": "Enabled", "pie": "Disabled"}, f)

with open("mock_yara_deb.txt", "w") as f:
    f.write("Suspicious_Packer package.deb\n")

print("\n[1/3] Testing LIEF Adapter...")
lief_findings = parse_lief_report("mock_lief.json")
print(f"   ✅ LIEF adapter processed. Found {len(lief_findings)} issues.")

print("\n[2/3] Testing checksec Adapter...")
checksec_findings = parse_checksec_report("mock_checksec.json")
print(f"   ✅ checksec adapter processed. Found {len(checksec_findings)} issues.")

print("\n[3/3] Testing YARA DEB Adapter...")
yara_findings = parse_yara_deb_report("mock_yara_deb.txt")
print(f"   ✅ YARA DEB adapter processed. Found {len(yara_findings)} issues.")

print("\n" + "=" * 70)
print(" 📄 DEB PIPELINE RESULTS")
print("=" * 70)
all_findings = lief_findings + checksec_findings + yara_findings
print(json.dumps(all_findings, indent=2))

for file in ["mock_lief.json", "mock_checksec.json", "mock_yara_deb.txt"]:
    if os.path.exists(file):
        os.remove(file)

print("\n✅ DEB PIPELINE TEST COMPLETE!")
