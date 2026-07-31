import json
from adapters.nikto_adapter import parse_nikto_report

print("=" * 70)
print(" 🌐 TESTING WEB/API PIPELINE")
print("=" * 70)

# Simulate Nikto JSON output (using the exact structure your adapter expects)
mock_nikto = {
    "nikto": {
        "scandetails": [
            {
                "id": "001",
                "OSVDB": "1234",
                "method": "GET",
                "url": "/admin",
                "description": "Admin panel found",
                "severity": "Medium"
            }
        ]
    }
}

with open("mock_nikto.json", "w") as f:
    json.dump(mock_nikto, f)

print("\n[1/1] Testing Nikto Adapter...")
nikto_findings = parse_nikto_report("mock_nikto.json")
print(f"   ✅ Nikto adapter processed. Found {len(nikto_findings)} issues.")

print("\n" + "=" * 70)
print(" 📄 WEB PIPELINE RESULTS")
print("=" * 70)
print(json.dumps(nikto_findings, indent=2))

import os
os.remove("mock_nikto.json")
print("\n✅ WEB PIPELINE TEST COMPLETE!")
