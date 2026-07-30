import json
from adapters.pefile_adapter import parse_pefile_report
from adapters.manalyze_adapter import parse_manalyze_report
from adapters.lief_adapter import parse_lief_report
from adapters.checksec_adapter import parse_checksec_report

# Create dummy JSON files to simulate the orchestrator's output
dummy_pefile = {"file_name": "test.exe", "is_packed": True, "is_suspicious": True}
dummy_manalyze = [{"severity": "high", "name": "Suspicious Import", "description": "Found bad import"}]
dummy_lief = {"file_name": "test_bin", "is_pie": False, "has_nx": True, "sections": [{"name": ".text", "entropy": 7.5}]}
dummy_checksec = {"file": "test_bin", "relro": "Partial", "canary": "No", "nx": "Enabled", "pie": "Disabled"}

with open("dummy_pefile.json", "w") as f: json.dump(dummy_pefile, f)
with open("dummy_manalyze.json", "w") as f: json.dump(dummy_manalyze, f)
with open("dummy_lief.json", "w") as f: json.dump(dummy_lief, f)
with open("dummy_checksec.json", "w") as f: json.dump(dummy_checksec, f)

# Run the adapters
print("--- Testing pefile_adapter ---")
print(parse_pefile_report("dummy_pefile.json"))

print("\n--- Testing manalyze_adapter ---")
print(parse_manalyze_report("dummy_manalyze.json"))

print("\n--- Testing lief_adapter ---")
print(parse_lief_report("dummy_lief.json"))

print("\n--- Testing checksec_adapter ---")
print(parse_checksec_report("dummy_checksec.json"))
