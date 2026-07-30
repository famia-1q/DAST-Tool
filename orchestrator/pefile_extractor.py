import pefile
import json
import sys
import os

def extract_pe_metadata(file_path):
    """Extract comprehensive PE metadata using pefile."""
    try:
        pe = pefile.PE(file_path)
        
        metadata = {
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "machine_type": hex(pe.FILE_HEADER.Machine),
            "timestamp": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "sections": [],
            "imports": [],
            "exports": [],
            "is_packed": False,
            "is_suspicious": False
        }
        
        # Extract sections
        for section in pe.sections:
            metadata["sections"].append({
                "name": section.Name.decode().rstrip('\x00'),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": section.get_entropy()
            })
            # Check for packing indicators
            if section.get_entropy() > 7.0:
                metadata["is_packed"] = True
        
        # Extract imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                metadata["imports"].append(entry.dll.decode())
        
        # Extract exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                metadata["exports"].append(exp.name.decode() if exp.name else "N/A")
        
        # Suspicious indicators
        suspicious_imports = ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']
        for imp in metadata["imports"]:
            if any(sus in imp for sus in suspicious_imports):
                metadata["is_suspicious"] = True
                break
        
        return metadata
        
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 pefile_extractor.py <exe_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = extract_pe_metadata(file_path)
    
    # Output as JSON
    print(json.dumps(result, indent=2))
