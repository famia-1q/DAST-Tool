import lief
import json
import sys
import os

def extract_elf_metadata(file_path):
    """Extract comprehensive ELF metadata using LIEF."""
    try:
        binary = lief.parse(file_path)
        
        if binary is None:
            return {"error": "Failed to parse ELF binary"}
        
        metadata = {
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "format": str(binary.format),
            "architecture": str(binary.header.architecture),
            "entry_point": hex(binary.header.entrypoint),
            "is_pie": binary.is_pie,
            "has_nx": binary.has_nx,
            "sections": [],
            "segments": [],
            "libraries": [],
            "symbols": []
        }
        
        # Extract sections
        for section in binary.sections:
            metadata["sections"].append({
                "name": section.name,
                "size": section.size,
                "virtual_address": hex(section.virtual_address),
                "entropy": section.entropy
            })
        
        # Extract segments
        for segment in binary.segments:
            metadata["segments"].append({
                "type": str(segment.type),
                "virtual_address": hex(segment.virtual_address),
                "memory_size": segment.memory_size
            })
        
        # Extract imported libraries
        if hasattr(binary, 'libraries'):
            metadata["libraries"] = list(binary.libraries)
        
        # Extract symbols (limited to first 50 for performance)
        if hasattr(binary, 'symbols'):
            metadata["symbols"] = [str(sym) for sym in binary.symbols[:50]]
        
        return metadata
        
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 lief_extractor.py <elf_binary>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    result = extract_elf_metadata(file_path)
    
    # Output as JSON
    print(json.dumps(result, indent=2))
