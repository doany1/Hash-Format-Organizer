
import re
import hashlib
import bcrypt
import sys
from pathlib import Path

def process_line(line):
    """Process single line of input"""
    line = line.strip()
    if not line:
        return None
        
    # Split hash and password
    parts = re.split(r'[\s:]+', line, 1)
    if len(parts) != 2:
        return None
        
    hash_str, password = parts
    return categorize_hash(hash_str, password)

def categorize_hash(hash_str, password):
    """Determine hash type and validate"""
    hash_type = detect_hash_type(hash_str)
    
    if hash_type != 'unknown' and validate_hash(hash_type, password, hash_str):
        return f"{hash_str}:{password}:{hash_type}"
    return f"{hash_str}:{password}:unknown"

def detect_hash_type(hash_str):
    """Identify hash format using patterns"""
    if re.match(r'^\$2[aby]\$', hash_str):
        return 'bcrypt'
    elif len(hash_str) == 32 and re.match(r'^[a-f0-9]+$', hash_str):
        return 'MD5'
    elif len(hash_str) == 64 and re.match(r'^[a-f0-9]+$', hash_str):
        return 'SHA-256'
    elif len(hash_str) == 128 and re.match(r'^[a-f0-9]+$', hash_str):
        return 'SHA-512'
    elif len(hash_str) == 40 and re.match(r'^[a-f0-9]+$', hash_str):
        return 'SHA-1'
    elif len(hash_str) == 32 and re.match(r'^[A-F0-9]+$', hash_str):
        return 'NTLM'
    return 'unknown'

def validate_hash(hash_type, password, stored_hash):
    """Verify hash matches password"""
    try:
        if hash_type == 'MD5':
            return hashlib.md5(password.encode()).hexdigest() == stored_hash
        elif hash_type == 'NTLM':
            return hashlib.new('md4', password.encode('utf-16le')).hexdigest() == stored_hash
        elif hash_type.startswith('SHA-'):
            algo = hash_type.split('-')[1].lower()
            return hashlib.new(algo, password.encode()).hexdigest() == stored_hash
        elif hash_type == 'bcrypt':
            return bcrypt.checkpw(password.encode(), stored_hash.encode())
    except Exception:
        return False

def main():
    """Main processing function"""
    if len(sys.argv) != 2:
        print("Usage: python sort_hashes.py input_file")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_files = {}

    # Create output directories
    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # Initialize output files
    hash_types = ['MD5', 'NTLM', 'SHA-1', 'SHA-256', 'SHA-512', 'bcrypt', 'unknown']
    for ht in hash_types:
        output_files[ht] = open(output_dir / f"{ht}_hashes.txt", 'w', encoding='utf-8')

    # Process input
    with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
        for i, line in enumerate(f):
            result = process_line(line)
            if result:
                hash_type = result.split(':')[-1]
                output_files[hash_type].write(result + '\n')
            
            if i % 1000 == 0:
                print(f"Processed {i} lines...", end='\r')

    # Cleanup
    for f in output_files.values():
        f.close()
    print("\nProcessing complete. Files saved to /output directory.")

if __name__ == "__main__":
    main()
