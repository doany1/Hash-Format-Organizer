# Hash Format Organizer 🔐

**Sort unknown password hashes into common formats (NTLM, bcrypt, SHA-2, MD5)**

![Python Version](https://img.shields.io/badge/Python-3.7%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Features
- Auto-detects 6+ hash formats
- Processes large files (>2GB tested)
- Creates categorized output files
- Error handling for malformed entries

Supported formats: `NTLM | bcrypt | SHA-1 | SHA-256 | SHA-512 | MD5`

## Installation:
             git clone https://github.com/doany1/hash-format-organizer.git
             cd hash-organizer
             pip install -r (read requirements) 


## Usage:
`python sort_hashes.py input_file.txt`

 Example output:
 Processing 1,000 lines...
 Completed! Check *_hashes.txt files

## Input Format:
`5f4dcc3b5aa765d61d8327deb882cf99:password123`
`$2a$12$3yvflnYPL7bE1Fq3D5VrHe...:SecurePass!`

## Output Files:
                 ▪️ MD5_hashes.txt

                 ▪️ NTLM_hashes.txt

                 ▪️ SHA-256_hashes.txt

                 ▪️ SHA-512_hashes.txt

                 ▪️ bcrypt_hashes.txt

                 ▪️ unknown_hashes.txt

▪️Format: hash:password:hash_type


## requirements.txt

`bcrypt==4.0.1`
