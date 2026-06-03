---
name: ffuf
description: Web fuzzing, directory discovery, parameter fuzzing
category: tooling
---

# FFUF Usage Guide

FFUF is a fast web fuzzer for directory discovery, parameter fuzzing, and vhost enumeration.

## Common Usage
```bash
# Directory discovery
ffuf -w /usr/share/wordlists/dirb/common.txt -u https://target.com/FUZZ

# Extension filtering
ffuf -w wordlist.txt -u https://target.com/FUZZ -e .php,.asp,.aspx,.jsp

# Recursive scanning
ffuf -w wordlist.txt -u https://target.com/FUZZ -recursion -recursion-depth 2

# Parameter fuzzing (GET)
ffuf -w params.txt -u https://target.com/api?FUZZ=test

# POST parameter fuzzing
ffuf -w params.txt -u https://target.com/api -X POST -d "FUZZ=test"

# VHost enumeration
ffuf -w vhosts.txt -u https://target.com -H "Host: FUZZ.target.com"
```

## Matchers & Filters
```bash
# Match by status code
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 200,301,302

# Filter by response size
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 1234

# Filter by number of words
ffuf -w wordlist.txt -u https://target.com/FUZZ -fw 50
```

## Best Practices
- Use `-fc` to filter common status codes
- Combine with `-recursion` for deep discovery
- Use accurate wordlists for specific technologies
- Filter out false positives with response size
