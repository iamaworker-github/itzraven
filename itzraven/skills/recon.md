---
name: recon
description: OSINT, subdomain enumeration, port scanning, technology fingerprinting, subfinder mastery, deep recon
category: tooling
---

# Reconnaissance Methodology

## Attack Surface
Reconnaissance is the first phase of any security assessment, mapping the target's attack surface.

## External Recon
1. **Subdomain Enumeration**
   - Passive: Certificate Transparency (crt.sh), DNS dumpster, Shodan, Censys
   - Active: Subfinder, DNS brute-force with common wordlists
   - Permutation: Generate permutations of discovered subdomains

2. **Technology Detection**
   - HTTP headers: Server, X-Powered-By, Set-Cookie
   - WAF detection: wafw00f
   - JavaScript library analysis: Retire.js
   - Framework detection from HTML/CSS patterns

3. **Port Scanning**
   - Top 1000 ports with service detection
   - SYN scan for speed (requires root)
   - Service version detection on open ports
   - NSE scripts for vulnerability detection

4. **Web Crawling**
   - Spider all accessible pages
   - Parse JS files for API endpoints
   - Look for hidden directories
   - Archive analysis (Wayback Machine)

## Subfinder Mastery (Deep Subdomain Enumeration)

### Basic Usage
```bash
# Single domain
subfinder -d target.com -silent

# Multi-domain from file
subfinder -dL domains.txt -all -silent -o subdomains.txt

# Recursive (subdomain → subdomain)
subfinder -d target.com -recursive -silent
```

### Advanced Flags
```bash
# Use all sources (max coverage)
subfinder -d target.com -all -recursive -silent

# Rate limiting for stealth
subfinder -d target.com -t 50 -timeout 30 -silent

# Output to file
subfinder -d target.com -all -recursive -silent -o subdomains.txt

# JSON output for automation
subfinder -d target.com -all -recursive -silent -oJ -o subdomains.json
```

### Integration with Other Tools
```bash
# Full recon chain
subfinder -d target.com -all -recursive -silent | \
  httpx -silent -sc -cl -title -td -o live_hosts.txt

# Filter only live hosts with specific status codes
cat subdomains.txt | httpx -silent -sc -mc 200,403,301 -o filtered.txt

# Screenshot all live hosts
cat live_hosts.txt | httpx -silent -screenshot -screenshot-output screenshots/

# Passive + Active combo
subfinder -d target.com -silent | dnsx -silent -a -resp -o resolved.txt
```

### Source-Specific Enumeration
```bash
# Only passive sources (never touch target)
subfinder -d target.com -silent -only-passive -recursive

# Only certificate transparency
subfinder -d target.com -silent -s ct

# Chaos dataset (if API key configured)
subfinder -d target.com -silent -s chaos
```

### Permutation Attack
```bash
# Generate permutations of known subdomains
cat subdomains.txt | alterx -silent -o permutations.txt

# Validate permutations
cat permutations.txt | dnsx -silent -a -resp -o resolved_perms.txt
```

## Internal Recon
- Network segmentation testing
- Service discovery on internal networks
- Active directory enumeration (if applicable)
- Cloud provider metadata endpoints

## Validation
- Confirm DNS resolution for discovered subdomains
- Verify HTTP response for scanned ports
- Screenshot discovered web services
- Prioritize live, responsive targets
