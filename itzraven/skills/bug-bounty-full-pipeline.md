---
name: bug-bounty-full-pipeline
description: Complete 7-phase bug bounty pipeline — scope review → recon → discovery → enumeration → testing → two-eye → POC → report
category: methodology
---

# Bug Bounty Full Pipeline (2026)

> Complete workflow: from scope to submission. Every phase feeds the next.

```
┌─────────────────────────────────────────────────────────────┐
│                    BUG BOUNTY PIPELINE                       │
│                                                              │
│  SCOPE REVIEW                                               │
│       ↓                                                      │
│  PHASE 1: RECONNAISSANCE                                    │
│  Passive → Active → Subdomain Enumeration                   │
│       ↓                                                      │
│  PHASE 2: DISCOVERY                                         │
│  HTTP Probing → JS Analysis → URL Discovery                 │
│       ↓                                                      │
│  PHASE 3: ENUMERATION                                       │
│  Parameters → Cloud → APIs → Content → Infrastructure       │
│       ↓                                                      │
│  PHASE 4: TESTING                                           │
│  RCE → SQLi → SSRF → LFI → AuthBypass → IDOR → XSS         │
│       ↓                                                      │
│  PHASE 5: TWO-EYE APPROACH                                  │
│  Systematic Coverage + Curiosity-Driven Investigation        │
│       ↓                                                      │
│  PHASE 6: POC CREATION                                      │
│  Video + Screenshots + HTTP Logs                            │
│       ↓                                                      │
│  PHASE 7: REPORT                                            │
│  Executive Summary → Technical → Remediation → Evidence     │
└─────────────────────────────────────────────────────────────┘
```

## PHASE 0 — Scope Review
- Read scope document carefully
- Identify in-scope: domains, IPs, wildcards, technologies
- Note out-of-scope: assets, attack types, rate limits
- Check for safe harbor, disclosure policy
- Review disclosed reports for the program

## PHASE 1 — Reconnaissance
```bash
# Passive (no target touch)
subfinder -d $TARGET -all -recursive -silent -o subs_passive.txt
amass enum -passive -d $TARGET -o subs_amass.txt
curl -s "https://crt.sh/?q=%.$TARGET&output=json" | jq -r '.[].name_value' | sort -u > subs_crt.txt

# Active
puredns bruteforce ~/wordlists/subdomains-top1million-5000.txt $TARGET -r resolvers.txt -o subs_active.txt
alterx -l subs_passive.txt -silent | dnsx -silent -a -o subs_perm.txt

# Merge all
cat subs_*.txt | sort -u > all_subs.txt
```

## PHASE 2 — Discovery
```bash
# Live host probing
httpx -l all_subs.txt -sc -cl -title -td -o live_hosts.txt

# URL collection
cat live_hosts.txt | waybackurls | tee urls_wayback.txt
gau $TARGET >> urls_gau.txt
katana -u $TARGET -silent -o urls_katana.txt

# JS analysis
cat urls_*.txt | grep -E '\.js$|\.js\?' | sort -u > js_files.txt
# Fetch all JS, scan for secrets, extract endpoints
```

## PHASE 3 — Enumeration
- **Parameters**: arjun, paramspider, x8
- **Cloud**: S3Scanner, CloudEnum, bucket-stream
- **APIs**: kiterunner, GraphQL introspection
- **Content**: ffuf directory fuzzing
- **Infrastructure**: Nmap, ASN mapping

## PHASE 4 — Vulnerability Testing
Priority order: RCE → SQLi → SSRF → LFI → Auth Bypass → IDOR → Stored XSS → CSRF → Open Redirect → Info Disclosure
```bash
nuclei -l live_hosts.txt -t ~/nuclei-templates/ -severity critical,high -o nuclei_critical.txt
```

## PHASE 5 — Two-Eye Approach
- **First Eye**: Systematic — go through every subdomain, endpoint, parameter
- **Second Eye**: Curiosity — look for unusual patterns, odd subdomains, response size anomalies

## PHASE 6 — PoC Creation
- Video: OBS Studio, < 3 minutes
- Screenshots: Annotated with arrows/text
- HTTP logs: Raw request/response from Burp
- Minimal reproduction: Strip to essential steps

## PHASE 7 — Report
```
Title: Vulnerability Report
├── Overview
├── Steps to Reproduce
├── Impact
├── Proof of Concept
├── Remediation
└── References
```
