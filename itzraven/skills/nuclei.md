---
name: nuclei
description: Template-based vulnerability scanning with Nuclei
category: tooling
---

# Nuclei Usage Guide

Nuclei is a fast vulnerability scanner that uses YAML templates to find security issues.

## Common Usage
```bash
# Basic scan
nuclei -u https://target.com

# All templates
nuclei -u https://target.com -t ~/nuclei-templates/

# Severity filtering
nuclei -u https://target.com -severity critical,high

# Rate limiting
nuclei -u https://target.com -rate-limit 150 -bulk-size 25

# With output
nuclei -u https://target.com -o results.txt

# JSON output for automation
nuclei -u https://target.com -json -o results.json
```

## Tags
- `cves`: Known CVE checks
- `exposures`: Exposed panels/configs
- `misconfig`: Security misconfigurations
- `tech`: Technology fingerprinting

## Best Practices
- Always use rate limiting to avoid WAF blocks
- Combine with httpx for live host filtering
- Use severity filtering for CI/CD pipelines
- Verify findings manually to reduce false positives
