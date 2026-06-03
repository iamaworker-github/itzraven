---
name: sql_injection
description: SQL injection variants, WAF bypasses, blind techniques
category: vulnerabilities
---

# SQL Injection Testing

## Attack Surface
SQL injection occurs when user input is improperly sanitized before being used in SQL queries. Common injection points:
- URL parameters (GET/POST)
- HTTP headers (User-Agent, X-Forwarded-For, Cookie)
- JSON/XML request bodies
- File upload metadata

## Methodology
1. **Detection Phase**
   - Inject single quote `'` and observe error responses
   - Use boolean-based tests: `' AND 1=1--`, `' AND 1=2--`
   - Time-based tests: `'; WAITFOR DELAY '0:0:5'--` (MSSQL), `' AND SLEEP(5)--` (MySQL)
   - Out-of-band detection using DNS/HTTP interactions

2. **Enumeration Phase**
   - Determine database type from error messages and behavior
   - Extract table/column structure via `UNION SELECT`
   - Use `ORDER BY` to determine column count

3. **Exploitation Phase**
   - Data extraction with `UNION SELECT`
   - Blind SQLi with boolean/time-based inference
   - Out-of-band exfiltration via DNS/HTTP

## Bypass Methods
- **WAF Bypass**: Use case variation `'UnIoN SeLeCt'`, comments `/**/`, encoding
- **Filter Bypass**: Hex encoding `0x...`, `CHAR()`, `CONCAT()` functions
- **Blacklist Bypass**: Double URL encoding, newline injection, alternate operators

## Validation
- Confirm SQL error messages reveal database structure
- Verify data extraction returns actual database content
- Time-based must show statistically significant delay (>2s) vs baseline
- Boolean-based must show consistent TRUE/FALSE response differences
