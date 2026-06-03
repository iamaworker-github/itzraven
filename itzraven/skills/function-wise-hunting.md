---
name: function-wise-hunting
description: Feature-based bug bounty methodology — test each application function for ALL vulnerability types instead of scanning by vulnerability class
category: methodology
---

# Function-Wise Hunting Methodology

> Instead of scanning for "all XSS" or "all IDOR" — test each feature/function for every possible vulnerability type.

## Core Principle
Traditional hunting: scan entire app for one vuln class (XSS → SQLi → SSRF → ...)
Function-wise: pick ONE feature → test ALL vuln types against it → move to next feature

## Feature Categories & What to Test

### Authentication
| Test | Vuln Type |
|------|-----------|
| Username enumeration | Info Disclosure |
| Password reset token prediction | IDOR / Crypto Failure |
| 2FA bypass | Auth Bypass |
| OAuth login CSRF | CSRF / AC |
| JWT alg:none | Auth Bypass |
| Session fixation | Session Mgmt |
| Rate limit on login | Rate Limit Bypass |

### Search / Filter
| Test | Vuln Type |
|------|-----------|
| `' OR '1'='1` in search | SQLi |
| `<script>` in search | XSS (Reflected) |
| `{{7*7}}` in search | SSTI |
| `../../../etc/passwd` in filename | LFI |
| XPath injection in filters | XPathi |
| NoSQL operators in JSON search | NoSQLi |

### File Upload
| Test | Vuln Type |
|------|-----------|
| Upload `.php` / `.jsp` | RCE |
| Upload SVG with XXE | XXE |
| Upload zip/tar with symlink | Path Traversal |
| ImageTragick payloads | Command Injection |
| Zipped XML with XXE | Blind XXE |
| Upload bomb (zip of death) | DoS |
| Filename with `../` | Path Traversal |

### API Endpoints
| Test | Vuln Type |
|------|-----------|
| Change `id` parameter | IDOR / BOLA |
| Change HTTP method | BOPLA |
| Add JSON fields | Mass Assignment |
| Negatives / INT_MAX | Business Logic |
| Race condition (concurrent reqs) | Race |
| GraphQL introspection | Info Disclosure |
| GraphQL batch query | Rate Limit Bypass |

### Payment / Checkout
| Test | Vuln Type |
|------|-----------|
| Negative quantity | Business Logic |
| Decimal manipulation | Business Logic |
| Coupon code abuse | Business Logic |
| Skip payment step | Business Logic |
| Race condition on checkout | Race |
| Integer overflow on price | Business Logic |

### Profile / Settings
| Test | Vuln Type |
|------|-----------|
| Change other user's data | IDOR |
| XSS in bio/name fields | Stored XSS |
| Mass assignment (`role:admin`) | AC Bypass |
| HTML injection in rich text | HTMLi |

## Finding Flow by Feature
```
Feature: Checkout
├── SQLi in promo code
├── XSS in shipping name
├── IDOR on order history
├── Race condition on payment
├── Business logic (negative qty)
├── SSTI in email template
├── Mass assignment on order JSON
└── Rate limit bypass on coupon abuse
```

## Benefits
- Finds business logic flaws generic scans miss
- Better understanding of app functionality
- Reports are more impactful (chained exploits)
- Less tool noise, more real findings
