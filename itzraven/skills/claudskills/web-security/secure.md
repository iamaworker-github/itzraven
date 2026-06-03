---
name: "secure"
description: "Full-stack security posture assessment with 0-100 risk scoring. Scans dependency vulnerabilities (npm audit, pip-audit, cargo audit, govulncheck), dangerous code patterns (SQL injection, eval, command"
category: web-security
subcategory: web-security
tags: ["type:audit"]
relevance: 8
source: ""
author: ""
license: ""
---
# secure


## Description
Full-stack security posture assessment with 0-100 risk scoring. Scans dependency vulnerabilities (npm audit, pip-audit, cargo audit, govulncheck), dangerous code patterns (SQL injection, eval, command injection, ReDoS, innerHTML, XSS vectors), authentication gaps (missing auth middleware, CSRF, hardcoded JWT secrets, insecure session flags), insecure crypto (MD5/SHA1 password hashing, Math.random for tokens, hardcoded encryption keys), configuration issues (exposed .env files, debug mode, permissive CORS, missing security headers CSP/HSTS, Docker root containers, default credentials), and data handling problems (PII in logs, missing input validation, file upload exploits, missing rate limiting). Produces a prioritized risk report and routes to specialized skills (pentest, owasp, gdpr, encryption, soc2). Use as a first-pass security triage before deeper audits or before shipping to production.


## Tags
type:audit


## Relevance Score
8
