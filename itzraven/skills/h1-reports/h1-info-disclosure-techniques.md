---
name: "h1-info-disclosure-techniques"
description: "Information Disclosure patterns from HackerOne reports — API key leak, memory leak via API, private key disclosure, source code exposure, Heartbleed, session disclosure, Google API key leak"
category: web-security
tags: ["info-disclosure", "secret-leak", "api-key", "source-code", "cloud-leak", "hackerone"]
relevance: 9
---

# H1 Information Disclosure Techniques

Real-world info disclosure with $150-$10000 bounties:

## 1. Cloud/AWS Key Disclosure
Report: BCM Messenger AWS Bucket key in cleartext ($300)
Report: Slack private key disclosed ($2000)
- Check: `.env`, `.aws/credentials`, `credentials.json`, `config.json`
- Check: Client-side JS bundles for API keys
- Check: Mobile app decompilation for embedded keys
- Check: Public GitHub repos, gists, pastebins

## 2. Memory Leak via API
Report: Mail.ru arbitrary memory leak through API ($10000)
- Test: API endpoints with negative/large buffer sizes
- Test: Format string vulnerabilities in error messages
- Look for: Stack traces, heap dumps, memory contents

## 3. Source Code Exposure
Report: Razer PHP source code exposed ($200)
- Check: `.git/config`, `.svn/entries`, `.DS_Store`
- Check: Backup files: `index.php~`, `index.php.bak`, `index.php.old`
- Check: `/server-status`, `/phpinfo.php`, `/info.php`
- Check: `/WEB-INF/web.xml`, `/WEB-INF/classes/`
- Check: Debug endpoints: `/debug`, `/actuator`, `/swagger-ui.html`

## 4. API Endpoint Data Leak
Report: Mail.ru API disclosing subscriber emails ($250)
Report: Starbucks unauthenticated API leaking employee PII ($4000)
- Test: Remove auth headers from API requests
- Test: Change method (GET→POST→PUT→DELETE)
- Test: Version rollback (`/api/v1/users` → `/api/v0/users`)

## 5. Heartbleed Testing
Report: Uber Heartbleed vulnerability ($1500)
- Test: OpenSSL Heartbleed on HTTPS endpoints
- Command: `nmap -sV --script ssl-heartbleed target.com`
- What leaks: Private keys, session tokens, passwords in memory

## 6. Google API Key Leak
Report: Identify leaked unrestricted Google API key ($150)
- Check: Public web pages, JS files, mobile apps
- Test: If API key is unrestricted, use it against Google APIs

## 7. Session/Credential Disclosure
Report: Shopify session disclosure after logout ($500)
- Test: Logout, check if session cookie still works
- Test: Password stored in client-side accessible storage

## Common Disclosure Endpoints:
```
/.git/config
/.env
/backup.sql
/dump.sql
/phpinfo.php
/server-status
/debug
/api/health
/api/version
/swagger.json
/openapi.json
/robots.txt
/sitemap.xml
/crossdomain.xml
/clientaccesspolicy.xml
```
