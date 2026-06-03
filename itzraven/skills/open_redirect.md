---
name: open_redirect
description: Redirect bypasses, URL parsing tricks, SSRF chaining
category: vulnerabilities
---

# Open Redirect Testing

## Attack Surface
Open redirect occurs when an application accepts user-controlled URLs and redirects browsers to them.
- Redirect parameters: `?redirect=`, `?next=`, `?return=`, `?url=`
- Referer-based redirects
- Forward proxies
- Path-based redirects

## Methodology
1. **Detection**
   - Test with external URL: `?url=https://evil.com`
   - Test with protocol-relative URL: `?url=//evil.com`
   - Test with data URL: `?url=data:text/html,<script>alert(1)</script>`
   - Test with URL fragments: `?url=https://example.com@evil.com`

2. **Bypass Methods**
   - Double slash: `//evil.com`
   - Question mark: `?evil.com`
   - At symbol: `@evil.com`
   - Backslash: `\evil.com`
   - Unicode characters: `。evil.com` (Chinese period)
   - Open redirect via path: `/redirect/https://evil.com`
   - CRLF injection: `%0d%0a` header injection

3. **Chaining**
   - SSRF via open redirect to internal IPs
   - OAuth token theft via redirect URI manipulation
   - Phishing via redirect chain to malicious site

## Validation
- Browser redirects to specified external URL
- Redirect without user confirmation/warning
- Redirect with JavaScript `window.location`
- Meta refresh redirect to attacker URL
