---
name: host-header-injection
description: Host header injection and web cache poisoning — password reset poisoning, cache poisoning, SSRF via host
category: vulnerabilities
---

# Host Header Injection Methodology

## Injection Points
Test these headers in order:
```
X-Forwarded-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Host: attacker.com
Forwarded: host=attacker.com
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Forwarded-For: attacker.com
X-Client-IP: attacker.com
```

## Password Reset Poisoning
1. Intercept password reset request
2. Add `X-Forwarded-Host: attacker.com`
3. If reset link in email uses `X-Forwarded-Host` → redirect to attacker
4. Victim clicks reset link → token goes to attacker

## Web Cache Poisoning
1. Find unkeyed header (Host, X-Forwarded-Host, X-Original-URL)
2. Send request with poisoned header value
3. If cached → all users get attacker-controlled redirect
4. Common with AEM (Adobe Experience Manager): `/api.json`
5. Try `Host: localhost` → cached response may target internal services

## SSRF via Host Header
- Set `Host: 127.0.0.1:8080` → internal service accessible
- Set `Host: 169.254.169.254` → AWS metadata endpoint
- Set `Host: internal-admin.target.com` → virtual host routing

## Double Host Header
```
GET / HTTP/1.1
Host: target.com
Host: evil.com
```
Some servers use first Host, backend uses second → confusion

## Special Characters
- `Host: target.com.evil.com` (subdomain match)
- `Host: evil.com/target.com` (path confusion)
- `Host: target.com:evil.com` (port confusion)
- Absolute URL: `GET https://evil.com/ HTTP/1.1` with `Host: target.com`
