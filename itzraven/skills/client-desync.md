---
name: client-desync
description: Client-side desync attacks — connection pool poisoning, CL.TE/TE.CL desync via browser, cache poisoning
category: vulnerabilities
---

# Client-Side Desync Methodology

## What It Is
Client-Side Desync (CSD) attacks exploit how browsers and reverse proxies interpret Content-Length vs Transfer-Encoding to poison connection pools and hijack victim requests.

## Attack Types

### 1. CL.TE Desync (Classic)
```
POST / HTTP/1.1
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
X-Ignore: X
```
- Frontend uses Content-Length, backend uses Transfer-Encoding
- Second request gets prepended to victim's request

### 2. TE.CL Desync
```
POST / HTTP/1.1
Content-Length: 4
Transfer-Encoding: chunked

5c
POST /admin HTTP/1.1
Content-Length: 15

x=1
0
```
- Frontend uses Transfer-Encoding, backend uses Content-Length

### 3. Client-Side Specific
- Browser uses `Transfer-Encoding: chunked` but proxy uses `Content-Length`
- Poison socket: victim's next request hijacked via poisoned connection
- Cache poisoning: store malicious response in CDN for all users

## Detection
1. Send CL.TE and TE.CL probe requests
2. Check for timeouts, protocol errors, or unexpected responses
3. Follow-up request reveals if socket was poisoned

## Exploitation
- **Pivot to XSS**: Poison socket delivers XSS payload to victim
- **Pivot to SSRF**: Poison socket maps internal services
- **Cache Poisoning**: Store redirect to attacker.com

## Tools
- `Request Smuggler` (Burp extension)
- `http-sniffer` for CL.TE detection
- Custom Go/Python scripts with raw socket handling
