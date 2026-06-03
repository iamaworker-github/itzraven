---
name: rate-limit-bypass
description: Rate limit bypass techniques via HTTP method manipulation, IP spoofing headers, and distributed attacks
category: vulnerabilities
---

# Rate Limit Bypass Methodology

## HTTP Method Customization
- Change GET → POST, PUT, PATCH, DELETE, OPTIONS
- Try HEAD method (often unrate-limited for APIs)
- Try CONNECT, TRACE, TRACK methods
- Change HTTP version (HTTP/1.0 vs HTTP/1.1 vs HTTP/2)
- Use WebSocket upgrade instead of HTTP

## IP Spoofing Headers
Add these below Host header, rotating IP addresses:
```
X-Forwarded-For: IP
X-Forwarded-IP: IP
X-Client-IP: IP
X-Remote-IP: IP
X-Originating-IP: IP
X-Host: IP
X-Client: IP
Forwarded: for=IP
X-Real-IP: IP
X-ProxyUser-IP: IP
```
- Double the header: `X-Forwarded-For:` then `X-Forwarded-For: IP`
- Use RFC1918 IPs: `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`
- Use localhost: `127.0.0.1`, `::1`

## Parameter Pollution
- Add junk parameters to create unique cache keys
- Append random query params: `?cb=random_value`
- Change parameter order
- Add duplicate parameters

## Distributed Attack Vectors
- Rotate User-Agent on each request
- Use different cookies/sessions
- Modify Accept-Language, Accept-Encoding headers
- Remove or add cookies between requests
- Use different Content-Type (application/json vs application/x-www-form-urlencoded)

## Timing-Based Bypass
- Send requests slower than rate limit window
- Use race condition: send all requests simultaneously
- Pause between bursts
- Check if reset happens at specific intervals (hourly, daily)
