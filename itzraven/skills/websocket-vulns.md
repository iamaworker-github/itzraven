---
name: websocket-vulns
description: WebSocket vulnerabilities — upgrade bypass, cross-origin hijacking, message smuggling, WS fuzzing
category: vulnerabilities
---

# WebSocket Vulnerability Methodology

## Upgrade Request Manipulation
```
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
```
Test variations:
- Remove `Upgrade` header → falls back to HTTP
- Change `Sec-WebSocket-Version` to invalid values
- Send non-base64 `Sec-WebSocket-Key`
- Send key in different header names

## Cross-Origin WebSocket Hijacking
1. Check `Origin` header validation on WebSocket upgrade
2. If no Origin check → any website can open connection
3. Craft HTML page that opens WebSocket to target
4. Read messages via `ws.onmessage` → steal data

## Message Smuggling
- Inject CRLF in WebSocket messages: `message\r\n\r\nHTTP/1.1 200 OK\r\n`
- Try unicode/encoding bypasses in message content
- Send oversized frames (length > 2^63)
- Ping/pong flooding (DoS)

## WS Fuzzing
1. Fuzz all message types (text, binary, ping, pong, close)
2. Send malformed frames (invalid opcodes, masked bit wrong)
3. Try path traversal in WS URL: `ws://target.com/../../admin`
4. Send messages after server close frame

## Common Vulnerabilities
- No authentication on WebSocket (session in query param)
- No CSRF protection (Origin check missing)
- Message injection (no input sanitization)
- No rate limiting on WS messages
- Information disclosure in WS handshake
- WS → HTTP fallback downgrade

## Tools
- Burp WebSocket Tab / WS Intruder
- `wscat` — CLI WebSocket testing
- Custom WS fuzzer with Python `websockets` lib
