---
name: Advanced HTTP Request Smuggling
category: web-security
description: Modern request smuggling techniques — HTTP/3 desync, WebSocket smuggling, client-side desync, CONNECT tunneling
tags: [request-smuggling, http-smuggling, desync, h2c, websocket]
---

## Advanced HTTP Request Smuggling

### CL.TE / TE.CL (Classic)
- CL.TE: Content-Length + Transfer-Encoding headers conflict
- TE.CL: Transfer-Encoding first, Content-Length consumed by backend
- Detection: send ambiguous request, observe next request poisoning

### HTTP/2 Desync
- H2 front-end downgrades to H1 back-end → H2:CL smuggling
- H2 exclusive features: `:method` + `content-length` conflict
- Response queue poisoning via H2 stream interleaving
- HEADERS frame + CONTINUATION frame smuggling

### HTTP/3 (QUIC) Desync
- QUIC stream multiplexing creates new desync vectors
- QPACK header compression manipulation
- Stream cancellation + partial request body
- 0-RTT request replay for desync

### Client-Side Desync (CSD)
- Browser connection pool poisoning
- Exploit: server waits for body, browser sends new request on same connection
- Attack: inject malicious prefix that server interprets as new request
- Cache poisoning via browser-side connection reuse

### WebSocket Desync
- WebSocket upgrade process smuggling
- Frame manipulation during upgrade handshake
- Post-upgrade data injected into next HTTP request
- Subprotocol negotiation abuse

### Pause-Based Desync
- TCP flow control exploitation with slow-send sockets
- Send headers fast, delay body transmission
- Exploit read timeout differences between proxies
- Python socket: `send(partial) → sleep(5) → send(rest)`

### Header Oversizing
- Max header size differs between front-end and back-end
- Send oversized header → front-end accepts, back-end rejects → connection desync
- Use `\x00` null bytes, tab characters in header values

### CONNECT Tunneling Smuggling
- Abuse proxy CONNECT method
- `CONNECT backend:80 HTTP/1.1` → raw TCP tunnel
- Inject requests through tunnel to bypass front-end
- HTTP/2 CONNECT stream reuse

### H2C Upgrade Smuggling
- Cleartext HTTP/2 upgrade: `Upgrade: h2c`
- Front-end doesn't support h2c, passes upgrade to backend
- Backend upgrades to H2C → raw binary frames
- Inject PREFACE + SETTINGS frame to hijack backend connection

### Detection Bypass Techniques
- Null byte injection: `Transfer-Encoding:\x00chunked`
- Header value pollution: duplicate headers with different values
- Vertical tab / form feed in header values
- Case manipulation: `transfer-encoding: Chunked`
- Unicode whitespace in header names
- Pseudo-header smuggling in H2→H1 downgrade

### Real CVEs
- CVE-2023-45853: MiniTool Partition Wizard
- CVE-2023-38545: SOCKS5 heap overflow
- CVE-2022-31629: PHP CGI request smuggling
- CVE-2024-25600: WordPress plugin smuggling
