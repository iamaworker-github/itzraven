---
name: Fast Security Checking Methodology
category: utility
description: Rapid assessment checklist for time-boxed engagements — recon, auth, API, cloud, K8s, WAF bypass, WebSocket, gRPC in one methodology
tags: [fast-checking, triage, quick-win, methodology]
---

## Fast Security Checking Methodology

### Recon Phase (5 min)
- Gather subdomains (subfinder, amass, crtsh)
- Tech stack detection (httpx -td, whatweb, wappalyzer)
- Port scan top 1000 (naabu)
- Crawl JS files for endpoints, API keys, secrets

### Authentication (5 min)
- Default credentials test (admin:admin, root:root)
- Password reset flow analysis (token predictability)
- 2FA bypass (phone number change, backup code abuse)
- Session fixation, cookie attributes (HttpOnly, Secure, SameSite)

### Access Control (5 min)
- IDOR: increment IDs in URL params /\?id=1 → /\?id=2
- Role-based: try admin endpoints as low-priv user
- HTTP method override (X-HTTP-Method-Override: PUT)
- Mass assignment: add extra fields in JSON body

### Input Validation (10 min)
- XSS: `<script>alert(1)</script>` in every input field
- SQLi: `' OR '1'='1`, `" OR 1=1 --`
- SSTI: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
- LFI: `../../../etc/passwd`
- XXE: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- Command Injection: `;id`, `|id`, `` `id` ``
- SSRF: use collaborator/ interactsh to detect OOB

### File Upload (3 min)
- Check extension filters (.php → .php5, .phtml, .phar)
- Content-Type bypass (image/png → application/x-php)
- Polyglot images (exiftool + PHP payload)
- Zip slip via archive extraction

### API Security (5 min)
- Rate limiting: send 100 requests in 1s
- BOLA/IDOR: use another user's ID in API calls
- GraphQL introspection: `{__schema{types{name}}}`
- Mass assignment: add unexpected fields to JSON
- JWT: alg:none, kid injection, weak secret cracking

### Cloud (3 min)
- S3 bucket listing: `http://bucket.s3.amazonaws.com`
- IMDSv1: `curl http://169.254.169.254/latest/meta-data/`
- Open AWS/GCP/Azure storage containers

### Kubernetes (3 min)
- Open dashboard on port 30000-32767
- kubelet API: `curl https://node:10250/pods`
- etcd on port 2379 without auth
- Privileged pod creation

### WAF Bypass (2 min)
- Case switching: `<sCrIpT>`
- Encoding: `%3Cscript%3E`
- Comments in payload: `/**/OR/**/1=1`
- HTTP parameter pollution: `?id=1&id=2`
- Unicode normalization: `%C0%BCscript%C0%BE`

### WebSocket (2 min)
- Check auth on upgrade handshake
- Message injection after connection
- Cross-origin WebSocket connections
- Out-of-scope message forwarding

### gRPC (2 min)
- Check reflection API on :50051
- Message tampering with grpcurl
- Streaming abuse (infinite messages)
- Protocol confusion (gRPC-Web vs gRPC)
