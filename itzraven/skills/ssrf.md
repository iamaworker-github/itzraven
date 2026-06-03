---
name: ssrf
description: Server-side request forgery, protocol handlers, cloud metadata
category: vulnerabilities
---

# SSRF Testing

## Attack Surface
SSRF occurs when a server-side application makes HTTP requests to user-supplied URLs.
- URL parameters: `?url=`, `?file=`, `?path=`, `?dest=`
- Webhook/callback URL fields
- File upload processors that fetch remote resources
- PDF generators that accept URLs

## Methodology
1. **Detection**
   - Classic: `http://127.0.0.1:22`, `http://localhost:3306`
   - Cloud metadata: `http://169.254.169.254/latest/meta-data/` (AWS)
   - Cloud metadata: `http://metadata.google.internal/` (GCP)
   - Cloud metadata: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure)
   - Protocol smuggling: `file:///etc/passwd`, `dict://localhost:11211/`

2. **Advanced Bypass**
   - DNS rebinding: use custom domains that resolve to internal IPs
   - URL parsing confusion: `http://127.0.0.1#@evil.com`
   - IPv6 loopback: `http://[::1]:22`
   - Decimal IP: `http://2130706433/`
   - Shortened IP: `http://0/`

3. **Blind SSRF**
   - Use Interactsh/OOB testing service
   - Inject URL to external callback collector
   - Monitor for DNS/HTTP callbacks

## Validation
- Confirm response contains internal service banners
- AWS metadata returns `ami-id`, `instance-id`, `iam/` credentials
- File protocol returns file contents
- Timeout + callback confirms blind SSRF
