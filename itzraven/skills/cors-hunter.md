---
name: cors-hunter
description: CORS misconfiguration testing — origin reflection, wildcard origins, preflight bypass, and credential leakage
category: vulnerabilities
---

# CORS Testing Methodology

## Origin Reflection
1. Set `Origin: https://evil.com`
2. Check if `Access-Control-Allow-Origin: https://evil.com` is reflected
3. Test variations: null, subdomain.evil.com, evil.com.evil.com

## Wildcard Origins
- `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`
- If both present → exploitable (any website can read authenticated responses)
- Even without credentials, wildcard can leak non-sensitive data

## Null Origin Bypass
- Set `Origin: null` (from data: URI or sandboxed iframe)
- Set `Origin:` (empty Origin header)
- Use `file://` protocol to force null origin
- Use `data:` URI scheme

## Preflight Bypass
- Simple requests (GET, POST with Content-Type application/x-www-form-urlencoded) skip preflight
- Test with custom headers removed to force simple request
- Some servers apply different CORS policies for preflight vs actual request

## Internal IP/Port Scanning
- CORS misconfig allows scanning internal networks
- Use `Origin: http://192.168.1.1:8080` and check if reflected
- Enumerate internal services via CORS headers

## Common Bypasses
- `Origin: https://evil.com` → `Origin: https://evil.com.target.com`
- `Origin: https://target.com.evil.com` (subdomain)
- `Origin: https://target.com@evil.com` (credentials in URL)
- `Origin: https://target.com` with unicode normalization
- `Origin: http://target.com` (HTTP → HTTPS mismatch accepted)

## Impact
- Read sensitive data from authenticated user's context
- API key/session token exfiltration
- CSRF bypass for state-changing operations
- Internal network reconnaissance
