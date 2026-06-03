---
name: "h1-backmeup-recon"
description: "BackMeUp + subdomain enumeration + takeover detection workflow. URL collection via gau/gauplus/gospider/katana/wayback with sensitive data leak detection and 3rd party URL filtering"
category: web-security
tags: ["recon", "subdomain", "backmeup", "url-collection", "sensitive-data", "takeover", "hackerone"]
relevance: 10
---

# BackMeUp Recon Workflow

## Step 1: URL Collection
Runs these tools in parallel via `backmeup.sh`:
- **gau** — getallurls (wayback, commoncrawl, otx, urlscan)
- **gauplus** — enhanced version of gau
- **gospider** — spider with JS rendering, subdomain discovery
- **katana** — passive + active crawling (depth & breadth-first)
- **waybackurls** — Wayback Machine URLs
- **waymore** — enhanced wayback data collection
- **cariddi** — automated scanning with extensions
- **crawley** — web crawler
- **hakrawler** — fast web crawler

## Step 2: 3rd Party URL Filtering
⚠️ **Important**: Tools like gospider/katana/crawley follow links to external sites
(Facebook, Google, CDN, analytics). Always filter with:
```bash
grep -E "^(https?://)?([a-z0-9-]+\.)*target\.com"
```

## Step 3: Sensitive Data Leak Detection
BackMeUp uses 162 extensions + regex patterns to find:
- API keys (`api_key`, `apikey`, `secret`)
- AWS keys (`AKIA...`)
- JWT tokens (`eyJ...`)
- Passwords, tokens, connection strings
- Database dumps (`.sql`, `.bkp`, `.db`)
- Config files (`.env`, `.config`, `.yml`)

## Step 4: Subdomain Extraction
From collected URLs, extract unique subdomains:
```bash
cat urls.txt | cut -d/ -f3 | sort -u | grep "\.target.com$"
```

## Step 5: Subdomain Takeover Check
Check each subdomain for dangling CNAME records:

| Service | CNAME Pattern | Fingerprint |
|---------|--------------|-------------|
| AWS S3 | `.s3.amazonaws.com` | `NoSuchBucket` |
| GitHub Pages | `.github.io` | `There isn't a GitHub Pages site here` |
| Heroku | `.herokuapp.com` | `No such app` |
| CloudFront | `.cloudfront.net` | `ERROR: The request could not be satisfied` |
| Azure | `.azureedge.net` | `404 Not Found` |
| Shopify | `.myshopify.com` | `Sorry, this shop is currently unavailable` |
| Vercel | `.vercel.app` | `The deployment could not be found` |
| Netlify | `.netlify.app` | `Not Found - Request ID` |
| Squarespace | `.squarespace.com` | `No Such Site` |
| Tumblr | `.tumblr.com` | `There's nothing here` |
| WordPress | `.wordpress.com` | `Do you want to register` |
| Strikingly | `.strikingly.com` | `page not found` |
| Intercom | `.custom.intercom.io` | `This page is not available` |
| Freshdesk | `.freshdesk.com` | `The page you are looking for does not exist` |

## Top Bounty Takeover Reports:
- Roblox: Subdomain takeover via expired Hubspot ($2500)
- Uber: Dangling AWS record → zone transfer + cookie theft ($500)
- Shopify: Unclaimed subdomain takeover ($5000+)
