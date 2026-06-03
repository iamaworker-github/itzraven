---
name: "h1-osint-techniques"
description: "Complete OSINT toolkit based on awesome-osint, cipher387, GitHub OSINT, SpiderFoot — GitHub recon, email/domain intel, username search across 3000+ sites, public records, social media, certificate transparency"
category: web-security
tags: ["osint", "recon", "github", "email", "domain", "username", "social-media", "public-records", "hackerone"]
relevance: 10
---

# Comprehensive OSINT Techniques

## 1. GitHub OSINT (Most Valuable)
GitHub API se user/org info + REAL EMAILS from commit metadata:

```python
# Key endpoints
GET https://api.github.com/users/{username}      # Profile, created_at, company, location
GET /users/{user}/repos                           # All repos with languages, topics
GET /repos/{owner}/{repo}/commits                 # Commit author EMAILS (gold mine!)
GET /orgs/{org}/members                           # Organization members
GET /search/code?q=org:target+api_key             # Search org code for secrets
```

**Critical technique**: `created_at` field reveals sockpuppet accounts.
**Email gold mine**: Commit metadata often contains REAL email even when profile email is hidden.

## 2. Certificate Transparency (crt.sh) — No Auth Required
```bash
# Find ALL subdomains from SSL certs (free, unlimited)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

## 3. Username Search (50+ Platforms)
Check same username across platforms:
```
github, twitter, reddit, instagram, medium, hackerone, bugcrowd,
keybase, telegram, pinterest, twitch, tiktok, youtube, linkedin,
devto, producthunt, gitlab, bitbucket, replit, pastebin, docker,
npm, pypi, flickr, soundcloud, spotify, steam, buymeacoffee, kofi,
tryhackme, hackthebox, ctftime
```

## 4. Email Intelligence
- **EmailRep.io** — reputation + breach data
- **Have I Been Pwned** — breach history (needs API key)
- **Hunter.io** — email verification + pattern discovery
- **holehe** — check email on 120+ sites via forgot-password flow

## 5. Domain Intelligence (Multi-Source)
```
crt.sh        → subdomains (free, no auth)
SecurityTrails→ subdomains + DNS history (50/mo free)
URLScan.io    → screenshots + page data (50/mo free)
Wayback CDX   → historical page URLs (limit=50000!)
Shodan        → exposed services (1 credit/query)
DNS Dumpster  → DNS map visualization (free)
AlienVault OTX→ threat intelligence (free)
BuiltWith     → tech stack (50/mo free)
```

## 6. Public Records
- **OpenCorporates** — company registrations worldwide (free API)
- **Wayback Machine** — historical page snapshots
- **ICIJ Offshore Leaks** — offshore company database
- **OCCRP Aleph** — international public records

## 7. People Search
- **Name → social profiles**: LinkedIn, Crunchbase, IDCrawl
- **Email → accounts**: EmailRep, HIBP, holehe
- **Username → platforms**: multi-platform checker (50+ sites)
- **Phone → carrier**: FreeCarrierLookup, AbstractAPI

## 8. Dark Web OSINT
- **Ahmia.fi** — clearnet-accessible onion search
- **IntelX** — dark web + data leak search
- **OnionSearch** — 16+ onion engines simultaneously

## Rate Limiting Guide:
```
GitHub API:     60/hr unauthenticated, 5000/hr with PAT
HIBP:           1 request per 1.5 seconds
SecurityTrails: 50/mo free
URLScan.io:     50/mo free, 100/day public
Censys:         250/mo free
Shodan:         100 credits ($49 one-time)
```
