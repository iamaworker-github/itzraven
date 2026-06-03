---
name: "h1-bugbounty-workflow"
description: "Complete bug bounty hunting workflow based on HackerOne top earners — methodology gates, depth matrices, sibling rule, crown jewel mapping, and platform-specific report writing"
category: web-security
tags: ["bugbounty", "methodology", "hunting", "hackerone", "workflow"]
relevance: 10
---

# Bug Bounty Hunting Workflow (From Top H1 Earners)

## Phase 1: Target Understanding
1. Read scope carefully — check `in-scope:` vs `out-of-scope:`
2. Check safe harbor & disclosure policy
3. Review last 10 disclosed reports in program hacktivity
4. Identify crown jewels: payments, auth, PII, admin functions
5. Note: "The best bug bounty hunters spend 30% of their time on reconnaissance"

## Phase 2: Surface Mapping
1. Subdomain enumeration: `subfinder`, `amass`, `assetfinder`
2. Live host discovery: `httpx`, `httprobe`
3. Tech stack detection: `wappalyzer`, `whatweb`
4. JS bundle analysis: `jsubfinder`, `linkfinder`, manual review
5. API endpoint discovery: `kiterunner`, `gau`, `waybackurls`
6. Parameter discovery: `paramspider`, `arjun`

## Phase 3: Targeted Hunting
Apply the **Sibling Rule** — if you find one bug, test ALL siblings:
- Same endpoint × different methods (GET/POST/PUT/DELETE)
- Same pattern × different parameters
- Same vuln class × different entry points

**20-Minute Rotation** — if no progress in 20 mins, switch targets

**Depth Matrix** — test every `entrypoint × method × content-type × encoding × bypass`:
- Minimum 30 combinations on P1 surface
- Don't stop at first blocked payload — mutate and continue

## Phase 4: Validation & Chain
- Validate every finding with a clean PoC
- Test chaining: low + medium = critical
- Common chains:
  - Open Redirect + OAuth → Account Takeover
  - XSS + CSRF → Full account compromise
  - SSRF + Cloud Metadata → Cloud credentials
  - LFI + Log Poisoning → RCE

## Phase 5: Report Writing
HackerOne top reports have:
1. Clear, concise title with vuln type + impact
2. Step-by-step reproduction (anyone should be able to follow)
3. Working PoC (not theoretical)
4. Business impact (not just technical)
5. Quality screenshot/Video

### Platform Tips:
- **HackerOne**: CVSS score, clean PoC, business impact
- **Bugcrowd**: Clear remediation suggestions, priority rating
- **Intigriti**: Developer-friendly reports, concise reproduction

## Top Bounty Categories (by payout):
1. RCE — $10k-$100k
2. Account Takeover — $3k-$50k
3. IDOR (critical data) — $2k-$25k
4. SSRF (cloud metadata) — $3k-$35k
5. Business Logic (payment) — $2k-$15k
6. SQLi (data exfiltration) — $500-$25k
7. XSS (blind/admin) — $500-$10k
