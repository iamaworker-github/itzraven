---
name: js-secrets-analysis
description: Automated JS secrets pipeline — extract, fetch, scan for API keys, tokens, endpoints, cloud credentials from JavaScript files
category: recon
---

# JS Secrets Analysis Pipeline

> Extract every JavaScript file from a target, fetch all content, scan for hardcoded secrets and hidden endpoints.

## PHASE 1 — JS File Discovery
```bash
# Collect all JS files from Wayback/Gau/Katana
cat waybackurls.txt gau.txt katana.txt | grep -E '\.js$|\.js\?' | sort -u > js_files.txt
```

## PHASE 2 — Fetch & Aggregate
```bash
mkdir -p _jsrecon
while read jsurl; do
  echo "[*] Fetching: $jsurl"
  curl -sL "$jsurl" -H "User-Agent: Mozilla/5.0" --max-time 10
done < js_files.txt > all_js_content.js
```

## PHASE 3 — Deep Scan
```bash
# jsecrets scan
cat all_js_content.js | jsecrets -i - > jsecrets_all.txt

# High-value patterns
cat all_js_content.js | grep -E "(api[_-]?key|token|secret|password|endpoint|bucket|s3|aws|auth|bearer)" -i | sort -u > potential_secrets.txt

# Extract all URLs/endpoints
cat all_js_content.js | grep -Eo 'https?://[a-zA-Z0-9./_-]+' | sort -u > extracted_urls.txt

# Firebase URLs
cat all_js_content.js | grep -Eo 'https?://[a-zA-Z0-9-]+\.firebaseio\.com' | sort -u

# AWS buckets
cat all_js_content.js | grep -Eo '[a-zA-Z0-9.-]+\.s3\.amazonaws\.com|[a-zA-Z0-9.-]+\.s3-website[^"]+' | sort -u

# GraphQL endpoints
cat all_js_content.js | grep -Eo 'https?://[^"'"'"' ]+/graphql' | sort -u

# Internal paths
cat all_js_content.js | grep -Eo '["'"'"'](/api/[^"'"'"']*)["'"'"']' | sort -u
```

## PHASE 4 — Pattern Categories

| Pattern | Example | Severity |
|---------|---------|----------|
| API Keys | `sk-...`, `pk-...`, `AIza...` | High |
| JWT Tokens | `eyJ...` | High |
| AWS Keys | `AKIA...` | Critical |
| Firebase URLs | `*.firebaseio.com` | High |
| Internal IPs | `10.0.0.1`, `192.168.x.x` | Medium |
| GraphQL URLs | `/graphql` | Medium |
| Bucket URLs | `*.s3.amazonaws.com` | High |
| Auth Tokens | `Bearer ...` | Critical |
| Slack Tokens | `xoxb-`, `xoxp-` | Critical |
| Private Keys | `-----BEGIN` | Critical |

## Automation
```bash
# Full pipeline (single command)
cat ../waybackurls.txt ../gau.txt 2>/dev/null | grep -E '\.js$|\.js\?' | sort -u > js_files.txt
while read jsurl; do echo "[*] Fetching: $jsurl"; curl -sL "$jsurl" -H "User-Agent: Mozilla/5.0" --max-time 10; done < js_files.txt > all_js_content.js
cat all_js_content.js | jsecrets -i - > jsecrets_all.txt
cat all_js_content.js | grep -iE "(api.key|token|secret|password|endpoint|bucket|s3|aws|auth|bearer)" | sort -u > potential_secrets.txt
```
