---
name: vdp-hunter
description: Hidden VDP & self-hosted bug bounty program discovery via OSINT, dorking, Crunchbase, GitHub, Wayback Machine
category: recon
---

# VDP Hunter — Hidden Bug Bounty Program Discovery

> Self-hosted programs, university VDPs, startup security pages, and invite-only bounty programs.

## Google Dorking for Security.txt
```
inurl:"/security.txt" "security contact"
intitle:"bug bounty" -site:hackerone.com -site:bugcrowd.com
inurl:"/responsible-disclosure" | inurl:"/vulnerability-disclosure"
inurl:"/security" AND "report a vulnerability"
intitle:"report a security issue" inurl:"/contact"
inurl:"/.well-known/security.txt"
```

## Startup VDP Recon (Crunchbase + Recon)
1. Find recently funded startups on Crunchbase/AngelList
2. Check: `/security.txt`, `/.well-known/security.txt`, `/vulnerability-disclosure`, `/responsible-disclosure`
3. Subdomain recon on their main domain
4. JS file scanning for security endpoints
5. Check GitHub README for "security" or "bug bounty" mentions

## Wayback Machine VDP Discovery
- Some VDPs get deleted or expired — Archive.org caches them
- Check historical `/.well-known/security.txt` and `/security.txt`
- Look for `hall-of-fame.md`, `security.md`, `responsible-disclosure-policy.md` in historical backups

## GitHub Recon for Bounty Programs
- Search: `"bug bounty" in:readme`, `"security.txt"`, `"vulnerability disclosure"`
- Look for `SECURITY.md` in repos
- Check company GitHub orgs for bounty references

## University & Government VDPs
- Target `.edu`, `.gov`, `.org` domains — many run VDPs off-platform
- Check `/security.txt` on all subdomains
- Look for infosec/security department pages

## Telegram / Discord / Slack Communities
- Many startups launch invite-only VDPs in tight communities
- Join bug bounty Discord servers, Telegram channels
- Monitor "looking for testers" posts

## Automation
```bash
# Scan a list of domains for security.txt
for domain in $(cat domains.txt); do
  curl -sL "https://$domain/.well-known/security.txt" -o /dev/null -w "%{http_code} $domain\n"
done

# Find bug bounty mentions in GitHub
gh search code "bug bounty" --limit 50 --json repository,path,url
```
