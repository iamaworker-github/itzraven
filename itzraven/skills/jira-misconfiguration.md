---
name: jira-misconfiguration
description: JIRA misconfiguration exploitation — unauthenticated CVEs, exposed dashboards, SSRF via webhooks, directory traversal
category: vulnerabilities
---

# JIRA Misconfiguration Methodology

## Unauthenticated Endpoints
```
/jira/    → check if login is enforced
/jira/secure/Dashboard.jspa   → anonymous dashboard access
/jira/browse/<project>        → browse projects without login
/jira/rest/api/2/search       → REST API without auth
/jira/rest/api/2/project      → list all projects
/jira/rest/api/2/user         → enumerate users
/jira/rest/api/2/group        → enumerate groups
```

## CVE-Based Attacks

| CVE | Impact |
|---|---|
| CVE-2020-36239 | Privilege escalation via crafted input |
| CVE-2021-26085 | SSRF via `ViewIdentitySection` |
| CVE-2021-43947 | Path traversal via `/s/r` endpoint |
| CVE-2022-0540 | Authentication bypass in Jira Seraph |
| CVE-2022-26135 | SSRF via `MobilePlugin` |
| CVE-2023-22501 | Broken authentication via /rest/ |
| CVE-2023-22518 | Authentication bypass in all versions |

## SSRF via JIRA
- Webhooks → JIRA sends POST to attacker-controlled URL
- `ViewExternalLink` → renders external content server-side
- `OAuth` flow → SSRF in OAuth callback
- `Project Import` → fetch XML from external URL

## Sensitive Information Disclosure
- `/jira/rest/api/2/application-properties` → app config
- `/jira/rest/plugins/1.0/` → installed plugins
- `/jira/rest/api/2/dashboard` → shared dashboards
- `/jira/rest/api/2/auditing/record` → audit logs (if misconfigured)

## Directory Traversal
```
/jira/s/<hash>/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
/jira/s/<hash>/_/WEB-INF/web.xml
/jira/s/<hash>/_/WEB-INF/classes/seraph-config.xml
```

## Tools
- `jira_scan.py` — automated JIRA checker
- Nuclei templates for JIRA CVEs
- Burp + custom wordlist for JIRA endpoints
