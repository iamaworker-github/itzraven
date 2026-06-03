---
name: "h1-account-takeover-techniques"
description: "Account Takeover patterns from HackerOne reports — subdomain takeover for cookie theft, link injection in contact forms, password reset logic flaws, OAuth misconfiguration, SAML bypass"
category: identity-access
tags: ["account-takeover", "subdomain-takeover", "oauth", "saml", "password-reset", "hackerone"]
relevance: 10
---

# H1 Account Takeover Techniques

Real-world ATO vulnerabilities with $500-$15000 bounties:

## 1. Subdomain Takeover → Account Takeover
Report: Uber dangling AWS record allows zone transfer ($500)
Report: Roblox Subdomain takeover via expired Hubspot ($2500)
- Test: CNAME records pointing to expired/unclaimed SaaS services
- Services to check: GitHub Pages, Heroku, AWS S3, Hubspot, Shopify, Tumblr, Squarespace, Bitbucket, AWS CloudFront
- Impact: Steal cookies from `*.target.com`

## 2. Link Injection in Contact Forms
Report: Insolar account takeover through link injection ($1000)
- Technique: Inject clickable links in contact/profile fields
- Impact: Phishing links sent to admins who view the form

## 3. Password Reset Logic Flaws
- Token in email link → check if:
  - Token is predictable (timestamp, user ID)
  - Token doesn't expire
  - Token can be reused
  - No token required (direct IDOR on reset)
  - Host header changes reset link domain

## 4. OAuth Misconfiguration
Test OAuth flows:
- `redirect_uri` not validated → steal code via open redirect
- `state` parameter not validated → CSRF on OAuth login
- `response_type=token` → access token in URL fragment (leaked via Referer)

## 5. SAML SSO Bypass
- Test: Register with same email as victim on SAML IdP
- Test: XML Signature Wrapping (XSW)
- Test: Assertion replay (use old valid assertion)
- Test: `http://` instead of `https://` in ACS URL

## 6. Brute Force / Rate Limiting Bypass
- Test: X-Forwarded-For header to bypass IP-based rate limiting
- Test: Rotate User-Agent per request
- Test: Race condition on login (send many requests simultaneously)

## 7. 2FA Bypass
- Test: Direct API calls that skip 2FA step
- Test: Backup codes unlimited usage
- Test: OTP token time window too long
- Test: 2FA not required on API/reseller endpoints

## ATO Priority Targets:
- Password reset functionality
- Email change functionality  
- OAuth/SAML login flows
- Session token handling
- Multi-factor authentication
- Support account recovery
