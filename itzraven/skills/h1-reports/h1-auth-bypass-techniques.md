---
name: "h1-auth-bypass-techniques"
description: "Authentication Bypass patterns from HackerOne reports — recovery code brute force, email verification chain, phone-based access, session fixation, CORS misconfiguration"
category: identity-access
tags: ["auth-bypass", "authentication", "session", "account-takeover", "hackerone"]
relevance: 10
---

# H1 Authentication Bypass Techniques

Real-world auth bypass vulnerabilities with $1500-$15000 bounties:

## 1. Recovery Code Brute Force
Report: Mail.ru brute force account takeover via recovery code ($3000)
- Test: Password reset / account recovery endpoints
- Look for: Short numeric codes (4-6 digits), no rate limiting
- Technique: Brute force 0000-9999 recovery codes

## 2. Email Verification Chain Attack
Report: Shopify takeover any store via email chain ($15000)
1. Register account with victim's email
2. Request email verification
3. Change email BEFORE clicking verification link
4. Complete verification on attacker's email
5. Result: Victim's store is now under attacker's control

## 3. Phone-Number Based Access
Report: Mail.ru knowing phone number → partial access ($8000)
- Test: Phone number as sole authentication factor
- Look for: APIs that accept phone number without OTP verification

## 4. CORS Misconfiguration Auth Bypass
Report: SEMrush CORS misconfiguration ($1000)
- Test: `Origin: https://evil.com` → check for `Access-Control-Allow-Origin: https://evil.com`
- Impact: Read authenticated API responses from user's browser

## 5. Path Manipulation Auth Bypass
Report: Shopify changing `/login` to `/new-password` bypasses auth ($7500)
- Test: Replace `/login` with `/new-password`, `/admin`, `/reset-password` in URL
- Look for: Different auth enforcement on similar paths

## 6. Session Fixation / Improper Invalidation
Report: Shopify session not invalidated after logout ($500)
- Test: Logout, then reuse old session token
- Look for: Old session still valid after password change

## 7. Password Reset Token Exploitation
- Test: Token in URL → check if reusable
- Test: Token expiration time
- Test: Host header injection in reset link
```
POST /reset-password
Host: attacker.com
→ Reset link sent to victim contains attacker domain
```

## Common Auth Bypass Checklist:
- [ ] Default credentials: admin:admin, admin:password, root:root
- [ ] Rate limiting on login/reset endpoints
- [ ] JWT with `alg: none` or weak secret
- [ ] OAuth redirect_uri validation bypass
- [ ] GraphQL introspection enabled without auth
- [ ] API keys in client-side code
