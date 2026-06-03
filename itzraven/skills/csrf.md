---
name: csrf
description: Cross-site request forgery, token bypasses, anti-CSRF mechanisms
category: vulnerabilities
---

# CSRF Testing

## Attack Surface
Cross-Site Request Forgery exploits the trust a site has in an authenticated user's browser.
- State-changing actions (password change, email update, fund transfer)
- Forms without CSRF tokens
- APIs without origin/referer validation
- JSON endpoints that accept form-encoded data
- CORS misconfigurations enabling cross-origin requests

## Methodology
1. **Token Analysis**
   - Check if CSRF token exists in forms
   - Test if token is validated server-side
   - Check if token is tied to user session
   - Test token reuse across sessions
   - Check for predictable tokens (timestamp, user ID hash)

2. **Anti-CSRF Bypass**
   - Remove token parameter entirely
   - Send empty token
   - Use same token from different user
   - Change HTTP method (POST -> GET with query params)
   - Use JSON content-type if form-encoded is blocked
   - Add custom header and test preflight handling

3. **Origin/Referer Check Bypass**
   - Drop Referer header entirely
   - Use open redirect to bypass origin checks
   - Use null origin in sandboxed iframe
   - Use referer policy to control header sending

## Validation
- Action executed without valid CSRF token
- Cross-origin form submission succeeds
- State change performed with crafted request from different origin
