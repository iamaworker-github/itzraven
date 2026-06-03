---
name: password-reset-attacks
description: Password reset functionality testing — token leakage, poisoning, prediction, and race conditions
category: vulnerabilities
---

# Password Reset Attack Methodology

## Token Leakage
1. Send password reset request
2. Monitor all outbound requests during reset flow
3. Look for token in:
   - Referer header when navigating from email client
   - Third-party requests (analytics, tracking pixels)
   - WebSocket messages
   - Response bodies in JSON/XML
   - URL redirect chains
   - Browser console errors
   - Cache storage

## Token Prediction
1. Collect multiple reset tokens for same user
2. Analyze pattern (timestamp-based, sequential, weak random)
3. Common issues:
   - Token = MD5(email + timestamp) → predictable
   - Token = sequential integer → enumerate
   - Token = short numeric code (6 digits) → brute-force
   - No rate limiting on token validation

## Token Expiration Issues
- Check if old tokens remain valid after password change
- Check if tokens expire after use (replay)
- Check if tokens have reasonable TTL (< 1 hour)

## Host Header Poisoning
1. Intercept reset request
2. Inject headers: `X-Forwarded-Host`, `X-Host`, `Forwarded`
3. Check if reset link email reflects these headers
4. If yes, attacker can redirect reset link to their domain

## Account Enumeration via Reset
- Different responses for valid vs invalid emails
- Timing differences in responses
- Token sent vs not sent confirmation messages
- CAPTCHA bypass during reset enumeration

## Rate Limit Bypass on Reset
- Rotate User-Agent, X-Forwarded-For
- Change Content-Type
- Try different HTTP methods (HEAD, OPTIONS)
- Add junk parameters to bypass caching
