---
name: account-takeover
description: Account takeover via chaining low-impact bugs, token leaks, CSRF, and password reset poisoning
category: vulnerabilities
---

# Account Takeover Methodology

## Chaining Low-Impact Bugs for Account Takeover
Combine multiple low-severity issues to escalate into full account takeover:

1. **XSS + CSRF**: Use stored XSS to steal CSRF tokens, then perform actions as victim
2. **XSS + No Rate Limit**: Brute-force OTP/security questions after XSS exfiltrates necessary context
3. **Password Reset Poisoning + Token Leak**: Poison Host header to send reset link to attacker domain, intercept token
4. **Sensitive Data Exposure + Weak Password**: Extract user email/phone from API responses, use for password reset
5. **IDOR + Token Predictability**: Access other users' tokens via predictable patterns in reset links

## Token Leaks in Responses
- Check JSON responses for password reset tokens in unexpected fields
- Look for tokens in Referer headers when navigating away from password reset pages
- Monitor WebSocket messages during reset flow for token leakage
- Inspect URL redirect chains after clicking reset links
- Check browser console logs, network tab for leaked tokens

## Password Reset Poisoning
1. Intercept password reset request
2. Add headers: `X-Forwarded-Host: attacker.com`, `X-Host: attacker.com`
3. If the reset link email uses these headers, the link becomes `attacker.com/reset?token=abc`
4. Victim clicks link → token goes to attacker

## CSRF-Based Account Takeover
- CSRF on email change → attacker controls recovery email
- CSRF on password change → direct password overwrite  
- CSRF on profile update with mobile number → OTP goes to attacker
