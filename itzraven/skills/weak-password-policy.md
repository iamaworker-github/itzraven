---
name: weak-password-policy
description: Weak password policy testing — brute force susceptibility, common weaknesses, and dictionary attack vectors
category: vulnerabilities
---

# Weak Password Policy Testing

## What to Test
1. Minimum password length (should be ≥ 8)
2. Character complexity requirements (uppercase, lowercase, digits, special)
3. Common password blacklist (password, 123456, qwerty, admin)
4. Password reuse across accounts
5. Password history enforcement (prevent reuse of last N passwords)
6. Rate limiting on login attempts
7. Account lockout threshold
8. Password change without old password verification

## Common Weaknesses
- No minimum length → `a`, `1` accepted
- Only alphabet required → no numbers/special chars required
- Maximum length too short → truncation to 8 chars
- Unicode normalization issues → `Ａ` (full-width) bypasses complexity
- Password hint reveals too much
- Security questions with public answers (mother's maiden name, birth city)

## Exploitation
- Brute force common passwords (rockyou.txt)
- Password spraying (same password, different users)
- Dictionary attacks with mutations (leet speak, capitalizations)
- Credential stuffing from breach data
- Check for default credentials (admin/admin, test/test)

## Account Lockout Flaws
- Lockout doesn't apply to API endpoints
- Lockout only applies to specific IP (bypass via X-Forwarded-For)
- Lockout resets after fixed time (wait and retry)
- CAPTCHA not enforced after N attempts
- Lockout count resets on successful login (login 9 times, then brute-force)
