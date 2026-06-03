---
name: oauth-security
description: OAuth 2.0 / OpenID Connect security testing methodology — misconfigurations, redirect URI bypass, CSRF, token theft
category: vulnerabilities
---

# OAuth Security Testing Methodology

## Attack Surface
- OAuth provider misconfiguration (client_secret exposed, weak redirect_uri validation)
- Authorization code interception (CSRF, PKCE missing)
- Implicit grant token leakage (fragment in redirect)
- Improper state parameter validation
- Redirect URI open redirect bypass

## Testing Steps

### 1. Redirect URI Validation Bypass
- Try path traversal: `redirect_uri=https://app.com/oauth/callback/attacker.com`
- Try subdomain: `redirect_uri=https://attacker.com.app.com/`
- Try open redirect in callback: `redirect_uri=https://app.com/redirect.php?url=attacker.com`
- Try localhost: `redirect_uri=https://app.com/oauth/callback?url=http://127.0.0.1:8080`
- Try unicode normalization: `redirect_uri=https://app.com/οauth/callback` (o vs ο)
- Try parameter pollution: `?redirect_uri=legit.com&redirect_uri=evil.com`

### 2. CSRF on OAuth Flow
- Missing `state` parameter → attacker can bind victim's account to attacker's session
- Predictable state parameter → attacker can forge authorization request
- Test with state parameter removed entirely

### 3. Code/Token Leakage
- Authorization code in URL logs (Referer header leakage)
- Token in browser history (implicit grant)
- Code in WebSocket upgrade request
- Token passed via POST instead of header

### 4. PKCE Downgrade
- If provider supports both PKCE and plain code challenge
- Remove `code_challenge` parameter → downgrade to plain flow
- Change `code_challenge_method` from `S256` to `plain`

### 5. client_secret Exposure
- Check mobile app decompilation for hardcoded client_secret
- Check JS source maps for client credentials
- Check public repos for leaked secrets

## Common Findings
- Missing state parameter → CSRF account binding
- Open redirect in redirect_uri → token theft
- No PKCE → authorization code interception
- Implicit grant with SPA → token in URL fragment exposed
- Weak redirect_uri validation → open redirect
