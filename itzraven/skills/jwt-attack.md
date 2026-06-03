---
name: jwt-attack
description: JWT attack methodology — alg confusion, key confusion, token forgery, and common vulnerabilities
category: vulnerabilities
---

# JWT Attack Methodology

## Structure
JWT = Header.Payload.Signature (Base64URL encoded)

## Attack Vectors

### 1. Algorithm Confusion (alg:none)
```json
{"alg": "none", "typ": "JWT"}
```
- Change `alg` to `none` and remove signature
- Try `None`, `NONE`, `nOnE` (case variations)

### 2. Weak HMAC Secret
- Crack with hashcat: `hashcat -m 16500 jwt.txt wordlist.txt`
- Common passwords, rockyou, haveibeenpwned lists
- Try base64-decoded public key as HMAC secret

### 3. RS256 → HS256 Confusion
- If server uses RS256 (RSA private key to sign, public to verify)
- Obtain public key (often at `/.well-known/jwks.json`, `/jwks.json`)
- Change alg to `HS256`, sign with public key as HMAC secret
- Server may accept it if it reuses verification code

### 4. JWK Injection
- Add embedded JWK header: `{"jwk": {"kty": "RSA", "n": "...", "e": "AQAB"}}`
- Server may trust attacker-controlled public key
- Tools: `jwt_tool`, `python-jwt`

### 5. Kid Injection
- `kid` header used for key lookup
- Try path traversal: `{"kid": "../../dev/null"}`
- Try SQLi in kid: `{"kid": "keys' UNION SELECT ..."}`
- Try command injection: `{"kid": "$(whoami)"}`

### 6. Expired Token Reuse
- Check if expiration is actually validated
- Modify `exp`, `nbf`, `iat` claims to future dates
- Set `exp` to 0 or negative (integer overflow)

### 7. Weak Signature Verification
- Remove signature entirely (some libraries skip verification)
- Send with random signature
- Modify payload only if server doesn't validate

## Tools
- `jwt_tool` - Comprehensive JWT testing
- `jwt-cracker` - Brute force HMAC secrets
- `jwt.io` - Debugger and decoder
