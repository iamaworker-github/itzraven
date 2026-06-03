---
name: authentication_jwt
description: JWT attacks, algorithm confusion, claim tampering
category: vulnerabilities
---

# JWT Authentication Testing

## Attack Surface
JWT tokens are used for authentication and session management.
- `alg: none` attack
- Algorithm confusion (RS256 -> HS256)
- Weak HMAC secret cracking
- Claim manipulation (`sub`, `admin`, `role`)
- Token expiration bypass
- JWK header injection

## Methodology
1. **Token Analysis**
   - Decode JWT base64 parts
   - Check `alg` header: is it `none`, or can it be switched?
   - Check `kid` header: is it vulnerable to path traversal or SQLi?
   - Check for symmetric keys in JWK/JKU headers

2. **Attack Techniques**
   - Algorithm confusion: change RS256 to HS256, sign with public key
   - `none` algorithm: set `"alg": "none"`, empty signature
   - Weak secret: bruteforce HMAC secret with rockyou.txt
   - JWK injection: provide own public key in `jwk` header, sign with private key
   - `kid` injection: `kid: "../../dev/null"`, `kid: "'; DROP TABLE keys--"`

3. **Claim Manipulation**
   - Change `sub` to access other users' data
   - Set `admin: true` or `role: admin`
   - Extend `exp` to far future
   - Set `iat` and `nbf` to past dates

## Validation
- Server accepts modified token and returns admin-level data
- Endpoint gives access to other user's resources with modified `sub`
- Token accepted after original expiration date
