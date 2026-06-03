---
name: "encryption"
description: "Audit and harden encryption across the full stack. Checks data-at-rest encryption (database TDE, field-level AES-256-GCM, file storage SSE, backup encryption), data-in-transit security (TLS 1.2+, HSTS"
category: identity-access
subcategory: identity-access
tags: ["type:audit"]
relevance: 1
source: ""
author: ""
license: ""
---
# encryption


## Description
Audit and harden encryption across the full stack. Checks data-at-rest encryption (database TDE, field-level AES-256-GCM, file storage SSE, backup encryption), data-in-transit security (TLS 1.2+, HSTS, certificate pinning, mTLS, WebSocket WSS), key management (KMS, envelope encryption, key rotation, key separation), password hashing (argon2id, bcrypt, scrypt, PBKDF2 work factors, salt uniqueness, migration plans), token security (JWT signing algorithms, CSPRNG, refresh token rotation), and API key management (hashed storage, scoping, revocation). Use when you need to audit crypto, fix weak hashing, implement envelope encryption, rotate keys, upgrade TLS, or harden token generation.


## Tags
type:audit


## Relevance Score
1
