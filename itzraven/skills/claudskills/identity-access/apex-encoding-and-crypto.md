---
name: "apex-encoding-and-crypto"
description: "Use when Apex must sign, verify, encrypt, hash, encode, or decode payloads — including HMAC for webhook signatures, RSA/ECDSA signing for JWT bearer flows, AES for stored secrets, base64/hex/URL encod"
category: identity-access
subcategory: identity-access
tags: ["type:integration"]
relevance: 3
source: ""
author: "Pranav Nagrecha"
license: ""
---
# apex-encoding-and-crypto


## Description
Use when Apex must sign, verify, encrypt, hash, encode, or decode payloads — including HMAC for webhook signatures, RSA/ECDSA signing for JWT bearer flows, AES for stored secrets, base64/hex/URL encoding, and digest comparisons for integration integrity. Triggers: 'Crypto.sign', 'Crypto.generateMac', 'EncodingUtil.base64Encode', 'JWT signing in Apex', 'verify webhook signature'. NOT for setting up Named Credentials or OAuth flows end-to-end — use apex-named-credentials-patterns; NOT for SOQL injection defense — use soql-security.


## Tags
type:integration


## Relevance Score
3
