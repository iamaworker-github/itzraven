---
name: "sast-jwt"
description: "Detect insecure JWT (JSON Web Token) implementations in a codebase using a two-phase approach: first map all JWT issuance and verification sites to understand the token lifecycle and signing configura"
category: identity-access
subcategory: identity-access
tags: []
relevance: 4
source: ""
author: ""
license: ""
---
# sast-jwt


## Description
Detect insecure JWT (JSON Web Token) implementations in a codebase using a two-phase approach: first map all JWT issuance and verification sites to understand the token lifecycle and signing configuration, then check each verification site for exploitable weaknesses such as algorithm confusion, missing signature verification, weak secrets, header injection, and missing claim validation. Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/jwt-results.md. If no JWT usage is found in Phase 1, Phase 2 is skipped. Use when asked to find JWT, token forgery, or authentication bypass bugs.


## Relevance Score
4
