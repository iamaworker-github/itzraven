---
name: "sast-hardcodedsecrets"
description: "Detect hardcoded sensitive data (API keys, access tokens, private keys, passwords, etc.) in publicly accessible code — frontend JavaScript, mobile apps, client-side bundles, and HTML templates. Uses a"
category: appsec
subcategory: appsec-tools
tags: ["lang:javascript"]
relevance: 0
source: ""
author: ""
license: ""
---
# sast-hardcodedsecrets


## Description
Detect hardcoded sensitive data (API keys, access tokens, private keys, passwords, etc.) in publicly accessible code — frontend JavaScript, mobile apps, client-side bundles, and HTML templates. Uses a three-phase approach: recon (find secret candidates), batched verify (confirm real secrets in public code paths, 3 candidates each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/hardcodedsecrets-results.md. Use when asked to find hardcoded secrets, leaked API keys, or exposed credentials.


## Tags
lang:javascript


## Relevance Score
0
