---
name: "sast-ssrf"
description: "Detect Server-Side Request Forgery (SSRF) vulnerabilities in a codebase using a three-phase approach: recon (find outbound call sites), batched verify (trace user input to destinations in parallel sub"
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# sast-ssrf


## Description
Detect Server-Side Request Forgery (SSRF) vulnerabilities in a codebase using a three-phase approach: recon (find outbound call sites), batched verify (trace user input to destinations in parallel subagents, 3 sites each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/ssrf-results.md. Use when asked to find SSRF or server-side request forgery bugs.


## Relevance Score
1
