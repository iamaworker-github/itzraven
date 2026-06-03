---
name: "sast-idor"
description: "Detect Insecure Direct Object Reference (IDOR) vulnerabilities in a codebase using a three-phase approach: recon (find candidates), batched verify (check authorization in parallel subagents, 3 candida"
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# sast-idor


## Description
Detect Insecure Direct Object Reference (IDOR) vulnerabilities in a codebase using a three-phase approach: recon (find candidates), batched verify (check authorization in parallel subagents, 3 candidates each), and merge (consolidate batch results). Checks endpoints for missing ownership or authorization checks on user-supplied identifiers. Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/idor-results.md. Use when asked to find IDOR or authorization bypass bugs.


## Relevance Score
1
