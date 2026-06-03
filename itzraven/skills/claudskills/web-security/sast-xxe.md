---
name: "sast-xxe"
description: "Detect XML External Entity (XXE) vulnerabilities in a codebase using a three-phase approach: recon (find XML parsing sites without external-entity hardening), batched verify (trace user input to each "
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# sast-xxe


## Description
Detect XML External Entity (XXE) vulnerabilities in a codebase using a three-phase approach: recon (find XML parsing sites without external-entity hardening), batched verify (trace user input to each site in parallel subagents, 3 sites each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/xxe-results.md. Use when asked to find XXE or XML injection bugs.


## Relevance Score
1
