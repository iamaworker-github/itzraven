---
name: "sast-xss"
description: "Detect Cross-Site Scripting (XSS) vulnerabilities in a codebase using a three-phase approach: recon (find HTML/JS/DOM sink sites), batched verify (trace user input to sinks in parallel subagents, 3 si"
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# sast-xss


## Description
Detect Cross-Site Scripting (XSS) vulnerabilities in a codebase using a three-phase approach: recon (find HTML/JS/DOM sink sites), batched verify (trace user input to sinks in parallel subagents, 3 sink sites each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/xss-results.md. Use when asked to find XSS or cross-site scripting bugs.


## Relevance Score
1
