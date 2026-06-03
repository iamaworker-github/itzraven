---
name: "sast-sqli"
description: "Detect SQL injection vulnerabilities in a codebase using a three-phase approach: recon (find unsafe SQL construction sites), batched verify (trace user input to those sites in parallel subagents, 3 si"
category: web-security
subcategory: web-security
tags: []
relevance: 2
source: ""
author: ""
license: ""
---
# sast-sqli


## Description
Detect SQL injection vulnerabilities in a codebase using a three-phase approach: recon (find unsafe SQL construction sites), batched verify (trace user input to those sites in parallel subagents, 3 sites each), and merge (consolidate batch results). Covers string concat, f-strings, unsafe ORM methods, and dynamic identifiers. Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/sqli-results.md. Use when asked to find SQLi or database injection bugs.


## Relevance Score
2
