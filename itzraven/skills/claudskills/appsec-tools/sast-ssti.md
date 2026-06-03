---
name: "sast-ssti"
description: "Detect Server-Side Template Injection (SSTI) vulnerabilities in a codebase using a three-phase approach: recon (find template rendering sites that use dynamic strings), batched verify (trace user inpu"
category: appsec
subcategory: appsec-tools
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# sast-ssti


## Description
Detect Server-Side Template Injection (SSTI) vulnerabilities in a codebase using a three-phase approach: recon (find template rendering sites that use dynamic strings), batched verify (trace user input to those sites in parallel subagents, 3 candidates each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/ssti-results.md. Use when asked to find SSTI or template injection bugs.


## Relevance Score
1
