---
name: "sast-pathtraversal"
description: "Detect path traversal vulnerabilities in a codebase using a three-phase approach: recon (find file-loading sinks with dynamic paths), batched verify (trace user input and mitigations in parallel subag"
category: appsec
subcategory: appsec-tools
tags: []
relevance: 0
source: ""
author: ""
license: ""
---
# sast-pathtraversal


## Description
Detect path traversal vulnerabilities in a codebase using a three-phase approach: recon (find file-loading sinks with dynamic paths), batched verify (trace user input and mitigations in parallel subagents, 3 sinks each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/pathtraversal-results.md. Use when asked to find path traversal, directory traversal, or file disclosure bugs.


## Relevance Score
0
