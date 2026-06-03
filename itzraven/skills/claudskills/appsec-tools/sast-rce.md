---
name: "sast-rce"
description: "Detect Remote Code Execution (RCE) vulnerabilities in a codebase using a three-phase approach: recon (find dangerous execution sinks), batched verify (trace user input to sinks in parallel subagents, "
category: appsec
subcategory: appsec-tools
tags: []
relevance: 2
source: ""
author: ""
license: ""
---
# sast-rce


## Description
Detect Remote Code Execution (RCE) vulnerabilities in a codebase using a three-phase approach: recon (find dangerous execution sinks), batched verify (trace user input to sinks in parallel subagents, 3 sinks each), and merge (consolidate batch results). Covers OS command injection, eval-like sinks, and unsafe deserialization. Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/rce-results.md. Use when asked to find RCE, command injection, or unsafe deserialization bugs.


## Relevance Score
2
