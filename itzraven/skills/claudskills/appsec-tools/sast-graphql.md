---
name: "sast-graphql"
description: "Detect GraphQL injection vulnerabilities in a codebase using a three-phase approach: recon (confirm GraphQL usage and find unsafe operation document assembly sites), batched verify (trace user input t"
category: appsec
subcategory: appsec-tools
tags: []
relevance: 2
source: ""
author: ""
license: ""
---
# sast-graphql


## Description
Detect GraphQL injection vulnerabilities in a codebase using a three-phase approach: recon (confirm GraphQL usage and find unsafe operation document assembly sites), batched verify (trace user input to those sites in parallel subagents, up to 3 candidate sites each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/graphql-results.md. If no GraphQL technology is found in Phase 1, later phases are skipped. Use when asked to find GraphQL injection, unsafe GraphQL document construction, or operation string injection bugs.


## Relevance Score
2
