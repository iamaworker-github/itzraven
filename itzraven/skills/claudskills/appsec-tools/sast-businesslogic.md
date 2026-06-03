---
name: "sast-businesslogic"
description: "Detect business logic vulnerabilities in a codebase using a three-phase approach: threat modeling (domain analysis and attack scenarios), batched verify (check exploitable gaps in parallel subagents, "
category: appsec
subcategory: appsec-tools
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# sast-businesslogic


## Description
Detect business logic vulnerabilities in a codebase using a three-phase approach: threat modeling (domain analysis and attack scenarios), batched verify (check exploitable gaps in parallel subagents, 3 scenarios each), and merge (consolidate batch results). Covers price manipulation, workflow bypass, limit violations, race conditions, reward abuse, etc. Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/businesslogic-results.md. Use when asked to find business logic, logic flaws, or abuse-of-function bugs.


## Relevance Score
1
