---
name: "sast-missingauth"
description: "Detect missing authentication and broken function-level authorization vulnerabilities in a codebase using a three-phase approach: recon (map endpoints and the role/permission system), batched verify ("
category: appsec
subcategory: appsec-tools
tags: []
relevance: 2
source: ""
author: ""
license: ""
---
# sast-missingauth


## Description
Detect missing authentication and broken function-level authorization vulnerabilities in a codebase using a three-phase approach: recon (map endpoints and the role/permission system), batched verify (check auth/authz in parallel subagents, 3 endpoints each), and merge (consolidate batch results). Covers unauthenticated access and vertical privilege escalation (e.g., regular user accessing admin-only functions). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/missingauth-results.md. Use when asked to find missing auth, broken access control, or privilege escalation bugs.


## Relevance Score
2
