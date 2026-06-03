---
name: "sast-fileupload"
description: "Detect insecure file upload vulnerabilities in a codebase using a three-phase approach: discovery (find all upload sites), batched verify (check extension bypass and related issues in parallel subagen"
category: appsec
subcategory: appsec-tools
tags: []
relevance: 0
source: ""
author: ""
license: ""
---
# sast-fileupload


## Description
Detect insecure file upload vulnerabilities in a codebase using a three-phase approach: discovery (find all upload sites), batched verify (check extension bypass and related issues in parallel subagents, 3 sites each), and merge (consolidate batch results). Requires sast/architecture.md (run sast-analysis first). Outputs findings to sast/fileupload-results.md. Use when asked to find file upload, unrestricted upload, or extension bypass bugs.


## Relevance Score
0
