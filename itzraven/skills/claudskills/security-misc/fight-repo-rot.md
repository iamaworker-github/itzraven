---
name: "fight-repo-rot"
description: "Finds what's rotting in a repo and returns a prioritized diagnosis — dead code first, then god files / hotspots / hardcoded paths / stale TODOs / lopsided import graphs. Dead-code candidates are tagge"
category: security
subcategory: security-misc
tags: ["type:audit", "type:debug"]
relevance: 1
source: ""
author: ""
license: ""
---
# fight-repo-rot


## Description
Finds what's rotting in a repo and returns a prioritized diagnosis — dead code first, then god files / hotspots / hardcoded paths / stale TODOs / lopsided import graphs. Dead-code candidates are tagged HIGH / MEDIUM / LOW confidence so the operator can delete with calibrated risk. Pure diagnosis — never edits code, never plans fixes, never runs verification. Hand off to refactor-verify for deletions and restructures, to project-conventions for config issues, to audit-security for CVE dependency rot. Language-agnostic.


## Tags
type:audit, type:debug


## Relevance Score
1
