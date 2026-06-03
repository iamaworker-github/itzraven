---
name: "logic-health"
description: "Sweep a directory, module, or full codebase for logic correctness and produce a scored health dashboard with systemic patterns. Trigger when the scope is multi-file — 'audit the whole codebase', 'heal"
category: security
subcategory: security-misc
tags: ["type:audit", "type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# logic-health


## Description
Sweep a directory, module, or full codebase for logic correctness and produce a scored health dashboard with systemic patterns. Trigger when the scope is multi-file — "audit the whole codebase", "health check", "audit src/", "audit auth and payments modules", "where should I focus testing", "onboarding review", "logic overview before we ship". SCOPE HARD RULE: multi-file or directory scope. One file or one function uses logic-review; a concrete failure uses logic-locate; two versions uses logic-diff; explaining a path uses logic-explain; "fix everything" (no scope named) uses logic-fix-all. Do NOT trigger for: single function/file, style/architecture-only audits, security-only scans, performance-only audits.


## Tags
type:audit, type:review


## Relevance Score
0
