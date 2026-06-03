---
name: "risk-pipeline-risk-pipeline-dispatch"
description: "Dispatch risk vector -> reviewer roster + impl/reviewer model + tdd_required. Triggers: s>=- security-reviewer, d>=- data-reviewer, r>=+ reversibility-reviewer, b>=+ full code-quality, u>=+ adds novel"
category: security
subcategory: security-misc
tags: ["type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# risk-pipeline-risk-pipeline-dispatch


## Description
Dispatch risk vector -> reviewer roster + impl/reviewer model + tdd_required. Triggers: s>=- security-reviewer, d>=- data-reviewer, r>=+ reversibility-reviewer, b>=+ full code-quality, u>=+ adds novelty-reviewer + research. Crit axes hard-block. Model routes impl by tier (haiku-4.5/sonnet-4.6/opus-4.7) with crit + u-crit escalation; reviewer one tier down with security/post-task same-tier overrides. TDD when d|s>=- or b|u>=+.


## Tags
type:review


## Relevance Score
0
