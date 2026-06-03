---
name: "review-for-ship"
description: "User-invoked skill to run a comprehensive pre-ship review using all review agents relevant to the project's tech stack, with rad-code-review as the final gate. Reads the stack profile and dispatches s"
category: security
subcategory: security-misc
tags: ["type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# review-for-ship


## Description
User-invoked skill to run a comprehensive pre-ship review using all review agents relevant to the project's tech stack, with rad-code-review as the final gate. Reads the stack profile and dispatches specialist agents in parallel, then runs rad-code-review for AI slop detection, architecture, security, and release readiness. Trigger when the user says "/review-for-ship", "review before shipping", "is this ready to deploy", "pre-ship review", "run all reviews", "comprehensive review", "final check before shipping", "production readiness check", "is this ready to merge", "ship check", "pre-deploy review", "audit everything".


## Tags
type:review


## Relevance Score
0
