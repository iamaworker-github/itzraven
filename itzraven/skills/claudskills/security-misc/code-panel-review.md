---
name: "code-panel-review"
description: "Run a multi-agent 'panel review' of the user's local code changes before they open a PR. Orchestrates five specialized reviewer agents (Security, Performance, Resilience, Bugs, Compliance) via the Git"
category: security
subcategory: security-misc
tags: ["ai:agent", "type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# code-panel-review


## Description
Run a multi-agent "panel review" of the user's local code changes before they open a PR. Orchestrates five specialized reviewer agents (Security, Performance, Resilience, Bugs, Compliance) via the GitHub Copilot SDK, collects their JSON findings, and synthesizes a consolidated, deduplicated, severity-ranked report. Use when the user wants a pre-PR review of their own uncommitted or unpushed changes. Trigger phrases include: "run the panel on this", "panel review my changes", "review my changes before I push", "pre-PR review", "run a code panel review". Do NOT use for: reviewing already-merged code, reviewing someone else's PR, quick single-file questions, or style/lint-only requests.


## Tags
ai:agent, type:review


## Relevance Score
0
