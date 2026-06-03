---
name: "codex-fix"
description: "Post-edit loop that invokes `/codex:rescue` for a second-model review of the current branch, collects the findings, and hands them off to `refactor-verify`'s review-driven fix mode for triage, verific"
category: appsec
subcategory: appsec-tools
tags: ["type:review"]
relevance: 1
source: ""
author: ""
license: ""
---
# codex-fix


## Description
Post-edit loop that invokes `/codex:rescue` for a second-model review of the current branch, collects the findings, and hands them off to `refactor-verify`'s review-driven fix mode for triage, verification, and committed resolution. A thin host-specific wrapper — the portable review-driven engine lives in `refactor-verify`. Requires Claude Code with the Codex plugin installed; on every other host the skill emits a one-line fallback and exits without error. Operators whose review findings come from any other source (pasted notes, human PR review, Sentry alert, gitleaks output, Semgrep report, GitHub Advanced Security) should invoke `refactor-verify` directly and skip this wrapper entirely.


## Tags
type:review


## Relevance Score
1
