---
name: "oma-deepsec"
description: "Drive Vercel's `deepsec` agent-powered vulnerability scanner end-to-end: installing the `.deepsec/` workspace, bootstrapping `INFO.md`, running cost-aware `scan` / `process` / `triage` / `revalidate` "
category: security
subcategory: security-misc
tags: ["lang:javascript", "cloud:vercel", "ai:agent", "type:scanner", "type:review"]
relevance: 2
source: "https://github.com/first-fluke/oh-my-agent/blob/HEAD/.agents/skills/oma-deepsec/SKILL.md"
author: "first-fluke"
license: "MIT"
---
# oma-deepsec


## Description
Drive Vercel's `deepsec` agent-powered vulnerability scanner end-to-end: installing the `.deepsec/` workspace, bootstrapping `INFO.md`, running cost-aware `scan` / `process` / `triage` / `revalidate` / `export` passes, gating PRs with `process --diff`, writing custom matchers, and triaging findings. Use whenever the user mentions deepsec, asks an agent to scan a repo for vulnerabilities, runs into `pnpm deepsec` / `bunx deepsec` commands, wants a CI-based PR security review, sees a `.deepsec/` directory, or asks about `INFO.md` / matchers / `process --diff` / `revalidate`, even when the tool name is not spoken. Deepsec scans are expensive (a single full scan can cost hundreds to tens of thousands of dollars) so the skill exists in part to keep the user from getting surprised.


## Tags
lang:javascript, cloud:vercel, ai:agent, type:scanner, type:review


## Source
https://github.com/first-fluke/oh-my-agent/blob/HEAD/.agents/skills/oma-deepsec/SKILL.md


## Relevance Score
2
