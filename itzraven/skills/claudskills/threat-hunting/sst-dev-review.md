---
name: "sst-dev-review"
description: "Post-cycle second-pass review of the last `/sst-dev-cycle` commit on any project. Reads what shipped (code + tests + spec + TODO + docs), evaluates it against the spec item it closed along several axe"
category: threat-hunting
subcategory: threat-hunting
tags: ["type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# sst-dev-review


## Description
Post-cycle second-pass review of the last `/sst-dev-cycle` commit on any project. Reads what shipped (code + tests + spec + TODO + docs), evaluates it against the spec item it closed along several axes (spec parity, correctness, coverage, discoverability, production verification, security, style, performance), and appends concrete follow-up items to the project's spec AND the handoff TODO's "Next up" if critical, blocking, or medium-to-major gaps are found. If nothing substantive turns up, leaves both unchanged and reports "clean." Does NOT fix issues — only names them and schedules them as spec work for the next `/sst-dev-cycle`. Pair with `/sst-dev-cycle` (chained via `bin/skill-chain.py sst-dev-cycle sst-dev-review`).


## Tags
type:review


## Relevance Score
0
