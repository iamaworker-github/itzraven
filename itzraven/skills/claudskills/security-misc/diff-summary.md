---
name: "diff-summary"
description: "One-call structured triage of a git diff. Returns per-file role classification (source/test/config/doc/generated/build/fixture/migration), risk tier (low/medium/high) with reasons, public-API touch de"
category: security
subcategory: security-misc
tags: ["lang:python"]
relevance: 1
source: ""
author: ""
license: ""
---
# diff-summary


## Description
One-call structured triage of a git diff. Returns per-file role classification (source/test/config/doc/generated/build/fixture/migration), risk tier (low/medium/high) with reasons, public-API touch detection, co-changed-test detection, secret-risk path flagging, and aggregate stats. Replaces the 5-20 Read calls an agent burns reading each modified file individually to figure out "what kind of change is this and how risky is it". Stateless, no network, stdlib Python only.


## Tags
lang:python


## Relevance Score
1
