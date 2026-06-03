---
name: "gh-protect"
description: "Audit or apply GitHub branch protection, tag rulesets, repo security settings, and signing requirements based on the active profile. TRIGGER when the user says 'check branch protection', 'audit GitHub"
category: security
subcategory: security-misc
tags: ["tool:github", "type:audit"]
relevance: 1
source: ""
author: ""
license: ""
---
# gh-protect


## Description
Audit or apply GitHub branch protection, tag rulesets, repo security settings, and signing requirements based on the active profile. TRIGGER when the user says "check branch protection", "audit GitHub protection", "apply branch protection", "enforce branch protection", "set up branch protection", "configure branch rules", "check tag protection", "audit repo security", "apply GitHub settings", "enable branch protection", "protection audit", "are my branches protected", "/nyann:gh-protect". Do NOT trigger on "is this repo healthy" — that's `doctor` (which includes a protection check among many other signals). Do NOT trigger on "bootstrap this project" — bootstrap applies protection as one step of the full pipeline.


## Tags
tool:github, type:audit


## Relevance Score
1
