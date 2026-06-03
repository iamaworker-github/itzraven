---
name: "secret-scan"
description: "Hardcoded-secret detection — AWS keys, GitHub PATs, Slack tokens, Stripe keys, generic high-entropy strings. Pre-commit (`--staged-only`), explicit paths, or full repo. Use when guarding `git commit`,"
category: security
subcategory: security-misc
tags: ["cloud:aws", "type:audit"]
relevance: 0
source: "https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/secret-scan/SKILL.md"
author: "Vulnetix"
license: "Apache-2.0"
---
# secret-scan


## Description
Hardcoded-secret detection — AWS keys, GitHub PATs, Slack tokens, Stripe keys, generic high-entropy strings. Pre-commit (`--staged-only`), explicit paths, or full repo. Use when guarding `git commit`, auditing a repo for leaked credentials, validating no secrets entered the diff before push, or producing a rotation list for an exposed-secret incident.


## Tags
cloud:aws, type:audit


## Source
https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/secret-scan/SKILL.md


## Relevance Score
0
