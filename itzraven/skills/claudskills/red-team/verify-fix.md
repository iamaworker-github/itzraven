---
name: "verify-fix"
description: "Post-fix verification — re-scan the repo, gate on `--exploits weaponized --severity high`, recheck the specific CVE against the new installed version, write the verdict to `.vulnetix/memory.yaml`. Use"
category: red-team
subcategory: red-team
tags: []
relevance: 2
source: "https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/verify-fix/SKILL.md"
author: "Vulnetix"
license: "Apache-2.0"
---
# verify-fix


## Description
Post-fix verification — re-scan the repo, gate on `--exploits weaponized --severity high`, recheck the specific CVE against the new installed version, write the verdict to `.vulnetix/memory.yaml`. Use when confirming a fix landed, validating a version bump did not introduce regressions, or producing a clean-scan attestation for compliance.


## Source
https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/verify-fix/SKILL.md


## Relevance Score
2
