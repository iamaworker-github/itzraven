---
name: "pick-abandoned-repository"
description: "Use this skill to pick exactly one GitHub repository that needs a refresh: scan a given list of owners, collect signals of neglect — long stretches without commits, failing or absent CI runs on the de"
category: security
subcategory: security-misc
tags: []
relevance: 0
source: "https://github.com/yegor256/skills/blob/HEAD/skills/pick-abandoned-repository/SKILL.md"
author: "yegor256"
license: "MIT"
---
# pick-abandoned-repository


## Description
Use this skill to pick exactly one GitHub repository that needs a refresh: scan a given list of owners, collect signals of neglect — long stretches without commits, failing or absent CI runs on the default branch, outdated or vulnerable dependencies — score every candidate, and pick the single most neglected repository. If every repository looks reasonably fresh, still pick one — the least fresh of the bunch — because the contract of this skill is to always end with exactly one repository chosen. One repository per run, then stop.


## Source
https://github.com/yegor256/skills/blob/HEAD/skills/pick-abandoned-repository/SKILL.md


## Relevance Score
0
