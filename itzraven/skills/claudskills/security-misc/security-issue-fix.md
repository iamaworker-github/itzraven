---
name: "security-issue-fix"
description: "Attempt to fix a security issue tracked in <tracker> by implementing the change in a public <upstream> PR. Runs the security-issue-sync skill first to reconcile the issue's state, then analyses the di"
category: security
subcategory: security-misc
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# security-issue-fix


## Description
Attempt to fix a security issue tracked in <tracker> by implementing the change in a public <upstream> PR. Runs the security-issue-sync skill first to reconcile the issue's state, then analyses the discussion to decide whether the issue is easily fixable (clear consensus, small scope, known location). If it is, proposes an implementation plan, waits for explicit user confirmation, writes the change in the user's local <upstream> clone, runs the local checks and tests, opens a PR from the user's fork via `gh pr create --web`, and updates the <tracker> tracking issue with the new PR link and any relevant labels. Public PR content is checked to make sure it does **not** reveal the CVE, the security nature of the change, or any link back to <tracker>.


## Relevance Score
1
