---
name: "security-issue-import"
description: "Scan <security-list> for reports that have not yet been copied into <tracker> as tracking issues, present the proposed imports to the user, and — defaulting to *import unless the user rejects upfront*"
category: appsec
subcategory: appsec-tools
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# security-issue-import


## Description
Scan <security-list> for reports that have not yet been copied into <tracker> as tracking issues, present the proposed imports to the user, and — defaulting to *import unless the user rejects upfront* — create the tracking issues with the `Needs triage` project-board status and draft a receipt-of- confirmation reply to each reporter. This is the first step of the handling process: the entry point that converts an inbound email thread into a tracker the rest of the skills (security-issue-sync, security-issue-fix, generate-cve-json) operate on.


## Relevance Score
1
