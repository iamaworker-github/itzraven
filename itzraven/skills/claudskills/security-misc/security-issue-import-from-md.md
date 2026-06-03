---
name: "security-issue-import-from-md"
description: "Open one or more `<tracker>` tracking issues from a markdown file containing a batch of security findings (typically the output of an AI security review or a third-party scanner). Each finding in the "
category: security
subcategory: security-misc
tags: ["type:scanner", "type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# security-issue-import-from-md


## Description
Open one or more `<tracker>` tracking issues from a markdown file containing a batch of security findings (typically the output of an AI security review or a third-party scanner). Each finding in the file becomes one tracker, landing in the `Needs triage` board column with the standard issue-template body fields populated from the markdown sections. Unlike `security-issue-import` (Gmail) and `security-issue-import-from-pr` (public PR), there is no inbound reporter to reply to and no PR to inspect — the file itself is the full report.


## Tags
type:scanner, type:review


## Relevance Score
0
