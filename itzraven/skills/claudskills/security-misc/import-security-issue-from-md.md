---
name: "import-security-issue-from-md"
description: "Open one or more `<tracker>` tracking issues from a markdown file containing a batch of security findings (typically the output of an AI security review or a third-party scanner). Each finding in the "
category: security
subcategory: security-misc
tags: ["type:scanner", "type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# import-security-issue-from-md


## Description
Open one or more `<tracker>` tracking issues from a markdown file containing a batch of security findings (typically the output of an AI security review or a third-party scanner). Each finding in the file becomes one tracker, landing in the `Needs triage` board column with the standard issue-template body fields populated from the markdown sections. Unlike `import-security-issue` (Gmail) and `import-security-issue-from-pr` (public PR), there is no inbound reporter to reply to and no PR to inspect — the file itself is the full report.


## Tags
type:scanner, type:review


## Relevance Score
0
