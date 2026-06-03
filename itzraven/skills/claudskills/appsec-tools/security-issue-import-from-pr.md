---
name: "security-issue-import-from-pr"
description: "Open a tracking issue in <tracker> for a security-relevant fix that has already been opened (or merged) as a public PR in <upstream>, in the case where there is no inbound `<security-list>` report. Th"
category: appsec
subcategory: appsec-tools
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# security-issue-import-from-pr


## Description
Open a tracking issue in <tracker> for a security-relevant fix that has already been opened (or merged) as a public PR in <upstream>, in the case where there is no inbound `<security-list>` report. The tracker lands in the `Assessed` board column (the team-deliberate import implies the security assessment has already happened) with the scope label applied, `pr created` / `pr merged` reflecting the PR's state, and `Remediation developer` / `PR with the fix` body fields populated from the PR — ready for `security-cve-allocate` to take over.


## Relevance Score
1
