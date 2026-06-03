---
name: "security-issue-deduplicate"
description: "Merge two <tracker> tracking issues that describe the same root-cause vulnerability (typically discovered independently by two reporters, arriving via different channels), preserving every reporter's "
category: security
subcategory: security-misc
tags: []
relevance: 2
source: ""
author: ""
license: ""
---
# security-issue-deduplicate


## Description
Merge two <tracker> tracking issues that describe the same root-cause vulnerability (typically discovered independently by two reporters, arriving via different channels), preserving every reporter's credit, every mailing-list thread reference, and every independent attack-vector description. Updates the kept issue's body in place, closes the duplicate with the `duplicate` label, and regenerates the CVE JSON attachment so both finders land in `credits[]`.


## Relevance Score
2
