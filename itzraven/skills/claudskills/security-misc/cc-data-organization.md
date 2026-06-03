---
name: "cc-data-organization"
description: "Audit and fix data organization: variable declarations, data types, magic numbers, naming conventions, and global data. Three modes: CHECKER (92-item checklist -> status table), APPLIER (type selectio"
category: security
subcategory: security-misc
tags: ["type:audit", "type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# cc-data-organization


## Description
Audit and fix data organization: variable declarations, data types, magic numbers, naming conventions, and global data. Three modes: CHECKER (92-item checklist -> status table), APPLIER (type selection and naming guidance), TRANSFORMER (fix violations). Cover modern types: concurrent/shared state, nullable/optional, temporal/timezone, security-sensitive. Use when reviewing code for data organization issues, choosing data types, or fixing magic numbers. Triggers on: review variables, data types, magic numbers, naming, global data, check types, fix floats, constants.


## Tags
type:audit, type:review


## Relevance Score
0
