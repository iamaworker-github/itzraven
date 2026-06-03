---
name: "logic-review"
description: "Find logic bugs in a single file or function via semi-formal execution tracing (Premises → Trace → Divergence → Remedy). Trigger when a user shares code and suspects something is wrong without naming "
category: security
subcategory: security-misc
tags: ["type:audit", "type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# logic-review


## Description
Find logic bugs in a single file or function via semi-formal execution tracing (Premises → Trace → Divergence → Remedy). Trigger when a user shares code and suspects something is wrong without naming a concrete failure — phrases like "review this", "does this look right", "check this function", "audit this code", "tests pass but prod fails". SCOPE HARD RULE: one file or one function only. For a directory or whole module use logic-health; for a confirmed failure (stack trace, failing test, specific wrong value) use logic-locate; for two versions use logic-diff; for repo-wide autonomous fixing use logic-fix-all. Do NOT trigger for: style/formatting, security scanning, performance, test generation, architecture or design questions.


## Tags
type:audit, type:review


## Relevance Score
0
