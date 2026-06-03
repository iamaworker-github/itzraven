---
name: "ha-logs"
description: "Self-service diagnostics — query Hope Agent's local SQLite databases (logs / sessions / async jobs) directly via the `exec` tool to investigate problems, analyze usage, and locate root causes. Trigger"
category: web-security
subcategory: web-security
tags: ["type:debug"]
relevance: 1
source: ""
author: "Hope Agent"
license: "MIT"
---
# ha-logs


## Description
Self-service diagnostics — query Hope Agent's local SQLite databases (logs / sessions / async jobs) directly via the `exec` tool to investigate problems, analyze usage, and locate root causes. Trigger on: user reports something broken / failing / slow / stuck / not responding ('X 不工作', 'X 报错', 'X 卡住', '为什么 X 失败', 'why did X fail', 'show me the logs', 'check what happened'); ad-hoc data analysis ('this week's token usage', '最近调用最多的工具', 'how many subagent runs failed', 'tool error rate', 'find sessions where X happened'); verifying a fix ('did the error stop after I changed Y'). Use BEFORE asking the user to paste log snippets — the data is on disk, query it directly. Read-only — SELECT only, never UPDATE/DELETE/INSERT/DROP.


## Tags
type:debug


## Relevance Score
1
