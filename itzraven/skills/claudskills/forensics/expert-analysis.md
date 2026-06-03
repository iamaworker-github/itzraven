---
name: "expert-analysis"
description: "Dispatches `forge-expert` subagents in parallel — one per chosen domain — to produce focused analyses of a feature against the codebase before a plan is drafted. Each expert covers one domain (archite"
category: forensics
subcategory: forensics
tags: []
relevance: 0
source: ""
author: ""
license: ""
---
# expert-analysis


## Description
Dispatches `forge-expert` subagents in parallel — one per chosen domain — to produce focused analyses of a feature against the codebase before a plan is drafted. Each expert covers one domain (architecture, performance, data/state, UI/UX, security, testing, build/tooling — pick from the role catalog) and returns a structured report citing `file:line` evidence. Use as Step 3 of the forge workflow, after the user has stated the feature and the orchestrator has gathered baseline codebase context. Do NOT auto-fire; always orchestrator-triggered to keep the workflow sequence intact.


## Relevance Score
0
