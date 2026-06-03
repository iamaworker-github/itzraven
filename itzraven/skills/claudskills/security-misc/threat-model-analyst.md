---
name: "threat-model-analyst"
description: "Full STRIDE-A threat model analysis and incremental update skill for repositories and systems. Supports two modes: (1) Single analysis — full STRIDE-A threat model of a repository, producing architect"
category: security
subcategory: security-misc
tags: []
relevance: 0
source: ""
author: ""
license: ""
---
# threat-model-analyst


## Description
Full STRIDE-A threat model analysis and incremental update skill for repositories and systems. Supports two modes: (1) Single analysis — full STRIDE-A threat model of a repository, producing architecture overviews, DFD diagrams, STRIDE-A analysis, prioritized findings, and executive assessments. (2) Incremental analysis — takes a previous threat model report as baseline, compares the codebase at the latest (or a given commit), and produces an updated report with change tracking (new, resolved, still-present threats), STRIDE heatmap, findings diff, and an embedded HTML comparison. Only activate when the user explicitly requests a threat model analysis, incremental update, or invokes /threat-model-analyst directly.


## Relevance Score
0
