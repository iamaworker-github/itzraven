---
name: "apm-review-panel"
description: "Use this skill to run a multi-persona expert advisory review on a labelled pull request in microsoft/apm. The panel fans out to five mandatory specialists plus a test-coverage specialist (active on ev"
category: security
subcategory: security-misc
tags: ["type:review"]
relevance: 0
source: ""
author: ""
license: ""
---
# apm-review-panel


## Description
Use this skill to run a multi-persona expert advisory review on a labelled pull request in microsoft/apm. The panel fans out to five mandatory specialists plus a test-coverage specialist (active on every PR that touches src/) plus two conditional specialists (auth, doc-writer), all running in their own agent threads, and a CEO synthesizer. The orchestrator is the sole writer to the PR: ONE recommendation comment, no verdict labels, no merge gating. The panel is advisory -- it surfaces findings, prioritizes follow-ups, and renders a ship-recommendation that the maintainer and author weigh. Activate when a non-trivial PR needs a cross-cutting recommendation (architecture, CLI logging, DevX UX, supply-chain security, growth/positioning, optionally auth, docs, and test coverage, with CEO arbitration).


## Tags
type:review


## Relevance Score
0
