---
name: "audit-contract"
description: "Adversarial smart contract security audit. Auto-selects 5-7 specialist agents based on contract features (from a roster of 12). Attacks from every relevant angle: SWC registry, signatures, reentrancy,"
category: identity-access
subcategory: identity-access
tags: ["type:audit", "type:integration"]
relevance: 1
source: "https://github.com/Thanasimos/Thanas-flare-builders-toolkit/blob/HEAD/audit-contract/SKILL.md"
author: "Thanasimos"
license: "MIT"
---
# audit-contract


## Description
Adversarial smart contract security audit. Auto-selects 5-7 specialist agents based on contract features (from a roster of 12). Attacks from every relevant angle: SWC registry, signatures, reentrancy, state machine, ERC20 edge cases, economic exploits, game theory, L2-specific, flash loans, DoS/griefing, privacy, backend integration, external boundary verification (live ABI / selector / hash checks against canonical references). Runs Slither if available. Writes Foundry PoC tests for critical findings. Produces a ranked finding list with severity and code fixes. Triggers on: "audit this contract", "security review", "attack this contract", "find vulnerabilities".


## Tags
type:audit, type:integration


## Source
https://github.com/Thanasimos/Thanas-flare-builders-toolkit/blob/HEAD/audit-contract/SKILL.md


## Relevance Score
1
