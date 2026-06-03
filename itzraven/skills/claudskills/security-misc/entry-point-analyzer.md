---
name: "entry-point-analyzer"
description: "Analyzes smart contract codebases to identify state-changing entry points for security auditing. Detects externally callable functions that modify state, categorizes them by access level (public, admi"
category: security
subcategory: security-misc
tags: ["type:audit"]
relevance: 0
source: ""
author: ""
license: ""
---
# entry-point-analyzer


## Description
Analyzes smart contract codebases to identify state-changing entry points for security auditing. Detects externally callable functions that modify state, categorizes them by access level (public, admin, role-restricted, contract-only), and generates structured audit reports. Excludes view/pure/read-only functions. Use when auditing smart contracts (Solidity, Vyper, Solana/Rust, Move, TON, CosmWasm) or when asked to find entry points, audit flows, external functions, access control patterns, or privileged operations.


## Tags
type:audit


## Relevance Score
0
