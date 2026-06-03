---
name: "flare-security"
description: "Security-first checklist for Flare-family contract design, deployment, and audit. Covers both (1) GENERIC EVM security patterns the user must apply by default — Ownable2Step over Ownable, ReentrancyGu"
category: identity-access
subcategory: identity-access
tags: ["type:audit"]
relevance: 0
source: "https://github.com/Thanasimos/Thanas-flare-builders-toolkit/blob/HEAD/flare-security/SKILL.md"
author: "Thanasimos"
license: "MIT"
---
# flare-security


## Description
Security-first checklist for Flare-family contract design, deployment, and audit. Covers both (1) GENERIC EVM security patterns the user must apply by default — Ownable2Step over Ownable, ReentrancyGuardTransient, SafeERC20, CEI, custom errors, no tx.origin, bounded loops, pull-over-push, immutable for constructor values — and (2) FLARE-SPECIFIC overlays that the generic audit skills don't catch: Permit2 chain availability, fee-on-transfer detection, blacklistable stablecoin surface, FTSO redistributor proxy upgradeability, basefee floors on testnets, public RPC log-range caps, EIP-3855 PUSH0 status. Use whenever you're designing or reviewing a contract that will live on Flare/Songbird/Coston2, before EVERY mainnet deploy, and as the gate for the `audit` and `audit-contract` skills' scope. Trigger on: "security review", "audit checklist", "is this safe for Flare", "ownership", "reentrancy", "Permit2 on Songbird", "blacklistable token", "FoT detection", "should I use OZ or transient guard".


## Tags
type:audit


## Source
https://github.com/Thanasimos/Thanas-flare-builders-toolkit/blob/HEAD/flare-security/SKILL.md


## Relevance Score
0
