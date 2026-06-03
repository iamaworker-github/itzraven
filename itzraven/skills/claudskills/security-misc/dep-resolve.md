---
name: "dep-resolve"
description: "Dependency-conflict resolution when a `/vulnetix:fix` version bump fails — diagnose the peer-dep tree, find a compatible safe version set, propose package-manager overrides (`overrides`/`resolutions`/"
category: security
subcategory: security-misc
tags: ["type:debug"]
relevance: 0
source: "https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/dep-resolve/SKILL.md"
author: "Vulnetix"
license: "Apache-2.0"
---
# dep-resolve


## Description
Dependency-conflict resolution when a `/vulnetix:fix` version bump fails — diagnose the peer-dep tree, find a compatible safe version set, propose package-manager overrides (`overrides`/`resolutions`/`replace`/`[patch]`), fall back to safe-harbour inline patching. Use when an upgrade is blocked by transitive constraints, a peer-dep conflict surfaces, or you need to override a vulnerable transitive without bumping the parent.


## Tags
type:debug


## Source
https://github.com/Vulnetix/pix-ai-coding-assistant/blob/HEAD/vulnetix/skills/dep-resolve/SKILL.md


## Relevance Score
0
