---
name: "txt-audit"
description: "Review Apple text code for correctness, performance, and modernization risk in a single pass with severity-ranked findings. Covers TextKit 1 fallback triggers, NSTextStorage subclass correctness (edit"
category: threat-hunting
subcategory: threat-hunting
tags: ["type:audit", "type:review"]
relevance: 0
source: ""
author: ""
license: "MIT"
---
# txt-audit


## Description
Review Apple text code for correctness, performance, and modernization risk in a single pass with severity-ranked findings. Covers TextKit 1 fallback triggers, NSTextStorage subclass correctness (edited / changeInLength / batched edits), didProcessEditing character-mutation bugs, deprecated glyph APIs, full-document ensureLayout, missing allowsNonContiguousLayout, NSLinguisticTagger / UIMenuController deprecations, missing performEditingTransaction wrappers on TextKit 2, Writing Tools coordinator gaps (writingToolsIgnoredRangesIn, isWritingToolsActive), String-vs-NSString length confusion in range arithmetic, and main-thread storage rules. Use when a user asks to audit, scan, or review a text editor codebase, when preparing an editor for shipping, when triaging a post-release regression in TextKit code, or when a pull request needs a structured pass focused on text-specific risks.


## Tags
type:audit, type:review


## Relevance Score
0
