---
name: "txt-bidi"
description: "Handle bidirectional text, right-to-left languages, mixed Arabic/Hebrew/Latin content, writing-direction APIs at every layer, and cursor/selection behavior in bidi text. Covers NSParagraphStyle.baseWr"
category: threat-hunting
subcategory: threat-hunting
tags: ["lang:swift"]
relevance: 0
source: ""
author: ""
license: "MIT"
---
# txt-bidi


## Description
Handle bidirectional text, right-to-left languages, mixed Arabic/Hebrew/Latin content, writing-direction APIs at every layer, and cursor/selection behavior in bidi text. Covers NSParagraphStyle.baseWritingDirection, the .writingDirection attributed-string key with embedding/override modes, AttributedString.writingDirection, UITextInput.setBaseWritingDirection, SwiftUI .environment(\.layoutDirection), iOS 26 Natural Selection (selectedRanges), Unicode bidi controls (LRM/RLM/LRE/RLE/PDF/FSI/PDI), .natural vs .left/.right alignment, and visual vs logical order. Use when adding RTL support, debugging cursor jumps in mixed content, fixing phone numbers that reorder in Arabic context, migrating to selectedRanges, or making a custom UITextInput view bidi-correct. Trigger on Arabic, Hebrew, RTL, or "cursor moves wrong" even without bidi APIs named. Do NOT use for general localization or locale-aware formatting (out of scope for this repo).


## Tags
lang:swift


## Relevance Score
0
