---
name: "txt-writing-tools"
description: "Integrate Writing Tools into UITextView, NSTextView, custom UITextInput views, or fully custom editors via UIWritingToolsCoordinator. Configure writingToolsBehavior and allowedWritingToolsResultOption"
category: threat-hunting
subcategory: threat-hunting
tags: []
relevance: 0
source: ""
author: ""
license: "MIT"
---
# txt-writing-tools


## Description
Integrate Writing Tools into UITextView, NSTextView, custom UITextInput views, or fully custom editors via UIWritingToolsCoordinator. Configure writingToolsBehavior and allowedWritingToolsResultOptions, declare protected ranges via writingToolsIgnoredRangesInEnclosingRange, gate edits with isWritingToolsActive, and pause syncing in willBegin/didEnd. Trigger on 'Apple Intelligence rewrite', 'AI summarize selection', 'compose with AI', 'why won't Writing Tools appear', or 'rewrite is breaking my code blocks' even without UIWritingToolsCoordinator named. Use when Writing Tools is missing from the menu, only the panel mode appears, rewrites corrupt code blocks, the inline animation isn't running, or a custom text engine needs to adopt UIWritingToolsCoordinator. Do NOT use for diagnosing general TextKit 1 fallback symptoms — see txt-fallback-triggers.


## Relevance Score
0
