---
name: "txt-measurement"
description: "Measure rendered size of strings and attributed strings, size views to fit text content, and read per-line metrics from NSLayoutManager and NSTextLayoutManager. Covers boundingRect with NSStringDrawin"
category: threat-hunting
subcategory: threat-hunting
tags: []
relevance: 0
source: ""
author: ""
license: "MIT"
---
# txt-measurement


## Description
Measure rendered size of strings and attributed strings, size views to fit text content, and read per-line metrics from NSLayoutManager and NSTextLayoutManager. Covers boundingRect with NSStringDrawingOptions, NSStringDrawingContext for auto-shrink, sizeThatFits, intrinsicContentSize, usedRect, enumerateLineFragments, usageBoundsForTextContainer, line-fragment typographic bounds, and the lineFragmentPadding/textContainerInset arithmetic that makes measurements match what UITextView actually renders. Use when text clips by a pixel, boundingRect returns a single-line size for multi-line text, a self-sizing UITextView refuses to size, intrinsicContentSize is wrong, or the user needs line counts. Do NOT use for paragraph style, hyphenation, or line height — see txt-line-breaking. Do NOT use for layout invalidation timing — see txt-layout-invalidation.


## Relevance Score
0
