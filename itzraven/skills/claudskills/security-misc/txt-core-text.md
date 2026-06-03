---
name: "txt-core-text"
description: "Use Core Text directly — CTLine, CTRun, CTFramesetter, CTTypesetter, CTFont, CTRunDelegate — for glyph-level access, custom typesetting, hit testing outside a text container, font tables, or per-glyph"
category: security
subcategory: security-misc
tags: []
relevance: 0
source: ""
author: ""
license: "MIT"
---
# txt-core-text


## Description
Use Core Text directly — CTLine, CTRun, CTFramesetter, CTTypesetter, CTFont, CTRunDelegate — for glyph-level access, custom typesetting, hit testing outside a text container, font tables, or per-glyph Core Graphics rendering. Use when you need glyph IDs and positions, custom line breaking, drawing text into a CGContext, OpenType feature inspection, or inline non-text elements with custom metrics. Read the actual rendering pipeline (especially the coordinate flip) before reciting fixes — most Core Text bugs are inverted axes or attribute-key type mismatches. Do NOT use when TextKit 2 already exposes the APIs you need — see txt-textkit2.


## Relevance Score
0
