---
name: "txt-colors"
description: "Pick text colors that adapt to dark mode, vibrancy, and accessibility settings across UIKit, AppKit, and SwiftUI — semantic label colors, AppKit's textColor vs labelColor split, dark-mode adaptation r"
category: threat-hunting
subcategory: threat-hunting
tags: ["lang:swift"]
relevance: 0
source: ""
author: ""
license: "MIT"
---
# txt-colors


## Description
Pick text colors that adapt to dark mode, vibrancy, and accessibility settings across UIKit, AppKit, and SwiftUI — semantic label colors, AppKit's textColor vs labelColor split, dark-mode adaptation rules, wide-color (Display P3), HDR/EDR limits for text. Use when text disappears in dark mode, an attributed string defaults to invisible black, an NSTextView body looks dim, you're picking between systemRed and a P3 red, or designing for high-contrast accessibility. Read the actual color initializers and trait responses before reciting fixes — the patterns here describe how color adaptation usually fails, not where the bug is in your code.


## Tags
lang:swift


## Relevance Score
0
