---
name: "auditing-actions"
description: "Use right after `board-superpowers:classifying-actions` returns a decision, every time a board-superpowers skill is recording what it is about to do or what it just did. For actions that proceed autom"
category: compliance
subcategory: compliance
tags: ["type:audit"]
relevance: 0
source: ""
author: ""
license: ""
---
# auditing-actions


## Description
Use right after `board-superpowers:classifying-actions` returns a decision, every time a board-superpowers skill is recording what it is about to do or what it just did. For actions that proceed automatically, apply once after the action lands. For actions that wait for architect approval, apply once when first proposing the action and again after the architect approves or declines. Apply even when the action seems too small to log — every mutating action gets a row, no exceptions. Do NOT use for read-only actions; reads are not audited. Do NOT invoke to determine the A/R/N decision — that is `board-superpowers:classifying-actions`.


## Tags
type:audit


## Relevance Score
0
