---
name: "classifying-actions"
description: "Use when a board-superpowers SKILL is about to perform a mutating action — changing card status, editing card body, pushing a claim branch, opening or merging a PR, writing project config, writing hos"
category: compliance
subcategory: compliance
tags: ["type:review"]
relevance: 1
source: ""
author: ""
license: ""
---
# classifying-actions


## Description
Use when a board-superpowers SKILL is about to perform a mutating action — changing card status, editing card body, pushing a claim branch, opening or merging a PR, writing project config, writing host-local credentials, deleting a worktree, deleting a branch — and needs to know whether the action proceeds automatically or waits for architect approval. Apply at every mutating-action decision point inside any board-superpowers skill (briefing-daily / intaking-requirement / reviewing-pr-queue / triaging-board / consuming-card / bootstrapping-repo). Apply even when the action looks obviously safe; the decision table is the source of truth, not intuition. Do NOT use for read-only actions or for queries that surface information without changing state. Do NOT invoke for the audit-row write step that follows the decision — that is `board-superpowers:auditing-actions`.


## Tags
type:review


## Relevance Score
1
