---
name: "reviewing-changes"
description: "Run a layered quality gate over a code change — code quality, security audit, and architecture consistency, in that order. Use after writing or modifying code, before opening or merging a PR, when rev"
category: web-security
subcategory: web-security
tags: ["lang:go", "type:audit", "type:review"]
relevance: 1
source: ""
author: ""
license: ""
---
# reviewing-changes


## Description
Run a layered quality gate over a code change — code quality, security audit, and architecture consistency, in that order. Use after writing or modifying code, before opening or merging a PR, when reviewing a diff or branch, or when asked for a code review, security audit, or architecture review. Produces severity-ranked findings (Critical / Major / Minor) tied to file:line, each with a concrete fix. Covers OWASP Top 10, SOLID, KISS / YAGNI / DRY, ruff + mypy for Python, golangci-lint for Go, solhint for Solidity, and common perf pitfalls (N+1, unbounded loops, leaks, missing indexes). For diffs over ~500 lines or 20 files, scopes the linter sweep to touched packages first and widens on demand. Read-only: never edits the diff, never runs unscoped Bash — every tool is a fixed command pattern (Bash(git diff *), Bash(uv run ruff *), Bash(golangci-lint *)). Composes with python-conventions, go-conventions, solidity-conventions, engineering-philosophy.


## Tags
lang:go, type:audit, type:review


## Relevance Score
1
