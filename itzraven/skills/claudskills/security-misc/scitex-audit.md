---
name: "scitex-audit"
description: "Unified repo security scanner for scientific Python projects — one call orchestrates `bandit` (Python AST security linter), `shellcheck` (shell-script linter), `pip-audit` (Python dependency CVE scann"
category: security
subcategory: security-misc
tags: ["lang:python", "type:audit", "type:scanner"]
relevance: 2
source: ""
author: ""
license: ""
---
# scitex-audit


## Description
Unified repo security scanner for scientific Python projects — one call orchestrates `bandit` (Python AST security linter), `shellcheck` (shell-script linter), `pip-audit` (Python dependency CVE scanner), and GitHub Security Advisory alerts, merging their findings into a single JSON report. Public API (1 symbol) — `audit(path: str = ".", checks: Optional[list[str]] = None, output_file: Optional[str] = None) -> dict` (`checks` picks a subset of backends; with `None` runs all available; returns `{checker: [findings]}`; optionally writes JSON to `output_file`). CLI entry — `scitex audit [path] [--checks bandit,shellcheck,pip-audit,github] [--output report.json]` (via parent `scitex` CLI). No MCP tools. Drop-in replacement for manually running `bandit -r .` + `shellcheck **/*.sh` + `pip-audit` + `gh api /repos/.../vulnerability-alerts` and stitching together four output formats, or configuring each tool separately in CI. Use whenever the user asks to "audit this repo for security issues", "run bandit on this project", "check Python deps for CVEs with pip-audit", "lint shell scripts with shellcheck", "merge security scan results into one report", "pull GitHub security advisories", or mentions `scitex audit`, `scitex.audit`, unified security scan.


## Tags
lang:python, type:audit, type:scanner


## Relevance Score
2
