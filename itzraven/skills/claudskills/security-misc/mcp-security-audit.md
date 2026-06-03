---
name: "mcp-security-audit"
description: "Audit MCP (Model Context Protocol) server configurations for security issues. Use this skill when: - Reviewing .mcp.json files for security risks - Checking MCP server args for hardcoded secrets or sh"
category: security
subcategory: security-misc
tags: ["ai:mcp", "type:audit", "type:review"]
relevance: 1
source: "https://github.com/microsoft/agent-governance-toolkit"
author: "microsoft"
license: ""
---
# mcp-security-audit


## Description
Audit MCP (Model Context Protocol) server configurations for security issues. Use this skill when: - Reviewing .mcp.json files for security risks - Checking MCP server args for hardcoded secrets or shell injection patterns - Validating that MCP servers use pinned versions (not @latest) - Detecting unpinned dependencies in MCP server configurations - Auditing which MCP servers a project registers and whether they're on an approved list - Checking for environment variable usage vs. hardcoded credentials in MCP configs - Any request like "is my MCP config secure?", "audit my MCP servers", or "check .mcp.json" keywords: [mcp, security, audit, secrets, shell-injection, supply-chain, governance]


## Tags
ai:mcp, type:audit, type:review


## Source
https://github.com/microsoft/agent-governance-toolkit


## Relevance Score
1
