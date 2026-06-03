---
name: "scanning-database-security"
description: "This skill enables Claude to perform comprehensive database security scans using the database-security-scanner plugin. It is triggered when the user requests a security assessment of a database, inclu"
category: red-team
subcategory: red-team
tags: ["type:scanner"]
relevance: 2
source: "https://github.com/jeremylongshore/claude-code-plugins-plus-skills/blob/HEAD/backups/skill-structure-cleanup-20251108-073936/plugins/database/database-security-scanner/skills/database-security-scanner/SKILL.md"
author: "jeremylongshore"
license: "MIT"
---
# scanning-database-security


## Description
This skill enables Claude to perform comprehensive database security scans using the database-security-scanner plugin. It is triggered when the user requests a security assessment of a database, including identifying vulnerabilities like weak passwords, SQL injection risks, and insecure configurations. The skill leverages OWASP guidelines to ensure thorough coverage and provides remediation suggestions. Use this skill when the user asks to "scan database security", "check database for vulnerabilities", "perform OWASP compliance check on database", or "assess database security posture". The plugin supports PostgreSQL and MySQL.


## Tags
type:scanner


## Source
https://github.com/jeremylongshore/claude-code-plugins-plus-skills/blob/HEAD/backups/skill-structure-cleanup-20251108-073936/plugins/database/database-security-scanner/skills/database-security-scanner/SKILL.md


## Relevance Score
2
