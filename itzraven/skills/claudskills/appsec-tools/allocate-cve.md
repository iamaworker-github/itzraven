---
name: "allocate-cve"
description: "Walk a security team member through allocating a CVE for an <tracker> tracking issue. Prints the ASF Vulnogram allocation URL and a CVE-ready title (the issue title stripped of redundant `<vendor>: <p"
category: appsec
subcategory: appsec-tools
tags: []
relevance: 1
source: "https://github.com/apache/airflow-steward/blob/f591c158f25e0ae5a07aaea9ab024ce5d40bc5ba/.claude/skills/write-skill/SKILL.md"
author: "apache"
license: "Apache-2.0"
---
# allocate-cve


## Description
Walk a security team member through allocating a CVE for an <tracker> tracking issue. Prints the ASF Vulnogram allocation URL and a CVE-ready title (the issue title stripped of redundant `<vendor>: <product>:` (e.g. `Apache Airflow:`), `[ Security Report ]`, trailing version parens and similar noise), waits for the allocated CVE ID (allocation is PMC-gated — non-PMC triagers relay to a PMC member), and then updates the tracker in place: fills in the *CVE tool link* field, adds the `cve allocated` label, posts a collapsed status-change comment, and runs `generate-cve-json --attach` to embed the paste-ready JSON in the body. Finishes by handing off to the `sync-security-issue` skill to reconcile the rest of the tracker (milestone, assignee, reporter drafts, fix-PR state) now that the CVE landing is complete.


## Source
https://github.com/apache/airflow-steward/blob/f591c158f25e0ae5a07aaea9ab024ce5d40bc5ba/.claude/skills/write-skill/SKILL.md


## Relevance Score
1
