---
name: "myco:vault-schema-extension"
description: "Use this skill when adding or evolving Myco's SQLite vault database schema and its Cloudflare D1 cloud counterpart — even if the user doesn't explicitly ask for 'schema work.' Covers: authoring versio"
category: web-security
subcategory: web-security
tags: ["cloud:cloudflare"]
relevance: 1
source: "https://github.com/goondocks-co/myco/blob/HEAD/.agents/skills/vault-schema-extension/SKILL.md"
author: "goondocks-co"
license: "Apache-2.0"
---
# myco:vault-schema-extension


## Description
Use this skill when adding or evolving Myco's SQLite vault database schema and its Cloudflare D1 cloud counterpart — even if the user doesn't explicitly ask for "schema work." Covers: authoring versioned migration scripts with correct error guards (IF NOT EXISTS, user_version bumps), evolving existing tables with ALTER TABLE in a backfill-safe sequence, creating and populating FTS5 full-text search indexes with auto-sync triggers, keeping local SQLite and D1 schemas in sync (including D1's lazy-migration behaviour where ALTER TABLE applies on the first request after deploy, not at deploy time), selecting the right query patterns (WHERE IN with json_each for dynamic ID sets, hydration joins instead of N+1 selects, cursor-based pagination instead of OFFSET), Grove multi-tenant database design for global daemon architecture, and updating the constants and query modules that complete the data layer surface. Every new Myco feature that stores data touches this domain.


## Tags
cloud:cloudflare


## Source
https://github.com/goondocks-co/myco/blob/HEAD/.agents/skills/vault-schema-extension/SKILL.md


## Relevance Score
1
