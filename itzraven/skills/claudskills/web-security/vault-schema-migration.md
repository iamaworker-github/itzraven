---
name: "myco:vault-schema-migration"
description: "Use this skill whenever you need to add, modify, or remove tables, columns, or indexes in the Myco vault SQLite schema — even if the user just asks to 'add a column' or 'create a new table.' The vault"
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: "https://github.com/goondocks-co/myco/blob/HEAD/.agents/skills/vault-schema-migration/SKILL.md"
author: "goondocks-co"
license: "Apache-2.0"
---
# myco:vault-schema-migration


## Description
Use this skill whenever you need to add, modify, or remove tables, columns, or indexes in the Myco vault SQLite schema — even if the user just asks to "add a column" or "create a new table." The vault uses a versioned createSchema migration chain where each schema version is a numbered step that builds on the previous one. Because user vaults accumulate real data across machines, any schema change that breaks the migration chain can corrupt or destroy vault data. This skill covers how to add a new version to the chain, write safe migration SQL, handle backfill steps, bump the schema version constant, sync D1 databases, and verify the migration works end-to-end before shipping.


## Source
https://github.com/goondocks-co/myco/blob/HEAD/.agents/skills/vault-schema-migration/SKILL.md


## Relevance Score
1
