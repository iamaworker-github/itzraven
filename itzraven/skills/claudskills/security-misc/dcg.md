---
name: "dcg"
description: "Destructive Command Guard. Installs a pre-tool-use hook that blocks unrecoverable shell commands (rm -rf /, git reset --hard, git clean -fd, rm of .env / credentials, force-pushing to main, fork bombs"
category: security
subcategory: security-misc
tags: []
relevance: 1
source: "https://github.com/momentmaker/kaijutsu/blob/HEAD/skills/community/dcg/SKILL.md"
author: "momentmaker"
license: "MIT"
---
# dcg


## Description
Destructive Command Guard. Installs a pre-tool-use hook that blocks unrecoverable shell commands (rm -rf /, git reset --hard, git clean -fd, rm of .env / credentials, force-pushing to main, fork bombs, shred / dd, etc.) before the agent executes them. Use when the user says "install dcg", "destructive command guard", "guard rails for destructive commands", or invokes /dcg.


## Source
https://github.com/momentmaker/kaijutsu/blob/HEAD/skills/community/dcg/SKILL.md


## Relevance Score
1
