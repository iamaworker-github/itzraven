---
name: "sdd-idea"
description: "Planning-only skill for SDD projects. SDD builds **web apps** on Django + htmx + SQLite + Pico.css in Docker — one stack, the only one. Turns a rough idea into PROJECT.md (spec + phased plan) plus a p"
category: web-security
subcategory: web-security
tags: ["lang:python", "tool:docker"]
relevance: 1
source: ""
author: ""
license: ""
---
# sdd-idea


## Description
Planning-only skill for SDD projects. SDD builds **web apps** on Django + htmx + SQLite + Pico.css in Docker — one stack, the only one. Turns a rough idea into PROJECT.md (spec + phased plan) plus a project-local tech-stack.md recipe. **Only runs when the user explicitly invokes `/sdd-idea`** (with or without accompanying text, e.g. `/sdd-idea` or `/sdd-idea хочу сделать трекер книг`). Do NOT auto-invoke on natural-language hints like "I have an idea", "let's plan an app", "new project", "хочу сделать приложение", "давай спроектируем", etc. — those phrases alone are not enough; wait for the explicit slash command. Do NOT write code, do NOT touch the host environment — outputs are PROJECT.md and tech-stack.md (plus versioned PROJECT.v<N>.md backups on rewrite). Hands off to /sdd-impl for actual building.


## Tags
lang:python, tool:docker


## Relevance Score
1
