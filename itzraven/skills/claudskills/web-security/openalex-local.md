---
name: "openalex-local"
description: "Offline, zero-API-key search over the full OpenAlex academic corpus — 284M+ works, abstracts, authors, DOIs in a local SQLite + FTS5 index. Public API — search (full-text), get / get_many (by OpenAlex"
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# openalex-local


## Description
Offline, zero-API-key search over the full OpenAlex academic corpus — 284M+ works, abstracts, authors, DOIs in a local SQLite + FTS5 index. Public API — search (full-text), get / get_many (by OpenAlex ID or DOI), exists, count, info, enrich_ids (batch metadata upgrade), configure / get_mode (local vs remote), save (export to JSON/BibTeX/text), plus `jobs`, `aio` (async), and `cache` submodules. Drop-in replacement for `pyalex.Works().search(...)`, the OpenAlex HTTP API (`https://api.openalex.org/works?search=...`), `requests.get` on DOI resolvers, and `bibtexparser` fetch helpers — but works offline, has no rate limits, and returns in milliseconds instead of seconds. Use whenever the user asks to "search papers", "find literature on X", "look up a DOI", "get metadata for this paper", "enrich these OpenAlex IDs", "batch-resolve DOIs to BibTeX", "search by title/abstract/author", "export citations as .bib", or mentions OpenAlex, FTS5 search on papers, local academic database, or wants to avoid hitting the OpenAlex HTTP API.


## Relevance Score
1
