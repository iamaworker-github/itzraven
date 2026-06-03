---
name: "tam-mapping"
description: "Build TAM databases from scratch using a 7-phase methodology (Source Discovery → Keyword Expansion → Config → Collection → Dedup → Exclusion → Enrichment hand-off). Triggers 'tam map', 'build tam', 't"
category: security
subcategory: security-misc
tags: []
relevance: 1
source: "https://github.com/Revgrowth1/ai-gtm-workflows"
author: "Revgrowth1"
license: ""
---
# tam-mapping


## Description
Build TAM databases from scratch using a 7-phase methodology (Source Discovery → Keyword Expansion → Config → Collection → Dedup → Exclusion → Enrichment hand-off). Triggers "tam map", "build tam", "total addressable market", "scrape industry", "map the market", "build a lead database", "venue partnerships tam", "labs tam", "residential tam", "installer tam". Entity-routed — Nites residential (Google Maps ZIP), Supply installer (SAM.gov + Houzz + state license dbs), Labs venue partnerships (Spider.cloud + AI Ark + Discolike + IcyPeas + BlitzAPI + Prospeo + MillionVerifier). Phase 4.5 cross-workspace EB exclusion is MANDATORY (HARD-FAIL on either workspace unreachable). Phase 5 enrichment is pluggable per ADR-008. Distinct from `list-building` (BC-2717 — assumes a TAM already exists via dbt audience views).


## Source
https://github.com/Revgrowth1/ai-gtm-workflows


## Relevance Score
1
