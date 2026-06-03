---
name: "bulk-api-2-patterns"
description: "Use when designing or hardening external-to-Salesforce integrations that orchestrate Bulk API 2.0 ingest or query jobs: OAuth-backed job lifecycle, mandatory UploadComplete, polling JobComplete/Failed"
category: identity-access
subcategory: identity-access
tags: ["tool:salesforce", "type:integration"]
relevance: 2
source: ""
author: "Pranav Nagrecha"
license: ""
---
# bulk-api-2-patterns


## Description
Use when designing or hardening external-to-Salesforce integrations that orchestrate Bulk API 2.0 ingest or query jobs: OAuth-backed job lifecycle, mandatory UploadComplete, polling JobComplete/Failed, CSV upload sizing, locator pagination for query results, partial-failure retry, and ordered multi-job loads (parent before child). Trigger keywords: bulk ingest job stuck in Open, retry only failed bulk rows, poll Bulk API 2 job status, Sforce-Locator pagination, multipart bulk ingest vs CSV upload. NOT for Bulk API 1.0 SOAP jobs (use data/bulk-api-patterns v1 sections), NOT for choosing batch vs real-time architecture alone (use integration/real-time-vs-batch-integration), NOT for low-level REST field/csv mechanics without integration context (use data/bulk-api-patterns).


## Tags
tool:salesforce, type:integration


## Relevance Score
2
