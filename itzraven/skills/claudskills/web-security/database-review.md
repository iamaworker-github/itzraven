---
name: "database-review"
description: "Review database schema design, query patterns, and data access layer for correctness and performance. Checks normalization balance, index coverage against actual queries, constraint completeness (NOT "
category: web-security
subcategory: web-security
tags: ["cloud:gcp", "type:review"]
relevance: 1
source: ""
author: ""
license: ""
---
# database-review


## Description
Review database schema design, query patterns, and data access layer for correctness and performance. Checks normalization balance, index coverage against actual queries, constraint completeness (NOT NULL, FK, unique, check, defaults), data type correctness (money as DECIMAL not FLOAT, timestamps with timezone), N+1 query detection, connection pooling configuration, transaction safety, and migration hygiene. Supports PostgreSQL, MySQL, SQLite, MongoDB, Firestore, DynamoDB, and all major ORMs. Use when you need to review a database schema, find missing indexes, detect N+1 queries, audit data types, check constraint coverage, optimize query patterns, or assess database scaling readiness.


## Tags
cloud:gcp, type:review


## Relevance Score
1
