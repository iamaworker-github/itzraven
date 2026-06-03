---
name: "apex-stripinaccessible-and-fls-enforcement"
description: "Use Security.stripInaccessible to enforce CRUD/FLS on user-supplied records before DML, and to scrub query results before returning them to clients. Covers AccessType.READABLE/CREATABLE/UPDATABLE/UPSE"
category: security
subcategory: security-misc
tags: ["type:integration"]
relevance: 1
source: ""
author: "Pranav Nagrecha"
license: ""
---
# apex-stripinaccessible-and-fls-enforcement


## Description
Use Security.stripInaccessible to enforce CRUD/FLS on user-supplied records before DML, and to scrub query results before returning them to clients. Covers AccessType.READABLE/CREATABLE/UPDATABLE/UPSERTABLE, the SObjectAccessDecision API, when to prefer WITH USER_MODE on the SOQL itself, and integration with the SecurityUtils template. NOT for class-level sharing keyword choice (with sharing / without sharing / inherited sharing — see apex-sharing-keywords). NOT for managed sharing or Apex managed sharing recalculations (see sharing-selection decision tree).


## Tags
type:integration


## Relevance Score
1
