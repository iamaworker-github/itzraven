---
name: "field-level-security-in-async-contexts"
description: "Use when async Apex (Queueable, Batch, Schedulable, @future) needs to honor the originating user's field-level security but the framework runs the job in a different security context than the user who"
category: security
subcategory: security-misc
tags: []
relevance: 1
source: ""
author: "Pranav Nagrecha"
license: ""
---
# field-level-security-in-async-contexts


## Description
Use when async Apex (Queueable, Batch, Schedulable, @future) needs to honor the originating user's field-level security but the framework runs the job in a different security context than the user who initiated it. Triggers: 'fls bypassed in batch apex', 'queueable runs as wrong user', 'stripInaccessible in async returns full record', 'WITH USER_MODE evaluating against system user', 'scheduled apex sees fields the original user could not'. NOT for synchronous FLS enforcement (use apex-stripinaccessible-and-fls-enforcement) or for the with/without sharing decision (use apex-with-without-sharing-decision).


## Relevance Score
1
