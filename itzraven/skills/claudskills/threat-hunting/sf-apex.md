---
name: "sf-apex"
description: "Generates and reviews Salesforce Apex code (Brite edition) with 150-point scoring. TRIGGER when user writes, reviews, or fixes Apex classes, triggers, test classes, batch/queueable/schedulable jobs, t"
category: threat-hunting
subcategory: threat-hunting
tags: ["tool:salesforce", "type:review", "type:integration"]
relevance: 1
source: ""
author: ""
license: "MIT"
---
# sf-apex


## Description
Generates and reviews Salesforce Apex code (Brite edition) with 150-point scoring. TRIGGER when user writes, reviews, or fixes Apex classes, triggers, test classes, batch/queueable/schedulable jobs, touches .cls/.trigger files, works in brite-salesforce, asks about LeadTriggerHandler / LeadAfterInsertService dispatch, Queueable BATCH_SIZE=90 self-chaining, @TestVisible + Test.isRunningTest() escape hatches, Bypass_Validation_Rules pattern, DisqualifiedRecycleScheduler, or Apex-first automation decisions. DO NOT TRIGGER when LWC JavaScript (use sf-lwc), Flow XML (use sf-flow), SOQL-only queries (use sf-soql), permission metadata (use sf-permissions), or non-Salesforce code.


## Tags
tool:salesforce, type:review, type:integration


## Relevance Score
1
