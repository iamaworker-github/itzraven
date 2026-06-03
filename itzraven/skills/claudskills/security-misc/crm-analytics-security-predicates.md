---
name: "crm-analytics-security-predicates"
description: "Row-level security in CRM Analytics datasets via security predicates — SAQL filter expressions stored on the dataset that apply at query time per running user. Covers the syntax (`'DatasetColumn' oper"
category: security
subcategory: security-misc
tags: ["tool:salesforce"]
relevance: 1
source: ""
author: "Pranav Nagrecha"
license: ""
---
# crm-analytics-security-predicates


## Description
Row-level security in CRM Analytics datasets via security predicates — SAQL filter expressions stored on the dataset that apply at query time per running user. Covers the syntax (`'DatasetColumn' operator value`), the `$User.*` context variables, multi-level predicates (role hierarchy + team + region), the performance cost of complex predicates, and the testing discipline (admins bypass predicates by default). NOT for Salesforce Core sharing rules (different runtime), NOT for App / Dashboard / Lens-level access (that's CRM Analytics App sharing, not predicates), NOT for field-level masking inside a dataset (use Encryption + dataset transformations).


## Tags
tool:salesforce


## Relevance Score
1
