---
name: "apex-dynamic-soql-binding-safety"
description: "Safe construction of dynamic SOQL — Database.query bind variables (:varName, API 60+ semantics), Database.queryWithBinds(query, Map<String,Object>, AccessLevel) (API 55+), field-name allowlisting, ORD"
category: security
subcategory: security-misc
tags: []
relevance: 1
source: ""
author: "Pranav Nagrecha"
license: ""
---
# apex-dynamic-soql-binding-safety


## Description
Safe construction of dynamic SOQL — Database.query bind variables (:varName, API 60+ semantics), Database.queryWithBinds(query, Map<String,Object>, AccessLevel) (API 55+), field-name allowlisting, ORDER BY direction whitelist, LIMIT/OFFSET typing, and the interaction with WITH USER_MODE / WITH SECURITY_ENFORCED. NOT for static SOQL — see apex-soql-fundamentals. NOT for FLS enforcement on results — see soql-security or apex-stripinaccessible-and-fls-enforcement.


## Relevance Score
1
