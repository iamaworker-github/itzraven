---
name: "br-owned-resource-guards"
description: "Add better-route 0.5.0 ownership checks for user-owned REST resources. Use when a route or Resource DSL endpoint must ensure the authenticated user owns the order, record, token, subscription, members"
category: threat-hunting
subcategory: threat-hunting
tags: []
relevance: 1
source: ""
author: ""
license: ""
---
# br-owned-resource-guards


## Description
Add better-route 0.5.0 ownership checks for user-owned REST resources. Use when a route or Resource DSL endpoint must ensure the authenticated user owns the order, record, token, subscription, membership, profile object, or other per-user object. Triggers on OwnershipGuardMiddleware, OwnedResourcePolicy, currentUserOwns, ownerResolver, bypassCapability, and customer-owned or user-owned API routes.


## Relevance Score
1
