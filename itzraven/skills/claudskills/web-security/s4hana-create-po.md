---
name: "s4hana-create-po"
description: "Create purchase orders (POs) in SAP S/4HANA Cloud Public or on-prem private edition via the OData V2 A_PurchaseOrder deep-insert at API_PURCHASEORDER_PROCESS_SRV. Use whenever the user wants to post, "
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: "https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-create-po/SKILL.md"
author: "ilia-inovaflow"
license: "MIT"
---
# s4hana-create-po


## Description
Create purchase orders (POs) in SAP S/4HANA Cloud Public or on-prem private edition via the OData V2 A_PurchaseOrder deep-insert at API_PURCHASEORDER_PROCESS_SRV. Use whenever the user wants to post, create, add, generate, seed, clone, or backdate purchase orders on S/4HANA — phrases like "make me a few POs", "post 20 POs", "seed PO demo data", "create PO for supplier X material Y", "clone these on-prem POs to cloud". Handles header+item deep-insert, CSRF token flow, master-data resolution (supplier/material/plant/currency from PO ItemCategory 0), idempotent bulk batches, and known field constraints (UoM='PC', no D/9 service item categories, no account-assignment deep-insert). Do NOT use for service-based POs (item category D/9), framework agreements, scheduling agreements, or PO updates — those need different shapes (track under generic skill until verified).


## Source
https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-create-po/SKILL.md


## Relevance Score
1
