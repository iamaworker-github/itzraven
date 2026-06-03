---
name: "s4hana-create-goods-receipt"
description: "Create Goods Receipts (Material Documents) in SAP S/4HANA Cloud Public or on-prem private edition via OData V2 A_MaterialDocumentHeader deep-insert at API_MATERIAL_DOCUMENT_SRV. Use whenever the user "
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: "https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-create-goods-receipt/SKILL.md"
author: "ilia-inovaflow"
license: "MIT"
---
# s4hana-create-goods-receipt


## Description
Create Goods Receipts (Material Documents) in SAP S/4HANA Cloud Public or on-prem private edition via OData V2 A_MaterialDocumentHeader deep-insert at API_MATERIAL_DOCUMENT_SRV. Use whenever the user wants to create, post, add, generate, seed, receive, or confirm receipt of goods on S/4HANA — phrases like "post a goods receipt", "receive goods for PO X", "create GR for these POs", "seed GR demo data", "post GRs", "complete the 3-way match", "post material document". Handles full header + item deep-insert, CSRF flow, partial vs full receipt, idempotent bulk batches with per-record logging, and the GoodsMovementRefDocType=B requirement for PO-based receipts. Do NOT use for goods issues (movement types 201/261/etc.), stock transfers (movement types 311/411/etc.), or inventory counts (use Physical Inventory API).


## Source
https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-create-goods-receipt/SKILL.md


## Relevance Score
1
