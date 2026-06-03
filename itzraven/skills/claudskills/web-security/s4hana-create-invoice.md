---
name: "s4hana-create-invoice"
description: "Create supplier (AP) invoices in SAP S/4HANA Cloud Public or on-prem private edition via the SOAP A2X 'Supplier Invoice ERP Create Request' service. Use whenever the user wants to post, create, add, g"
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: "https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-create-invoice/SKILL.md"
author: "ilia-inovaflow"
license: "MIT"
---
# s4hana-create-invoice


## Description
Create supplier (AP) invoices in SAP S/4HANA Cloud Public or on-prem private edition via the SOAP A2X "Supplier Invoice ERP Create Request" service. Use whenever the user wants to post, create, add, generate, seed, or backdate supplier/vendor/AP invoices on S/4HANA — including phrases like "make me a few invoices", "post 20 supplier invoices", "seed invoice demo data", "invoice these POs", "create supplier invoice for PO 4500...". Handles full SOAP envelope construction, CSRF-equivalent (none required for this service), tenant-ledger preflight, master-data lookup (material/qty/price from PO), partial vs full invoicing, idempotent bulk batches with per-record logging, and the FINS_ACDOC_CUST/201 ledger-config diagnosis path. Do NOT use for non-PO-based invoice creation, credit memos, or invoice cancellation — those need different envelope shapes (track them under generic skill until verified).


## Source
https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-create-invoice/SKILL.md


## Relevance Score
1
