---
name: "s4hana-update-record"
description: "Update existing records in SAP S/4HANA Cloud Public or on-prem private edition via OData V2 PATCH. Use whenever the user wants to update, change, edit, modify, patch, set, rename, adjust, or correct a"
category: web-security
subcategory: web-security
tags: []
relevance: 1
source: "https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-update-record/SKILL.md"
author: "ilia-inovaflow"
license: "MIT"
---
# s4hana-update-record


## Description
Update existing records in SAP S/4HANA Cloud Public or on-prem private edition via OData V2 PATCH. Use whenever the user wants to update, change, edit, modify, patch, set, rename, adjust, or correct any existing record on S/4HANA — purchase orders (dates, payment terms, item text/qty/price), business partners (name, address, payment terms, recon account), product descriptions (Toblerone-style overrides), service entry sheets (name, qty before approval), purchasing info records, supplier purchasing-org assignments, etc. Triggers on phrases like "update PO X", "change supplier address", "rename product", "backdate PO 4500...", "adjust PIR price for supplier Y", "set new payment terms for X". Handles GET-before-PATCH (to show current state), composite key resolution, CSRF flow, the "204 looks-like-success-but-no-change" trap (verifies via GET-after-PATCH), write-once field detection, and entity-disabled checks. Do NOT use for CREATE operations (use the s4hana-create-* skills), DELETE (most entities don't support DELETE on Cloud Public — block + rename instead), or for entities where update is entirely disabled (Supplier Invoice and Material Document — those return 405 CX_SADL_ENTITY_CUD_DISABLED and need cancel-recreate workflows).


## Source
https://github.com/ilia-inovaflow/s4hana-create-record-skills/blob/HEAD/skills/s4hana-update-record/SKILL.md


## Relevance Score
1
