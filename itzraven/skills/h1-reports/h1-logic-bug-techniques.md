---
name: "h1-logic-bug-techniques"
description: "Business Logic Error patterns from HackerOne reports — negative prices, rating manipulation, privilege escalation via backup, domain regex bypass, folder rename race"
category: web-security
tags: ["logic-bug", "business-logic", "price-manipulation", "privilege-escalation", "hackerone"]
relevance: 10
---

# H1 Business Logic Vulnerability Techniques

Real-world logic bugs with $100-$15000 bounties:

## 1. Price Manipulation
Report: SEMrush negative values for free goods ($2111)
- Test: Negative numbers in price/quantity fields
- Payload: `{"price": -100, "quantity": -1}`
- Look for: Negative totals, free items, balance increase

## 2. Rating/Score Manipulation
Report: Uber drivers altering their ratings ($1500)
- Test: Self-rating endpoints
- Look for: Missing validation that user can rate themselves

## 3. Privilege Escalation via Backup/Restore
Report: Ubiquiti backup restore privilege escalation ($1500)
- Test: Backup/restore functionality
- Look for: Restoring a backup from admin account onto user device

## 4. Domain Regex Bypass
Report: Google domain authority regex logic bug ($6000)
- Test: Register domains that bypass regex validation
- Example: `google.com.evil.com`, `google.com\.evil.com`
- Look for: Regex that doesn't anchor at end

## 5. Race Condition — Folder Rename
Report: NextCloud overwrite data by renaming folder ($250)
- Test: Concurrent operations on same resource
- Technique: Rename folder A to B's name while permissions are checked

## 6. Payment/Subscription Logic
Report: Coda adding paid function for 14 days free ($200)
- Test: Trial manipulation, subscription downgrade/upgrade race
- Look for: Missing validation on subscription tier changes

## 7. Wallet/Withdrawal Logic
Report: Mail.ru manager withdrawing from driver account ($8000)
- Test: Role-based operation validation
- Look for: Manager role performing owner-level financial operations

## Logic Bug Testing Checklist:
- [ ] Input negative numbers
- [ ] Input extremely large numbers
- [ ] Input special characters in price fields
- [ ] Race condition in concurrent requests
- [ ] Missing "self" action validation
- [ ] Step/flow skipping (skip payment step)
- [ ] Reusing one-time coupons/tokens
- [ ] Rounding errors in financial calculations
