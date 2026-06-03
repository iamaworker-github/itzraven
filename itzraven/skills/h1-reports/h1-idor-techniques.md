---
name: "h1-idor-techniques"
description: "Insecure Direct Object Reference patterns from real HackerOne reports — IDOR in order delivery, API keys, log files, device wipe, and marketplace hash manipulation"
category: web-security
tags: ["idor", "access-control", "authorization", "hackerone"]
relevance: 10
---

# H1 IDOR Testing Techniques

Real-world IDOR vulnerabilities from HackerOne reports with $250-$5000 bounties:

## 1. Order/Resource IDOR
Report: Mail.ru IDOR for order delivery address ($3000)
- Test: Change order ID in API calls
- Look for: Other users' delivery addresses, order details
- Payload: `/api/orders/{id}` → increment/decrement ID

## 2. API Key IDOR  
Report: Visma IDOR to change API-key description ($250)
- Test: Access API key management endpoints without ownership check
- Look for: Ability to modify/delete other users' API keys

## 3. Enumeration IDOR
Report: SEMrush IDOR to enumerate users with Google Analytics ($500)
- Test: User/company ID enumeration in params
- Look for: Incrementing IDs revealing other users' connected services

## 4. Device/Resource IDOR
Report: Nextcloud remote wipe of other users' device ($500)
- Test: Device management endpoints
- Look for: `device_id`, `resource_id` in API calls

## 5. Log File IDOR
Report: Razer IDOR to access log files through exposed signature ($500)
- Test: Log endpoints, debug endpoints
- Look for: UUIDs, signatures in mobile app traffic

## 6. Hash/Length Bypass IDOR
Report: SEMrush marketplace hash manipulation ($5000)
- Test: Parameter length restrictions, hash validation
- Look for: Weak hash validation on marketplace/transaction operations

## Testing Methodology:
1. Create two accounts (A + B)
2. Capture API requests from account A
3. Modify IDs/params to reference account B's resources
4. Check if account B's data is accessible
5. Test UUIDs, integers, base64-encoded IDs
6. Test path traversal in resource paths: `/api/user/../admin/resource`
