---
name: app-level-dos
description: Application-level DoS testing — email bounce issues, resource exhaustion, expensive operations, and input bomb
category: vulnerabilities
---

# Application Level DoS Methodology

## Email Bounce Issues
1. Find invite/notification functionality
2. Send invites to invalid/malformed email addresses
3. Check if bounce handling causes resource exhaustion
4. Look for email queues filling up
5. Test with thousands of invalid invitations
6. Check SES/SendGrid/Mailgun dashboard for bounced/blocked

## Resource Exhaustion
- **Expensive Queries**: Search/filter endpoints with expensive regex, sort operations
- **Large Payloads**: Upload large files, JSON with deep nesting
- **Zip Bombs**: Upload compressed files that expand to huge sizes
- **Recursive Operations**: GraphQL with deeply nested queries
- **Hash Collisions**: POST with parameters designed to cause hash table collisions
- **Regex DoS**: Submit input that triggers catastrophic backtracking

## Input Bomb Vectors
- billion laughs attack (XML entity expansion)
- JSON deep nesting (>10000 levels)
- Long Unicode strings (normalization issues)
- Multi-byte character repetition
- Null bytes, control characters
- File upload with infinite stream

## Rate Limit Exhaustion
- Bypass rate limits via header manipulation
- Distributed DoS from multiple IPs
- Race condition on rate limit reset
- API endpoint with no rate limiting (forgot password, email verification)

## Cache Poisoning DoS
- Submit malicious content that gets cached and served to all users
- Poison CDN cache with oversized content
- Cache invalidation flooding
