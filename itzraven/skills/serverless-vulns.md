---
name: serverless-vulns
description: Serverless security testing — AWS Lambda, GCP Cloud Functions, Azure Functions — event injection, SSRF, dependency poisoning
category: vulnerabilities
---

# Serverless Vulnerability Methodology

## Event Injection
- Lambda processes events from S3, SQS, DynamoDB Streams, API Gateway
- If attacker controls event content → inject malicious payloads
- Test with oversized events, special characters in S3 keys, SQLi in DynamoDB filter expressions

## SSRF in Functions
- Lambda functions often have full VPC access
- Test URL fetch endpoints in function logic
- Common targets: `http://169.254.169.254/latest/meta-data/`, internal ELB DNS, parameter store
- If function uses `requests.get(event['url'])` → full SSRF

## Dependency Poisoning
- Check `requirements.txt` or `package.json` for pinned vs unpinned deps
- Unpinned `pymongo>=3.0` → can be replaced with malicious version
- Check for outdated libraries with known CVEs

## IAM Misconfiguration
- Overly permissive Lambda execution role
- Function can read/write S3 buckets it shouldn't access
- Function can invoke other functions (privilege escalation)
- Function has `lambda:InvokeFunction` on `*`

## Environment Variable Leakage
- Check error messages that expose env vars
- Test for verbose error handling
- CloudWatch logs that expose secrets
- Test function response for env injection

## Third-Party Event Source Abuse
- If function is triggered by SNS/SQS from external accounts
- Attacker publishes malicious events
- Test with large payloads, recursive invocations, poisoning

## Tools
- `cloudsploit` — CSPM scanning
- `prowler` — AWS security assessment
- `serverless-scan` static analysis
- Manual curl to function URLs with various events
