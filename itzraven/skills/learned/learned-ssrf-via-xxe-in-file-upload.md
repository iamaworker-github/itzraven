---
name: "learned-ssrf-via-xxe-in-file-upload"
description: "Auto-generated skill from SSRF Agent: SSRF via XXE in file upload"
category: ssrf
tags: ["auto-learned", "ssrf", "critical"]
relevance: 9
source: "auto-generated from finding"
---

# learned-ssrf-via-xxe-in-file-upload

## Description
Auto-generated skill from SSRF Agent: SSRF via XXE in file upload

## Technique
Server processed external entity and made internal request

## Payload
```
POST http://testfire.net with XXE payload
```

## Remediation
Disable external entity processing in XML parser

## Auto-Generated
This skill was automatically created from a real finding during pentesting.
