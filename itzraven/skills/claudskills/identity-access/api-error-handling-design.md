---
name: "api-error-handling-design"
description: "Designing HTTP error classification, RFC 7807-style error payload structure, and client-side error parsing for Salesforce REST/SOAP integrations and custom Apex REST endpoints. Use when deciding which"
category: identity-access
subcategory: identity-access
tags: ["tool:salesforce", "type:integration"]
relevance: 2
source: "https://github.com/PranavNagrecha/AwesomeSalesforceSkills/blob/03f41a3ad58e942d13a224a98f3a769869f309f3/skills/integration/api-error-handling-design/SKILL.md"
author: "Pranav Nagrecha"
license: "Apache-2.0"
---
# api-error-handling-design


## Description
Designing HTTP error classification, RFC 7807-style error payload structure, and client-side error parsing for Salesforce REST/SOAP integrations and custom Apex REST endpoints. Use when deciding which HTTP status codes to return from custom Apex REST services, how to structure error response bodies, how to classify inbound API errors as retry-safe vs non-retry-safe, or how to parse Salesforce error responses on the consumer side. NOT for retry execution mechanics or circuit breaker implementation (use retry-and-backoff-patterns). NOT for Apex exception class design (use apex-error-handling-framework). NOT for OAuth error flows (use oauth-flows-and-connected-apps).


## Tags
tool:salesforce, type:integration


## Source
https://github.com/PranavNagrecha/AwesomeSalesforceSkills/blob/03f41a3ad58e942d13a224a98f3a769869f309f3/skills/integration/api-error-handling-design/SKILL.md


## Relevance Score
2
