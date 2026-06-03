---
name: "apex-named-credentials-patterns"
description: "Use when writing Apex that calls out to external endpoints via Named Credentials, working with custom header formula tokens ({!$Credential.OAuthToken}), querying per-user auth state through the UserEx"
category: identity-access
subcategory: identity-access
tags: ["type:debug"]
relevance: 2
source: ""
author: "Pranav Nagrecha"
license: ""
---
# apex-named-credentials-patterns


## Description
Use when writing Apex that calls out to external endpoints via Named Credentials, working with custom header formula tokens ({!$Credential.OAuthToken}), querying per-user auth state through the UserExternalCredential SObject, or diagnosing why Named Credential callouts fail. Trigger keywords: 'callout: prefix', 'named credential header formula', 'UserExternalCredential', 'External Credential per-user principal', 'Named Credential oauth token apex'. NOT for Named Credential setup in the Salesforce Setup UI — use integration/named-credentials-setup. NOT for general HTTP callout mechanics (HttpRequest, HttpResponse, mock patterns) — use integration/callouts-and-http-integrations.


## Tags
type:debug


## Relevance Score
2
