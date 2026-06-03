---
name: "stripe-webhook-signature-verifier"
description: "Verifies Stripe webhook payload signatures using the Stripe.js SDK and the stripe.webhooks.constructEvent method. Validates the Stripe-Signature header against the raw request body and a configured en"
category: security
subcategory: security-misc
tags: ["tool:stripe"]
relevance: 0
source: "https://github.com/stripe/stripe-node"
author: ""
license: ""
---
# stripe-webhook-signature-verifier


## Description
Verifies Stripe webhook payload signatures using the Stripe.js SDK and the stripe.webhooks.constructEvent method. Validates the Stripe-Signature header against the raw request body and a configured endpoint secret. Handles tolerance windows for replay attack prevention and logs verification failures to Datadog via the Datadog Logs API.


## Tags
tool:stripe


## Source
https://github.com/stripe/stripe-node


## Relevance Score
0
