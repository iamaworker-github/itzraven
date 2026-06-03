---
name: "stripe-switch-account"
description: "Rotates the active Stripe account of a SpecBox project safely. Wraps the switch_stripe_account MCP tool with a UX layer: shows current alias store, asks for from/to, runs dry-run, formats the plan in "
category: security
subcategory: security-misc
tags: ["tool:stripe"]
relevance: 1
source: ""
author: ""
license: ""
---
# stripe-switch-account


## Description
Rotates the active Stripe account of a SpecBox project safely. Wraps the switch_stripe_account MCP tool with a UX layer: shows current alias store, asks for from/to, runs dry-run, formats the plan in Markdown, asks for literal confirmation, executes, and surfaces the rollback runbook if something fails. Supports both account_mode='standard' (SaaS, e-commerce) and 'connect' (marketplace). Use when the user says "switch stripe account", "rotar cuenta stripe", "cambiar cuenta stripe", "cambiar de cuenta de stripe", "rotate stripe account", "stripe credentials rotation".


## Tags
tool:stripe


## Relevance Score
1
