---
name: "credential-leak-detector"
description: "PostToolUse hook that scans Bash tool output for leaked credentials — API keys, tokens, private keys, and secrets — before they reach the conversation. Blocks critical leaks, redacts high-severity mat"
category: security
subcategory: security-misc
tags: ["ai:claude"]
relevance: 0
source: "https://github.com/JKHeadley/instar/blob/HEAD/skills/credential-leak-detector/SKILL.md"
author: "JKHeadley"
license: "MIT"
---
# credential-leak-detector


## Description
PostToolUse hook that scans Bash tool output for leaked credentials — API keys, tokens, private keys, and secrets — before they reach the conversation. Blocks critical leaks, redacts high-severity matches, and warns on suspicious patterns. 14 detection patterns covering OpenAI, Anthropic, AWS, GitHub, Stripe, Google, Slack, SendGrid, Twilio, PEM keys, bearer tokens, and generic secrets. No external dependencies. Trigger words: security, credential leak, secret exposure, key detection, token scan, API key leaked, credential guard, secret scanner, prevent credential leak.


## Tags
ai:claude


## Source
https://github.com/JKHeadley/instar/blob/HEAD/skills/credential-leak-detector/SKILL.md


## Relevance Score
0
