---
name: "modularize-chrome-browser"
description: "Modularize a chrome/browser/ subfolder by splitting its sources out of the monolithic //chrome/browser:browser target into dedicated source_set targets in the subfolder's own BUILD.gn. Use when the us"
category: threat-hunting
subcategory: threat-hunting
tags: []
relevance: 1
source: "https://github.com/chromium/chromium/blob/54350e061083b35f74254af992576bee14eee976/agents/projects/bedrock/modularize-chrome-browser/SKILL.md"
author: "chromium"
license: "BSD-3-Clause"
---
# modularize-chrome-browser


## Description
Modularize a chrome/browser/ subfolder by splitting its sources out of the monolithic //chrome/browser:browser target into dedicated source_set targets in the subfolder's own BUILD.gn. Use when the user asks to modularize, extract, or create BUILD targets for a chrome/browser/ subfolder, or mentions "Project Bedrock", "//chrome/browser modularization", or wants to split a subfolder into header/impl/test targets. Also use when the user says "modularize chrome/browser/X" for any X.


## Source
https://github.com/chromium/chromium/blob/54350e061083b35f74254af992576bee14eee976/agents/projects/bedrock/modularize-chrome-browser/SKILL.md


## Relevance Score
1
