---
name: "electron-security"
description: "Use when working on Electron applications — detected by `electron` in package.json dependencies, presence of `main.ts`/`main.js` entry, or `BrowserWindow` usage in source. Enforces contextIsolation tr"
category: security
subcategory: security-misc
tags: ["type:integration"]
relevance: 1
source: ""
author: ""
license: ""
---
# electron-security


## Description
Use when working on Electron applications — detected by `electron` in package.json dependencies, presence of `main.ts`/`main.js` entry, or `BrowserWindow` usage in source. Enforces contextIsolation true, nodeIntegration false, CSP, and draggable region discipline. Do NOT use for regular web apps, Node.js CLI tools, or non-Electron desktop frameworks (Tauri, Neutralino, NW.js).


## Tags
type:integration


## Relevance Score
1
