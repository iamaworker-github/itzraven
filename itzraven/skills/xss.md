---
name: xss
description: XSS types, filter bypasses, DOM exploitation
category: vulnerabilities
---

# Cross-Site Scripting (XSS) Testing

## Attack Surface
XSS occurs when user-controlled data is rendered in web pages without proper encoding.
- **Reflected XSS**: Input is immediately returned in response
- **Stored XSS**: Input is saved and later displayed to users
- **DOM-based XSS**: Client-side JS processes unsafe data from URL fragment/document sources

## Methodology
1. **Detection**
   - Inject simple payloads: `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`
   - Check all input vectors: URL params, POST body, headers, cookies, file names
   - Test every reflection point in the response

2. **Context Analysis**
   - HTML element context: `<tag>PAYLOAD</tag>` - break out with `>`
   - Attribute context: `<tag attr="PAYLOAD">` - break out with `"`
   - JavaScript context: `<script>var x = 'PAYLOAD'` - break out with `';`
   - CSS context: `<style>PAYLOAD</style>` - use `expression()` or `url()`

3. **DOM-based Testing**
   - Check URL fragment `#` handling
   - Test `document.write`, `innerHTML`, `eval()` sinks
   - Check `postMessage` handlers
   - Verify JS frameworks' template injection

## Bypass Methods
- **Filter Bypass**: `<scr<script>ipt>`, `\x3cscript\x3e`, Unicode encoding
- **Event Handler Bypass**: Use less common events: `onmouseover`, `onfocus`, `onhashchange`
- **Protocol Bypass**: `javascript:`, `data:text/html`, `vbscript:`

## Validation
- Confirm alert/prompt execution in browser
- Verify payload executes in victim's session context
- DOM XSS must execute without page reload
- Use `document.domain` check for same-origin verification
