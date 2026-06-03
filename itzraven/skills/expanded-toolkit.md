---
name: expanded-toolkit
description: Itzraven Expanded Security Toolkit — 100+ integrated pentesting & OSINT tools. Use Docker-based wrappers for secret scanning, cloud audit, AD assessment, mobile testing, forensics, and more.
---

# Expanded Security Toolkit

Itzraven now integrates **80+ security tools** beyond the original set. All tools are accessible through the `ToolRegistry` and automatically use Docker when available.

## New Tool Categories

### OSINT & Recon (new: Holehe, Maigret, Sherlock, SpiderFoot, TruffleHog, Gitleaks)
| Tool | What it does | Usage |
|---|---|---|
| `holehe` | Check email on 120+ sites | `await registry.execute(ToolAction("holehe", {"email": "user@example.com"}))` |
| `maigret` | Username OSINT across 3000+ sites | `await registry.execute(ToolAction("maigret", {"username": "johndoe"}))` |
| `sherlock` | Search username on social networks | `await registry.execute(ToolAction("sherlock", {"username": "johndoe"}))` |
| `trufflehog` | Scan git/filesystem for secrets | `await registry.execute(ToolAction("trufflehog", {"path": "./repo"}))` |
| `gitleaks` | Detect hardcoded secrets in git | `await registry.execute(ToolAction("gitleaks", {"path": "./repo"}))` |

### Network & TLS (new: RustScan, testssl.sh, Masscan)
| Tool | What it does | Usage |
|---|---|---|
| `rustscan` | Scans 65k ports in 3s | `await registry.execute(ToolAction("rustscan", {"target": "example.com"}))` |
| `testssl` | Deep TLS/SSL audit | `await registry.execute(ToolAction("testssl", {"host": "example.com:443"}))` |
| `masscan` | Fast internet port scanner | Use via ToolRunner directly |

### Active Directory (new: Certipy, Responder, Kerbrute, Impacket)
| Tool | What it does | Usage |
|---|---|---|
| `certipy` | AD CS enumeration & abuse | `await registry.execute(ToolAction("certipy", {"target": "dc.example.com", "user": "user", "password": "pass"}))` |
| `responder` | LLMNR/NBT-NS poisoning | `await registry.execute(ToolAction("responder", {"interface": "eth0"}))` |
| `kerbrute` | Kerberos pre-auth brute-force | `await registry.execute(ToolAction("kerbrute", {"domain": "example.local", "wordlist": "/path/to/names.txt"}))` |
| `impacket` | AD protocol toolkit | `await registry.execute(ToolAction("impacket", {"module": "secretsdump", "args": "target/user:pass@dc"}))` |

### Cloud Security (new: Prowler, Trivy, ScoutSuite, Pacu)
| Tool | What it does | Usage |
|---|---|---|
| `prowler` | Multi-cloud security audit (AWS/Azure/GCP/K8s) | `await registry.execute(ToolAction("prowler", {"provider": "aws"}))` |
| `trivy` | Container/K8s/IaC vulnerability scanner | `await registry.execute(ToolAction("trivy", {"target": "nginx:latest", "scan_type": "image"}))` |
| `scoutsuite` | Multi-cloud security auditing | Use via ToolRunner directly |
| `pacu` | AWS exploitation framework | Use via ToolRunner directly |

### Post-Exploitation (new: PEASS-ng, Chisel, Evil-WinRM, Havoc)
| Tool | What it does | Usage |
|---|---|---|
| `peass` | LinPEAS/WinPEAS priv esc enumeration | `await registry.execute(ToolAction("peass", {"os_type": "linux"}))` |
| `chisel` | TCP/UDP tunneling for pivoting | `await registry.execute(ToolAction("chisel", {"mode": "server", "port": "8080"}))` |
| `evil-winrm` | WinRM shell for Windows pentesting | Use via ToolRunner directly |

### Mobile Security (new: MobSF, Frida)
| Tool | What it does | Usage |
|---|---|---|
| `mobsf` | Mobile app security scanner | `await registry.execute(ToolAction("mobsf", {"apk_path": "/path/to/app.apk"}))` |
| `frida` | Dynamic instrumentation | `await registry.execute(ToolAction("frida", {"target": "com.app.name"}))` |

### Forensics (new: Binwalk, Volatility)
| Tool | What it does | Usage |
|---|---|---|
| `binwalk` | Firmware analysis & extraction | `await registry.execute(ToolAction("binwalk", {"filepath": "firmware.bin"}))` |
| `volatility` | Memory forensics | `await registry.execute(ToolAction("volatility", {"image_path": "memory.dump", "plugin": "windows.info"}))` |

## Auto-Docker Execution

All new tools automatically use Docker when available:
```python
from itzraven.core.tool_runner import ToolRunner
runner = ToolRunner()
result = await runner.execute("information_gathering.Holehe", args="user@example.com")
print(result.status, result.stdout[:500])
```

## Tool Search & Discovery

```python
runner = ToolRunner()
# Search by keyword
tools = runner.search_tools(query="tls")
# Search by category
tools = runner.search_tools(category="cloud_security")
# List all categories
cats = runner.list_categories()
# Get predefined workflows
workflows = runner.get_workflows()
```

## Automation Chains

The registry has 12 predefined workflows:
- `recon`: subfinder → httpx → nuclei → amass
- `web_audit`: httpx → nuclei → ffuf → gobuster → wafw00f → testssl
- `osint_email`: holehe → theharvester → infoga
- `osint_username`: maigret → sherlock → socialscan
- `secret_scan`: trufflehog → gitleaks → gitdork
- `ad_assessment`: bloodhound → certipy → kerbrute → impacket → netexec → responder
- `cloud_audit`: prowler → scoutsuite → pacu → trivy
- `mobile_test`: mobsf → frida → objection → jadx
- `forensics`: volatility → binwalk → pspy
- `tls_audit`: testssl → nuclei
- `port_scan`: masscan → rustscan → nmap
- `web_fuzz`: ffuf → gobuster → dirsearch → arjun
