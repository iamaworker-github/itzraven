"""
Categorized Security Methodology — OSINT / Pentest / CTF

Synthesized from:
- ProjectDiscovery.io Blog (Neo AI, Nuclei, naabu, httpx)
- PayloadsAllTheThings (SwisskyRepo)
- SANS OSINT Resources
- OSINTFramework.com
- IntelTechniques (Michael Bazzell)
- Bellingcat Resources
- TraceLabs Search Party
- OhShint (PI OSINT Blog)
- Awesome OSINT (jivoi, 26K+ stars)
- OSINT Combine Blog

Each methodology is tagged with category, source, tools, and techniques.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Optional


class Category(Enum):
    OSINT = "osint"
    PENTEST = "pentest"
    CTF = "ctf"


@dataclass
class MethodologyNode:
    name: str
    category: Category
    source: str
    tools: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    sub_nodes: List["MethodologyNode"] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    bypasses: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category.value,
            "source": self.source,
            "tools": self.tools,
            "techniques": self.techniques,
            "data_sources": self.data_sources,
            "sub_nodes": [s.to_dict() for s in self.sub_nodes],
            "commands": self.commands,
            "bypasses": self.bypasses,
        }


# ═══════════════════════════════════════════════════════════════════════════
# OSINT METHODOLOGIES
# ═══════════════════════════════════════════════════════════════════════════

OSINT_METHODOLOGIES = MethodologyNode(
    name="OSINT Methodology",
    category=Category.OSINT,
    source="All Sources",
    tools=["theHarvester", "SpiderFoot", "Maltego", "Recon-ng", "Sherlock", "Holehe", "Social-analyzer"],
    techniques=["Passive recon", "Social media mining", "Data breach searching", "Geolocation", "People search"],
    sub_nodes=[
        MethodologyNode(
            name="People & Identity Intelligence",
            category=Category.OSINT,
            source="IntelTechniques, SANS, Awesome OSINT",
            tools=[
                "Sherlock", "WhatsMyName", "Namechk", "KnowEm", "Usersearch",
                "Social-Searcher", "IDCrawl", "Pipl", "Spokeo", "BeenVerified",
                "ZoomInfo", "ThumbsUp", "Lusha", "Apollo", "Clearbit",
                "Holehe", "Epieos", "DeHashed", "Snusbase", "LeakCheck",
            ],
            techniques=[
                "Username enumeration across 400+ platforms",
                "Email-to-identity correlation",
                "Phone number intelligence (country, carrier, VoIP detection)",
                "Data broker aggregation (Pipl, Spokeo, BeenVerified)",
                "Breach corpus lookup for credential associations",
                "Social media cross-referencing",
                "Professional network mining (LinkedIn, LinkedIn Sales Navigator)",
                "Background check aggregation",
                "Court records & public filings search",
                "Voter registration & property records",
            ],
            data_sources=["Social networks", "Data brokers", "Public records", "Breach corpuses"],
            commands=[
                "sherlock username",
                "holehe email@example.com",
                "theHarvester -d example.com -b linkedin,google",
                "social-analyzer -u username -m local",
            ],
        ),
        MethodologyNode(
            name="Domain & Network Intelligence",
            category=Category.OSINT,
            source="ProjectDiscovery, OSINTFramework, Awesome OSINT",
            tools=[
                "Amass", "Subfinder", "SecurityTrails", "CRT.sh", "DNSDumpster",
                "DNSTwist", "Findomain", "Sublist3r", "Shodan", "Censys",
                "ZoomEye", "FOFA", "ONYPHE", "GreyNoise", "Netlas.io",
                "SecurityTrails", "Whois", "Whoxy", "IPinfo", "IP2Location",
                "BuiltWith", "Wappalyzer", "WhatWeb",
            ],
            techniques=[
                "WHOIS history & reverse WHOIS",
                "DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV)",
                "Certificate Transparency log monitoring",
                "Subdomain discovery via passive sources (crt.sh, securitytrails)",
                "ASN & IP range discovery",
                "Reverse IP lookup (same server domains)",
                "Technology stack fingerprinting",
                "WAF detection & bypass assessment",
                "Favicon hash matching (Shodan)",
                "JARM/TLS fingerprinting",
            ],
            data_sources=["WHOIS databases", "DNS records", "Certificate logs", "Internet scanners"],
            commands=[
                "subfinder -d example.com",
                "amass enum -passive -d example.com",
                "httpx -l domains.txt -status-code -tech-detect",
                "naabu -host example.com -top-ports 1000",
                "nuclei -l live_hosts.txt -as",
            ],
        ),
        MethodologyNode(
            name="Social Media Intelligence (SOCMINT)",
            category=Category.OSINT,
            source="Bellingcat, OSINT Combine, SANS",
            tools=[
                "Twint", "Nitter", "Bibliogram", "Teddit", "Libreddit",
                "Osintgram", "Instaloader", "Youtube-DL", "MediaHarvest",
                "Pushshift", "Pullpush", "RedditMetis", "DiscordLeaks",
                "Telegram Bots", "VK API",
            ],
            techniques=[
                "Twitter/X: advanced search operators, geolocation, thread analysis",
                "Instagram: follower analysis, location tagging, story archiving",
                "Reddit: subreddit monitoring, deleted post recovery, author analysis",
                "LinkedIn: company hierarchy, employee role changes, tech stack leakage",
                "Telegram: channel monitoring, message history, metadata extraction",
                "Discord: server discovery, message archiving, OPSEC analysis",
                "Facebook: group intelligence, page insights, mutual connections",
                "TikTok: video metadata, comment analysis, trend tracking",
                "Cross-platform identity correlation (same username/email/photo)",
                "Social network graph analysis (influence mapping)",
            ],
            data_sources=["Twitter/X", "Reddit", "LinkedIn", "Instagram", "Telegram", "Discord"],
            commands=[
                "snscrape --jsonl twitter-search 'from:username since:2024-01-01'",
                "instaloader profile username",
                "gallery-dl https://www.instagram.com/p/XXX",
            ],
        ),
        MethodologyNode(
            name="Geolocation & Spatial OSINT",
            category=Category.OSINT,
            source="Bellingcat, OSINTCombine, SANS, TraceLabs",
            tools=[
                "Google Earth", "Google Maps", "Yandex Maps", "Bing Maps",
                "Sentinel Hub", "Planet Labs", "USGS EarthExplorer",
                "OpenStreetMap", "Overpass Turbo", "GeoHints",
                "SunCalc", "ShadowMap", "MapChecking",
                "PeakFinder", "What3Words", "GeoIP",
            ],
            techniques=[
                "Satellite imagery analysis (temporal comparison, change detection)",
                "Reverse image search for location matching",
                "Sun/shadow analysis for time & location verification",
                "Building & infrastructure matching (rooflines, windows, signage)",
                "Street view comparison across time",
                "Landmark & point-of-interest triangulation",
                "Geolocation via flora, fauna, climate indicators",
                "Power line & utility pole identification by country",
                "Road markings & traffic sign country identification",
                "License plate region identification",
                "Language & script analysis from street signs",
                "CCTV coverage mapping",
            ],
            data_sources=["Satellite imagery", "Street view", "Geolocation databases", "Map APIs"],
            commands=[
                "# Sentinel Hub: https://apps.sentinel-hub.com/eo-browser/",
                "# Overpass Turbo: https://overpass-turbo.eu/",
                "# GeoHints: https://geohints.com/",
            ],
        ),
        MethodologyNode(
            name="Breach & Leak Intelligence",
            category=Category.OSINT,
            source="ProjectDiscovery, IntelTechniques, Awesome OSINT",
            tools=[
                "HaveIBeenPwned", "DeHashed", "LeakCheck", "Snusbase",
                "IntelX", "LeakIX", "PSBDMP", "Github-dork",
                "TruffleHog", "Gitleaks", "GitGuardian",
                "BucketFinder", "GrayhatWarfare",
            ],
            techniques=[
                "Credential stuffing database correlation",
                "GitHub secret scanning (API keys, tokens, passwords in code)",
                "Pastebin scraping with NLP-based secret detection",
                "S3 bucket disclosure scanning",
                "Stealer log aggregation (RedLine, Vidar, Raccoon)",
                "Dark web forum monitoring (Dread, Exploit.in)",
                "Telegram channel leak monitoring",
                "Public repository secret pattern matching",
                "Cloud storage misconfiguration scanning",
                "Dependency confusion vulnerability checking",
            ],
            data_sources=["Breach corpuses", "GitHub API", "Paste sites", "Dark web forums"],
            commands=[
                "trufflehog github --repo=https://github.com/org/repo",
                "gitleaks detect --source . --verbose",
                "gh-dork -d example.com",
            ],
        ),
        MethodologyNode(
            name="Visual & Multimedia OSINT",
            category=Category.OSINT,
            source="Bellingcat, Awesome OSINT, SANS",
            tools=[
                "ExifTool", "Forensically", "FotoForensics", "Jeffrey's Image Metadata Viewer",
                "InVID", "YouTube DataViewer", "MediaHarvest",
                "TinEye", "Google Images", "Yandex Images", "Bing Images",
                "FFmpeg", "ExifCleaner",
            ],
            techniques=[
                "EXIF metadata extraction (GPS, camera, software, timestamps)",
                "Error Level Analysis (ELA) for tamper detection",
                "Reverse image search across multiple engines",
                "Video keyframe extraction & reverse search",
                "Deepfake detection (MTCNN, face alignment, temporal consistency)",
                "Watermark removal & clone detection",
                "Image geolocation via embedded coordinates",
                "Social media profile photo reverse search",
                "Screenshot analysis (OS/browser/date identification)",
                "CCTV footage analysis (timestamp verification, field of view)",
            ],
            data_sources=["Image metadata", "Video platforms", "Search engines"],
            commands=[
                "exiftool -a -u -gps:all image.jpg",
                "ffmpeg -i video.mp4 -vf fps=1 thumb_%04d.png",
                "youtube-dl --write-auto-sub --sub-lang en URL",
            ],
        ),
        MethodologyNode(
            name="Document & File Intelligence",
            category=Category.OSINT,
            source="IntelTechniques, SANS, Awesome OSINT",
            tools=[
                "Metagoofil", "FOCA", "DocScraper", "PDFParser",
                "Apache Tika", "Strings", "Binwalk",
            ],
            techniques=[
                "Document metadata extraction (author, software, paths, printers)",
                "PDF analysis (embedded files, JavaScript, metadata)",
                "Office document macro analysis (VBA extraction)",
                "Hidden data in documents (revisions, comments, tracked changes)",
                "File carving & recovery from document fragments",
                "Font & template identification for forgery detection",
            ],
            data_sources=["Public documents", "Cloud storage", "SharePoint"],
            commands=[
                "metagoofil -d example.com -t pdf -l 50",
                "exiftool -a document.pdf",
            ],
        ),
        MethodologyNode(
            name="Dark Web & Anonymized Intelligence",
            category=Category.OSINT,
            source="SANS, Awesome OSINT, TraceLabs",
            tools=[
                "Ahmia", "OnionScan", "TorBot", "DarkSearch",
                "Tor Metrics", "ExoneraTor",
            ],
            techniques=[
                "Dark web marketplace monitoring",
                "Onion service discovery & fingerprinting",
                "Bitcoin blockchain analysis (taint tracing, cluster analysis)",
                "Cryptocurrency address clustering",
                "Ransomware leak site monitoring",
                "Forum credential trading surveillance",
            ],
            data_sources=["Tor network", "Blockchain data", "Dark web forums"],
        ),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
# PENTEST METHODOLOGIES
# ═══════════════════════════════════════════════════════════════════════════

PENTEST_METHODOLOGIES = MethodologyNode(
    name="Pentest Methodology",
    category=Category.PENTEST,
    source="PayloadsAllTheThings, ProjectDiscovery",
    tools=["Nuclei", "Naabu", "HTTPx", "Burp Suite", "Metasploit", "SQLmap", "Nmap"],
    sub_nodes=[
        MethodologyNode(
            name="Web Application Pentesting",
            category=Category.PENTEST,
            source="PayloadsAllTheThings, ProjectDiscovery",
            tools=["Burp Suite", "Caido", "ZAP", "HTTPx", "Nuclei"],
            techniques=[
                "Information gathering & fingerprinting",
                "Configuration & deployment testing",
                "Identity & session management testing",
                "Authorization testing (IDOR, privilege escalation)",
                "Input validation testing (SQLi, XSS, SSTI, LFI, Command Injection)",
                "Error handling testing",
                "Cryptography testing (weak SSL/TLS, padding oracle)",
                "Business logic testing",
                "Client-side testing (CSRF, CORS, Clickjacking, WebSockets)",
                "API testing (REST, GraphQL, WebSocket, gRPC)",
                "LLM & AI security testing (prompt injection, model extraction)",
            ],
            commands=[
                "nuclei -u https://example.com -as",
                "httpx -u https://example.com -sc -title -tech-detect -jarm",
            ],
            sub_nodes=[
                MethodologyNode(
                    name="SQL Injection",
                    category=Category.PENTEST,
                    source="PayloadsAllTheThings, PortSwigger",
                    tools=["SQLmap", "sqlmap", "Burp Intruder", "NoSQLMap"],
                    techniques=[
                        "Error-based SQLi", "Union-based SQLi",
                        "Blind SQLi (boolean, time-based)",
                        "Out-of-band SQLi (OAST/DNS)",
                        "Second-order SQLi",
                        "NoSQL injection (MongoDB, Elasticsearch)",
                        "WAF bypass techniques (comment injection, case variation, encoding)",
                        "Database-specific payloads (MySQL, MSSQL, Oracle, PostgreSQL, SQLite)",
                    ],
                    bypasses=[
                        "OR 1=1 → OR 2=7923=7923",
                        "SELECT → SEL/**/ECT (comment injection)",
                        "1' OR '1'='1 → 1' OR '1'='2 (boolean detection)",
                        "sleep(5) → waitfor delay '0:0:5' (mssql)",
                        "' OR '1'='1' -- → ' OR '1'='1' /* (mysql comment)",
                    ],
                ),
                MethodologyNode(
                    name="Cross-Site Scripting (XSS)",
                    category=Category.PENTEST,
                    source="PayloadsAllTheThings",
                    tools=["XSStrike", "XSSer", "DalFox", "Burp Intruder"],
                    techniques=[
                        "Reflected XSS", "Stored XSS", "DOM-based XSS",
                        "Self-XSS", "Blind XSS",
                        "XSS via file upload (SVG, HTML files)",
                        "XSS via mXSS (Mutation XSS)",
                        "XSS via JSONP endpoints",
                        "Content Security Policy (CSP) bypass techniques",
                    ],
                    bypasses=[
                        "alert(1) → alert(document.domain) → eval(name)",
                        "<script>alert(1)</script> → <img src=x onerror=alert(1)>",
                        "→ → → (unicode normalization bypass)",
                        "<svg onload=alert(1)> → <svg onload=alert(1)//",
                        "filter bypass: <script> → <sCrIpT> → %3Cscript%3E",
                    ],
                ),
                MethodologyNode(
                    name="Server-Side Request Forgery (SSRF)",
                    category=Category.PENTEST,
                    source="PayloadsAllTheThings, ProjectDiscovery",
                    tools=["SSRFMap", "Gopherus", "Burp Collaborator"],
                    techniques=[
                        "Basic SSRF via URL parameters",
                        "SSRF via Referer header",
                        "SSRF via file upload (URL in metadata)",
                        "SSRF via PDF generator",
                        "Blind SSRF via OAST",
                        "Cloud metadata service access (AWS IMDS, GCP, Azure)",
                        "Container metadata access (Docker, Kubernetes API)",
                    ],
                    bypasses=[
                        "127.0.0.1 → 2130706433 (decimal IP)",
                        "localhost → 0x7f000001 (hex IP)",
                        "127.0.0.1 → 0177.0.0.1 (octal IP)",
                        "http://example.com@127.0.0.1 (URL auth bypass)",
                        "http://127.0.0.1:#{port} (DNS rebinding)",
                    ],
                ),
                MethodologyNode(
                    name="Server-Side Template Injection (SSTI)",
                    category=Category.PENTEST,
                    source="PayloadsAllTheThings",
                    tools=["TplMap", "Burp Intruder"],
                    techniques=[
                        "Jinja2 SSTI (Python/Flask)",
                        "FreeMarker SSTI (Java)",
                        "Velocity SSTI (Java)",
                        "Twig SSTI (PHP)",
                        "Smarty SSTI (PHP)",
                        "Mako SSTI (Python)",
                        "ERB SSTI (Ruby on Rails)",
                    ],
                    bypasses=[
                        "{{7*7}} → {{7*'7'}} → {{config}} → {{self}}",
                        "${7*7} → #{7*7} → *{7*7}",
                    ],
                ),
            ],
        ),
        MethodologyNode(
            name="Network Pentesting",
            category=Category.PENTEST,
            source="PayloadsAllTheThings, ProjectDiscovery",
            tools=["Naabu", "Nmap", "RustScan", "Masscan", "NetExec", "Impacket"],
            techniques=[
                "Port scanning & service discovery",
                "Banner grabbing & version detection",
                "Vulnerability scanning (Nuclei, OpenVAS, Nessus)",
                "Brute-force attacks (Hydra, Medusa, Patator)",
                "Network sniffing & MiTM (Responder, BetterCAP)",
                "SMB enumeration & exploitation",
                "LDAP enumeration",
                "SNMP enumeration",
                "VPN & tunneling detection",
            ],
            commands=[
                "naabu -host 192.168.1.0/24 -top-ports 1000",
                "nmap -sCV -p- 192.168.1.1",
                "netexec smb 192.168.1.0/24 --shares",
            ],
        ),
        MethodologyNode(
            name="Active Directory Pentesting",
            category=Category.PENTEST,
            source="PayloadsAllTheThings",
            tools=["BloodHound", "Impacket", "NetExec", "Mimikatz", "Rubeus"],
            techniques=[
                "LDAP anonymous query & enumeration",
                "Kerberos attacks (AS-REP Roasting, Kerberoasting, Golden Ticket)",
                "NTLM relay & pass-the-hash",
                "SMB relay (Responder + ntlmrelayx)",
                "DCSync attacks",
                "ACL abuse (AD permission exploitation)",
                "GPO abuse & management",
                "AD Certificate Services abuse (ESC1-ESC13)",
                "Domain trust exploitation",
                "LAPS & Group Policy Preferences exploitation",
            ],
        ),
        MethodologyNode(
            name="Cloud Pentesting",
            category=Category.PENTEST,
            source="PayloadsAllTheThings, ProjectDiscovery",
            tools=["ScoutSuite", "Prowler", "CloudSploit", "Stratus Red Team"],
            techniques=[
                "AWS S3 bucket enumeration & misconfiguration",
                "AWS IAM privilege escalation",
                "AWS Lambda function URL discovery",
                "GCP storage bucket enumeration",
                "Azure Blob storage discovery",
                "Cloud metadata service exploitation (IMDS)",
                "Kubernetes API server discovery",
                "Helm chart analysis & secret extraction",
                "Serverless function analysis",
            ],
        ),
        MethodologyNode(
            name="Container & Orchestration Pentesting",
            category=Category.PENTEST,
            source="PayloadsAllTheThings",
            tools=["Docker Bench Security", "kube-hunter", "kube-bench", "Trivy", "Grype"],
            techniques=[
                "Docker socket abuse (mount /var/run/docker.sock)",
                "Container escape via capabilities (CAP_SYS_ADMIN, --privileged)",
                "Kubernetes RBAC enumeration",
                "K8s Secrets extraction",
                "K8s API server anonymous access",
                "Helm/Tiller abuse",
                "Container image vulnerability scanning",
            ],
        ),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
# CTF METHODOLOGIES
# ═══════════════════════════════════════════════════════════════════════════

CTF_METHODOLOGIES = MethodologyNode(
    name="CTF Methodology",
    category=Category.CTF,
    source="PayloadsAllTheThings, TraceLabs, OSINTCombine",
    tools=["Pwntools", "Z3", "Angr", "Ghidra", "IDA", "GDB", "R2"],
    sub_nodes=[
        MethodologyNode(
            name="Web CTF",
            category=Category.CTF,
            source="PayloadsAllTheThings",
            tools=["Burp Suite", "SQLmap", "XSStrike", "CyberChef"],
            techniques=[
                "Source code review (hidden comments, debug endpoints)",
                "JWT token manipulation (alg=none, weak secret, kid injection)",
                "Local File Inclusion (LFI) → RCE via log poisoning",
                "File upload validation bypass (magic bytes, extension, content-type)",
                "Prototype pollution (Node.js, browser JS)",
                "GraphQL introspection & query injection",
                "Race condition exploitation (turbo intruder)",
                "CORS misconfiguration exploitation",
                "Cache poisoning & web cache deception",
                "Dependency confusion (supply chain)",
            ],
        ),
        MethodologyNode(
            name="Binary Exploitation (PWN)",
            category=Category.CTF,
            source="PayloadsAllTheThings, Nightmare",
            tools=["Pwntools", "GDB", "ROPgadget", "One_gadget", "Angr", "Z3"],
            techniques=[
                "Stack buffer overflow (ret2shellcode, ret2libc, ROP)",
                "Format string vulnerability (arbitrary read/write)",
                "Heap exploitation (fastbin, tcache, unsorted bin, large bin)",
                "Return Oriented Programming (ROP) chains",
                "Sigreturn Oriented Programming (SROP)",
                "ret2csu / ret2dl_resolve",
                "Stack pivot & partial overwrite",
                "Integer overflow → heap corruption",
                "Race condition (TOCTOU) in setuid binaries",
                "Kernel exploitation (ioctl, userfaultfd, dirty pipe)",
            ],
        ),
        MethodologyNode(
            name="Reverse Engineering",
            category=Category.CTF,
            source="Nightmare, PayloadsAllTheThings",
            tools=["Ghidra", "IDA Free", "Radare2", "GDB", "Angr", "Z3"],
            techniques=[
                "Static analysis (symbolic execution with angr/Z3)",
                "Dynamic analysis (debugging, tracing)",
                "Obfuscation deobfuscation (ollvm, movfuscator, virtualization)",
                "Anti-debugging bypass (ptrace, timing, /proc/self)",
                "CRC/checksum bypass for patching",
                "Custom VM/bytecode reversing",
                "Firmware extraction & analysis (binwalk, firmware-mod-kit)",
                "Encrypted binary unpacking (PE, ELF, Mach-O)",
                "Go/Rust binary symbol recovery",
            ],
        ),
        MethodologyNode(
            name="Cryptography CTF",
            category=Category.CTF,
            source="PayloadsAllTheThings",
            tools=["CyberChef", "RsaCtfTool", "HashCat", "John", "SageMath"],
            techniques=[
                "RSA attacks (small e, Wiener, Hastad, Fermat, common modulus)",
                "AES/block cipher attacks (CBC bit-flip, ECB byte-at-a-time, padding oracle)",
                "Hash length extension attack (SHA1, SHA2, MD5)",
                "Stream cipher key reuse (many-time-pad)",
                "Diffie-Hellman subgroup confinement",
                "ECC attacks (invalid curve, small subgroup)",
                "Classical cipher cracking (substitution, transposition, Vigenere)",
                "PRNG prediction (LCG, MT19937, glibc rand)",
            ],
        ),
        MethodologyNode(
            name="Forensics CTF",
            category=Category.CTF,
            source="PayloadsAllTheThings, SANS",
            tools=["Volatility", "Autopsy", "Binwalk", "Foremost", "Strings"],
            techniques=[
                "Memory forensics (process list, cmdline, network connections)",
                "Disk image analysis (MBR/GPT, partition recovery, deleted files)",
                "PCAP analysis (Wireshark, tshark, Zeek)",
                "File carving (foremost, scalpel, photorec)",
                "Registry analysis (Windows forensics)",
                "Browser forensics (history, cookies, downloads, cache)",
                "Log analysis (syslog, EventLog, Apache, nginx, auditd)",
                "Steganography detection (zsteg, steghide, stegsolve)",
                "NTFS analysis ($MFT, $LogFile, alternate data streams)",
                "USB device forensics (PnP events, registry keys)",
            ],
        ),
        MethodologyNode(
            name="OSINT CTF (TraceLabs Search Party Style)",
            category=Category.CTF,
            source="TraceLabs, OSINTCombine, Bellingcat",
            tools=["Hunchly", "Maltego", "OSINT VM", "Google Dorking"],
            techniques=[
                "Flag-based OSINT gathering (each flag builds person profile)",
                "Missing person intelligence (TraceLabs Search Party)",
                "Geolocation challenges (find coordinates from photos)",
                "Social media profile reconstruction from partial data",
                "Bitcoin transaction tracing",
                "Satellite imagery analysis (before/after comparison)",
                "Phone number intelligence gathering",
                "Email address correlation across platforms",
                "Dark web persona identification",
                "Video metadata extraction & timeline reconstruction",
            ],
        ),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
# MANDATORY DATASETS
# ═══════════════════════════════════════════════════════════════════════════

MANDATORY_DATASETS = {
    "breach_corpuses": {
        "description": "Aggregated credential breach databases for password reuse and identity correlation",
        "sources": [
            "HaveIBeenPwned API (hash-only lookup)",
            "DeHashed (paid, most comprehensive)",
            "Snusbase (commercial breach aggregator)",
            "LeakCheck (free tier available)",
            "IntelX (free breach search)",
            "Firefox Monitor (API)",
            "Spycloud (enterprise breach data)",
        ],
        "techniques": [
            "Hash-based breach lookup (k-anonymity model)",
            "Email-to-breach correlation",
            "Password reuse pattern detection",
            "Credential stuffing simulation (password rotation analysis)",
        ],
    },
    "whois_history": {
        "description": "Historical WHOIS records for domain ownership tracking",
        "sources": [
            "WhoisXML API (historical WHOIS)",
            "SecurityTrails (WHOIS history)",
            "DomainTools (WHOIS history, reverse WHOIS)",
            "WhoisFreaks API",
            "BetterWhois (bulk lookup)",
            "Whoxy (WHOIS history API)",
        ],
        "techniques": [
            "Domain ownership change tracking (registrant history)",
            "Reverse WHOIS (find all domains owned by same entity)",
            "WHOIS similarity clustering (same email, name, address, phone)",
            "Registrar history for domain takeover detection",
            "Expired domain monitoring",
        ],
    },
    "dns_history": {
        "description": "Historical DNS records for infrastructure evolution tracking",
        "sources": [
            "SecurityTrails (DNS history API)",
            "DNSDumpster (free, limited)",
            "VirusTotal (passive DNS)",
            "AlienVault OTX (passive DNS)",
            "Censys (DNS history)",
            "RiskIQ (passive DNS, now Microsoft)",
            "WhoisXML (DNS history)",
        ],
        "techniques": [
            "Historical IP resolution tracking (migrated hosting providers)",
            "Former subdomain discovery (forgotten infrastructure)",
            "DNS pattern analysis (CDN migration detection)",
            "Fast-flux detection via historical DNS changes",
            "DNS zone transfer history for comprehensive records",
        ],
    },
    "social_metadata": {
        "description": "Social media metadata for identity verification and network mapping",
        "sources": [
            "Twitter API (profile metadata, tweet metadata)",
            "Reddit Pushshift (full Reddit archive)",
            "Instagram metadata (profile photos, location history)",
            "LinkedIn Sales Navigator (company hierarchy)",
            "Facebook Graph API (limited post-metadata)",
            "Telegram MTProto API (profile photos, last seen)",
        ],
        "techniques": [
            "Cross-platform username verification (400+ platforms via Sherlock)",
            "Profile photo reverse image search across platforms",
            "Friend/follower network graph analysis",
            "Timestamp-based activity pattern analysis",
            "Language & location inference from content",
            "Social media account creation date estimation",
        ],
    },
    "exif_datasets": {
        "description": "Image metadata databases for geolocation and device fingerprinting",
        "sources": [
            "Flickr API (public EXIF data, geotags)",
            "Google Images (reverse search)",
            "Yandex Images (reverse search, stronger geo matching)",
            "Image metadata from public photo sharing platforms",
            "Shodan (webcam EXIF data)",
        ],
        "techniques": [
            "GPS coordinate extraction & map reverse lookup",
            "Camera model fingerprinting (device attribution)",
            "Software version tracking (Photoshop, Lightroom)",
            "Timestamp verification (image was taken before/after event)",
            "Thumbnail analysis (JPEG quality, embedded preview)",
            "Copyright & author metadata extraction",
        ],
    },
    "github_leaks": {
        "description": "GitHub code search for exposed secrets, credentials, and API keys",
        "sources": [
            "GitHub Code Search API (authenticated, higher rate limits)",
            "TruffleHog (local git scanning)",
            "Gitleaks (CI/CD secret detection)",
            "GitGuardian (public GitHub monitoring)",
            "GitRob (organization scanning)",
            "Dorkly (automated GitHub dorking)",
        ],
        "techniques": [
            "Regex-based secret pattern matching (60+ patterns: AWS, GCP, Slack, Stripe, JWT)",
            "Filename-based secret detection (.env, credentials.json, id_rsa)",
            "Commit history scanning (removed secrets still in history)",
            "Organization-level repository enumeration",
            "Gist monitoring (often overlooked)",
            "Wiki & discussion board scanning",
        ],
        "patterns": {
            "aws_key": "AKIA[0-9A-Z]{16}",
            "github_token": "ghp_[a-zA-Z0-9]{36}",
            "slack_token": "xox[baprs]-[0-9a-zA-Z-]{10,}",
            "stripe_key": "sk_live_[0-9a-z]{32}",
            "google_api": "AIza[0-9A-Za-z_-]{35}",
            "private_key": "-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----",
        },
    },
    "paste_sites": {
        "description": "Pastebin and code snippet monitoring for exposed data",
        "sources": [
            "PSBDMP (paste search engine)",
            "Pastebin (scraping via API)",
            "Pastebin Pro (paid, full history)",
            "GitHub Gists",
            "Ghostbin",
            "Hastebin",
            "Rentry.co",
        ],
        "techniques": [
            "Keyword-based paste monitoring (domain, company, employee names)",
            "Regex-based secret extraction from paste content",
            "User account monitoring (known leaker accounts)",
            "Cross-referencing paste content with breach data",
            "Temporal analysis (paste frequency patterns)",
        ],
    },
    "archived_urls": {
        "description": "Web archive data for historical content, defunct pages, and hidden endpoints",
        "sources": [
            "Wayback Machine (Internet Archive CDX API)",
            "Archive.is (distributed web archive)",
            "Google Cache",
            "CachedView",
            "CC Search (Common Crawl)",
            "Stillio (paid web archiving)",
        ],
        "techniques": [
            "Historical page content recovery (removed pages)",
            "Endpoint discovery via URL path history",
            "JavaScript file history (exposed API keys, endpoints)",
            "robots.txt history (discovered hidden directories)",
            "sitemap.xml history (complete page inventory)",
            "Old page version comparison (vulnerability timeline)",
            "Admin panel URL discovery from archived paths",
        ],
    },
    "map_geolocation_datasets": {
        "description": "Geographic data for location verification, infrastructure mapping, and target tracking",
        "sources": [
            "Google Maps API (places, geocoding, elevation)",
            "OpenStreetMap Overpass API (queryable map database)",
            "Sentinel Hub EO Browser (satellite imagery)",
            "USGS EarthExplorer (historical satellite)",
            "Planet Labs (daily satellite imagery, paid)",
            "Mapillary (street-level imagery, crowdsourced)",
            "PeakFinder (mountain identification)",
            "SunCalc (sun position calculator)",
            "GeoIP databases (MaxMind, IPinfo)",
            "What3Words API (3-word location encoding)",
        ],
        "techniques": [
            "Coordinate reverse lookup (find address from GPS)",
            "Satellite image temporal comparison (before/after event)",
            "Building footprint extraction from satellite",
            "Street-level imagery comparison (Google Street View + Mapillary)",
            "IP geolocation clustering (COLO/HQ detection)",
            "Cellular tower triangulation from metadata",
            "WiFi BSSID geolocation (Apple/Mozilla location services)",
            "Shipping container tracking (MarineTraffic, VesselFinder)",
            "Aircraft tracking (ADS-B, FlightRadar24, OpenSky)",
            "Rail & cargo shipment tracking APIs",
        ],
    },
}


ALL_CATEGORIZED = {
    "osint": OSINT_METHODOLOGIES,
    "pentest": PENTEST_METHODOLOGIES,
    "ctf": CTF_METHODOLOGIES,
    "datasets": MANDATORY_DATASETS,
}


def get_methodology(category: str) -> Optional[MethodologyNode]:
    return ALL_CATEGORIZED.get(category)


def search_methodology(query: str, category: Optional[str] = None) -> List[dict]:
    results = []
    cats = [category] if category else ["osint", "pentest", "ctf"]
    for cat in cats:
        root = ALL_CATEGORIZED.get(cat)
        if not root or not isinstance(root, MethodologyNode):
            continue
        _search_node(root, query.lower(), results)
    return results


def _search_node(node: MethodologyNode, query: str, results: List[dict]):
    if query in node.name.lower():
        results.append({"name": node.name, "category": node.category.value, "source": node.source})
        return
    for tech in node.techniques:
        if query in tech.lower():
            results.append({"name": node.name, "category": node.category.value, "technique": tech})
            return
    for tool in node.tools:
        if query in tool.lower():
            results.append({"name": node.name, "category": node.category.value, "tool": tool})
            return
    for sub in node.sub_nodes:
        _search_node(sub, query, results)


def list_all_tools() -> Dict[str, List[str]]:
    tools = {"osint": set(), "pentest": set(), "ctf": set()}
    for cat in tools:
        node = ALL_CATEGORIZED.get(cat)
        if node:
            _collect_tools(node, tools[cat])
    return {k: sorted(v) for k, v in tools.items()}


def _collect_tools(node: MethodologyNode, tool_set: set):
    tool_set.update(node.tools)
    for sub in node.sub_nodes:
        _collect_tools(sub, tool_set)
