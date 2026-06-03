"""
Methodology RAG — retrieves pentesting methodologies, attack patterns, and
testing strategies based on target type, technology, and vulnerability class.
"""

from typing import Dict, List, Optional


METHODOLOGIES = {
    "web_general": """
General Web Application Testing:
1. Reconnaissance: subdomains, endpoints, tech fingerprinting
2. Authentication: test login bypass, JWT, OAuth, session management
3. Authorization: IDOR, privilege escalation, role manipulation
4. Input Validation: SQLi, XSS, SSTI, LFI, Command Injection, SSRF
5. Business Logic: workflow bypass, race conditions, parameter manipulation
6. API Testing: rate limiting, mass assignment, injection, auth
7. Configuration: default creds, debug endpoints, misconfigured CORS/headers
""",
    "sqli_testing": """
SQL Injection Testing Methodology:
1. Identify injectable params (GET, POST, cookies, headers)
2. Test with: ', ", ', ', ", ", ', %27, %22
3. Time-based: ' OR SLEEP(5)--, ' WAITFOR DELAY '0:0:5'--
4. Union-based: ' UNION SELECT 1,2,3...--
5. Error-based: extract info from error messages
6. Blind: true/false comparison with AND 1=1 / AND 1=2
7. Out-of-band: use DNS/HTTP exfiltration if available
8. DB fingerprinting: specific syntax for MySQL, MSSQL, Oracle, PostgreSQL
""",
    "xss_testing": """
Cross-Site Scripting Testing:
1. Reflected: test every input parameter
2. Stored: inject into forms, comments, profile fields
3. DOM-based: analyze client-side JS for sink sources
4. Context-aware encoding: HTML context, JS context, URL context
5. Polyglot payloads for WAF bypass
6. Test CSP headers for bypass opportunities
""",
    "api_testing": """
API Security Testing:
1. Auth: missing auth, broken JWT, token in URL
2. Rate limiting: brute force, DoS via unthrottled endpoints
3. Mass assignment: extra fields in JSON body
4. Injection: SQLi/NoSQLi in params, XXE in XML
5. IDOR: iterate through object IDs
6. Pagination: parameter manipulation for data exposure
7. HTTP methods: test PUT/DELETE/PATCH on sensitive endpoints
8. Content-type switching: JSON vs XML vs form-encoded
""",
    "cloud_testing": """
Cloud Security Testing:
1. S3 bucket enumeration, misconfiguration, public access
2. IAM role/policy review, privilege escalation paths
3. Metadata service access (169.254.169.254)
4. SSRF to cloud metadata
5. KMS/key management review
6. CloudTrail/audit log review
7. Lambda function injection/invocation
8. Container escape via misconfigured ECS/EKS
""",
    "network_testing": """
Network Penetration Testing:
1. Port scanning (top 1000 + service detection)
2. Service version fingerprinting
3. Default credential testing
4. Known CVE checks per service version
5. TLS/SSL configuration review
6. SNMP enumeration
7. SMB/RPC enumeration
8. DNS zone transfer attempts
""",
}


METHODOLOGY_INDEX: Dict[str, List[str]] = {
    "web": ["web_general", "sqli_testing", "xss_testing", "api_testing"],
    "api": ["api_testing", "web_general"],
    "sqli": ["sqli_testing"],
    "xss": ["xss_testing"],
    "cloud": ["cloud_testing"],
    "aws": ["cloud_testing"],
    "network": ["network_testing"],
    "login": ["web_general"],
    "auth": ["web_general"],
    "jwt": ["web_general"],
    "idor": ["web_general"],
    "ssrf": ["web_general", "cloud_testing"],
}


def get_methodology(key: str) -> Optional[str]:
    return METHODOLOGIES.get(key)


def get_methodologies_for_query(query: str) -> List[str]:
    q = query.lower()
    results = []
    for keyword, keys in METHODOLOGY_INDEX.items():
        if keyword in q:
            for k in keys:
                meth = METHODOLOGIES.get(k)
                if meth and meth not in results:
                    results.append(meth)
    if not results:
        default = METHODOLOGIES.get("web_general")
        if default:
            results.append(default)
    return results


def get_context_for_query(query: str) -> str:
    methodologies = get_methodologies_for_query(query)
    if not methodologies:
        return ""
    lines = ["[Security Testing Methodologies]"]
    for m in methodologies:
        lines.append(m)
    return "\n".join(lines)


def get_all_methodologies() -> Dict[str, str]:
    return dict(METHODOLOGIES)
