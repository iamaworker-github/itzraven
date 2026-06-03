"""
Wordlist RAG — target-specific wordlist generation and endpoint enumeration
based on technology fingerprint and vulnerability class.
"""

from typing import Dict, List
from pathlib import Path


TECH_PATHS: Dict[str, List[str]] = {
    "wordpress": [
        "/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-includes/",
        "/wp-json/", "/xmlrpc.php", "/wp-config.php.bak",
        "/wp-content/plugins/", "/wp-content/themes/",
    ],
    "joomla": [
        "/administrator/", "/components/", "/modules/", "/plugins/",
        "/templates/", "/language/", "/libraries/", "/cache/",
        "/configuration.php.bak", "/htaccess.txt",
    ],
    "drupal": [
        "/user/login", "/admin/", "/sites/", "/modules/", "/themes/",
        "/misc/", "/includes/", "/scripts/", "/update.php",
        "/authorize.php", "/install.php",
    ],
    "magento": [
        "/admin/", "/admin_login/", "/index.php/admin/",
        "/static/", "/media/", "/var/", "/app/", "/vendor/",
        "/setup/", "/cron.php",
    ],
    "php": [
        "/info.php", "/phpinfo.php", "/test.php", "/phpmyadmin/",
        "/admin.php", "/config.php", "/db_admin.php",
    ],
    "nodejs": [
        "/package.json", "/.env", "/.env.example", "/robots.txt",
        "/sitemap.xml", "/api/", "/graphql", "/health",
    ],
    "flask": [
        "/admin/", "/api/", "/static/", "/templates/",
        "/config", "/debug", "/routes",
    ],
    "spring": [
        "/actuator/", "/actuator/health", "/actuator/info",
        "/actuator/env", "/actuator/beans", "/actuator/mappings",
        "/swagger-ui/", "/v2/api-docs", "/v3/api-docs",
    ],
    "aspnet": [
        "/web.config", "/bin/", "/App_Data/", "/App_Code/",
        "/admin/", "/api/", "/Swagger/",
    ],
    "rails": [
        "/assets/", "/system/", "/uploads/", "/config/",
        "/db/", "/log/", "/tmp/", "/vendor/",
    ],
}


COMMON_ENDPOINTS = [
    "/robots.txt", "/sitemap.xml", "/.env", "/.git/HEAD",
    "/.git/config", "/.DS_Store", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/security.txt",
    "/.well-known/", "/.well-known/security.txt",
    "/api/", "/api/v1/", "/api/v2/", "/graphql",
    "/swagger.json", "/swagger-ui/", "/openapi.json",
    "/admin/", "/login", "/register", "/signup",
    "/backup/", "/backup.sql", "/dump/",
]


def get_paths_for_tech(tech_name: str) -> List[str]:
    key = tech_name.lower().replace(" ", "")
    for k, v in TECH_PATHS.items():
        if k in key or key in k:
            return v
    return []


def get_endpoints_for_target(target_type: str, techs: List[str]) -> List[str]:
    endpoints = list(COMMON_ENDPOINTS)
    for tech in techs:
        endpoints.extend(get_paths_for_tech(tech))
    return list(set(endpoints))


def get_context_for_tech(tech_name: str) -> str:
    paths = get_paths_for_tech(tech_name)
    if not paths:
        return ""
    return f"[Known endpoints for {tech_name}]\n" + "\n".join(f"  {p}" for p in paths)


def load_custom_wordlist(path: str) -> List[str]:
    try:
        p = Path(path)
        if p.exists():
            return [
                line.strip() for line in p.read_text().splitlines()
                if line.strip() and not line.startswith(("#", "!"))
            ]
    except Exception:
        pass
    return []
