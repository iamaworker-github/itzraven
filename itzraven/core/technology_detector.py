"""
Technology Detector — Fingerprints target technologies for reactive agent dispatch.
Detects CMS, frameworks, languages, and infrastructure from HTTP responses.
"""

import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
import httpx
from itzraven.core.logger import get_logger

logger = get_logger()


@dataclass
class Technology:
    name: str
    category: str  # cms, framework, language, server, db, analytics, etc.
    version: Optional[str] = None
    confidence: float = 0.0
    evidence: str = ""


@dataclass
class TechProfile:
    technologies: List[Technology] = field(default_factory=list)
    raw_headers: Dict[str, str] = field(default_factory=dict)
    raw_body_snippets: List[str] = field(default_factory=list)
    status_code: int = 0

    @property
    def detected_cms(self) -> List[str]:
        return [t.name for t in self.technologies if t.category == "cms"]

    @property
    def detected_frameworks(self) -> List[str]:
        return [t.name for t in self.technologies if t.category == "framework"]

    @property
    def detected_languages(self) -> List[str]:
        return [t.name for t in self.technologies if t.category == "language"]

    @property
    def has_cms(self) -> bool:
        return any(t.category == "cms" for t in self.technologies)

    @property
    def has_graphql(self) -> bool:
        return any("graphql" in t.name.lower() for t in self.technologies)

    def get_agent_triggers(self) -> List[str]:
        triggers: List[str] = []
        for t in self.technologies:
            if t.category == "cms":
                triggers.append(f"cms:{t.name.lower()}")
            elif t.category == "framework":
                triggers.append(f"framework:{t.name.lower()}")
            elif t.category == "language":
                triggers.append(f"lang:{t.name.lower()}")
        if self.has_graphql:
            triggers.append("api:graphql")
        if self.status_code == 403 or self.status_code == 401:
            triggers.append("waf:detected")
        return triggers


TECH_SIGNATURES: Dict[str, Dict] = {
    # CMS Signatures
    "wordpress": {
        "category": "cms",
        "headers": {"x-powered-by": re.compile(r"wordpress", re.I)},
        "cookies": [re.compile(r"wordpress_logged_in", re.I)],
        "body_patterns": [
            re.compile(r'wp-content', re.I),
            re.compile(r'wp-includes', re.I),
            re.compile(r'wp-json', re.I),
            re.compile(r'\/wp-admin\/', re.I),
            re.compile(r'<meta name=["\']generator["\'] content=["\']WordPress', re.I),
        ],
        "paths": ["/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-json/", "/xmlrpc.php"],
    },
    "drupal": {
        "category": "cms",
        "headers": {"x-drupal": re.compile(r".*", re.I), "x-generator": re.compile(r"Drupal", re.I)},
        "cookies": [],
        "body_patterns": [
            re.compile(r"Drupal\.signed", re.I),
            re.compile(r'Drupal\.ajax', re.I),
            re.compile(r'mysite\.drupal', re.I),
            re.compile(r'<meta name=["\']Generator["\'] content=["\']Drupal', re.I),
            re.compile(r'sites\/default\/', re.I),
            re.compile(r'\/node\/\d+', re.I),
        ],
        "paths": ["/user/login", "/admin", "/node/1", "/sites/default/", "/CHANGELOG.txt"],
    },
    "joomla": {
        "category": "cms",
        "headers": {"x-content-encoded-by": re.compile(r"Joomla", re.I), "x-generator": re.compile(r"Joomla", re.I)},
        "cookies": [re.compile(r"joomla_remember_me", re.I)],
        "body_patterns": [
            re.compile(r'joomla', re.I),
            re.compile(r'Joomla!', re.I),
            re.compile(r'<meta name=["\']generator["\'] content=["\']Joomla', re.I),
            re.compile(r'\/media\/system\/', re.I),
            re.compile(r'\/components\/com_', re.I),
            re.compile(r'option=com_', re.I),
        ],
        "paths": ["/administrator/", "/components/", "/modules/", "/plugins/"],
    },
    "magento": {
        "category": "cms",
        "headers": {"x-magento": re.compile(r".*", re.I), "x-magento-cache": re.compile(r".*", re.I)},
        "cookies": [re.compile(r"mage-", re.I), re.compile(r"mage-cache", re.I)],
        "body_patterns": [
            re.compile(r'Magento', re.I),
            re.compile(r'mage/requirejs', re.I),
            re.compile(r'mage\/cookies', re.I),
            re.compile(r'Magento_', re.I),
            re.compile(r'static\/version\d+', re.I),
        ],
        "paths": ["/admin", "/static/version/", "/media/", "/setup/"],
    },
    "prestashop": {
        "category": "cms",
        "headers": {"x-powered-by": re.compile(r"PrestaShop", re.I)},
        "cookies": [re.compile(r"PrestaShop", re.I)],
        "body_patterns": [
            re.compile(r'PrestaShop', re.I),
            re.compile(r'prestashop', re.I),
            re.compile(r'\/modules\/', re.I),
            re.compile(r'\/themes\/', re.I),
        ],
        "paths": ["/admin/", "/modules/", "/themes/", "/img/"],
    },
    "moodle": {
        "category": "cms",
        "headers": {},
        "cookies": [re.compile(r"MoodleSession", re.I)],
        "body_patterns": [
            re.compile(r'Moodle', re.I),
            re.compile(r'moodle', re.I),
            re.compile(r'<meta name=["\']generator["\'] content=["\']Moodle', re.I),
            re.compile(r'\/theme\/moodle', re.I),
            re.compile(r'\/pluginfile\.php', re.I),
            re.compile(r'course\/view\.php', re.I),
        ],
        "paths": ["/admin/", "/course/", "/login/", "/pluginfile.php", "/moodle/"],
    },
    # Framework Signatures
    "php": {
        "category": "language",
        "headers": {"x-powered-by": re.compile(r"PHP", re.I), "server": re.compile(r"PHP", re.I)},
        "cookies": [],
        "body_patterns": [re.compile(r'\.php', re.I)],
        "paths": [],
    },
    "nodejs": {
        "category": "language",
        "headers": {"x-powered-by": re.compile(r"Express", re.I), "server": re.compile(r"Node|NodeJS", re.I)},
        "cookies": [],
        "body_patterns": [re.compile(r'__NEXT_DATA__', re.I), re.compile(r'next\.js', re.I), re.compile(r'nuxt', re.I)],
        "paths": [],
    },
    "flask": {
        "category": "framework",
        "headers": {"server": re.compile(r"Werkzeug", re.I), "x-powered-by": re.compile(r"Flask", re.I)},
        "cookies": [re.compile(r"session=", re.I)],
        "body_patterns": [re.compile(r'{{[^}]+}}', re.I)],
        "paths": [],
    },
    "aspnet": {
        "category": "framework",
        "headers": {
            "x-powered-by": re.compile(r"ASP\.NET", re.I),
            "x-aspnet-version": re.compile(r".*", re.I),
            "x-aspnetmvc-version": re.compile(r".*", re.I),
        },
        "cookies": [re.compile(r"ASPXAUTH", re.I), re.compile(r"ASP.NET_SessionId", re.I)],
        "body_patterns": [re.compile(r'__VIEWSTATE', re.I), re.compile(r'__EVENTVALIDATION', re.I)],
        "paths": [],
    },
    "spring": {
        "category": "framework",
        "headers": {"x-application-context": re.compile(r".*", re.I)},
        "cookies": [],
        "body_patterns": [
            re.compile(r'Spring', re.I),
            re.compile(r'Whitelabel Error Page', re.I),
            re.compile(r'spring-web', re.I),
            re.compile(r'\/actuator\/', re.I),
        ],
        "paths": ["/actuator/", "/actuator/health", "/actuator/info", "/actuator/env"],
    },
    "ruby": {
        "category": "language",
        "headers": {"server": re.compile(r"Phusion|Passenger|WEBrick|Thin|Unicorn|Puma", re.I), "x-powered-by": re.compile(r"Ruby|Rails", re.I)},
        "cookies": [re.compile(r"_session", re.I)],
        "body_patterns": [
            re.compile(r'<meta.*csrf-param', re.I),
            re.compile(r'rails', re.I),
            re.compile(r'data-remote', re.I),
        ],
        "paths": [],
    },
    # GraphQL
    "graphql": {
        "category": "api",
        "headers": {},
        "cookies": [],
        "body_patterns": [
            re.compile(r'graphql', re.I),
            re.compile(r'\"query\"\s*:', re.I),
            re.compile(r'\"mutation\"\s*:', re.I),
        ],
        "paths": ["/graphql", "/graphiql", "/v1/graphql", "/api/graphql", "/gql", "/query"],
    },
    # WAF
    "cloudflare": {
        "category": "waf",
        "headers": {"server": re.compile(r"cloudflare", re.I), "cf-ray": re.compile(r".*", re.I)},
        "cookies": [re.compile(r"__cfduid", re.I)],
        "body_patterns": [re.compile(r'Cloudflare', re.I)],
        "paths": [],
    },
    "aws": {
        "category": "cloud",
        "headers": {"server": re.compile(r"AmazonS3|CloudFront|AWS", re.I), "x-amz-": re.compile(r".*", re.I)},
        "cookies": [],
        "body_patterns": [re.compile(r'<Code>NoSuchBucket</Code>', re.I)],
        "paths": [],
    },
    "nginx": {
        "category": "server",
        "headers": {"server": re.compile(r"nginx", re.I)},
        "cookies": [],
        "body_patterns": [],
        "paths": [],
    },
    "apache": {
        "category": "server",
        "headers": {"server": re.compile(r"Apache", re.I)},
        "cookies": [],
        "body_patterns": [],
        "paths": [],
    },
}


def _check_body_patterns(body: str, patterns: List[re.Pattern]) -> bool:
    for p in patterns:
        if p.search(body):
            return True
    return False


def _check_headers(headers: Dict[str, str], sig_headers: Dict[str, re.Pattern]) -> bool:
    for hdr, pattern in sig_headers.items():
        for rh, rv in headers.items():
            if hdr.lower() == rh.lower():
                if pattern.search(rv):
                    return True
    return False


def _check_cookies(headers: Dict[str, str], patterns: List[re.Pattern]) -> bool:
    set_cookie = headers.get("set-cookie", "") + headers.get("Set-Cookie", "")
    for p in patterns:
        if p.search(set_cookie):
            return True
    return False


async def detect_technologies(target_url: str, timeout: float = 15.0) -> TechProfile:
    """Detect technologies on the target."""
    profile = TechProfile()

    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"

    try:
        async with httpx.AsyncClient(timeout=timeout, verify=False, follow_redirects=True) as client:
            resp = await client.get(target_url)
            profile.status_code = resp.status_code
            body = resp.text
            headers = {k.lower(): v for k, v in resp.headers.items()}
            profile.raw_headers = headers
            profile.raw_body_snippets = [body[:3000]]

            for tech_name, signature in TECH_SIGNATURES.items():
                score = 0.0
                evidence_parts = []

                if _check_headers(headers, signature["headers"]):
                    hdr_evidence = [f"header:{h}" for h in signature["headers"]]
                    evidence_parts.extend(hdr_evidence)
                    score += 0.4

                if _check_cookies(headers, signature.get("cookies", [])):
                    evidence_parts.append("cookie_match")
                    score += 0.3

                if signature.get("body_patterns") and _check_body_patterns(body, signature["body_patterns"]):
                    evidence_parts.append("body_pattern")
                    score += 0.3

                if score > 0:
                    profile.technologies.append(Technology(
                        name=tech_name,
                        category=signature["category"],
                        confidence=min(score, 1.0),
                        evidence="; ".join(evidence_parts),
                    ))

            return profile

    except httpx.ConnectError:
        logger.debug(f"Tech detector: Could not connect to {target_url}")
    except httpx.TimeoutException:
        logger.debug(f"Tech detector: Timeout connecting to {target_url}")
    except Exception as e:
        logger.debug(f"Tech detector: Error scanning {target_url}: {e}")

    return profile


async def detect_technologies_deep(target_url: str, timeout: float = 30.0) -> TechProfile:
    """Deep technology detection — crawls common paths for CMS signatures."""
    profile = await detect_technologies(target_url, timeout)

    if not target_url.startswith("http"):
        target_url = f"https://{target_url}"

    target_base = target_url.rstrip("/")

    # Check known paths for CMS
    cms_paths_to_check = [
        ("/wp-admin/", "wordpress"), ("/wp-login.php", "wordpress"),
        ("/user/login", "drupal"), ("/sites/default/", "drupal"),
        ("/administrator/", "joomla"),
        ("/graphql", "graphql"), ("/graphiql", "graphql"),
        ("/actuator/health", "spring"),
    ]

    existing = {t.name.lower() for t in profile.technologies}
    already_detected = {t.name.lower() for t in profile.technologies}

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=False) as client:
            for path, tech_name in cms_paths_to_check:
                if tech_name in already_detected:
                    continue
                try:
                    r = await client.get(f"{target_base}{path}")
                    if r.status_code < 500:
                        profile.technologies.append(Technology(
                            name=tech_name,
                            category=TECH_SIGNATURES.get(tech_name, {}).get("category", "unknown"),
                            confidence=0.5,
                            evidence=f"path:{path} returned {r.status_code}",
                        ))
                except Exception:
                    continue
    except Exception:
        pass

    return profile


class TechnologyDetector:
    """Cached technology detector for reactive agent dispatch."""

    def __init__(self):
        self._cache: Dict[str, TechProfile] = {}

    async def fingerprint(self, target: str, deep: bool = True) -> TechProfile:
        if target in self._cache:
            return self._cache[target]
        if deep:
            profile = await detect_technologies_deep(target)
        else:
            profile = await detect_technologies(target)
        self._cache[target] = profile
        return profile

    def get_cached(self, target: str) -> Optional[TechProfile]:
        return self._cache.get(target)

    def clear_cache(self):
        self._cache.clear()


_detector_instance: Optional[TechnologyDetector] = None


def get_tech_detector() -> TechnologyDetector:
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = TechnologyDetector()
    return _detector_instance
