"""
Itzraven OSINT Toolkit — Multi-source passive intelligence gathering.
GitHub, Domain, Email, Username, Social Media, Public Records.
"""
__all__ = [
    "GitHubOSINT", "DomainOSINT", "UsernameOSINT",
    "EmailOSINT", "SocialMediaOSINT", "PublicRecordsOSINT",
]
import asyncio
import json
import re
from typing import Dict, List, Optional, Set, Any
from urllib.parse import urlparse

import httpx

from itzraven.core.logger import get_logger

logger = get_logger()


class GitHubOSINT:
    """GitHub OSINT — user/org info, commit emails, repo analysis, code search."""

    def __init__(self, token: str = ""):
        self.token = token
        self.headers = {"Authorization": f"token {token}"} if token else {}
        self.headers["User-Agent"] = "ItzravenOSINT/1.0"
        self.base = "https://api.github.com"

    async def user_info(self, username: str) -> Dict:
        async with httpx.AsyncClient(headers=self.headers) as c:
            r = await c.get(f"{self.base}/users/{username}")
            return r.json() if r.status_code == 200 else {"error": f"HTTP {r.status_code}"}

    async def user_repos(self, username: str, max_pages: int = 3) -> List[Dict]:
        repos = []
        async with httpx.AsyncClient(headers=self.headers) as c:
            for page in range(1, max_pages + 1):
                r = await c.get(f"{self.base}/users/{username}/repos",
                                params={"per_page": 100, "page": page, "sort": "updated"})
                if r.status_code != 200:
                    break
                repos.extend(r.json())
        return repos

    async def commit_emails(self, owner: str, repo: str, max_pages: int = 3) -> Set[str]:
        emails = set()
        async with httpx.AsyncClient(headers=self.headers) as c:
            for page in range(1, max_pages + 1):
                r = await c.get(f"{self.base}/repos/{owner}/{repo}/commits",
                                params={"per_page": 100, "page": page})
                if r.status_code != 200:
                    break
                for commit in r.json():
                    author = commit.get("commit", {}).get("author", {})
                    email = author.get("email", "")
                    if email and "@" in email:
                        emails.add(email.strip("<>").lower())
        return emails

    async def org_info(self, org: str) -> Dict:
        async with httpx.AsyncClient(headers=self.headers) as c:
            r = await c.get(f"{self.base}/orgs/{org}")
            return r.json() if r.status_code == 200 else {}

    async def search_code(self, query: str, org: str = "") -> List[Dict]:
        q = f"org:{org} {query}" if org else query
        async with httpx.AsyncClient(headers=self.headers) as c:
            r = await c.get(f"{self.base}/search/code", params={"q": q, "per_page": 50})
            return r.json().get("items", []) if r.status_code == 200 else []

    async def search_users(self, query: str) -> List[Dict]:
        async with httpx.AsyncClient(headers=self.headers) as c:
            r = await c.get(f"{self.base}/search/users", params={"q": query})
            return r.json().get("items", []) if r.status_code == 200 else []


class DomainOSINT:
    """Multi-source domain intelligence — crt.sh, SecurityTrails, DNS, WHOIS."""

    async def crtsh_subdomains(self, domain: str) -> Set[str]:
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as c:
                r = await c.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if r.status_code != 200:
                    return set()
                subs = set()
                for entry in r.json():
                    name = entry.get("name_value", "")
                    subs.update(n.strip() for n in name.split("\n") if n.strip())
                return {s for s in subs if s.endswith(domain)}
        except Exception as e:
            logger.debug(f"crtsh failed: {e}")
            return set()

    async def securitytrails_subdomains(self, domain: str, api_key: str = "") -> Set[str]:
        if not api_key:
            return set()
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers={"APIKEY": api_key},
                )
                data = r.json()
                subs = data.get("subdomains", [])
                return {f"{sub}.{domain}" for sub in subs}
        except Exception:
            return set()

    async def dns_records(self, domain: str) -> Dict[str, List[str]]:
        records = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}
        try:
            import dns.resolver
            for rtype in records:
                try:
                    answers = await asyncio.get_event_loop().run_in_executor(
                        None, lambda rt=rtype: [str(r) for r in dns.resolver.resolve(domain, rt)]
                    )
                    records[rtype] = answers[:10]
                except Exception:
                    pass
        except ImportError:
            pass
        return records

    async def urlscan_domain(self, domain: str, api_key: str = "") -> Dict:
        if not api_key:
            return {}
        try:
            headers = {"API-Key": api_key} if api_key else {}
            async with httpx.AsyncClient(headers=headers, timeout=10) as c:
                r = await c.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}")
                return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    async def full_recon(self, domain: str, st_api_key: str = "") -> Dict:
        subs = await self.crtsh_subdomains(domain)
        st_subs = await self.securitytrails_subdomains(domain, st_api_key)
        all_subs = subs | st_subs
        dns = await self.dns_records(domain)
        return {"subdomains": sorted(all_subs)[:100], "dns": dns}


class UsernameOSINT:
    """Check username across 50+ platforms (sherlock/maigret-style)."""

    PLATFORMS = {
        "github": "https://github.com/{u}",
        "twitter": "https://twitter.com/{u}",
        "reddit": "https://reddit.com/user/{u}",
        "instagram": "https://instagram.com/{u}",
        "medium": "https://medium.com/@{u}",
        "hackerone": "https://hackerone.com/{u}",
        "bugcrowd": "https://bugcrowd.com/{u}",
        "keybase": "https://keybase.io/{u}",
        "telegram": "https://t.me/{u}",
        "pinterest": "https://pinterest.com/{u}",
        "twitch": "https://twitch.tv/{u}",
        "tiktok": "https://tiktok.com/@{u}",
        "youtube": "https://youtube.com/@{u}",
        "facebook": "https://facebook.com/{u}",
        "linkedin": "https://linkedin.com/in/{u}",
        "devto": "https://dev.to/{u}",
        "hackernews": "https://news.ycombinator.com/user?id={u}",
        "producthunt": "https://producthunt.com/@{u}",
        "behance": "https://behance.net/{u}",
        "dribbble": "https://dribbble.com/{u}",
        "gitlab": "https://gitlab.com/{u}",
        "bitbucket": "https://bitbucket.org/{u}",
        "replit": "https://replit.com/@{u}",
        "codepen": "https://codepen.io/{u}",
        "pastebin": "https://pastebin.com/u/{u}",
        "slideshare": "https://slideshare.net/{u}",
        "quora": "https://quora.com/profile/{u}",
        "wikipedia": "https://en.wikipedia.org/wiki/User:{u}",
        "pypi": "https://pypi.org/user/{u}",
        "npm": "https://npmjs.com/~{u}",
        "docker": "https://hub.docker.com/u/{u}",
        "flickr": "https://flickr.com/people/{u}",
        "soundcloud": "https://soundcloud.com/{u}",
        "vimeo": "https://vimeo.com/{u}",
        "spotify": "https://open.spotify.com/user/{u}",
        "patreon": "https://patreon.com/{u}",
        "etsy": "https://etsy.com/shop/{u}",
        "wordpress": "https://{u}.wordpress.com",
        "gravatar": "https://gravatar.com/{u}",
        "aboutme": "https://about.me/{u}",
        "angelco": "https://angel.co/u/{u}",
        "goodreads": "https://goodreads.com/{u}",
        "imgur": "https://imgur.com/user/{u}",
        "disqus": "https://disqus.com/by/{u}",
        "hubpages": "https://hubpages.com/@{u}",
        "buymeacoffee": "https://buymeacoffee.com/{u}",
        "kofi": "https://ko-fi.com/{u}",
        "ctftime": "https://ctftime.org/user/{u}",
        "tryhackme": "https://tryhackme.com/p/{u}",
        "hackthebox": "https://app.hackthebox.eu/profile/{u}",
    }

    async def check(self, username: str, max_sites: int = 30) -> List[Dict]:
        results = []
        sites = list(self.PLATFORMS.items())[:max_sites]
        async with httpx.AsyncClient(timeout=5, follow_redirects=False) as c:
            for site_name, url_pattern in sites:
                url = url_pattern.format(u=username)
                try:
                    r = await c.get(url)
                    if r.status_code == 200:
                        results.append({"site": site_name, "url": url, "status": "found"})
                    elif r.status_code in (301, 302):
                        loc = r.headers.get("location", "")
                        if "notfound" not in loc.lower() and "404" not in loc:
                            results.append({"site": site_name, "url": url, "status": "redirect", "location": loc})
                except Exception:
                    continue
        return results


class EmailOSINT:
    """Email intelligence — breach checking, reputation, verification."""

    async def check_hibp(self, email: str, api_key: str = "") -> List[Dict]:
        if not api_key:
            return []
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={"hibp-api-key": api_key, "user-agent": "ItzravenOSINT"},
                )
                if r.status_code == 200:
                    return r.json()
        except Exception:
            pass
        return []

    async def emailrep(self, email: str, api_key: str = "") -> Dict:
        try:
            headers = {"Key": api_key} if api_key else {}
            async with httpx.AsyncClient(headers=headers, timeout=10) as c:
                r = await c.get(f"https://emailrep.io/{email}")
                return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    async def extract_from_web(self, domain: str) -> Set[str]:
        emails = set()
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as c:
                r = await c.get(f"https://{domain}")
                text = r.text
                found = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.(com|org|net|io|dev|app|me)", text)
                for f in found:
                    if domain in f:
                        emails.add(f.lower())
        except Exception:
            pass
        return emails


class SocialMediaOSINT:
    """Social media profile discovery and analysis."""

    async def search_name(self, full_name: str) -> List[Dict]:
        query = full_name.replace(" ", "+")
        results = []
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as c:
            searches = [
                ("google", f"https://www.google.com/search?q={query}"),
                ("linkedin", f"https://www.linkedin.com/pub/dir/?first={full_name.split()[0]}&last={' '.join(full_name.split()[1:])}"),
                ("crunchbase", f"https://www.crunchbase.com/textsearch?q={query}"),
            ]
            for name, url in searches:
                try:
                    r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
                    if r.status_code == 200:
                        results.append({"source": name, "url": url, "status": "checked"})
                except Exception:
                    continue
        return results


class PublicRecordsOSINT:
    """Public records and business registration lookups."""

    async def opencorporates_search(self, company: str) -> List[Dict]:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"https://api.opencorporates.com/v0.4/companies/search",
                                params={"q": company, "per_page": 10})
                if r.status_code == 200:
                    data = r.json()
                    return [c["company"] for c in data.get("results", {}).get("companies", [])]
        except Exception:
            pass
        return []

    async def wayback_pages(self, domain: str, limit: int = 50) -> List[str]:
        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit={limit}")
                if r.status_code == 200 and len(r.json()) > 1:
                    return [row[2] for row in r.json()[1:] if len(row) > 2]
        except Exception:
            pass
        return []
