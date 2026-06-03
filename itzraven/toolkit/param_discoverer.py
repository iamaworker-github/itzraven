"""
Parameter Discovery — finds hidden GET/POST parameters using reflection-based detection.

Approach (inspired by Arjun):
1. Send baseline request to fingerprint normal response
2. For each param in wordlist, append it and check if response changes
3. Valid params cause response length delta or content change
"""

import asyncio
import json
import random
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, quote

import httpx

from itzraven.core.logger import get_logger

logger = get_logger()

DEFAULT_PARAMS = [
    "id", "page", "limit", "offset", "sort", "order", "filter", "search", "q",
    "type", "format", "output", "callback", "redirect", "url", "file", "path",
    "debug", "test", "admin", "token", "key", "api", "secret", "view",
    "action", "mode", "method", "func", "do", "op", "cmd", "command",
    "lang", "locale", "theme", "name", "email", "user", "pass", "password",
    "category", "cat", "product", "pid", "sku", "brand", "price",
    "from", "to", "start", "end", "date", "time", "year", "month", "day",
    "status", "state", "tab", "section", "include", "template", "theme",
    "load", "fetch", "read", "get", "download", "upload", "import", "export",
    "show", "hide", "display", "src", "href", "ref", "source",
    "pid", "post_id", "article_id", "news_id", "item_id", "cat_id",
    "uid", "user_id", "author", "owner", "created_by",
    "api_key", "apikey", "api_key", "secret_key", "access_token",
    "xsrf", "csrf", "nonce", "state", "scope", "grant_type",
    "callback_url", "return_url", "redirect_uri", "next", "continue",
    "r", "url", "u", "to", "dest", "destination",
    "img", "image", "photo", "picture", "file", "filename",
    "page", "p", "pg", "page_id", "pages",
    "order", "order_by", "sort_by", "sort", "ordering",
    "search", "q", "query", "keyword", "term", "s",
    "filter", "filters", "where", "condition",
    "limit", "per_page", "count", "max", "size",
    "offset", "start", "from", "skip",
    "format", "fmt", "output", "view", "template",
    "ajax", "json", "xml", "callback", "jsonp",
    "lang", "language", "locale", "hl", "lr",
    "debug", "debug_mode", "test", "dry_run",
    "admin", "sudo", "su", "super",
]

COMMON_PARAMS = [
    "id", "page", "search", "q", "limit", "offset", "sort",
    "filter", "type", "format", "debug", "admin", "token",
    "redirect", "url", "file", "action", "cmd", "lang", "category",
    "product", "uid", "api_key", "callback", "view", "mode",
]


class ParameterDiscoverer:
    def __init__(self, wordlist: Optional[List[str]] = None):
        self.wordlist = wordlist or DEFAULT_PARAMS
        self.timeout = 8.0

    async def discover_get(self, url: str) -> List[str]:
        base = url.rstrip("?&")
        discovered: List[str] = []

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            baseline = await self._get_baseline(client, base)
            if baseline is None:
                return []

            baseline_length = len(baseline)
            baseline_hash = hash(baseline[:2000])

            for param in self.wordlist:
                test_url = f"{base}?{param}=1"
                try:
                    resp = await client.get(test_url)
                    if resp.status_code >= 500:
                        continue
                    length = len(resp.text)
                    delta = abs(length - baseline_length)
                    resp_hash = hash(resp.text[:2000])

                    if resp_hash != baseline_hash and delta > 5:
                        discovered.append(param)
                        logger.debug(f"  [param] Found: {param} (delta={delta})")
                except Exception:
                    continue

        return list(set(discovered))

    async def discover_post(self, url: str) -> List[str]:
        discovered: List[str] = []

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            baseline = await self._get_baseline(client, url, method="POST")
            if baseline is None:
                return []

            baseline_length = len(baseline)
            baseline_hash = hash(baseline[:2000])

            for param in self.wordlist:
                try:
                    resp = await client.post(url, data={param: "1"})
                    if resp.status_code >= 500:
                        continue
                    length = len(resp.text)
                    delta = abs(length - baseline_length)
                    resp_hash = hash(resp.text[:2000])

                    if resp_hash != baseline_hash and delta > 5:
                        discovered.append(param)
                        logger.debug(f"  [param] Found POST: {param} (delta={delta})")
                except Exception:
                    continue

        return list(set(discovered))

    async def discover(self, url: str, method: str = "GET") -> List[str]:
        if method.upper() == "POST":
            return await self.discover_post(url)
        return await self.discover_get(url)

    async def _get_baseline(self, client: httpx.AsyncClient, url: str, method: str = "GET") -> Optional[str]:
        try:
            if method == "POST":
                resp = await client.post(url)
            else:
                resp = await client.get(url)
            if resp.status_code < 500:
                return resp.text
        except Exception:
            pass
        return None


async def discover_parameters(url: str, method: str = "GET") -> List[str]:
    d = ParameterDiscoverer()
    return await d.discover(url, method)
