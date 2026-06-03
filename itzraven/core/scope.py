import fnmatch
import ipaddress
import re
from pathlib import Path
from typing import List, Optional, Set
from urllib.parse import urlparse

import yaml

from itzraven.core.logger import get_logger

logger = get_logger()


class ScopeValidator:
    def __init__(self):
        self._allow_patterns: List[str] = []
        self._exclude_patterns: List[str] = []
        self._allowed_cidrs: List[ipaddress.IPv4Network] = []
        self._excluded_cidrs: List[ipaddress.IPv4Network] = []
        self._allowed_domains: Set[str] = set()
        self._excluded_domains: Set[str] = set()

    def add_scope(self, pattern: str) -> None:
        self._allow_patterns.append(pattern)
        if self._is_cidr(pattern):
            self._allowed_cidrs.append(ipaddress.IPv4Network(pattern, strict=False))
        elif not self._is_wildcard(pattern):
            domain = self._extract_domain(pattern)
            if domain:
                self._allowed_domains.add(domain)

    def add_exclude_scope(self, pattern: str) -> None:
        self._exclude_patterns.append(pattern)
        if self._is_cidr(pattern):
            self._excluded_cidrs.append(ipaddress.IPv4Network(pattern, strict=False))
        elif not self._is_wildcard(pattern):
            domain = self._extract_domain(pattern)
            if domain:
                self._excluded_domains.add(domain)

    def load_from_file(self, path: str) -> None:
        path_obj = Path(path)
        if not path_obj.exists():
            logger.warning(f"Scope file not found: {path}")
            return
        try:
            data = yaml.safe_load(path_obj.read_text())
            if not data:
                return
            for pattern in data.get("scope", []):
                self.add_scope(str(pattern))
            for pattern in data.get("exclude", []):
                self.add_exclude_scope(str(pattern))
            logger.info(f"Loaded {len(self._allow_patterns)} scope + {len(self._exclude_patterns)} exclude rules")
        except Exception as e:
            logger.error(f"Failed to load scope file: {e}")

    def is_in_scope(self, target: str) -> bool:
        if self._is_explicitly_excluded(target):
            return False

        if not self._allow_patterns and not self._allowed_cidrs and not self._allowed_domains:
            return True

        return self._matches_any_pattern(target, self._allow_patterns) or self._matches_cidr(target)

    def validate_command(self, cmd: str, scope_list: Optional[List[str]] = None) -> bool:
        urls = self._extract_urls_from_command(cmd)
        for url in urls:
            if not self.is_in_scope(url):
                logger.warning(f"Blocking command — target {url} is out of scope")
                return False
        return True

    def _is_explicitly_excluded(self, target: str) -> bool:
        if self._matches_any_pattern(target, self._exclude_patterns):
            return True
        for cidr in self._excluded_cidrs:
            try:
                ip = ipaddress.IPv4Address(self._resolve_to_ip(target))
                if ip in cidr:
                    return True
            except (ValueError, ipaddress.AddressValueError):
                pass
        domain = self._extract_domain(target)
        if domain and domain in self._excluded_domains:
            return True
        return False

    def _matches_any_pattern(self, target: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if self._is_wildcard(pattern):
                if fnmatch.fnmatch(target, pattern):
                    return True
                domain = self._extract_domain(target)
                if domain and fnmatch.fnmatch(domain, pattern):
                    return True
            else:
                if pattern in target:
                    return True
                domain = self._extract_domain(target)
                if domain and domain == pattern:
                    return True
        return False

    def _matches_cidr(self, target: str) -> bool:
        try:
            ip = ipaddress.IPv4Address(self._resolve_to_ip(target))
            for cidr in self._allowed_cidrs:
                if ip in cidr:
                    return True
        except (ValueError, ipaddress.AddressValueError):
            pass
        return False

    @staticmethod
    def _is_cidr(pattern: str) -> bool:
        return "/" in pattern and any(c.isdigit() for c in pattern)

    @staticmethod
    def _is_wildcard(pattern: str) -> bool:
        return "*" in pattern or "?" in pattern

    @staticmethod
    def _extract_domain(target: str) -> Optional[str]:
        parsed = urlparse(target)
        host = parsed.hostname or target
        return host.strip() if host else None

    @staticmethod
    def _resolve_to_ip(target: str) -> str:
        import socket
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return target

    @staticmethod
    def _extract_urls_from_command(cmd: str) -> List[str]:
        url_pattern = re.compile(r'https?://[^\s"\'<>]+')
        return url_pattern.findall(cmd)

    def get_summary(self) -> dict:
        return {
            "allow_patterns": self._allow_patterns,
            "exclude_patterns": self._exclude_patterns,
            "allowed_domains": list(self._allowed_domains),
            "excluded_domains": list(self._excluded_domains),
            "allowed_cidrs": [str(c) for c in self._allowed_cidrs],
            "excluded_cidrs": [str(c) for c in self._excluded_cidrs],
        }
