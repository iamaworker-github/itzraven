import re
import os
from typing import List, Set, Optional

from itzraven.core.logger import get_logger

logger = get_logger()

FLAG_PATTERNS = [
    re.compile(r"flag\{[^}]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[^}]+\}", re.IGNORECASE),
    re.compile(r"FLAG\{[^}]+\}", re.IGNORECASE),
    re.compile(r"[A-Za-z0-9+/]{20,}={0,2}"),  # base64-like blobs
    re.compile(r"[0-9a-f]{32,}", re.IGNORECASE),  # MD5/SHA-like hex strings
]


class FlagExtractor:
    def __init__(self):
        self.patterns = FLAG_PATTERNS

    def extract(self, text: str) -> List[str]:
        if not text:
            return []
        found: Set[str] = set()
        for pattern in self.patterns:
            for match in pattern.finditer(text):
                found.add(match.group(0))
        return sorted(found)

    def extract_from_file(self, path: str) -> List[str]:
        if not os.path.isfile(path):
            logger.warning(f"File not found: {path}")
            return []
        try:
            with open(path, "rb") as f:
                raw = f.read()
            try:
                text = raw.decode("utf-8", errors="replace")
            except UnicodeDecodeError:
                text = raw.decode("latin-1", errors="replace")
            return self.extract(text)
        except Exception as e:
            logger.error(f"Error reading {path}: {e}")
            return []

    def extract_from_output(self, output: str) -> List[str]:
        return self.extract(output)
