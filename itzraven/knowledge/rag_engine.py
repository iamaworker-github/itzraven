from typing import List, Dict, Any, Optional

from itzraven.core.logger import get_logger
from itzraven.knowledge.writeup_store import WriteupStore
from itzraven.knowledge.payload_store import PayloadStore

logger = get_logger(__name__)


class RAGEngine:
    """Retrieval-Augmented Generation engine for security knowledge."""

    def __init__(self):
        self.writeup_store = WriteupStore()
        self.payload_store = PayloadStore()

    def search(self, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
        return self.writeup_store.search(query, limit=top_k)

    def search_payloads(self, vuln_class: str) -> List[Dict[str, str]]:
        return self.payload_store.search(vuln_class)

    def search_techniques(self, vuln_class: str) -> List[Dict[str, Any]]:
        return self.writeup_store.search("", vuln_class=vuln_class, limit=10)
