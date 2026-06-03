"""
RAG (Retrieval-Augmented Generation) System for security context injection.

Modules:
  - cve_db: CVE lookup and retrieval
  - methodology: Pentesting methodology/playbook retrieval
  - wordlist: Target-specific wordlist generation
  - context: Unified context builder for LLM prompts
"""

from itzraven.core.rag.cve_db import get_cve_db, CVEDatabase
from itzraven.core.rag.context import get_rag_context, RAGContext

