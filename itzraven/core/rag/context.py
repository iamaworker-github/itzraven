"""
RAG Context Builder — unified context injection for LLM prompts.

Combines CVE data, methodologies, wordlists, and past findings into
a single context string that gets injected into the agent's system prompt.
"""

from typing import Dict, List, Optional, Any

from itzraven.core.rag.cve_db import get_cve_db
from itzraven.core.rag import methodology as meth
from itzraven.core.rag import wordlist as wl
from itzraven.core.logger import get_logger

logger = get_logger()


class RAGContext:
    def __init__(self):
        self._cve_db = get_cve_db()
        self._enabled: bool = True

    def set_enabled(self, enabled: bool):
        self._enabled = enabled

    def build_context(
        self,
        target: str = "",
        technologies: Optional[List[str]] = None,
        vulnerability_focus: str = "",
        include_cves: bool = True,
        include_methodologies: bool = True,
        include_endpoints: bool = True,
    ) -> str:
        if not self._enabled:
            return ""

        parts: List[str] = []
        techs = technologies or []

        if include_cves and techs:
            for tech in techs:
                ctx = self._cve_db.get_context_for_tech(tech)
                if ctx:
                    parts.append(ctx)

        if include_cves and vulnerability_focus:
            ctx = self._cve_db.get_context_for_query(vulnerability_focus)
            if ctx:
                parts.append(ctx)

        if include_methodologies:
            query_parts = [vulnerability_focus, *techs, target]
            query = " ".join(q for q in query_parts if q)
            ctx = meth.get_context_for_query(query)
            if ctx:
                parts.append(ctx)

        if include_endpoints and techs:
            for tech in techs:
                ctx = wl.get_context_for_tech(tech)
                if ctx:
                    parts.append(ctx)

        if include_endpoints:
            common = wl.get_endpoints_for_target("", techs)
            if common:
                parts.append("[Common endpoints to check]\n" + "\n".join(f"  {p}" for p in common[:20]))

        return "\n\n".join(parts)

    def build_system_prompt_suffix(self, **kwargs) -> str:
        context = self.build_context(**kwargs)
        if not context:
            return ""
        return f"\n\n## RAG Context\n{context}"

    def inject_into_prompt(self, prompt: str, **kwargs) -> str:
        suffix = self.build_system_prompt_suffix(**kwargs)
        if suffix:
            return prompt + suffix
        return prompt


_rag_context: Optional[RAGContext] = None


def get_rag_context() -> RAGContext:
    global _rag_context
    if _rag_context is None:
        _rag_context = RAGContext()
    return _rag_context
