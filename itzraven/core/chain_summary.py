"""
Chain Summarization — PentAGI-inspired AST-based context compression.

Preserves critical QA pairs while drastically reducing token usage.
Replaces naive truncation with structured summarization.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class QAEntry:
    question: str
    answer: str
    importance: float = 0.5  # 0.0 to 1.0
    action_type: str = ""
    tags: List[str] = field(default_factory=list)

    def token_count(self) -> int:
        return len(self.question.split()) + len(self.answer.split())

    def compress(self, max_tokens: int = 50) -> "QAEntry":
        q_tokens = self.question.split()
        a_tokens = self.answer.split()
        budget = max_tokens - len(q_tokens)
        if budget < 10:
            q_tokens = q_tokens[:10]
            a_tokens = []
        elif len(a_tokens) > budget:
            a_tokens = a_tokens[:budget]
        return QAEntry(question=" ".join(q_tokens), answer=" ".join(a_tokens), importance=self.importance, action_type=self.action_type, tags=self.tags)


class ChainSummarizer:
    def __init__(self, max_context_tokens: int = 2000, qa_token_budget: int = 300):
        self._history: Dict[str, List[QAEntry]] = {}
        self._max_context = max_context_tokens
        self._qa_budget = qa_token_budget

    def record(self, session_id: str, question: str, answer: str, action_type: str = "", importance: float = 0.5, tags: Optional[List[str]] = None):
        if session_id not in self._history:
            self._history[session_id] = []
        entry = QAEntry(question=question, answer=answer, importance=importance, action_type=action_type, tags=tags or [])
        self._history[session_id].append(entry)

    def summarize(self, session_id: str, max_tokens: Optional[int] = None) -> str:
        budget = max_tokens or self._qa_budget
        entries = self._history.get(session_id, [])
        if not entries:
            return ""

        # Sort by importance (higher first), then recency
        sorted_entries = sorted(entries, key=lambda e: (-e.importance, len(self._history[session_id]) - entries.index(e)))

        compressed: List[QAEntry] = []
        used = 0
        for e in sorted_entries:
            tokens = e.token_count()
            if used + tokens > budget:
                ce = e.compress(max_tokens=budget - used)
                if ce.token_count() > 0:
                    compressed.append(ce)
                break
            compressed.append(e)
            used += tokens

        # Build concise summary
        lines = ["<chain-summary>"]
        for e in compressed:
            action_tag = f" [{e.action_type}]" if e.action_type else ""
            lines.append(f"  Q: {e.question[:100]}{action_tag}")
            lines.append(f"  A: {e.answer[:200]}")
            if e.importance > 0.7:
                lines.append(f"  (key finding)")
            lines.append("")
        lines.append(f"  History: {len(entries)} actions, {len(compressed)} summarized")
        lines.append("</chain-summary>")
        return "\n".join(lines)

    def clear(self, session_id: str):
        self._history.pop(session_id, None)

    def get_stats(self, session_id: str) -> Dict[str, Any]:
        entries = self._history.get(session_id, [])
        if not entries:
            return {"total": 0, "high_importance": 0, "action_types": {}}
        action_types: Dict[str, int] = {}
        high_imp = 0
        for e in entries:
            action_types[e.action_type] = action_types.get(e.action_type, 0) + 1
            if e.importance > 0.7:
                high_imp += 1
        return {"total": len(entries), "high_importance": high_imp, "action_types": action_types}


_chain_summarizer: Optional[ChainSummarizer] = None


def get_chain_summarizer() -> ChainSummarizer:
    global _chain_summarizer
    if _chain_summarizer is None:
        _chain_summarizer = ChainSummarizer()
    return _chain_summarizer
