"""
Robust JSON extraction utilities for LLM responses.

Handles:
- Direct JSON objects
- Markdown-fenced blocks (```json ... ``` and ``` ... ```)
- Noisy text with embedded JSON
- Balanced brace matching
"""

import json
import re
from typing import Any, Dict, List, Optional, TypeVar, Union

T = TypeVar("T")


def extract_json(text: str) -> Optional[Union[Dict, List]]:
    if not text or not text.strip():
        return None
    text = text.strip()

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    candidates = _extract_fenced_blocks(text)
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    candidates = _extract_balanced_json_candidates(text)
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue

    return None


def extract_json_safe(text: str, default: Any = None) -> Any:
    result = extract_json(text)
    return result if result is not None else default


def _extract_fenced_blocks(text: str) -> List[str]:
    blocks = []
    pattern = r"```(?:json)?\s*\n?(.*?)\n?```"
    matches = re.findall(pattern, text, re.DOTALL)
    for m in matches:
        m = m.strip()
        if m:
            blocks.append(m)
    return blocks


def _extract_balanced_json_candidates(text: str) -> List[str]:
    candidates = []
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                candidate = text[start:i + 1]
                if len(candidate) >= 2:
                    candidates.append(candidate)
                start = -1
    return candidates
