import hashlib
import struct
from typing import Set, Optional, List
from dataclasses import dataclass, field


@dataclass
class BloomFilter:
    capacity: int = 100_000
    error_rate: float = 0.001
    _bitarray: int = 0
    _num_hash: int = field(init=False)
    _size: int = field(init=False)
    _count: int = 0

    def __post_init__(self):
        import math
        self._size = self._optimal_size(self.capacity, self.error_rate)
        self._num_hash = self._optimal_hashes(self.capacity, self._size)
        self._bitarray = 0

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        import math
        return int(-n * math.log(p) / (math.log(2) ** 2))

    @staticmethod
    def _optimal_hashes(n: int, m: int) -> int:
        import math
        return max(1, int((m / n) * math.log(2)))

    def _hashes(self, item: str) -> List[int]:
        result = []
        for i in range(self._num_hash):
            h = hashlib.sha256(f"{item}:{i}".encode()).digest()
            val = struct.unpack(">Q", h[:8])[0]
            result.append(val % self._size)
        return result

    def add(self, item: str) -> bool:
        was_present = True
        for h in self._hashes(item):
            bit = 1 << (h % 64)
            if not (self._bitarray & bit):
                was_present = False
            self._bitarray |= bit
        if not was_present:
            self._count += 1
        return was_present

    def check(self, item: str) -> bool:
        for h in self._hashes(item):
            bit = 1 << (h % 64)
            if not (self._bitarray & bit):
                return False
        return True

    @property
    def count(self) -> int:
        return self._count

    @property
    def size(self) -> int:
        return self._size

    def clear(self):
        self._bitarray = 0
        self._count = 0


class FindingDeduplicator:
    _instance: Optional["FindingDeduplicator"] = None

    def __init__(self, capacity: int = 100_000):
        self._bloom = BloomFilter(capacity=capacity)
        self._exact_set: Set[str] = set()

    def is_duplicate(self, finding_title: str, agent_name: str, evidence: str = "") -> bool:
        key = f"{agent_name}:{finding_title}:{hash(evidence)}"
        if key in self._exact_set:
            return True
        if self._bloom.check(key):
            if key in self._exact_set:
                return True
        self._exact_set.add(key)
        self._bloom.add(key)
        return False

    def clear(self):
        self._bloom.clear()
        self._exact_set.clear()

    @classmethod
    def get_instance(cls) -> "FindingDeduplicator":
        if cls._instance is None:
            cls._instance = FindingDeduplicator()
        return cls._instance


_finding_dedup: Optional[FindingDeduplicator] = None


def get_finding_dedup() -> FindingDeduplicator:
    global _finding_dedup
    if _finding_dedup is None:
        _finding_dedup = FindingDeduplicator()
    return _finding_dedup
