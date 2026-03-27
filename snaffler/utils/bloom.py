"""Simple bloom filter for probabilistic set membership testing."""

import hashlib
import math


class BloomFilter:
    """Space-efficient probabilistic set. False positives possible, false negatives never."""

    def __init__(self, expected_items: int, false_positive_rate: float = 0.01):
        # Calculate optimal size and hash count
        self._size = max(1, int(-expected_items * math.log(false_positive_rate) / (math.log(2) ** 2)))
        self._hash_count = max(1, int(self._size / expected_items * math.log(2)))
        self._bits = bytearray(self._size // 8 + 1)
        self._count = 0

    def add(self, item: str):
        for i in range(self._hash_count):
            idx = self._hash(item, i) % self._size
            self._bits[idx // 8] |= (1 << (idx % 8))
        self._count += 1

    def __contains__(self, item: str) -> bool:
        for i in range(self._hash_count):
            idx = self._hash(item, i) % self._size
            if not (self._bits[idx // 8] & (1 << (idx % 8))):
                return False
        return True  # probably in the set (may be false positive)

    def __len__(self):
        return self._count

    @staticmethod
    def _hash(item: str, seed: int) -> int:
        h = hashlib.md5(f"{seed}:{item}".encode(), usedforsecurity=False)
        return int.from_bytes(h.digest()[:8], 'little')
