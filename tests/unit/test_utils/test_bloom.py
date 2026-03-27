"""Tests for the bloom filter used in resume file dedup."""

import sys

from snaffler.utils.bloom import BloomFilter


# ---------- basic add / contains ----------


def test_add_and_contains():
    """Added items are found in the filter."""
    bf = BloomFilter(100)
    bf.add("hello")
    bf.add("world")
    assert "hello" in bf
    assert "world" in bf


def test_missing_item_not_found():
    """Items never added are (almost certainly) not found."""
    bf = BloomFilter(100)
    bf.add("hello")
    assert "goodbye" not in bf
    assert "xyz" not in bf


def test_empty_filter_returns_false():
    """Empty filter returns False for everything."""
    bf = BloomFilter(1000)
    assert "anything" not in bf
    assert "" not in bf
    assert "//HOST/SHARE/file.txt" not in bf


def test_len_tracks_additions():
    """__len__ returns the number of add() calls."""
    bf = BloomFilter(100)
    assert len(bf) == 0
    bf.add("a")
    assert len(bf) == 1
    bf.add("b")
    assert len(bf) == 2
    # duplicate add still increments count (bloom doesn't dedup)
    bf.add("a")
    assert len(bf) == 3


# ---------- no false negatives ----------


def test_no_false_negatives_10k_items():
    """Add 10000 items; every single one must be found (zero false negatives)."""
    n = 10_000
    bf = BloomFilter(n, false_positive_rate=0.01)
    items = [f"//host/share/path/to/file_{i}.txt" for i in range(n)]

    for item in items:
        bf.add(item)

    for item in items:
        assert item in bf, f"False negative for {item!r}"


# ---------- false positive rate ----------


def test_false_positive_rate_reasonable():
    """False positive rate should be close to the configured rate (1%)."""
    n = 10_000
    bf = BloomFilter(n, false_positive_rate=0.01)
    for i in range(n):
        bf.add(f"item_{i}")

    # Test 100k items that were NOT added
    false_positives = 0
    test_count = 100_000
    for i in range(test_count):
        if f"not_item_{i}" in bf:
            false_positives += 1

    # Allow up to 2% (generous margin for statistical variation)
    rate = false_positives / test_count
    assert rate < 0.02, f"False positive rate {rate:.4f} exceeds 2%"


# ---------- memory size ----------


def test_memory_reasonable_for_1m_items():
    """Bloom filter for 1M items at 1% FP rate should use ~1.2 MB."""
    bf = BloomFilter(1_000_000, false_positive_rate=0.01)
    # The bit array size in bytes
    bit_array_bytes = len(bf._bits)
    # At 1% FP rate, optimal is ~9.6 bits/item = ~1.2 MB for 1M items
    assert bit_array_bytes < 2_000_000, (
        f"Bit array is {bit_array_bytes} bytes, expected < 2 MB"
    )
    # Should be at least 1 MB (sanity check -- not too small)
    assert bit_array_bytes > 500_000, (
        f"Bit array is {bit_array_bytes} bytes, expected > 500 KB"
    )


def test_memory_reasonable_for_10m_items():
    """Bloom filter for 10M items at 1% FP rate should use ~12 MB."""
    bf = BloomFilter(10_000_000, false_positive_rate=0.01)
    bit_array_bytes = len(bf._bits)
    # ~12 MB expected, allow up to 15 MB
    assert bit_array_bytes < 15_000_000, (
        f"Bit array is {bit_array_bytes} bytes, expected < 15 MB"
    )
    assert bit_array_bytes > 8_000_000, (
        f"Bit array is {bit_array_bytes} bytes, expected > 8 MB"
    )


# ---------- edge cases ----------


def test_single_item_filter():
    """Filter with expected_items=1 still works."""
    bf = BloomFilter(1)
    bf.add("only")
    assert "only" in bf
    assert "other" not in bf


def test_empty_string():
    """Empty string can be added and found."""
    bf = BloomFilter(100)
    bf.add("")
    assert "" in bf


def test_unicode_strings():
    """Unicode strings work correctly."""
    bf = BloomFilter(100)
    bf.add("cafe\u0301")
    bf.add("\u2603")  # snowman
    assert "cafe\u0301" in bf
    assert "\u2603" in bf


def test_case_sensitive():
    """Bloom filter is case-sensitive (caller lowercases before adding)."""
    bf = BloomFilter(100)
    bf.add("hello")
    assert "hello" in bf
    assert "HELLO" not in bf
    assert "Hello" not in bf
