"""Simulate large-scale scan state to verify performance doesn't degrade."""

import time
import types

from snaffler.resume.scan_state import SQLiteStateStore, ScanState
from snaffler.utils.bloom import BloomFilter


# ---------- helpers ----------


def _create_store_with_files(tmp_path, total_files, checked_count):
    """Create a store with total_files entries, checked_count marked as checked.

    Returns (store, checked_paths, unchecked_paths).
    """
    db_path = str(tmp_path / "large.db")
    store = SQLiteStateStore(db_path)

    # Batch insert all files
    batch_size = 10000
    all_files = []
    for i in range(total_files):
        unc_path = f"//DC{i % 10:02d}/SHARE{i % 50:02d}/dir{i % 100:03d}/file_{i:06d}.txt"
        all_files.append((unc_path, f"//DC{i % 10:02d}/SHARE{i % 50:02d}", i * 10, float(1700000000 + i)))

        if len(all_files) >= batch_size:
            store.store_files(all_files)
            all_files.clear()

    if all_files:
        store.store_files(all_files)

    # Mark the first checked_count files as checked
    checked_paths = []
    unchecked_paths = []
    mark_batch = []
    for i in range(total_files):
        unc_path = f"//DC{i % 10:02d}/SHARE{i % 50:02d}/dir{i % 100:03d}/file_{i:06d}.txt"
        if i < checked_count:
            checked_paths.append(unc_path)
            mark_batch.append(unc_path)
            if len(mark_batch) >= batch_size:
                store.mark_files_checked_batch(mark_batch)
                mark_batch.clear()
        else:
            unchecked_paths.append(unc_path)

    if mark_batch:
        store.mark_files_checked_batch(mark_batch)

    return store, checked_paths, unchecked_paths


# ---------- Large-scale correctness ----------


class TestLargeScaleCorrectness:
    """Insert 100K files, mark 50K as checked, verify correctness."""

    def test_should_skip_file_works_at_scale(self, tmp_path):
        """should_skip_file correctly identifies checked vs unchecked at 100K scale."""
        store, checked_paths, unchecked_paths = _create_store_with_files(
            tmp_path, total_files=100_000, checked_count=50_000
        )

        # Wrap in ScanState which initializes bloom filter
        state = ScanState(store)

        # Sample: check that some checked files return True
        for path in checked_paths[:100]:
            assert state.should_skip_file(path), f"Expected checked file to be skipped: {path}"

        # Sample: check that some unchecked files return False
        # (bloom filter may have false positives, but the in-memory set should not)
        for path in unchecked_paths[:100]:
            assert not state.should_skip_file(path), f"Expected unchecked file to not be skipped: {path}"

        state.close()


# ---------- Bloom filter properties ----------


class TestBloomFilterProperties:
    def test_bloom_no_false_negatives(self, tmp_path):
        """Bloom filter must never produce false negatives for checked files."""
        store, checked_paths, _ = _create_store_with_files(
            tmp_path, total_files=100_000, checked_count=50_000
        )

        # Build a bloom filter the same way ScanState does
        count = store.count_checked_files()
        bloom = BloomFilter(max(count * 2, 100_000))
        for path_lower in store.iter_checked_file_keys():
            bloom.add(path_lower)

        # Every checked file MUST be in the bloom filter (no false negatives)
        false_negatives = 0
        for path in checked_paths:
            if path.lower() not in bloom:
                false_negatives += 1

        assert false_negatives == 0, f"Bloom filter produced {false_negatives} false negatives"
        store.close()

    def test_bloom_false_positive_rate_reasonable(self, tmp_path):
        """Bloom filter false positive rate should be below 2% for unchecked files."""
        store, _, unchecked_paths = _create_store_with_files(
            tmp_path, total_files=100_000, checked_count=50_000
        )

        # Build bloom filter
        count = store.count_checked_files()
        bloom = BloomFilter(max(count * 2, 100_000))
        for path_lower in store.iter_checked_file_keys():
            bloom.add(path_lower)

        # Check false positive rate on unchecked files
        false_positives = 0
        for path in unchecked_paths:
            if path.lower() in bloom:
                false_positives += 1

        fp_rate = false_positives / len(unchecked_paths)
        assert fp_rate < 0.02, (
            f"Bloom filter false positive rate {fp_rate:.4f} ({false_positives}/{len(unchecked_paths)}) "
            f"exceeds 2% threshold"
        )
        store.close()


# ---------- Bloom filter unit tests ----------


class TestBloomFilterUnit:
    def test_add_and_contains(self):
        """Basic add/contains operations."""
        bf = BloomFilter(1000)
        bf.add("hello")
        bf.add("world")

        assert "hello" in bf
        assert "world" in bf
        assert len(bf) == 2

    def test_never_false_negative(self):
        """All added items must always be found."""
        bf = BloomFilter(10000)
        items = [f"item_{i}" for i in range(5000)]
        for item in items:
            bf.add(item)

        for item in items:
            assert item in bf

    def test_missing_items(self):
        """Items never added should mostly not be found (low FP rate)."""
        bf = BloomFilter(10000)
        for i in range(5000):
            bf.add(f"added_{i}")

        false_positives = sum(1 for i in range(5000) if f"not_added_{i}" in bf)
        # With 10K capacity and 5K items at 1% default FP rate, expect very few
        assert false_positives < 100  # <2% of 5000

    def test_len_tracks_additions(self):
        bf = BloomFilter(100)
        assert len(bf) == 0
        bf.add("a")
        assert len(bf) == 1
        bf.add("b")
        assert len(bf) == 2


# ---------- Performance ----------


class TestPerformance:
    def test_should_skip_file_10k_lookups_under_1s(self, tmp_path):
        """10K should_skip_file lookups should complete in under 1 second."""
        store, checked_paths, unchecked_paths = _create_store_with_files(
            tmp_path, total_files=100_000, checked_count=50_000
        )

        state = ScanState(store)

        # Mix of checked and unchecked paths
        test_paths = checked_paths[:5000] + unchecked_paths[:5000]

        start = time.monotonic()
        for path in test_paths:
            state.should_skip_file(path)
        elapsed = time.monotonic() - start

        assert elapsed < 1.0, f"10K lookups took {elapsed:.2f}s (should be <1s)"
        state.close()


# ---------- iter_unchecked_files streaming ----------


class TestIterUncheckedFilesStreaming:
    def test_iter_unchecked_returns_all_unchecked(self, tmp_path):
        """iter_unchecked_files should return all 50K unchecked files."""
        store, _, unchecked_paths = _create_store_with_files(
            tmp_path, total_files=100_000, checked_count=50_000
        )

        # Collect via the streaming generator
        unchecked_from_iter = list(store.iter_unchecked_files())

        assert len(unchecked_from_iter) == 50_000

        # Verify the paths match (iter returns (path, size, mtime) tuples)
        iter_paths = {item[0] for item in unchecked_from_iter}
        expected_paths = {p for p in unchecked_paths}
        assert iter_paths == expected_paths
        store.close()

    def test_iter_unchecked_is_generator(self, tmp_path):
        """iter_unchecked_files should return a generator, not load all at once."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        # Insert a few files
        store.store_files([
            (f"//HOST/SHARE/f{i}.txt", "//HOST/SHARE", i, 0.0)
            for i in range(100)
        ])

        result = store.iter_unchecked_files()
        # Should be a generator or have __next__
        assert hasattr(result, '__iter__')
        assert hasattr(result, '__next__') or isinstance(result, types.GeneratorType)
        store.close()

    def test_iter_unchecked_excludes_all_checked(self, tmp_path):
        """After marking all files checked, iterator should yield nothing."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        paths = [f"//HOST/SHARE/f{i}.txt" for i in range(100)]
        store.store_files([
            (p, "//HOST/SHARE", i, 0.0) for i, p in enumerate(paths)
        ])
        store.mark_files_checked_batch(paths)

        unchecked = list(store.iter_unchecked_files())
        assert len(unchecked) == 0
        store.close()


# ---------- ScanState iter_unchecked_files delegation ----------


class TestScanStateIterUnchecked:
    def test_scan_state_iter_unchecked_delegates(self, tmp_path):
        """ScanState.iter_unchecked_files should delegate to store."""
        db_path = str(tmp_path / "test.db")
        store = SQLiteStateStore(db_path)

        store.store_files([
            ("//HOST/SHARE/a.txt", "//HOST/SHARE", 100, 0.0),
            ("//HOST/SHARE/b.txt", "//HOST/SHARE", 200, 0.0),
        ])
        store.mark_file_checked("//HOST/SHARE/a.txt")

        state = ScanState(store)
        items = list(state.iter_unchecked_files())

        assert len(items) == 1
        assert items[0][0] == "//HOST/SHARE/b.txt"
        state.close()
