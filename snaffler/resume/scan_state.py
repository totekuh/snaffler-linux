import sqlite3
import threading

from snaffler.utils.bloom import BloomFilter
from snaffler.utils.path_utils import extract_share_root as _extract_share


class ScanState:
    def __init__(self, store):
        self.store = store
        # Bloom filter for fast checked-file dedup (probabilistic, no false negatives)
        count = store.count_checked_files()
        self._bloom = BloomFilter(max(count * 2, 100_000))  # 2x headroom
        self._bloom_lock = threading.Lock()
        # Seed bloom filter from DB (streaming, not loading all paths into memory)
        self._seed_bloom()

    def _seed_bloom(self):
        """Populate bloom filter from existing checked files in DB."""
        for path_lower in self.store.iter_checked_file_keys():
            self._bloom.add(path_lower)

    # ---------- phase flags ----------

    def is_phase_done(self, phase: str) -> bool:
        return self.store.get_sync_flag(phase)

    def mark_phase_done(self, phase: str):
        self.store.set_sync_flag(phase)

    def get_sync_value(self, key: str) -> str | None:
        return self.store.get_sync_value(key)

    def set_sync_value(self, key: str, value: str):
        self.store.set_sync_value(key, value)

    def clear_phase_flags(self):
        self.store.clear_phase_flags()

    # ---------- computers ----------

    def store_computers(self, computers: list):
        self.store.store_computers([c.upper() for c in computers])

    def load_computers(self) -> list:
        return self.store.load_computers()

    def set_computer_ip(self, name: str, ip: str):
        self.store.update_computer_ip(name.upper(), ip)

    def load_resolved_computers(self) -> list:
        return self.store.load_resolved_computers()

    def load_unresolved_computers(self) -> list:
        return self.store.load_unresolved_computers()

    def should_skip_computer(self, name: str) -> bool:
        return self.store.has_checked_computer(name.upper())

    def mark_computer_done(self, name: str):
        self.store.mark_computer_checked(name.upper())

    # ---------- shares ----------

    def store_shares(self, shares: list):
        self.store.store_shares(shares)

    def load_shares(self) -> list:
        return self.store.load_shares()

    def load_unreadable_shares(self) -> list:
        return self.store.load_unreadable_shares()

    def update_share_readable(self, unc_path: str):
        self.store.update_share_readable(unc_path)

    def should_skip_share(self, unc_path: str) -> bool:
        return self.store.has_checked_share(unc_path)

    def mark_share_done(self, unc_path: str):
        self.store.mark_share_checked(unc_path)

    # ---------- files ----------

    def should_skip_file(self, unc_path: str) -> bool:
        path_lower = unc_path.lower()
        with self._bloom_lock:
            if path_lower not in self._bloom:
                return False  # definitely not checked (bloom has no false negatives)
        # Bloom says probably checked -- verify with DB to avoid false positive
        return self.store.is_file_checked(path_lower)

    def mark_file_done(self, unc_path: str):
        """Mark file as checked in the bloom filter only.

        The DB write is batched by the caller (via ``_BatchWriter``) for
        dramatically lower SQLite contention under high thread counts.
        """
        path_lower = unc_path.lower()
        with self._bloom_lock:
            self._bloom.add(path_lower)

    # ---------- directories ----------

    def store_dir(self, unc_path: str, share: str):
        self.store.store_dir(unc_path, share)

    def store_dirs(self, dirs: list):
        self.store.store_dirs(dirs)

    def mark_dir_walked(self, unc_path: str):
        self.store.mark_dir_walked(unc_path)

    def load_unwalked_dirs(self, share: str | None = None) -> list:
        return self.store.load_unwalked_dirs(share)

    def load_walked_dirs(self) -> list:
        return self.store.load_walked_dirs()

    # ---------- files (batch) ----------

    def store_file(self, unc_path: str, share: str, size: int = 0, mtime: float = 0.0):
        self.store.store_file(unc_path, share, size, mtime)

    def store_files(self, files: list):
        self.store.store_files(files)

    def load_unchecked_files(self) -> list:
        return self.store.load_unchecked_files()

    def iter_unchecked_files(self):
        """Yield unchecked files via the streaming generator."""
        return self.store.iter_unchecked_files()

    def count_target_files(self) -> int:
        return self.store.count_target_files()

    # ---------- findings ----------

    def store_finding(self, **kwargs):
        self.store.store_finding(**kwargs)

    def load_findings(self):
        return self.store.load_findings()

    def count_findings(self) -> int:
        return self.store.count_findings()

    def count_findings_by_triage(self) -> dict:
        return self.store.count_findings_by_triage()

    # ---------- counts (for progress) ----------

    def count_checked_computers(self) -> int:
        return self.store.count_checked_computers()

    def count_checked_shares(self) -> int:
        return self.store.count_checked_shares()

    def count_checked_files(self) -> int:
        return self.store.count_checked_files()

    def close(self):
        self.store.close()


class SQLiteStateStore:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self._init()

    def _init(self):
        # PRAGMAs must be set outside any transaction.
        # page_size only takes effect on fresh databases (before first CREATE
        # TABLE); on existing DBs it is a no-op unless followed by VACUUM.
        self.conn.execute("PRAGMA page_size=8192;")
        try:
            self.conn.execute("PRAGMA journal_mode=WAL;")
        except Exception:
            pass  # WAL unsupported — fall back to default journal mode
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        # 64 MB page cache (negative value = kibibytes)
        self.conn.execute("PRAGMA cache_size=-65536;")
        # 256 MB memory-mapped I/O for faster reads on large DBs;
        # on 32-bit systems SQLite silently caps this to the available
        # address space, so no special handling is needed.
        self.conn.execute("PRAGMA mmap_size=268435456;")

        with self.conn:
            # --- drop legacy tables ---
            self.conn.execute("DROP TABLE IF EXISTS checked_computer")
            self.conn.execute("DROP TABLE IF EXISTS checked_share")
            self.conn.execute("DROP TABLE IF EXISTS checked_file")

            # --- schema (COLLATE NOCASE on path/name PKs — SMB is case-insensitive) ---
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS sync "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_computer "
                "(name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT, "
                "done INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_share "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE, "
                "readable INTEGER DEFAULT NULL, "
                "done INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_dir "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE, "
                "share TEXT NOT NULL COLLATE NOCASE, "
                "walked INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_file "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE, "
                "share TEXT NOT NULL COLLATE NOCASE, "
                "size INTEGER, mtime REAL, "
                "checked INTEGER DEFAULT 0)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS finding ("
                "finding_id TEXT PRIMARY KEY, "
                "file_path  TEXT NOT NULL, "
                "triage     TEXT NOT NULL, "
                "rule_name  TEXT NOT NULL, "
                "match_text TEXT, "
                "context    TEXT, "
                "size       INTEGER, "
                "mtime      TEXT, "
                "found_at   TEXT NOT NULL"
                ")"
            )

            # --- indexes ---
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_triage "
                "ON finding(triage)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_dir_share "
                "ON target_dir(share)"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_file_share "
                "ON target_file(share)"
            )
            # --- partial indexes for resume queries (only index incomplete rows) ---
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_file_checked "
                "ON target_file(checked) WHERE checked = 0"
            )
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_target_dir_walked "
                "ON target_dir(walked) WHERE walked = 0"
            )
            try:
                self.conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_target_computer_done "
                    "ON target_computer(done) WHERE done = 0"
                )
            except Exception:
                pass  # legacy DB where target_computer lacks 'done' column


    # ---------- sync flags ----------

    def get_sync_flag(self, key: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM sync WHERE key = ?", (key,)
            )
            return cur.fetchone() is not None

    def set_sync_flag(self, key: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO sync VALUES (?, '1')", (key,)
            )
            self.conn.commit()

    def get_sync_value(self, key: str) -> str | None:
        with self.lock:
            cur = self.conn.execute(
                "SELECT value FROM sync WHERE key = ?", (key,)
            )
            row = cur.fetchone()
            return row[0] if row else None

    def set_sync_value(self, key: str, value: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO sync VALUES (?, ?)", (key, value)
            )
            self.conn.commit()

    def clear_phase_flags(self):
        with self.lock:
            self.conn.execute(
                "DELETE FROM sync WHERE key IN "
                "('computer_discovery_done', 'dns_resolution_done', "
                "'share_discovery_done')"
            )
            self.conn.commit()

    # ---------- target computers ----------

    def store_computers(self, computers: list):
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO target_computer (name) VALUES (?)",
                [(c,) for c in computers],
            )
            self.conn.commit()

    def load_computers(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT name FROM target_computer"
            ).fetchall()
            return [r[0] for r in rows]

    def update_computer_ip(self, name: str, ip: str):
        with self.lock:
            self.conn.execute(
                "UPDATE target_computer SET ip = ? WHERE name = ?",
                (ip, name),
            )
            self.conn.commit()

    def load_resolved_computers(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT name FROM target_computer WHERE ip IS NOT NULL"
            ).fetchall()
            return [r[0] for r in rows]

    def load_unresolved_computers(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT name FROM target_computer WHERE ip IS NULL"
            ).fetchall()
            return [r[0] for r in rows]

    # ---------- target shares ----------

    def store_shares(self, shares: list):
        """Store shares. Accepts plain strings or (unc_path, readable) tuples."""
        with self.lock:
            for item in shares:
                if isinstance(item, tuple):
                    unc_path, readable = item
                    self.conn.execute(
                        "INSERT INTO target_share (unc_path, readable) VALUES (?, ?) "
                        "ON CONFLICT(unc_path) DO UPDATE SET readable = ?",
                        (unc_path, int(readable), int(readable)),
                    )
                else:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO target_share (unc_path) VALUES (?)",
                        (item,),
                    )
            self.conn.commit()

    def load_shares(self) -> list:
        """Load readable shares (readable=1 or readable=NULL for backwards compat)."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_share WHERE readable IS NULL OR readable = 1"
            ).fetchall()
            return [r[0] for r in rows]

    def load_unreadable_shares(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_share WHERE readable = 0"
            ).fetchall()
            return [r[0] for r in rows]

    def update_share_readable(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "UPDATE target_share SET readable = 1 WHERE unc_path = ?",
                (unc_path,),
            )
            self.conn.commit()

    # ---------- checked computers (via done column) ----------

    def has_checked_computer(self, name: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT done FROM target_computer WHERE name = ?", (name,)
            )
            row = cur.fetchone()
            return row is not None and row[0] == 1

    def mark_computer_checked(self, name: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_computer (name) VALUES (?)",
                (name,),
            )
            self.conn.execute(
                "UPDATE target_computer SET done = 1 WHERE name = ?",
                (name,),
            )
            self.conn.commit()

    # ---------- checked shares (via done column) ----------

    def has_checked_share(self, unc_path: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT done FROM target_share WHERE unc_path = ?",
                (unc_path,),
            )
            row = cur.fetchone()
            return row is not None and row[0] == 1

    def mark_share_checked(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_share (unc_path) VALUES (?)",
                (unc_path,),
            )
            self.conn.execute(
                "UPDATE target_share SET done = 1 WHERE unc_path = ?",
                (unc_path,),
            )
            self.conn.commit()

    # ---------- files (via target_file table) ----------

    def load_checked_files(self) -> set:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_file WHERE checked = 1"
            ).fetchall()
            return {r[0].lower() for r in rows}

    def iter_checked_file_keys(self):
        """Yield lowercased paths of checked files for bloom filter seeding."""
        with self.lock:
            cursor = self.conn.execute(
                "SELECT unc_path FROM target_file WHERE checked = 1"
            )
            while True:
                batch = cursor.fetchmany(10000)
                if not batch:
                    break
                for row in batch:
                    yield row[0].lower()

    def is_file_checked(self, path_lower: str) -> bool:
        """Check if a specific file is marked as checked in the DB."""
        with self.lock:
            row = self.conn.execute(
                "SELECT 1 FROM target_file WHERE unc_path = ? AND checked = 1",
                (path_lower,),
            ).fetchone()
            return row is not None

    def mark_file_checked(self, unc_path: str):
        with self.lock:
            share = _extract_share(unc_path)
            self.conn.execute(
                "INSERT OR IGNORE INTO target_file (unc_path, share) VALUES (?, ?)",
                (unc_path, share),
            )
            self.conn.execute(
                "UPDATE target_file SET checked = 1 WHERE unc_path = ?",
                (unc_path,),
            )
            self.conn.commit()

    def mark_files_checked_batch(self, paths: list):
        """Mark multiple files as checked in one transaction.

        Uses an upsert (ON CONFLICT ... DO UPDATE) so it handles the race
        with BatchWriter file inserts that may not have flushed yet.
        """
        with self.lock:
            for unc_path in paths:
                share = _extract_share(unc_path)
                self.conn.execute(
                    "INSERT INTO target_file (unc_path, share, checked) "
                    "VALUES (?, ?, 1) "
                    "ON CONFLICT(unc_path) DO UPDATE SET checked = 1",
                    (unc_path, share),
                )
            self.conn.commit()

    def store_file(self, unc_path: str, share: str, size: int = 0, mtime: float = 0.0):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_file "
                "(unc_path, share, size, mtime) VALUES (?, ?, ?, ?)",
                (unc_path, share, size, mtime),
            )
            self.conn.commit()

    def store_files(self, files: list):
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO target_file "
                "(unc_path, share, size, mtime) VALUES (?, ?, ?, ?)",
                files,
            )
            self.conn.commit()

    def load_unchecked_files(self) -> list:
        with self.lock:
            result = []
            cursor = self.conn.execute(
                "SELECT unc_path, size, mtime FROM target_file WHERE checked = 0"
            )
            while True:
                batch = cursor.fetchmany(5000)
                if not batch:
                    break
                result.extend((r[0], r[1], r[2]) for r in batch)
            return result

    def iter_unchecked_files(self):
        """Yield unchecked files in batches (generator).

        Uses LIMIT/OFFSET pagination so the lock is only held briefly per
        batch, and memory usage stays bounded even with millions of rows.
        """
        offset = 0
        batch_size = 10000
        while True:
            with self.lock:
                rows = self.conn.execute(
                    "SELECT unc_path, size, mtime FROM target_file "
                    "WHERE checked = 0 LIMIT ? OFFSET ?",
                    (batch_size, offset),
                ).fetchall()
            if not rows:
                break
            for r in rows:
                yield (r[0], r[1], r[2])
            offset += len(rows)

    def count_target_files(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_file"
            ).fetchone()[0]

    # ---------- directories (target_dir table) ----------

    def store_dir(self, unc_path: str, share: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO target_dir (unc_path, share) VALUES (?, ?)",
                (unc_path, share),
            )
            self.conn.commit()

    def store_dirs(self, dirs: list):
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO target_dir (unc_path, share) VALUES (?, ?)",
                dirs,
            )
            self.conn.commit()

    def mark_dir_walked(self, unc_path: str):
        with self.lock:
            share = _extract_share(unc_path)
            # Upsert: batch writer may not have flushed the INSERT yet
            self.conn.execute(
                "INSERT INTO target_dir (unc_path, share, walked) VALUES (?, ?, 1) "
                "ON CONFLICT(unc_path) DO UPDATE SET walked = 1",
                (unc_path, share),
            )
            self.conn.commit()

    def load_unwalked_dirs(self, share: str | None = None) -> list:
        with self.lock:
            if share is not None:
                rows = self.conn.execute(
                    "SELECT unc_path FROM target_dir WHERE walked = 0 AND share = ?",
                    (share,),
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT unc_path FROM target_dir WHERE walked = 0"
                ).fetchall()
            return [r[0] for r in rows]

    def load_walked_dirs(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_dir WHERE walked = 1"
            ).fetchall()
            return [r[0] for r in rows]

    # ---------- findings ----------

    def store_finding(
        self,
        finding_id: str,
        file_path: str,
        triage: str,
        rule_name: str,
        match_text: str = None,
        context: str = None,
        size: int = None,
        mtime: str = None,
        found_at: str = None,
    ):
        from datetime import datetime

        if found_at is None:
            found_at = datetime.now().isoformat()
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO finding "
                "(finding_id, file_path, triage, rule_name, match_text, "
                "context, size, mtime, found_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    file_path,
                    triage,
                    rule_name,
                    match_text,
                    context,
                    size,
                    mtime,
                    found_at,
                ),
            )
            self.conn.commit()

    def load_findings(self) -> list:
        with self.lock:
            cur = self.conn.execute(
                "SELECT finding_id, file_path, triage, rule_name, "
                "match_text, context, size, mtime, found_at "
                "FROM finding ORDER BY found_at"
            )
            cols = [d[0] for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count_findings(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM finding"
            ).fetchone()[0]

    def count_findings_by_triage(self) -> dict:
        """Return {triage_label: count} for all findings."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT triage, COUNT(*) FROM finding GROUP BY triage"
            ).fetchall()
            return {row[0]: row[1] for row in rows}

    # ---------- counts (for progress) ----------

    def count_checked_computers(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_computer WHERE done = 1"
            ).fetchone()[0]

    def count_checked_shares(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_share WHERE done = 1"
            ).fetchone()[0]

    def count_checked_files(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM target_file WHERE checked = 1"
            ).fetchone()[0]

    def close(self):
        with self.lock:
            try:
                self.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
            try:
                self.conn.close()
            except Exception:
                pass  # already closed
