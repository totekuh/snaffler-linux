import sqlite3
import threading


def _extract_share(path: str) -> str:
    """Extract //server/share from a UNC path, or return local paths unchanged."""
    normalized = path.replace("\\", "/")
    if not normalized.startswith("//"):
        return path
    parts = [p for p in normalized.split("/") if p]
    if len(parts) >= 2:
        return f"//{parts[0]}/{parts[1]}"
    return path


class ScanState:
    def __init__(self, store):
        self.store = store
        self.aborted = False  # reserved for cooperative shutdown
        # In-memory cache of checked files for O(1) lookups (case-insensitive)
        self._checked_files: set = store.load_checked_files()
        self._checked_lock = threading.Lock()

    # ---------- phase flags ----------

    def is_phase_done(self, phase: str) -> bool:
        return self.store.get_sync_flag(phase)

    def mark_phase_done(self, phase: str):
        self.store.set_sync_flag(phase)

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

    def should_skip_share(self, unc_path: str) -> bool:
        return self.store.has_checked_share(unc_path)

    def mark_share_done(self, unc_path: str):
        self.store.mark_share_checked(unc_path)

    # ---------- files ----------

    def should_skip_file(self, unc_path: str) -> bool:
        with self._checked_lock:
            return unc_path.lower() in self._checked_files

    def mark_file_done(self, unc_path: str):
        with self._checked_lock:
            self._checked_files.add(unc_path.lower())
        self.store.mark_file_checked(unc_path)

    # ---------- directories ----------

    def store_dir(self, unc_path: str, share: str):
        self.store.store_dir(unc_path, share)

    def store_dirs(self, dirs: list):
        self.store.store_dirs(dirs)

    def mark_dir_walked(self, unc_path: str):
        self.store.mark_dir_walked(unc_path)

    def load_unwalked_dirs(self, share: str | None = None) -> list:
        return self.store.load_unwalked_dirs(share)

    # ---------- files (batch) ----------

    def store_file(self, unc_path: str, share: str, size: int = 0, mtime: float = 0.0):
        self.store.store_file(unc_path, share, size, mtime)

    def store_files(self, files: list):
        self.store.store_files(files)

    def load_unchecked_files(self) -> list:
        return self.store.load_unchecked_files()

    def count_target_files(self) -> int:
        return self.store.count_target_files()

    # ---------- findings ----------

    def store_finding(self, **kwargs):
        self.store.store_finding(**kwargs)

    def load_findings(self):
        return self.store.load_findings()

    def count_findings(self) -> int:
        return self.store.count_findings()

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
        with self.conn:
            self.conn.execute("PRAGMA journal_mode=WAL;")
            self.conn.execute("PRAGMA synchronous=NORMAL;")

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

            # --- migrate: add done column to target_computer if missing ---
            cols = {
                row[1]
                for row in self.conn.execute("PRAGMA table_info(target_computer)")
            }
            if "done" not in cols:
                self.conn.execute(
                    "ALTER TABLE target_computer ADD COLUMN done INTEGER DEFAULT 0"
                )

            # --- migrate: add done column to target_share if missing ---
            cols = {
                row[1]
                for row in self.conn.execute("PRAGMA table_info(target_share)")
            }
            if "done" not in cols:
                self.conn.execute(
                    "ALTER TABLE target_share ADD COLUMN done INTEGER DEFAULT 0"
                )

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
        with self.lock:
            self.conn.executemany(
                "INSERT OR IGNORE INTO target_share (unc_path) VALUES (?)",
                [(s,) for s in shares],
            )
            self.conn.commit()

    def load_shares(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_share"
            ).fetchall()
            return [r[0] for r in rows]

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
            self.conn.close()
