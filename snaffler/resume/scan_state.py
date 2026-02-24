import sqlite3
import threading


class ScanState:
    def __init__(self, store):
        self.store = store
        self.aborted = False  # reserved for cooperative shutdown

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
        return self.store.has_checked_file(unc_path)

    def mark_file_done(self, unc_path: str):
        self.store.mark_file_checked(unc_path)

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

            # --- schema (COLLATE NOCASE on path/name PKs — SMB is case-insensitive) ---
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS sync "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_computer "
                "(name TEXT PRIMARY KEY COLLATE NOCASE, ip TEXT)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS target_share "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS checked_computer "
                "(name TEXT PRIMARY KEY COLLATE NOCASE)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS checked_share "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS checked_file "
                "(unc_path TEXT PRIMARY KEY COLLATE NOCASE)"
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
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_finding_triage "
                "ON finding(triage)"
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
                "INSERT OR IGNORE INTO target_share VALUES (?)",
                [(s,) for s in shares],
            )
            self.conn.commit()

    def load_shares(self) -> list:
        with self.lock:
            rows = self.conn.execute(
                "SELECT unc_path FROM target_share"
            ).fetchall()
            return [r[0] for r in rows]

    # ---------- checked computers ----------

    def has_checked_computer(self, name: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM checked_computer WHERE name = ?", (name,)
            )
            return cur.fetchone() is not None

    def mark_computer_checked(self, name: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO checked_computer VALUES (?)",
                (name,),
            )
            self.conn.commit()

    # ---------- checked shares ----------

    def has_checked_share(self, unc_path: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM checked_share WHERE unc_path = ?",
                (unc_path,),
            )
            return cur.fetchone() is not None

    def mark_share_checked(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO checked_share VALUES (?)",
                (unc_path,),
            )
            self.conn.commit()

    # ---------- files ----------

    def has_checked_file(self, unc_path: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "SELECT 1 FROM checked_file WHERE unc_path = ?",
                (unc_path,),
            )
            return cur.fetchone() is not None

    def mark_file_checked(self, unc_path: str):
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO checked_file VALUES (?)",
                (unc_path,),
            )
            self.conn.commit()

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
                "SELECT COUNT(*) FROM checked_computer"
            ).fetchone()[0]

    def count_checked_shares(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM checked_share"
            ).fetchone()[0]

    def count_checked_files(self) -> int:
        with self.lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM checked_file"
            ).fetchone()[0]

    def close(self):
        with self.lock:
            self.conn.close()
