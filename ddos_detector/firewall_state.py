"""Single-owner, crash-durable firewall journal stored outside Git."""
import json
from pathlib import Path
import sqlite3


class FirewallState:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._owner = sqlite3.connect(str(path) + ".lock", timeout=0)
        try:
            # Keep a separate database write lock for the lifetime of this
            # process, including while snapshot transactions are committed.
            self._owner.execute("BEGIN EXCLUSIVE")
            self._db = sqlite3.connect(path)
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
            self._db.execute("CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
            self._db.commit()
        except Exception:
            self._owner.close()
            raise

    def load(self):
        row = self._db.execute("SELECT data FROM state WHERE id=1").fetchone()
        return json.loads(row[0]) if row else None

    def save(self, snapshot, event=None):
        payload = json.dumps(snapshot, allow_nan=False)
        with self._db:
            self._db.execute("INSERT OR REPLACE INTO state VALUES (1, ?)", (payload,))
            if event is not None:
                self._db.execute("INSERT INTO audit (data) VALUES (?)", (json.dumps(event, allow_nan=False),))

    def events(self):
        return [json.loads(row[0]) for row in self._db.execute("SELECT data FROM audit ORDER BY id")]

    def close(self):
        self._db.close()
        self._owner.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
