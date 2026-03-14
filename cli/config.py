"""
SQLite configuration store for the IoT Prompt Injection Lab CLI.

On first run, the .properties file is loaded into a local SQLite database
so users don't need to pass connection details on every command invocation.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path.home() / ".injection-lab" / "config.db"


def init_db() -> sqlite3.Connection:
    """Initialise the SQLite config database and return a connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""")
    conn.commit()
    return conn


def load_properties(path: str):
    """Load a .properties file into the SQLite config store.

    Lines starting with # are comments. Empty lines are skipped.
    Key-value pairs are split on the first = sign.
    """
    conn = init_db()
    count = 0
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition("=")
            if not _:
                continue
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
                (key.strip(), value.strip()),
            )
            count += 1
    conn.commit()
    conn.close()
    return count


def get(key: str, default: str = "") -> str:
    """Retrieve a config value by key."""
    conn = init_db()
    row = conn.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    conn.close()
    return row[0] if row else default


def set_config(key: str, value: str):
    """Set a config value."""
    conn = init_db()
    conn.execute(
        "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
        (key, value),
    )
    conn.commit()
    conn.close()


def get_all() -> list[tuple[str, str]]:
    """Return all config key-value pairs."""
    conn = init_db()
    rows = conn.execute("SELECT key, value FROM config ORDER BY key").fetchall()
    conn.close()
    return rows


def delete(key: str) -> bool:
    """Delete a config key. Returns True if it existed."""
    conn = init_db()
    cur = conn.execute("DELETE FROM config WHERE key = ?", (key,))
    conn.commit()
    conn.close()
    return cur.rowcount > 0
