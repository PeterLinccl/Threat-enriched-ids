import json
import sqlite3
import time
from pathlib import Path


class ReputationCache:
    """Store IP reputation results separately for each provider."""

    def __init__(self, db_path="data/reputation_cache.sqlite3"):
        # Create the data directory before opening the SQLite database.
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)

        # The same IP can have one cached result per provider.
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS reputation_cache (
                ip TEXT NOT NULL,
                provider TEXT NOT NULL,
                result_json TEXT NOT NULL,
                expires_at REAL NOT NULL,
                PRIMARY KEY (ip, provider)
            )
        """)
        self.conn.commit()

    def get(self, ip, provider):
        """Return a valid cached result, or None on a miss or expiry."""
        row = self.conn.execute(
            "SELECT result_json, expires_at FROM reputation_cache "
            "WHERE ip = ? AND provider = ?",
            (ip, provider),
        ).fetchone()

        if row is None or time.time() >= row[1]:
            return None

        # SQLite stores the result as text; convert it back to a dictionary.
        return json.loads(row[0])

    def put(self, ip, provider, result, ttl_seconds=3600):
        """Save a result for the given number of seconds."""
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")

        # Replace an older result for the same IP and provider.
        self.conn.execute(
            "INSERT OR REPLACE INTO reputation_cache "
            "(ip, provider, result_json, expires_at) VALUES (?, ?, ?, ?)",
            (ip, provider, json.dumps(result), time.time() + ttl_seconds),
        )
        self.conn.commit()

    def close(self):
        """Close the database connection when finished."""
        self.conn.close()