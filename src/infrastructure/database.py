"""Database implementation.

Implements Requirements:
- DB-1: Account Management Schema - Database schema
- DB-2: Status Tracking Schema - Status schema
"""

import contextlib
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path

from ..domain.exceptions import ConfigurationError
from ..domain.interfaces import IStatusRepository

logger = logging.getLogger(__name__)


class Database:
    """Database implementation.

    Implements:
    - DB-1: Database operations
    """

    _conn: sqlite3.Connection
    _lock: threading.Lock

    def __init__(self, db_path: str):
        """Initialize database."""
        self.db_path = Path(db_path)
        self._initialize_db()

    def _initialize_db(self) -> None:
        """Initialize database schema."""
        try:
            # Create directory if needed
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            self._lock = threading.Lock()
            self._conn = sqlite3.connect(
                str(self.db_path),
                isolation_level=None,   # true autocommit; we manage transactions explicitly
                check_same_thread=False,
            )
            self._conn.execute("PRAGMA synchronous = FULL")
            self._conn.execute("PRAGMA journal_mode = DELETE")

            # Create tables
            with self._conn:
                self._conn.executescript("""
                    CREATE TABLE IF NOT EXISTS seen_domains (
                        domain TEXT PRIMARY KEY,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS accounts (
                        email TEXT PRIMARY KEY,
                        token_path TEXT NOT NULL,
                        is_default BOOLEAN DEFAULT 0,
                        added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );

                    CREATE TABLE IF NOT EXISTS message_cache (
                        message_id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        cached_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS unsubscribe_history (
                        domain TEXT PRIMARY KEY,
                        sender_email TEXT NOT NULL,
                        unsubscribe_url TEXT,
                        attempted_at REAL NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS messages (
                        message_id TEXT PRIMARY KEY,
                        domain TEXT NOT NULL,
                        sender_email TEXT NOT NULL,
                        sender_display_name TEXT,
                        subject TEXT NOT NULL,
                        received_at REAL NOT NULL,
                        is_unread INTEGER NOT NULL DEFAULT 1,
                        unsubscribe_link TEXT,
                        unsubscribe_post INTEGER NOT NULL DEFAULT 0,
                        synced_at REAL NOT NULL,
                        delivered_to TEXT NOT NULL DEFAULT ''
                    );
                    CREATE INDEX IF NOT EXISTS idx_messages_domain
                        ON messages(domain);
                    CREATE INDEX IF NOT EXISTS idx_messages_received_at
                        ON messages(received_at);

                    CREATE TABLE IF NOT EXISTS sync_state (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS excluded_message_ids (
                        message_id TEXT PRIMARY KEY,
                        excluded_at REAL NOT NULL,
                        sender_email TEXT NOT NULL DEFAULT '',
                        domain TEXT NOT NULL DEFAULT ''
                    );
                """)

            # Migrate existing DBs that lack new columns
            for _sql in [
                "ALTER TABLE excluded_message_ids ADD COLUMN sender_email TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE excluded_message_ids ADD COLUMN domain TEXT NOT NULL DEFAULT ''",
                "ALTER TABLE messages ADD COLUMN delivered_to TEXT NOT NULL DEFAULT ''",
            ]:
                try:
                    self._conn.execute(_sql)
                except sqlite3.OperationalError:
                    pass  # column already exists

            logger.debug("Database initialized in synchronous mode")

        except sqlite3.Error as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise ConfigurationError("Failed to initialize database") from e

    @contextlib.contextmanager
    def transaction(self):
        """Thread-safe explicit transaction. Use instead of `with self._conn:`."""
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            try:
                self._conn.close()
                self._conn = None  # type: ignore[assignment]
                logger.debug("Database connection closed")
            except sqlite3.Error as e:
                logger.error(f"Error closing database connection: {str(e)}")

    def __del__(self) -> None:
        """Ensure connection is closed on deletion."""
        self.close()



class StatusRepository(IStatusRepository):
    """Status repository implementation.

    Implements:
    - DB-2: Status tracking
    """

    def __init__(self, config, db: Database | None = None):
        self.config = config
        self._db = db or Database(config.get_db_path())

    def get_seen_domains(self) -> set[str]:
        """Get set of seen domains."""
        try:
            cursor = self._db._conn.execute(
                "SELECT domain FROM seen_domains"
            )
            domains = {row[0] for row in cursor.fetchall()}
            logger.debug(f"Retrieved {len(domains)} seen domains")
            return domains

        except sqlite3.Error as e:
            logger.error(f"Failed to get seen domains: {str(e)}")
            return set()

    def mark_domain_seen(self, domain: str) -> None:
        """Mark domain as seen."""
        try:
            with self._db.transaction() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO seen_domains (domain) VALUES (?)", (domain,)
                )
            logger.debug(f"Marked domain as seen: {domain}")
        except sqlite3.Error as e:
            logger.error(f"Failed to mark domain {domain} as seen: {str(e)}")

    def record_unsubscribe(self, domain: str, sender_email: str, unsubscribe_url: str) -> None:
        """Record a successful unsubscribe attempt for a domain."""
        try:
            with self._db.transaction() as conn:
                conn.execute(
                    """INSERT OR REPLACE INTO unsubscribe_history
                       (domain, sender_email, unsubscribe_url, attempted_at)
                       VALUES (?, ?, ?, ?)""",
                    (domain, sender_email, unsubscribe_url, time.time()),
                )
        except sqlite3.Error as e:
            logger.error(f"Failed to record unsubscribe for {domain}: {e}")

    def forget_unsubscribe(self, sender_email: str) -> None:
        try:
            with self._db.transaction() as conn:
                conn.execute(
                    "DELETE FROM unsubscribe_history WHERE sender_email = ?", (sender_email,)
                )
        except sqlite3.Error as e:
            logger.error(f"Failed to forget unsubscribe for {sender_email}: {e}")

    def get_unsubscribe_history(self) -> dict[str, dict]:
        """Return {domain: {sender_email, unsubscribe_url, attempted_at}} for all recorded domains."""
        try:
            rows = self._db._conn.execute(
                "SELECT domain, sender_email, unsubscribe_url, attempted_at FROM unsubscribe_history"
            ).fetchall()
            return {
                row[0]: {
                    "sender_email": row[1],
                    "unsubscribe_url": row[2],
                    "attempted_at": row[3],
                }
                for row in rows
            }
        except sqlite3.Error as e:
            logger.error(f"Failed to load unsubscribe history: {e}")
            return {}

    def __del__(self):
        """Clean up resources."""
        if hasattr(self, '_db'):
            self._db.close()
            logger.debug("Status repository cleanup complete")


class MessageCache:
    """SQLite-backed cache for Gmail message metadata.

    Stores parsed message fields as JSON, keyed by message ID, with a TTL.
    Avoids re-fetching headers for messages already seen in a previous run.
    """

    DEFAULT_TTL = 7 * 24 * 3600  # 1 week

    def __init__(self, db: Database, ttl_seconds: int = DEFAULT_TTL):
        self._db = db
        self._ttl = ttl_seconds

    def get_cached(self, message_ids: list[str]) -> dict[str, dict]:
        """Return {message_id: data_dict} for all IDs that are cached and not expired."""
        if not message_ids:
            return {}
        cutoff = time.time() - self._ttl
        result: dict[str, dict] = {}
        for i in range(0, len(message_ids), 500):
            chunk = message_ids[i:i + 500]
            placeholders = ",".join("?" * len(chunk))
            rows = self._db._conn.execute(
                f"SELECT message_id, data FROM message_cache "
                f"WHERE message_id IN ({placeholders}) AND cached_at > ?",
                (*chunk, cutoff),
            ).fetchall()
            result.update({row[0]: json.loads(row[1]) for row in rows})
        return result

    def store(self, messages: dict[str, dict]) -> None:
        """Insert or replace cache entries for a batch of messages."""
        now = time.time()
        with self._db.transaction() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO message_cache (message_id, data, cached_at) "
                "VALUES (?, ?, ?)",
                [(mid, json.dumps(data), now) for mid, data in messages.items()],
            )

    def invalidate(self, message_id: str) -> None:
        """Remove a single entry so it is re-fetched next time."""
        with self._db.transaction() as conn:
            conn.execute(
                "DELETE FROM message_cache WHERE message_id = ?", (message_id,)
            )

    def purge_expired(self) -> int:
        """Delete all expired entries. Returns number of rows removed."""
        cutoff = time.time() - self._ttl
        with self._db.transaction() as conn:
            cur = conn.execute(
                "DELETE FROM message_cache WHERE cached_at <= ?", (cutoff,)
            )
        return cur.rowcount
