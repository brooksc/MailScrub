"""Local SQLite message store and Gmail sync orchestrator."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime

from ..domain.models.message import EmailMessage
from ..domain.models.sender import EmailSender
from .database import Database
from .gmail import GmailRepository

logger = logging.getLogger(__name__)

# The canonical query for messages we care about (exclude Trash so deleted messages don't resurface)
SYNC_QUERY = "{category:promotions unsubscribe} -in:trash -in:sent -in:spam -is:starred"


class MessageStore:
    """Persistent local store for Gmail message metadata.

    Replaces the need to re-fetch headers on every run. The store holds all
    messages that matched the sync query at the time of the last sync. Mutations
    (unsubscribe, ignore, trash) remove messages from the store immediately so
    they don't reappear until the next sync.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Sync state
    # ------------------------------------------------------------------

    def get_last_sync_at(self) -> float | None:
        row = self._db._conn.execute(
            "SELECT value FROM sync_state WHERE key = 'last_sync_at'"
        ).fetchone()
        return float(row[0]) if row else None

    def set_last_sync_at(self, ts: float) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sync_state (key, value) VALUES ('last_sync_at', ?)",
                (str(ts),),
            )

    def get_dismissed_reappeared(self) -> dict[str, int]:
        """Return {sender_email: message_count} for each sender dismissed from the reappeared dialog."""
        import json
        row = self._db._conn.execute(
            "SELECT value FROM sync_state WHERE key = 'reappeared_dismissed'"
        ).fetchone()
        return json.loads(row[0]) if row else {}

    def set_dismissed_reappeared(self, counts: dict[str, int]) -> None:
        import json
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO sync_state (key, value) VALUES ('reappeared_dismissed', ?)",
                (json.dumps(counts),),
            )

    def has_seen_help(self) -> bool:
        row = self._db._conn.execute(
            "SELECT value FROM sync_state WHERE key = 'help_seen'"
        ).fetchone()
        return row is not None

    def mark_help_seen(self) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO sync_state (key, value) VALUES ('help_seen', '1')"
            )

    # ------------------------------------------------------------------
    # ID diffing
    # ------------------------------------------------------------------

    def get_missing_ids(self, message_ids: list[str]) -> list[str]:
        """Return IDs not yet in the store and not permanently excluded."""
        if not message_ids:
            return []
        known: set = set()
        for i in range(0, len(message_ids), 500):
            chunk = message_ids[i:i + 500]
            placeholders = ",".join("?" * len(chunk))
            for table in ("messages", "excluded_message_ids"):
                rows = self._db._conn.execute(
                    f"SELECT message_id FROM {table} WHERE message_id IN ({placeholders})",
                    chunk,
                ).fetchall()
                known.update(r[0] for r in rows)
        return [mid for mid in message_ids if mid not in known]

    def add_excluded_ids(
        self, message_ids: list[str], sender_email: str = '', domain: str = ''
    ) -> None:
        """Permanently exclude message IDs so they are never re-fetched."""
        if not message_ids:
            return
        now = time.time()
        with self._db.transaction() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO excluded_message_ids "
                "(message_id, excluded_at, sender_email, domain) VALUES (?, ?, ?, ?)",
                [(mid, now, sender_email, domain) for mid in message_ids],
            )

    def get_ignored_senders(self) -> list[dict]:
        """Return ignored senders grouped by sender_email (or domain/unknown fallback), newest first."""
        rows = self._db._conn.execute(
            """SELECT
                   COALESCE(NULLIF(sender_email, ''), NULLIF(domain, ''), '(unknown)') AS group_key,
                   sender_email,
                   domain,
                   COUNT(*) AS count,
                   MAX(excluded_at) AS ignored_at
               FROM excluded_message_ids
               GROUP BY group_key
               ORDER BY ignored_at DESC"""
        ).fetchall()
        return [
            {
                "group_key": r[0],
                "sender_email": r[1],
                "domain": r[2],
                "count": r[3],
                "ignored_at": r[4],
            }
            for r in rows
        ]

    def remove_ignored_sender(self, group_key: str) -> None:
        """Remove all exclusions for a sender group so they reappear on next sync."""
        with self._db.transaction() as conn:
            if group_key == '(unknown)':
                conn.execute(
                    "DELETE FROM excluded_message_ids WHERE sender_email = '' AND domain = ''"
                )
            else:
                # group_key is either a sender_email or a domain (fallback for old records)
                conn.execute(
                    "DELETE FROM excluded_message_ids "
                    "WHERE sender_email = ? OR (sender_email = '' AND domain = ?)",
                    (group_key, group_key),
                )

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def store_raw_messages(self, raw_messages: dict) -> None:
        """Parse and upsert a batch of raw Gmail API message dicts."""
        now = time.time()
        rows = []
        for msg_id, raw in raw_messages.items():
            payload = raw.get("payload", {})
            headers = {h["name"]: h["value"] for h in payload.get("headers", [])}
            sender = EmailSender.from_header(headers.get("From", ""))
            subject = headers.get("Subject", "")
            internal_date = int(raw.get("internalDate", 0)) / 1000
            labels = raw.get("labelIds", [])
            is_unread = "UNREAD" in labels
            unsub = headers.get("List-Unsubscribe", "") or None
            unsub_post = "List-Unsubscribe-Post" in headers
            to_header = headers.get("Delivered-To", "") or headers.get("To", "")
            delivered_to = EmailSender.from_header(to_header).email if to_header else ""
            rows.append((
                msg_id,
                sender.domain,
                sender.email,
                sender.display_name or "",
                subject,
                internal_date,
                1 if is_unread else 0,
                unsub,
                1 if unsub_post else 0,
                now,
                delivered_to,
            ))
        with self._db.transaction() as conn:
            conn.executemany(
                """INSERT OR REPLACE INTO messages
                   (message_id, domain, sender_email, sender_display_name,
                    subject, received_at, is_unread, unsubscribe_link,
                    unsubscribe_post, synced_at, delivered_to)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                rows,
            )

    def delete_messages(self, message_ids: list[str]) -> None:
        """Remove messages from the local store (called after unsubscribe/ignore/trash)."""
        if not message_ids:
            return
        for i in range(0, len(message_ids), 500):
            chunk = message_ids[i:i + 500]
            placeholders = ",".join("?" * len(chunk))
            with self._db.transaction() as conn:
                conn.execute(
                    f"DELETE FROM messages WHERE message_id IN ({placeholders})",
                    chunk,
                )

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_all_messages(self) -> list[EmailMessage]:
        """Return all stored messages as EmailMessage objects, newest first."""
        rows = self._db._conn.execute(
            """SELECT message_id, domain, sender_email, sender_display_name,
                      subject, received_at, is_unread, unsubscribe_link, unsubscribe_post,
                      delivered_to
               FROM messages
               ORDER BY received_at DESC"""
        ).fetchall()
        result = []
        for row in rows:
            sender = EmailSender(
                display_name=row[3] or "",
                email=row[2],
                domain=row[1],
            )
            result.append(EmailMessage(
                id=row[0],
                sender=sender,
                subject=row[4],
                received_at=datetime.fromtimestamp(row[5]),
                is_unread=bool(row[6]),
                unsubscribe_link=row[7],
                unsubscribe_post=bool(row[8]),
                delivered_to=row[9] or "",
            ))
        return result

    def count(self) -> int:
        return self._db._conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]

    def clear_messages(self) -> None:
        """Delete all downloaded message headers. Preserves exclusions, history, and sync state."""
        self._db._conn.execute("DELETE FROM messages")
        self._db._conn.commit()


class SyncResult:
    def __init__(self, fetched: int, total_new: int, interrupted: bool) -> None:
        self.fetched = fetched
        self.total_new = total_new
        self.interrupted = interrupted


class GmailSyncer:
    """Orchestrates syncing Gmail messages into the local MessageStore.

    Incremental sync:
      - On first run (no last_sync_at): fetches ALL matching IDs.
      - On subsequent runs: appends ``after:TIMESTAMP`` to the query so
        Gmail only returns recently arrived messages.
      - ``--full-sync``: ignores last_sync_at and re-fetches all IDs.

    In all cases, the ID list is diffed against what's already in the store,
    and headers are only fetched for genuinely new messages.

    Ctrl-C resilience:
      - Each batch of 25 messages is committed to the DB before moving on.
      - ``last_sync_at`` is only written on *successful* completion.
      - On the next run the syncer re-fetches IDs for the same window,
        diffs against what was already saved, and fetches only the remainder.
    """

    BATCH_SIZE = 25

    def __init__(self, gmail_repo: GmailRepository, store: MessageStore) -> None:
        self._repo = gmail_repo
        self._store = store

    def sync(
        self,
        full_sync: bool = False,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> SyncResult:
        """Run a sync pass. Calls on_progress(fetched, total_new) after each batch."""
        if full_sync:
            self._store.clear_messages()
            logger.debug("Full sync — cleared local message cache")
        last_sync = None if full_sync else self._store.get_last_sync_at()

        query = SYNC_QUERY
        if last_sync:
            # Gmail ``after:`` accepts Unix epoch seconds
            query = f"{SYNC_QUERY} after:{int(last_sync)}"
            logger.debug(f"Incremental sync since {datetime.fromtimestamp(last_sync)}")
        else:
            logger.debug("Full sync — fetching all matching IDs")

        # Step 1: cheap ID-only list (paginated, no headers)
        all_ids = self._repo.list_message_ids(query)
        logger.debug(f"Gmail returned {len(all_ids)} IDs")

        if not all_ids:
            self._store.set_last_sync_at(time.time())
            return SyncResult(fetched=0, total_new=0, interrupted=False)

        # Step 2: diff against store
        new_ids = self._store.get_missing_ids(all_ids)
        logger.debug(f"{len(new_ids)} IDs not yet in local store")

        if not new_ids:
            self._store.set_last_sync_at(time.time())
            return SyncResult(fetched=0, total_new=0, interrupted=False)

        # Step 3: batch-fetch headers, commit per batch, handle Ctrl-C
        fetched = 0
        interrupted = False

        try:
            for i in range(0, len(new_ids), self.BATCH_SIZE):
                if i > 0:
                    time.sleep(1.0)
                chunk = new_ids[i:i + self.BATCH_SIZE]
                raw = self._repo.fetch_message_headers(chunk)
                if raw:
                    self._store.store_raw_messages(raw)
                    fetched += len(raw)
                if on_progress:
                    on_progress(fetched, len(new_ids))
        except KeyboardInterrupt:
            interrupted = True
            logger.info(f"Sync interrupted after {fetched}/{len(new_ids)} messages — saved to DB")

        # Step 4: persist sync timestamp only on clean completion
        if not interrupted:
            self._store.set_last_sync_at(time.time())

        return SyncResult(fetched=fetched, total_new=len(new_ids), interrupted=interrupted)
