"""Gmail API repository implementation.

Implements Requirements:
- CORE-1: Gmail API Integration - API client
- CORE-2: Rate Limiting - Request throttling
- CORE-3: Error Handling - API errors
"""

import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ..domain.exceptions import MessageError
from ..domain.interfaces import IMessageRepository
from ..domain.models.message import EmailMessage
from ..domain.models.sender import EmailSender

logger = logging.getLogger(__name__)

# Rate limiting constants
REQUESTS_PER_SECOND = 10
MIN_REQUEST_INTERVAL = 1.0 / REQUESTS_PER_SECOND
INITIAL_BACKOFF = 1.0  # Initial backoff delay in seconds
MAX_BACKOFF = 32.0  # Maximum backoff delay in seconds
BACKOFF_FACTOR = 2  # Exponential backoff multiplier
MAX_RETRIES = 5  # Maximum number of retry attempts

SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
READONLY_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


class GmailRepository(IMessageRepository):
    """Gmail repository implementation."""

    def __init__(self, config, cache=None):
        """Initialize repository."""
        self.config = config
        self._cache = cache  # optional MessageCache
        self._service: Any = None
        self._last_request_time = time.time()
        self._retry_count = 0
        self._request_count = 0
        self._rate_limit_hits = 0

        self._token_path = str(Path(self.config.get_token_path()))
        self._credentials_path = str(Path(self.config.get_credentials_path()))
        logger.debug(f"Initialized GmailRepository with credentials_path={self._credentials_path}, token_path={self._token_path}")

        Path(self._token_path).parent.mkdir(parents=True, exist_ok=True)
        Path(self._credentials_path).parent.mkdir(parents=True, exist_ok=True)

        self._primary_email: str | None = None
        self._send_as_addresses: list[str] | None = None
        self._granted_scopes: set[str] = set()

    def initialize_new_account(self) -> str:
        """Run OAuth flow, save token, return the authenticated email address."""
        try:
            credentials_path = Path(self.config.get_credentials_path())
            if not credentials_path.exists():
                raise MessageError(
                    f"Please place your Google OAuth credentials file at: {credentials_path}"
                )

            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_path), SCOPES)
            creds = flow.run_local_server(port=0)
            self._service = build('gmail', 'v1', credentials=creds)
            self._granted_scopes = set(creds.scopes or [])

            email = self.get_primary_email()

            # Save token keyed by email so multiple accounts coexist
            token_dir = Path(self.config.get_token_dir())
            token_dir.mkdir(parents=True, exist_ok=True)
            token_path = token_dir / f"{email}.json"
            with open(token_path, "w") as f:
                f.write(creds.to_json())

            # Update token path on the config so subsequent calls use this file
            self._token_path = str(token_path)

            return email

        except Exception as e:
            logger.error(f"Failed to initialize new Gmail account: {str(e)}")
            raise MessageError("Failed to initialize new Gmail account") from e

    def _initialize_service(self) -> None:
        """Initialize Gmail API service if not already initialized."""
        logger.debug("Starting Gmail service initialization")

        if self._service:
            logger.debug("Gmail service already initialized")
            return

        try:
            logger.debug("Checking for credentials file")
            if not os.path.exists(self._credentials_path):
                logger.debug(f"No credentials file found at {self._credentials_path}")
                raise ValueError("No valid credentials found. Please run with --new flag.")

            logger.debug("Loading credentials from file")
            creds = None
            if os.path.exists(self._token_path):
                logger.debug("Found existing token file, attempting to load")
                creds = Credentials.from_authorized_user_file(self._token_path, SCOPES)

            logger.debug(f"Checking if credentials are valid: {creds is not None}")
            if not creds or not creds.valid:
                logger.debug("Credentials invalid or expired, attempting refresh")
                if creds and creds.expired and creds.refresh_token:
                    logger.debug("Refreshing expired credentials")
                    creds.refresh(Request())
                else:
                    logger.debug("Getting new credentials from flow")
                    flow = InstalledAppFlow.from_client_secrets_file(
                        self._credentials_path, SCOPES
                    )
                    creds = flow.run_local_server(port=0)

                logger.debug("Saving credentials to token file")
                with open(self._token_path, "w") as token:
                    token.write(creds.to_json())

            logger.debug("Building Gmail service")
            self._granted_scopes = set(creds.scopes or [])
            self._service = build("gmail", "v1", credentials=creds)
            logger.debug("Gmail service successfully initialized")

        except Exception as e:
            logger.error(f"Failed to initialize Gmail service: {str(e)}", exc_info=True)
            raise

    @property
    def is_read_only(self) -> bool:
        """True if the granted OAuth scopes are read-only (gmail.modify not present)."""
        if self._granted_scopes:
            return not any("gmail.modify" in s for s in self._granted_scopes)
        return False

    def _apply_rate_limit(self) -> None:
        """Apply rate limiting with exponential backoff."""
        now = time.time()
        elapsed = now - self._last_request_time
        self._request_count += 1

        # Calculate base delay
        if elapsed < MIN_REQUEST_INTERVAL:
            base_delay = MIN_REQUEST_INTERVAL - elapsed
        else:
            base_delay = 0

        # Apply exponential backoff if we've hit rate limits
        if self._retry_count > 0:
            backoff_delay = min(
                INITIAL_BACKOFF * (BACKOFF_FACTOR ** (self._retry_count - 1)),
                MAX_BACKOFF
            )
            total_delay = backoff_delay  # Don't add base delay during backoff
            logger.warning(
                f"Rate limit backoff: {backoff_delay:.2f}s (retry {self._retry_count}/{MAX_RETRIES})"
            )
        else:
            total_delay = base_delay

        if total_delay > 0:
            logger.debug(
                f"Rate limiting: delay={total_delay:.2f}s, requests={self._request_count}, "
                f"rate_limits={self._rate_limit_hits}"
            )
            time.sleep(total_delay)

        self._last_request_time = time.time()

    def _handle_rate_limit_error(self, error: HttpError, retry_count: int) -> bool:
        """Handle rate limit error and return True if should retry.

        retry_count is the caller's local counter (1-based attempt number).
        """
        if error.resp.status in (429, 503):
            self._rate_limit_hits += 1
            limit_percent = (
                (self._rate_limit_hits / self._request_count * 100)
                if self._request_count
                else 0.0
            )
            logger.warning(
                f"Rate limit hit: {self._rate_limit_hits} hits, "
                f"{limit_percent:.1f}% of {self._request_count} requests"
            )
            if retry_count <= MAX_RETRIES:
                backoff_delay = min(
                    INITIAL_BACKOFF * (BACKOFF_FACTOR ** (retry_count - 1)),
                    MAX_BACKOFF,
                )
                time.sleep(backoff_delay)
                return True
            logger.error(f"Max retries ({MAX_RETRIES}) exceeded")
            return False
        return False

    def get_primary_email(self) -> str:
        if self._primary_email is None:
            self._initialize_service()
            profile = self._service.users().getProfile(userId="me").execute()
            self._primary_email = str(profile["emailAddress"])
        return self._primary_email

    def get_send_as_addresses(self) -> list[str]:
        if self._send_as_addresses is None:
            self._initialize_service()
            result = self._service.users().settings().sendAs().list(userId="me").execute()
            self._send_as_addresses = [a["sendAsEmail"] for a in result.get("sendAs", [])]
        return self._send_as_addresses

    def list_message_ids(self, query: str | None = None) -> list[str]:
        """Return all message IDs matching query via paginated Gmail list calls."""
        self._initialize_service()
        message_ids = []
        page_token = None
        while True:
            params = dict(userId='me', q=query, maxResults=100)
            if page_token:
                params['pageToken'] = page_token
            response = self._service.users().messages().list(**params).execute()
            message_ids.extend(m['id'] for m in response.get('messages', []))
            page_token = response.get('nextPageToken')
            if not page_token:
                break
        logger.debug(f"Gmail list returned {len(message_ids)} IDs for query: {query!r}")
        return message_ids

    def fetch_message_headers(self, ids: list[str]) -> dict:
        """Batch-fetch metadata headers for the given IDs. Returns {id: raw_dict}."""
        if not ids:
            return {}
        self._initialize_service()
        BATCH_SIZE = 25
        raw: dict = {}
        failed: list = []

        def _on_msg(request_id, response, exception):
            if exception:
                failed.append(request_id)
            else:
                raw[request_id] = response

        def _run(chunk_ids):
            for i in range(0, len(chunk_ids), BATCH_SIZE):
                if i > 0:
                    time.sleep(1.0)
                chunk = chunk_ids[i:i + BATCH_SIZE]
                batch = self._service.new_batch_http_request(callback=_on_msg)
                for mid in chunk:
                    batch.add(
                        self._service.users().messages().get(
                            userId='me', id=mid, format='metadata',
                            metadataHeaders=['From', 'Subject', 'Date',
                                             'List-Unsubscribe', 'List-Unsubscribe-Post'],
                        ),
                        request_id=mid,
                    )
                batch.execute()

        _run(ids)
        if failed:
            retry = list(failed)
            logger.info(f"Retrying {len(retry)} rate-limited messages…")
            time.sleep(2.0)
            failed.clear()
            _run(retry)
            if failed:
                logger.warning(f"Permanently skipping {len(failed)} messages after retry")
        return raw

    def get_messages(self, query: str | None = None) -> list[EmailMessage]:
        """Get all matching messages, using the cache to skip already-fetched headers."""
        try:
            # 1. Collect ALL matching message IDs
            message_ids = self.list_message_ids(query)

            if not message_ids:
                return []

            # 2. Split into cached vs. needs-fetch
            cached_data: dict = {}
            uncached_ids: list = message_ids
            if self._cache:
                cached_data = self._cache.get_cached(message_ids)
                uncached_ids = [mid for mid in message_ids if mid not in cached_data]
                logger.debug(f"Cache hit: {len(cached_data)}, fetching: {len(uncached_ids)}")

            # 3. Batch-fetch only the uncached IDs
            raw_messages = self.fetch_message_headers(uncached_ids)

            # 4. Store newly fetched messages in cache
            if self._cache and raw_messages:
                self._cache.store({
                    mid: self._message_to_cache_dict(raw)
                    for mid, raw in raw_messages.items()
                })

            # 5. Parse and return in original order
            messages = []
            for msg_id in message_ids:
                try:
                    if msg_id in raw_messages:
                        messages.append(self._parse_message(raw_messages[msg_id]))
                    elif msg_id in cached_data:
                        messages.append(self._parse_cached(msg_id, cached_data[msg_id]))
                except Exception as e:
                    logger.warning(f"Skipping message {msg_id}: {e}")

            return messages

        except Exception as e:
            logger.error(f"Failed to get messages: {e}")
            raise MessageError("Failed to get messages") from e

    def get_message_by_id(self, message_id: str) -> EmailMessage | None:
        """Get specific message by ID."""
        self._initialize_service()
        for attempt in range(1, MAX_RETRIES + 2):
            try:
                self._apply_rate_limit()
                message = self._service.users().messages().get(
                    userId='me',
                    id=message_id,
                    format='full',
                ).execute()
                headers = {h['name']: h['value'] for h in message['payload']['headers']}
                sender = EmailSender.from_header(headers.get("From", ""))
                subject = headers.get('Subject', '')
                unsubscribe = headers.get('List-Unsubscribe', '') or None
                unsubscribe_post = 'List-Unsubscribe-Post' in headers
                labels = message.get('labelIds', [])
                return EmailMessage(
                    id=message_id,
                    sender=sender,
                    subject=subject,
                    received_at=datetime.fromtimestamp(int(message.get('internalDate', 0)) / 1000),
                    is_unread='UNREAD' in labels,
                    unsubscribe_link=unsubscribe,
                    unsubscribe_post=unsubscribe_post,
                )
            except (HttpError, OSError) as e:
                if isinstance(e, OSError):
                    if attempt > MAX_RETRIES:
                        logger.error(f"Failed to get message {message_id}: {e}")
                        return None
                    time.sleep(min(2.0 * attempt, MAX_BACKOFF))
                elif not self._handle_rate_limit_error(e, attempt):
                    logger.error(f"Failed to get message {message_id}: {e}")
                    return None
        return None

    def _get_or_create_label_id(self, name: str) -> str:
        """Return the Gmail label ID for name, creating the label if needed."""
        if not hasattr(self, '_label_cache'):
            self._label_cache = {}
        if name in self._label_cache:
            return self._label_cache[name]
        labels = self._service.users().labels().list(userId='me').execute().get('labels', [])
        for label in labels:
            self._label_cache[label['name']] = label['id']
        if name not in self._label_cache:
            created = self._service.users().labels().create(
                userId='me', body={'name': name}
            ).execute()
            self._label_cache[name] = created['id']
        return self._label_cache[name]

    def update_labels(
        self,
        message_id: str,
        add_labels: list[str],
        remove_labels: list[str],
    ) -> bool:
        """Update message labels. Accepts label names; resolves to IDs automatically."""
        self._initialize_service()
        for attempt in range(1, MAX_RETRIES + 2):
            try:
                self._apply_rate_limit()
                add_ids = [self._get_or_create_label_id(name) for name in add_labels]
                remove_ids = [self._get_or_create_label_id(name) for name in remove_labels]
                self._service.users().messages().modify(
                    userId='me',
                    id=message_id,
                    body={'addLabelIds': add_ids, 'removeLabelIds': remove_ids},
                ).execute()
                if self._cache:
                    self._cache.invalidate(message_id)
                return True
            except (HttpError, OSError) as e:
                if isinstance(e, OSError):
                    if attempt > MAX_RETRIES:
                        logger.error(f"Failed to update labels for {message_id}: {e}")
                        return False
                    time.sleep(min(2.0 * attempt, MAX_BACKOFF))
                elif not self._handle_rate_limit_error(e, attempt):
                    logger.error(f"Failed to update labels for {message_id}: {e}")
                    return False
        return False

    def trash_message(self, message_id: str) -> bool:
        """Move a message to Trash."""
        self._initialize_service()
        for attempt in range(1, MAX_RETRIES + 2):
            try:
                self._apply_rate_limit()
                self._service.users().messages().trash(userId='me', id=message_id).execute()
                if self._cache:
                    self._cache.invalidate(message_id)
                return True
            except (HttpError, OSError) as e:
                if isinstance(e, OSError):
                    if attempt > MAX_RETRIES:
                        logger.error(f"Failed to trash message {message_id}: {e}")
                        return False
                    time.sleep(min(2.0 * attempt, MAX_BACKOFF))
                elif not self._handle_rate_limit_error(e, attempt):
                    logger.error(f"Failed to trash message {message_id}: {e}")
                    return False
        return False

    def _parse_message(self, message: dict) -> EmailMessage:
        """Parse Gmail API message dict into EmailMessage."""
        payload = message.get('payload', {})
        headers = {h['name']: h['value'] for h in payload.get('headers', [])}
        sender = EmailSender.from_header(headers.get("From", ""))
        subject = headers.get('Subject', '')
        unsubscribe = headers.get('List-Unsubscribe', '') or None
        unsubscribe_post = 'List-Unsubscribe-Post' in headers
        labels = message.get('labelIds', [])
        return EmailMessage(
            id=message['id'],
            sender=sender,
            subject=subject,
            received_at=datetime.fromtimestamp(int(message.get('internalDate', 0)) / 1000),
            is_unread='UNREAD' in labels,
            unsubscribe_link=unsubscribe,
            unsubscribe_post=unsubscribe_post,
        )

    @staticmethod
    def _message_to_cache_dict(message: dict) -> dict:
        """Extract the fields we cache from a raw Gmail API response."""
        payload = message.get('payload', {})
        headers = {h['name']: h['value'] for h in payload.get('headers', [])}
        labels = message.get('labelIds', [])
        return {
            'from': headers.get('From', ''),
            'subject': headers.get('Subject', ''),
            'internalDate': message.get('internalDate', '0'),
            'is_unread': 'UNREAD' in labels,
            'unsubscribe_link': headers.get('List-Unsubscribe', '') or None,
            'unsubscribe_post': 'List-Unsubscribe-Post' in headers,
        }

    @staticmethod
    def _parse_cached(message_id: str, data: dict) -> EmailMessage:
        """Reconstruct an EmailMessage from a cache dict."""
        sender = EmailSender.from_header(data.get('from', ''))
        return EmailMessage(
            id=message_id,
            sender=sender,
            subject=data.get('subject', ''),
            received_at=datetime.fromtimestamp(int(data.get('internalDate', 0)) / 1000),
            is_unread=data.get('is_unread', False),
            unsubscribe_link=data.get('unsubscribe_link'),
            unsubscribe_post=data.get('unsubscribe_post', False),
        )
