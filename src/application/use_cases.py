"""Application use cases.

Implements Requirements:
- CORE-1: Gmail API Integration - Use cases
- CORE-4: Domain-Based Message Consolidation - Message grouping
- CORE-5: Message Statistics Tracking - Statistics handling
"""


from ..domain.models.message import EmailMessage
from ..domain.models.statistics import GroupStatistics
from ..domain.services import DomainService, MessageService, StatusService, UnsubscribeService
from ..infrastructure.message_store import SYNC_QUERY
from ..presentation.interfaces import IPresenter


class ListMessagesUseCase:
    """Use case for listing messages.

    When a MessageStore is provided, reads from the local DB (fast, no API
    calls). Falls back to the Gmail API for show_all=True or when no store
    is configured.
    """

    def __init__(
        self,
        message_service: MessageService,
        domain_service: DomainService,
        status_service: StatusService,
        presenter: IPresenter,
        message_store=None,
    ):
        self.message_service = message_service
        self.domain_service = domain_service
        self.status_service = status_service
        self.presenter = presenter
        self.message_store = message_store

    def execute_raw(self, show_all: bool = False):
        """Return (groups, seen_domains, reappeared).

        reappeared: list of (GroupStatistics, history_entry) for senders
        whose domain appears in the unsubscribe history.
        """
        seen_domains = self.status_service.get_seen_domains()
        history = self.status_service.get_unsubscribe_history()

        if self.message_store and not show_all:
            # Fast path: read from local store (sync already ran at startup)
            messages = self.message_store.get_all_messages()
        else:
            query = None if show_all else SYNC_QUERY
            with self.presenter.loading("Fetching emails…"):
                messages = self.message_service.get_messages(query)

        all_groups = self.domain_service.group_messages(messages)

        # History may be keyed by email (shared platforms) or domain (single-sender).
        # Check g.domain first (works for both), then fall back to sender email.
        def _history_match(g):
            h = history.get(g.domain)
            if h is None and g.messages:
                h = history.get(g.messages[0].sender.email)
            return h

        all_reappeared = [(g, h) for g in all_groups if (h := _history_match(g))]
        groups = [g for g in all_groups if not _history_match(g)]

        def _sender_key(g) -> str:
            return g.messages[0].sender.email if g.messages else g.domain

        truly_reappeared = []
        for g, h in all_reappeared:
            new_msgs = [m for m in g.messages if m.received_at.timestamp() > h["attempted_at"]]
            if new_msgs:
                # Emails received after the unsubscribe attempt → genuine reappearance
                truly_reappeared.append((g, h, len(new_msgs)))
            else:
                # All messages predate the unsubscribe — crash leftovers, surface for cleanup
                groups.append(g)

        # Suppress dialog entries whose new-message count hasn't grown since last dismissal
        dismissed = self.message_store.get_dismissed_reappeared() if self.message_store else {}
        reappeared = [
            (g, h) for g, h, new_count in truly_reappeared
            if new_count > dismissed.get(_sender_key(g), 0)
        ]
        return groups, seen_domains, reappeared

    def execute(self, show_all: bool = False) -> list[GroupStatistics]:
        groups, seen_domains, _ = self.execute_raw(show_all=show_all)
        self.presenter.present_messages(groups, seen_domains)
        return groups


class UnsubscribeUseCase:
    """Use case for unsubscribing from messages.

    Implements:
    - UNSUB-1: Unsubscribe handling
    """

    def __init__(
        self,
        message_service: MessageService,
        status_service: StatusService,
        unsubscribe_service: UnsubscribeService,
        presenter: IPresenter,
        message_store=None,
    ):
        self.message_service = message_service
        self.status_service = status_service
        self.unsubscribe_service = unsubscribe_service
        self.presenter = presenter
        self.message_store = message_store

    def execute(self, message_id: str) -> None:
        """Execute use case by message ID."""
        message = self.message_service.get_message_by_id(message_id)
        if not message:
            self.presenter.present_error("Message not found")
            return
        self.execute_on_message(message)

    def trash_messages(self, message_ids: list[str], on_progress=None) -> int:
        """Move messages to Trash. Returns count trashed."""
        trashed: list[str] = []
        total = len(message_ids)
        for mid in message_ids:
            if self.message_service.trash_message(mid):
                trashed.append(mid)
            if on_progress:
                on_progress(len(trashed), total)
        if self.message_store and trashed:
            self.message_store.delete_messages(trashed)
            self.message_store.add_excluded_ids(trashed)
        return len(trashed)

    def clear_reappeared(self, sender_emails: list[str]) -> None:
        """Remove senders from unsubscribe history so they never trigger the reappeared dialog."""
        for email in sender_emails:
            self.status_service.forget_unsubscribe(email)

    def execute_ignore(
        self, message_id: str, sender_email: str = '', domain: str = ''
    ) -> None:
        """Exclude a message locally so it won't appear in future listings."""
        if self.message_store:
            self.message_store.delete_messages([message_id])
            self.message_store.add_excluded_ids(
                [message_id], sender_email=sender_email, domain=domain
            )

    def execute_on_message(self, message: EmailMessage, from_email: str | None = None) -> bool:
        """Execute use case on an existing message object. Returns True on success.

        Implements:
        - UNSUB-1: Unsubscribe processing
        """
        if not message.unsubscribe_link:
            self.presenter.present_error("No unsubscribe link found")
            return False

        success = self.unsubscribe_service.process_unsubscribe(message, from_email=from_email)

        if success:
            if self.message_store:
                self.message_store.delete_messages([message.id])
            self.status_service.mark_domain_seen(message.sender.domain)

            from ..domain.services.unsubscribe import UnsubscribeService
            url = UnsubscribeService._extract_url(message.unsubscribe_link or "")
            self.status_service.record_unsubscribe(
                message.sender.email, message.sender.email, url
            )
        else:
            self.presenter.present_error(f"Failed to unsubscribe from {message.sender.email}")

        return success
