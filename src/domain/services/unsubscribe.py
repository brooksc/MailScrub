"""Unsubscribe service implementation."""

from ..interfaces import IUnsubscribeClient
from ..models.message import EmailMessage


class UnsubscribeService:
    """Service for handling unsubscribe operations."""

    def __init__(self, unsubscribe_client: IUnsubscribeClient):
        self._client = unsubscribe_client

    @staticmethod
    def _extract_url(header_value: str) -> str:
        import re
        for url in re.findall(r"<(https?://[^>]+)>", header_value):
            return url
        return ""

    @staticmethod
    def _extract_mailto(header_value: str) -> str:
        import re
        for addr in re.findall(r"<mailto:([^>]+)>", header_value):
            return addr
        return ""

    def process_unsubscribe(self, message: EmailMessage, from_email: str | None = None) -> bool:
        """Process unsubscribe via HTTPS or mailto fallback.

        from_email: if set, used as the From address for mailto: unsubscribes (send-as alias).
        HTTP unsubscribes are unaffected — the URL is personalised by the sender.
        """
        if not message.unsubscribe_link:
            return False
        url = self._extract_url(message.unsubscribe_link)
        if url:
            success = self._client.process_unsubscribe(url, use_post=message.unsubscribe_post)
            if success:
                return self._client.verify_unsubscribe(url)
            return False
        mailto = self._extract_mailto(message.unsubscribe_link)
        if mailto:
            return self._client.send_unsubscribe_email(mailto, from_addr=from_email)
        return False
