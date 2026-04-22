"""Message domain models."""

from dataclasses import dataclass
from datetime import datetime

from .sender import EmailSender


@dataclass(frozen=True)
class EmailMessage:
    id: str
    sender: EmailSender
    subject: str
    received_at: datetime
    is_unread: bool
    unsubscribe_link: str | None = None
    unsubscribe_post: bool = False  # True when List-Unsubscribe-Post header is present (RFC 8058)
    delivered_to: str = ''  # value of To: header; may differ from primary email for forwarded mail

    @property
    def has_unsubscribe(self) -> bool:
        return bool(self.unsubscribe_link)
