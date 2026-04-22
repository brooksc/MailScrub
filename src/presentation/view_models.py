"""View models for presentation layer.

Implements Requirements:
- UI-1: Message Display Format - View models
- UI-2: Display Table Structure - Data models
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from ..domain.models.statistics import GroupStatistics


def _relative_time(dt: datetime) -> str:
    """Format a datetime as a human-friendly relative string."""
    now = datetime.now(UTC)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    delta = now - dt
    seconds = int(delta.total_seconds())
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h ago"
    if seconds < 172800:
        return "Yesterday"
    if seconds < 604800:
        return f"{seconds // 86400}d ago"
    return f"{seconds // 604800}w ago"



@dataclass
class MessageRowViewModel:
    sender: str
    subject: str
    stats: str
    age: str
    is_unread: bool


@dataclass
class StatisticsViewModel:
    total_messages: int
    unread_messages: int
    total_domains: int


class MessageTableViewModel:
    """View model for message table.

    Implements:
    - UI-1: Table format
    - UI-2: Table structure
    - UI-5: Table format
    """

    def __init__(self, groups: list[GroupStatistics], seen_domains: set[str]):
        """Initialize view model.

        Args:
            groups: List of message groups
            seen_domains: Set of previously seen domains
        """
        self.rows: list[MessageRowViewModel] = []
        self.total_messages = 0
        self.unread_messages = 0
        self.total_domains = len(groups)

        # Process groups
        for group in groups:
            # Update statistics
            stats = group.statistics
            self.total_messages += stats.total_count
            self.unread_messages += stats.unread_count

            # One row per group: show sender and most recent subject
            latest = group.messages[0] if group.messages else None
            name = (latest.sender.display_name or latest.sender.email or group.domain) if latest else group.domain
            sender = f"{name} ({group.domain})" if name != group.domain else group.domain
            self.rows.append(
                MessageRowViewModel(
                    sender=sender,
                    subject=latest.subject if latest else "",
                    stats=f"{stats.total_count} ({stats.unread_percent:.0f}%)",
                    age=_relative_time(latest.received_at) if latest else "",
                    is_unread=stats.unread_count > 0,
                )
            )

        # Calculate unread percentage
        self.unread_percent = (
            round((self.unread_messages / self.total_messages) * 100)
            if self.total_messages > 0
            else 0
        )
