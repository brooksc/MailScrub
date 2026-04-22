"""Statistics domain models."""

from dataclasses import dataclass

from .message import EmailMessage


@dataclass(frozen=True)
class MessageStatistics:
    total_count: int
    unread_count: int
    domain_total: int
    domain_unread_count: int

    @property
    def unread_percent(self) -> float:
        return (self.unread_count / self.total_count * 100) if self.total_count > 0 else 0


@dataclass
class GroupStatistics:
    domain: str
    messages: list[EmailMessage]
    statistics: MessageStatistics

    @property
    def has_unsubscribe(self) -> bool:
        return any(m.has_unsubscribe for m in self.messages)

    @classmethod
    def from_messages(cls, domain: str, messages: list[EmailMessage]) -> "GroupStatistics":
        unread = [m for m in messages if m.is_unread]
        stats = MessageStatistics(
            total_count=len(messages),
            unread_count=len(unread),
            domain_total=len(messages),
            domain_unread_count=len(unread),
        )
        return cls(domain=domain, messages=messages, statistics=stats)
