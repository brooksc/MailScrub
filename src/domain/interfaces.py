"""Domain interfaces."""

from abc import ABC, abstractmethod

from .models.message import EmailMessage


class IMessageRepository(ABC):
    @abstractmethod
    def get_messages(self, query: str | None = None) -> list[EmailMessage]:
        pass

    @abstractmethod
    def get_message_by_id(self, message_id: str) -> EmailMessage | None:
        pass

    @abstractmethod
    def update_labels(
        self, message_id: str, add_labels: list[str], remove_labels: list[str]
    ) -> bool:
        pass

    @abstractmethod
    def trash_message(self, message_id: str) -> bool:
        pass


class IStatusRepository(ABC):
    @abstractmethod
    def get_seen_domains(self) -> set[str]:
        pass

    @abstractmethod
    def mark_domain_seen(self, domain: str) -> None:
        pass

    @abstractmethod
    def record_unsubscribe(self, domain: str, sender_email: str, unsubscribe_url: str) -> None:
        pass

    @abstractmethod
    def get_unsubscribe_history(self) -> dict[str, dict]:
        pass

    @abstractmethod
    def forget_unsubscribe(self, sender_email: str) -> None:
        pass


class IUnsubscribeClient(ABC):
    @abstractmethod
    def process_unsubscribe(self, url: str, use_post: bool = False) -> bool:
        pass

    @abstractmethod
    def verify_unsubscribe(self, url: str) -> bool:
        pass

    @abstractmethod
    def send_unsubscribe_email(self, mailto: str, from_addr: str | None = None) -> bool:
        pass
