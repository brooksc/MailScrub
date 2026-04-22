"""Status service."""

from ..interfaces import IStatusRepository


class StatusService:
    def __init__(self, repository: IStatusRepository):
        self.repository = repository

    def get_seen_domains(self) -> set[str]:
        return self.repository.get_seen_domains()

    def mark_domain_seen(self, domain: str) -> None:
        self.repository.mark_domain_seen(domain)

    def record_unsubscribe(self, domain: str, sender_email: str, unsubscribe_url: str) -> None:
        self.repository.record_unsubscribe(domain, sender_email, unsubscribe_url)

    def get_unsubscribe_history(self) -> dict[str, dict]:
        return self.repository.get_unsubscribe_history()

    def forget_unsubscribe(self, sender_email: str) -> None:
        self.repository.forget_unsubscribe(sender_email)
