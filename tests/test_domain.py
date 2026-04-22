"""Domain layer tests."""

from datetime import datetime

from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender
from src.domain.models.statistics import GroupStatistics, MessageStatistics
from src.domain.services.domain import DomainService


def make_message(domain: str, is_unread: bool = False, idx: int = 0) -> EmailMessage:
    sender = EmailSender(display_name="Test", email=f"test@{domain}", domain=domain)
    return EmailMessage(
        id=f"msg{idx}",
        sender=sender,
        subject="Subject",
        received_at=datetime(2024, 1, 1),
        is_unread=is_unread,
    )


def test_email_sender_from_header():
    sender = EmailSender.from_header("John Doe <john@example.com>")
    assert sender.display_name == "John Doe"
    assert sender.email == "john@example.com"
    assert sender.domain == "example.com"


def test_email_sender_from_header_email_only():
    sender = EmailSender.from_header("jane@example.com")
    assert sender.display_name == ""
    assert sender.email == "jane@example.com"
    assert sender.domain == "example.com"


def test_email_message_has_unsubscribe():
    sender = EmailSender(display_name="", email="a@b.com", domain="b.com")
    msg_with = EmailMessage(
        id="1", sender=sender, subject="s",
        received_at=datetime.now(), is_unread=False,
        unsubscribe_link="https://b.com/unsub",
    )
    msg_without = EmailMessage(
        id="2", sender=sender, subject="s",
        received_at=datetime.now(), is_unread=False,
    )
    assert msg_with.has_unsubscribe is True
    assert msg_without.has_unsubscribe is False


def test_domain_service_normalize_known():
    svc = DomainService()
    assert svc.normalize_domain("email.apple.com") == "apple.com"
    assert svc.normalize_domain("news.bloomberg.com") == "bloomberg.com"
    assert svc.normalize_domain("email2.anthropic.com") == "anthropic.com"


def test_domain_service_normalize_unknown():
    svc = DomainService()
    assert svc.normalize_domain("unknown.com") == "unknown.com"


def test_domain_service_group_messages():
    svc = DomainService()
    messages = [
        make_message("example.com", is_unread=True, idx=0),
        make_message("example.com", is_unread=False, idx=1),
        make_message("other.com", is_unread=True, idx=2),
    ]
    groups = svc.group_messages(messages)
    domains = [g.domain for g in groups]
    assert "example.com" in domains
    assert "other.com" in domains


def test_domain_service_group_messages_sorted_by_count():
    svc = DomainService()
    messages = (
        [make_message("big.com", idx=i) for i in range(5)] +
        [make_message("small.com", idx=i + 10) for i in range(2)]
    )
    groups = svc.group_messages(messages)
    assert groups[0].domain == "big.com"
    assert groups[0].statistics.total_count == 5


def test_group_statistics_from_messages():
    msgs = [make_message("x.com", is_unread=True, idx=i) for i in range(3)]
    msgs.append(make_message("x.com", is_unread=False, idx=99))
    group = GroupStatistics.from_messages("x.com", msgs)
    assert group.statistics.total_count == 4
    assert group.statistics.unread_count == 3


def test_message_statistics_unread_percent():
    stats = MessageStatistics(
        total_count=100, unread_count=25,
        domain_total=100, domain_unread_count=25,
    )
    assert stats.unread_percent == 25.0


def test_message_statistics_zero_total():
    stats = MessageStatistics(
        total_count=0, unread_count=0,
        domain_total=0, domain_unread_count=0,
    )
    assert stats.unread_percent == 0


def test_group_statistics_has_unsubscribe():
    sender = EmailSender(display_name="", email="t@x.com", domain="x.com")
    msgs = [
        EmailMessage(id="a", sender=sender, subject="s",
                     received_at=datetime.now(), is_unread=False,
                     unsubscribe_link="https://x.com/unsub"),
    ]
    stats = MessageStatistics(total_count=1, unread_count=0, domain_total=1, domain_unread_count=0)
    group = GroupStatistics(domain="x.com", messages=msgs, statistics=stats)
    assert group.has_unsubscribe is True
