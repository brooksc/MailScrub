"""Tests for display / view model layer."""

from datetime import datetime

from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender
from src.domain.models.statistics import GroupStatistics, MessageStatistics
from src.presentation.view_models import MessageTableViewModel


def make_group(domain: str = "example.com", count: int = 2, unread: int = 1) -> GroupStatistics:
    sender = EmailSender(display_name="Test", email=f"t@{domain}", domain=domain)
    messages = [
        EmailMessage(
            id=f"m{i}", sender=sender, subject=f"Sub {i}",
            received_at=datetime(2024, 1, 1), is_unread=(i < unread),
        )
        for i in range(count)
    ]
    stats = MessageStatistics(
        total_count=count, unread_count=unread,
        domain_total=count, domain_unread_count=unread,
    )
    return GroupStatistics(domain=domain, messages=messages, statistics=stats)


def test_table_view_model_totals():
    groups = [
        make_group("a.com", count=3, unread=2),
        make_group("b.com", count=2, unread=1),
    ]
    vm = MessageTableViewModel(groups, set())
    assert vm.total_messages == 5
    assert vm.unread_messages == 3
    assert vm.total_domains == 2


def test_table_view_model_rows_count():
    groups = [make_group("x.com", count=4), make_group("y.com", count=2)]
    vm = MessageTableViewModel(groups, set())
    assert len(vm.rows) == 2  # one row per group


def test_table_view_model_unread_percent():
    groups = [make_group("x.com", count=4, unread=2)]
    vm = MessageTableViewModel(groups, set())
    assert vm.unread_percent == 50


def test_table_view_model_empty_groups():
    vm = MessageTableViewModel([], set())
    assert vm.total_messages == 0
    assert vm.total_domains == 0
    assert vm.rows == []
