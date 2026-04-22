"""Tests for presentation layer."""

from datetime import datetime
from unittest.mock import patch

import pytest
from rich.console import Console

from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender
from src.domain.models.statistics import GroupStatistics, MessageStatistics
from src.presentation.presenters import ConsolePresenter
from src.presentation.view_models import MessageRowViewModel, MessageTableViewModel


def make_group(domain: str = "example.com", count: int = 3, unread: int = 1) -> GroupStatistics:
    sender = EmailSender(display_name="Test", email=f"t@{domain}", domain=domain)
    messages = [
        EmailMessage(
            id=f"msg{i}",
            sender=sender,
            subject=f"Subject {i}",
            received_at=datetime(2024, 1, 1),
            is_unread=(i < unread),
        )
        for i in range(count)
    ]
    stats = MessageStatistics(
        total_count=count, unread_count=unread,
        domain_total=count, domain_unread_count=unread,
    )
    return GroupStatistics(domain=domain, messages=messages, statistics=stats)


@pytest.fixture
def console():
    return Console(force_terminal=False)


@pytest.fixture
def presenter(console):
    return ConsolePresenter(console)


def test_present_messages_calls_console(presenter):
    groups = [make_group()]
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_messages(groups, set())
        mock_print.assert_called()


def test_present_error(presenter):
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_error("something broke")
        mock_print.assert_called_once()
        call_str = str(mock_print.call_args)
        assert "something broke" in call_str


def test_present_success(presenter):
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_success("all good")
        mock_print.assert_called_once()
        call_str = str(mock_print.call_args)
        assert "all good" in call_str


def test_message_table_view_model():
    groups = [make_group("example.com", count=3, unread=1)]
    vm = MessageTableViewModel(groups, set())
    assert vm.total_messages == 3
    assert vm.unread_messages == 1
    assert vm.total_domains == 1
    assert len(vm.rows) == 1  # one row per group


def test_message_table_view_model_empty():
    vm = MessageTableViewModel([], set())
    assert vm.total_messages == 0
    assert vm.unread_percent == 0
    assert vm.rows == []


def test_message_row_view_model():
    row = MessageRowViewModel(sender="t@example.com", subject="Hello", stats="3 (33%)", age="2d ago", is_unread=True)
    assert row.sender == "t@example.com"
    assert row.subject == "Hello"
    assert row.stats == "3 (33%)"
    assert row.age == "2d ago"
    assert row.is_unread is True
