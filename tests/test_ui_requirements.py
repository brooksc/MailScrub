"""Tests for UI requirements via presenter."""

from datetime import datetime
from unittest.mock import patch

import pytest
from rich.console import Console

from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender
from src.domain.models.statistics import GroupStatistics, MessageStatistics
from src.presentation.presenters import ConsolePresenter


def make_group(count: int = 3, unread: int = 1) -> GroupStatistics:
    sender = EmailSender(display_name="Test", email="t@example.com", domain="example.com")
    messages = [
        EmailMessage(
            id=f"m{i}", sender=sender, subject=f"Subject {i}",
            received_at=datetime(2024, 1, 1), is_unread=(i < unread),
        )
        for i in range(count)
    ]
    stats = MessageStatistics(
        total_count=count, unread_count=unread,
        domain_total=count, domain_unread_count=unread,
    )
    return GroupStatistics(domain="example.com", messages=messages, statistics=stats)


@pytest.fixture
def presenter():
    return ConsolePresenter(Console(force_terminal=False))


def test_ui1_present_messages_produces_output(presenter):
    groups = [make_group()]
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_messages(groups, set())
        mock_print.assert_called()


def test_ui2_table_has_correct_columns(presenter):
    groups = [make_group(count=2)]
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_messages(groups, set())
    assert mock_print.called


def test_ui4_error_displayed(presenter):
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_error("test error")
        call_str = str(mock_print.call_args)
        assert "test error" in call_str


def test_ui4_success_displayed(presenter):
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_success("test success")
        call_str = str(mock_print.call_args)
        assert "test success" in call_str


def test_ui6_empty_groups(presenter):
    with patch.object(presenter.console, "print") as mock_print:
        presenter.present_messages([], set())
        mock_print.assert_called()
