"""Test configuration and fixtures."""

import os
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender
from src.domain.models.statistics import GroupStatistics, MessageStatistics
from src.infrastructure.config import ConfigManager


@pytest.fixture(scope="session")
def test_config():
    config = ConfigManager(config_path="/tmp/mailscrub_test_config.json")
    config.set("testing", True)
    config.set("credentials_dir", os.environ.get("MAILSCRUB_CREDENTIALS_DIR", "/tmp/test/credentials"))
    config.set("token_dir", os.environ.get("MAILSCRUB_TOKEN_DIR", "/tmp/test/tokens"))
    return config


@pytest.fixture
def message_service() -> MagicMock:
    mock = MagicMock()
    mock.get_messages = MagicMock(return_value=[])
    mock.get_message_by_id = MagicMock(return_value=None)
    mock.update_labels = MagicMock(return_value=True)
    return mock


@pytest.fixture
def domain_service() -> MagicMock:
    mock = MagicMock()
    mock.group_messages = MagicMock(return_value=[])
    return mock


@pytest.fixture
def status_service() -> MagicMock:
    mock = MagicMock()
    mock.get_seen_domains = MagicMock(return_value=set())
    mock.mark_domain_seen = MagicMock()
    return mock


@pytest.fixture
def gmail_repository() -> MagicMock:
    mock = MagicMock()
    mock.get_messages.return_value = []
    mock.get_message_by_id.return_value = None
    mock.update_labels.return_value = True
    return mock


@pytest.fixture
def status_repository() -> MagicMock:
    mock = MagicMock()
    mock.get_seen_domains.return_value = set()
    mock.mark_domain_seen = MagicMock()
    return mock


@pytest.fixture
def presenter() -> MagicMock:
    mock = MagicMock()
    mock.present_messages = MagicMock()
    mock.present_error = MagicMock()
    mock.present_success = MagicMock()
    return mock


@pytest.fixture
def sample_sender() -> EmailSender:
    return EmailSender(
        display_name="Test Sender",
        email="test@example.com",
        domain="example.com",
    )


@pytest.fixture
def sample_messages(sample_sender) -> list[EmailMessage]:
    return [
        EmailMessage(
            id=f"msg{i}",
            sender=sample_sender,
            subject=f"Test Subject {i}",
            received_at=datetime(2024, 1, i + 1),
            is_unread=(i % 2 == 0),
            unsubscribe_link="https://example.com/unsubscribe" if i == 0 else None,
        )
        for i in range(5)
    ]


@pytest.fixture
def sample_groups(sample_messages: list[EmailMessage]) -> list[GroupStatistics]:
    stats = MessageStatistics(
        total_count=5,
        unread_count=3,
        domain_total=5,
        domain_unread_count=3,
    )
    return [
        GroupStatistics(
            domain="example.com",
            messages=sample_messages,
            statistics=stats,
        )
    ]
