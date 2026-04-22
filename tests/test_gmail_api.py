"""Tests for Gmail API infrastructure."""

import json
import os
from unittest.mock import MagicMock, patch

import pytest
from google.oauth2.credentials import Credentials

from src.domain.models.message import EmailMessage
from src.infrastructure.config import ConfigManager
from src.infrastructure.gmail import SCOPES, GmailRepository


@pytest.fixture
def mock_config():
    config = MagicMock(spec=ConfigManager)
    config.get_credentials_path.return_value = os.path.join(
        os.path.dirname(__file__), "test_credentials.json"
    )
    config.get_token_path.return_value = os.path.join(
        os.path.dirname(__file__), "test_token.json"
    )
    return config


def test_gmail_repository_constructs(mock_config):
    repo = GmailRepository(mock_config)
    assert repo is not None


def test_gmail_repository_parse_message(mock_config):
    repo = GmailRepository(mock_config)

    raw = {
        "id": "msg1",
        "threadId": "thread1",
        "labelIds": ["INBOX", "UNREAD"],
        "internalDate": "1704067200000",  # 2024-01-01 00:00:00 UTC
        "payload": {
            "headers": [
                {"name": "From", "value": "Test <test@example.com>"},
                {"name": "Subject", "value": "Hello"},
                {"name": "Date", "value": "Mon, 01 Jan 2024 00:00:00 +0000"},
                {"name": "List-Unsubscribe", "value": "<https://example.com/unsub>"},
            ]
        },
    }
    msg = repo._parse_message(raw)
    assert isinstance(msg, EmailMessage)
    assert msg.id == "msg1"
    assert msg.sender.domain == "example.com"
    assert msg.subject == "Hello"
    assert msg.is_unread is True
    assert msg.unsubscribe_link is not None


def test_token_round_trip(tmp_path):
    """initialize_new_account saves JSON keyed by email; returns the email."""
    creds_path = tmp_path / "credentials.json"
    token_dir = tmp_path / "tokens"
    test_email = "test@example.com"

    import shutil
    shutil.copy(
        os.path.join(os.path.dirname(__file__), "test_credentials.json"),
        creds_path,
    )

    config = MagicMock(spec=ConfigManager)
    config.get_credentials_path.return_value = str(creds_path)
    config.get_token_dir.return_value = str(token_dir)

    fake_creds = MagicMock(spec=Credentials)
    fake_creds.valid = True
    fake_creds.scopes = SCOPES
    fake_creds.to_json.return_value = json.dumps({
        "token": "fake_token",
        "refresh_token": "fake_refresh",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "fake_client_id",
        "client_secret": "fake_secret",
        "scopes": SCOPES,
    })

    repo = GmailRepository(config)

    with patch("src.infrastructure.gmail.InstalledAppFlow.from_client_secrets_file") as mock_flow:
        mock_flow.return_value.run_local_server.return_value = fake_creds
        with patch("src.infrastructure.gmail.build"):
            with patch.object(repo, "get_primary_email", return_value=test_email):
                email = repo.initialize_new_account()

    assert email == test_email
    token_path = token_dir / f"{test_email}.json"
    assert token_path.exists()
    parsed = json.loads(token_path.read_text())
    assert "token" in parsed

    # _initialize_service must be able to reload that JSON token
    with patch("src.infrastructure.gmail.Credentials.from_authorized_user_file", return_value=fake_creds):
        with patch("src.infrastructure.gmail.build") as mock_build:
            repo._service = None  # reset so it re-initializes
            repo._initialize_service()
            mock_build.assert_called_once()


def test_get_messages_uses_batch(mock_config):
    """get_messages should make exactly 2 HTTP calls: list then one batch."""
    repo = GmailRepository(mock_config)

    raw_msg = {
        "id": "msg1",
        "threadId": "t1",
        "labelIds": ["INBOX", "UNREAD"],
        "internalDate": "1704067200000",
        "payload": {
            "headers": [
                {"name": "From", "value": "Test <test@example.com>"},
                {"name": "Subject", "value": "Hello"},
                {"name": "List-Unsubscribe", "value": "<https://example.com/unsub>"},
            ]
        },
    }

    mock_service = MagicMock()
    mock_service.users().messages().list().execute.return_value = {
        "messages": [{"id": "msg1"}]
    }

    # Simulate batch: callback is called immediately with the response
    def fake_batch_execute():
        callback = mock_service.new_batch_http_request.call_args[1]['callback']
        callback("msg1", raw_msg, None)

    mock_batch = MagicMock()
    mock_batch.execute.side_effect = fake_batch_execute
    mock_service.new_batch_http_request.return_value = mock_batch

    repo._service = mock_service
    messages = repo.get_messages("has:list-unsubscribe")

    assert len(messages) == 1
    assert messages[0].id == "msg1"
    assert messages[0].is_unread is True
    # Batch was created and executed exactly once
    mock_service.new_batch_http_request.assert_called_once()
    mock_batch.execute.assert_called_once()


def test_get_messages_empty_result(mock_config):
    """get_messages returns [] when the list call finds nothing."""
    repo = GmailRepository(mock_config)
    mock_service = MagicMock()
    mock_service.users().messages().list().execute.return_value = {"messages": []}
    repo._service = mock_service

    result = repo.get_messages()
    assert result == []
    mock_service.new_batch_http_request.assert_not_called()


def test_gmail_repository_parse_message_no_unsubscribe(mock_config):
    repo = GmailRepository(mock_config)

    raw = {
        "id": "msg2",
        "threadId": "thread2",
        "labelIds": ["INBOX"],
        "internalDate": "1704067200000",
        "payload": {
            "headers": [
                {"name": "From", "value": "sender@example.com"},
                {"name": "Subject", "value": "No Unsub"},
            ]
        },
    }
    msg = repo._parse_message(raw)
    assert msg.is_unread is False
    assert msg.has_unsubscribe is False
