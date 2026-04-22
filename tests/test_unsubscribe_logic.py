"""Tests for detailed unsubscribe logic."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from src.domain.models.message import EmailMessage
from src.domain.models.sender import EmailSender
from src.domain.services.unsubscribe import UnsubscribeService
from src.infrastructure.unsubscribe import UnsubscribeClient


@pytest.mark.parametrize("header,expected_url", [
    ("<https://example.com/unsub>", "https://example.com/unsub"),
    ("<mailto:unsub@example.com>, <https://example.com/unsub>", "https://example.com/unsub"),
    ("<https://example.com/unsub>, <mailto:unsub@example.com>", "https://example.com/unsub"),
    ("<http://example.com/unsub>", "http://example.com/unsub"),
    ("https://example.com/unsub", ""), # Should be in brackets per RFC but we test our current implementation
])
def test_unsubscribe_service_extract_url(header, expected_url):
    # Note: UnsubscribeService._extract_url is currently using regex re.findall(r"<(https?://[^>]+)>", header_value)
    # The last case "https://example.com/unsub" will return "" which is correct for strict bracket matching
    client = MagicMock()
    svc = UnsubscribeService(client)
    assert svc._extract_url(header) == expected_url

def test_unsubscribe_client_uses_post_when_requested():
    client = UnsubscribeClient()
    url = "https://example.com/unsub"
    with patch.object(client._session, "post") as mock_post:
        mock_post.return_value = MagicMock(status_code=200)
        client.process_unsubscribe(url, use_post=True)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == url
        assert kwargs["data"] == "List-Unsubscribe=One-Click"
        assert kwargs["headers"]["Content-Type"] == "application/x-www-form-urlencoded"

def test_unsubscribe_service_process_with_post():
    client = MagicMock()
    client.process_unsubscribe.return_value = True
    client.verify_unsubscribe.return_value = True
    svc = UnsubscribeService(client)

    sender = EmailSender(display_name="T", email="t@t.com", domain="t.com")
    msg = EmailMessage(
        id="1", sender=sender, subject="S", received_at=datetime.now(),
        is_unread=False, unsubscribe_link="<https://example.com/unsub>",
        unsubscribe_post=True
    )

    svc.process_unsubscribe(msg)
    client.process_unsubscribe.assert_called_once_with("https://example.com/unsub", use_post=True)
