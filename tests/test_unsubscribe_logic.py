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


def _make_msg(link: str) -> EmailMessage:
    sender = EmailSender(display_name="T", email="t@t.com", domain="t.com")
    return EmailMessage(
        id="1", sender=sender, subject="S", received_at=datetime.now(),
        is_unread=False, unsubscribe_link=link,
    )


def test_unsubscribe_service_mailto_only():
    """mailto-only header should call send_unsubscribe_email, not process_unsubscribe."""
    client = MagicMock()
    client.send_unsubscribe_email.return_value = True
    svc = UnsubscribeService(client)

    msg = _make_msg("<mailto:unsub@example.com>")
    result = svc.process_unsubscribe(msg)

    assert result is True
    client.process_unsubscribe.assert_not_called()
    client.send_unsubscribe_email.assert_called_once_with(
        "unsub@example.com", from_addr=None
    )


def test_unsubscribe_service_mailto_passes_from_addr():
    client = MagicMock()
    client.send_unsubscribe_email.return_value = True
    svc = UnsubscribeService(client)

    msg = _make_msg("<mailto:unsub@example.com>")
    svc.process_unsubscribe(msg, from_email="alias@example.com")

    client.send_unsubscribe_email.assert_called_once_with(
        "unsub@example.com", from_addr="alias@example.com"
    )


def test_unsubscribe_service_no_url_or_mailto_returns_false():
    """A header with no parseable URL or mailto returns False without any network call."""
    client = MagicMock()
    svc = UnsubscribeService(client)

    msg = _make_msg("garbage header value")
    result = svc.process_unsubscribe(msg)

    assert result is False
    client.process_unsubscribe.assert_not_called()
    client.send_unsubscribe_email.assert_not_called()


def test_unsubscribe_service_no_link_returns_false():
    client = MagicMock()
    svc = UnsubscribeService(client)

    msg = _make_msg(None)  # type: ignore[arg-type]
    result = svc.process_unsubscribe(msg)

    assert result is False
    client.process_unsubscribe.assert_not_called()


# ---------------------------------------------------------------------------
# UnsubscribeClient.send_unsubscribe_email
# ---------------------------------------------------------------------------

def _make_client_with_repo():
    """Return (client, mock_service) pair wired up for send_unsubscribe_email."""
    mock_service = MagicMock()
    repo = MagicMock()
    repo._service = mock_service
    client = UnsubscribeClient(gmail_repo=repo)
    return client, mock_service


def test_send_unsubscribe_email_no_repo_returns_false():
    client = UnsubscribeClient()
    assert client.send_unsubscribe_email("unsub@example.com") is False


def test_send_unsubscribe_email_bare_address():
    """Bare email address → defaults subject/body, sends via Gmail API."""
    client, svc = _make_client_with_repo()
    result = client.send_unsubscribe_email("unsub@example.com")

    assert result is True
    call_kwargs = svc.users().messages().send.call_args[1]
    assert "raw" in call_kwargs["body"]


def test_send_unsubscribe_email_sets_to_header():
    client, svc = _make_client_with_repo()
    client.send_unsubscribe_email("unsub@example.com")

    # Decode the raw message to verify To header
    import base64
    raw = svc.users().messages().send.call_args[1]["body"]["raw"]
    decoded = base64.urlsafe_b64decode(raw).decode()
    assert "To: unsub@example.com" in decoded


def test_send_unsubscribe_email_mailto_uri_params():
    """mailto: URI with subject and body params → those values used."""
    client, svc = _make_client_with_repo()
    client.send_unsubscribe_email(
        "mailto:unsub@example.com?subject=Remove+Me&body=Please+remove"
    )

    import base64
    raw = svc.users().messages().send.call_args[1]["body"]["raw"]
    decoded = base64.urlsafe_b64decode(raw).decode()
    assert "Remove Me" in decoded
    assert "Please remove" in decoded


def test_send_unsubscribe_email_from_addr_included():
    client, svc = _make_client_with_repo()
    client.send_unsubscribe_email("unsub@example.com", from_addr="me@gmail.com")

    import base64
    raw = svc.users().messages().send.call_args[1]["body"]["raw"]
    decoded = base64.urlsafe_b64decode(raw).decode()
    assert "From: me@gmail.com" in decoded


def test_send_unsubscribe_email_no_from_addr_omits_from_header():
    client, svc = _make_client_with_repo()
    client.send_unsubscribe_email("unsub@example.com", from_addr=None)

    import base64
    raw = svc.users().messages().send.call_args[1]["body"]["raw"]
    decoded = base64.urlsafe_b64decode(raw).decode()
    assert "From:" not in decoded


def test_send_unsubscribe_email_api_exception_returns_false():
    client, svc = _make_client_with_repo()
    svc.users().messages().send().execute.side_effect = Exception("API error")
    result = client.send_unsubscribe_email("unsub@example.com")
    assert result is False
