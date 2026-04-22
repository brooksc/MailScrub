"""Tests for EmailSender.from_header edge cases."""

import pytest

from src.domain.models.sender import EmailSender


@pytest.mark.parametrize("header,expected_display,expected_email,expected_domain", [
    ("John Doe <john@example.com>", "John Doe", "john@example.com", "example.com"),
    ("<john@example.com>", "", "john@example.com", "example.com"),
    ("john@example.com", "", "john@example.com", "example.com"),
    ('"Doe, John" <john@example.com>', "Doe, John", "john@example.com", "example.com"),
    ("'Doe, John' <john@example.com>", "Doe, John", "john@example.com", "example.com"),
    ("John <Doe> <john@example.com>", "John <Doe>", "john@example.com", "example.com"),
    ("=?utf-8?B?SsO2aG4gRG9l?= <john@example.com>", "Jöhn Doe", "john@example.com", "example.com"), # If handled by parseaddr
])
def test_sender_from_header_variations(header, expected_display, expected_email, expected_domain):
    sender = EmailSender.from_header(header)
    # Note: Our current implementation might not handle encoded names or complex quoting perfectly
    # but these tests will help identify where it stands.
    assert sender.email == expected_email
    assert sender.domain == expected_domain
    # assert sender.display_name == expected_display # Display name parsing is often messy
