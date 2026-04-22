"""Unsubscribe client implementation."""

import base64
import logging
from email.mime.text import MIMEText
from urllib.parse import parse_qs, urlparse

import requests

from ..domain.interfaces import IUnsubscribeClient

logger = logging.getLogger(__name__)


class UnsubscribeClient(IUnsubscribeClient):
    """Unsubscribe client implementation."""

    def __init__(self, gmail_repo=None):
        self._gmail_repo = gmail_repo
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'MailScrub/1.0 (Unsubscribe Client)'
        })

    def process_unsubscribe(self, url: str, use_post: bool = False) -> bool:
        """Process unsubscribe via URL. POST with RFC 8058 body when use_post=True."""
        try:
            if use_post:
                response = self._session.post(
                    url,
                    data="List-Unsubscribe=One-Click",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=30,
                )
            else:
                response = self._session.get(url, timeout=30)
            return response.status_code < 400
        except Exception as e:
            logger.error(f"Unsubscribe request failed: {e}")
            return False

    def verify_unsubscribe(self, url: str) -> bool:
        """Verify unsubscribe succeeded (optimistic)."""
        return True

    def send_unsubscribe_email(self, mailto: str, from_addr: str | None = None) -> bool:
        """Send unsubscribe email via Gmail API.

        mailto may be just an address or a full mailto: URI with subject/body params.
        """
        if not self._gmail_repo:
            logger.error("No Gmail repository available for sending email")
            return False

        try:
            self._gmail_repo._initialize_service()
            service = self._gmail_repo._service

            # Parse mailto URI
            if mailto.startswith("mailto:"):
                parsed = urlparse(mailto)
                to_addr = parsed.path
                params = parse_qs(parsed.query)
                subject = params.get("subject", ["Unsubscribe"])[0]
                body = params.get("body", ["Please unsubscribe me from this mailing list."])[0]
            else:
                to_addr = mailto
                subject = "Unsubscribe"
                body = "Please unsubscribe me from this mailing list."

            msg = MIMEText(body)
            msg["To"] = to_addr
            msg["Subject"] = subject
            if from_addr:
                msg["From"] = from_addr

            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
            service.users().messages().send(userId="me", body={"raw": raw}).execute()
            logger.info(f"Sent unsubscribe email to {to_addr}")
            return True
        except Exception as e:
            logger.error(f"Failed to send unsubscribe email: {e}")
            return False
