"""Sender domain model."""

import re
from dataclasses import dataclass
from email.header import decode_header, make_header
from email.utils import parseaddr


@dataclass(frozen=True)
class EmailSender:
    display_name: str
    email: str
    domain: str

    @classmethod
    def from_header(cls, header_value: str) -> "EmailSender":
        if not header_value:
            return cls(display_name="", email="", domain="")

        # Decode RFC 2047 MIME encoding (e.g. =?UTF-8?B?...?=) before parsing,
        # otherwise parseaddr sees the encoded blob and extracts no email address.
        try:
            header_value = str(make_header(decode_header(header_value)))
        except Exception:
            pass

        display_name, email = parseaddr(header_value)

        if "@" not in email:
            matches = re.findall(r"<([^<>]+@[^<>]+)>", header_value)
            email = matches[-1] if matches else header_value.strip().strip("<>")

        decoded_name = ""
        if display_name:
            try:
                parts = decode_header(display_name)
                name_parts = []
                for content, charset in parts:
                    if isinstance(content, bytes):
                        name_parts.append(content.decode(charset or "utf-8", errors="replace"))
                    else:
                        name_parts.append(content)
                decoded_name = "".join(name_parts).strip()
            except Exception:
                decoded_name = display_name.strip()

        email = email.lower()
        domain = email.split("@")[1] if "@" in email else ""

        return cls(
            display_name=decoded_name or display_name.strip(),
            email=email,
            domain=domain,
        )
