"""Lecture d'un fichier .eml et extraction des éléments utiles à l'analyse."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from email import policy
from email.errors import HeaderParseError
from email.header import decode_header, make_header
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path


@dataclass
class Attachment:
    """Pièce jointe extraite du message."""

    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    """Représentation simplifiée d'un e-mail, indépendante du module email."""

    path: str
    subject: str = ""
    date: str = ""
    message_id: str = ""
    from_header: str = ""
    from_name: str = ""
    from_address: str = ""
    to: str = ""
    reply_to: str = ""
    return_path: str = ""
    received: list[str] = field(default_factory=list)
    authentication_results: list[str] = field(default_factory=list)
    received_spf: list[str] = field(default_factory=list)
    dkim_signatures: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    attachments: list[Attachment] = field(default_factory=list)


def _decode_header(value: str) -> str:
    """Décode les mots encodés RFC 2047 (=?utf-8?...?=) et met la valeur sur une ligne."""
    try:
        value = str(make_header(decode_header(value)))
    except (HeaderParseError, LookupError, UnicodeError, ValueError):
        pass
    return " ".join(value.split())


def _headers(msg: Message, name: str) -> list[str]:
    """Renvoie toutes les valeurs brutes d'un en-tête, dans l'ordre du fichier.

    On lit les valeurs brutes (raw_items) plutôt que les objets analysés par le module
    email : un nom affiché piégé comme « service@paypal.com » doit rester intact.
    """
    return [_decode_header(str(v)) for k, v in msg.raw_items() if k.lower() == name.lower()]


def _first(msg: Message, name: str) -> str:
    values = _headers(msg, name)
    return values[0] if values else ""


def _decode_text(part: Message) -> str:
    """Décode une partie texte en tolérant les jeux de caractères exotiques ou faux."""
    if isinstance(part, EmailMessage):
        try:
            content = part.get_content()
            if isinstance(content, str):
                return content
        except (LookupError, UnicodeError, KeyError, AssertionError):
            pass
    payload = part.get_payload(decode=True) or b""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _is_attachment(part: Message) -> bool:
    disposition = part.get_content_disposition()
    if disposition == "attachment":
        return True
    # Une partie nommée qui n'est pas du texte affichable est traitée comme une pièce jointe.
    return bool(part.get_filename()) and part.get_content_maintype() != "text"


def parse_email(path: str | Path) -> ParsedEmail:
    """Lit un fichier .eml et renvoie un objet ParsedEmail."""
    path = Path(path)
    with path.open("rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    from_header = _first(msg, "From")
    from_name, from_address = parseaddr(from_header)

    parsed = ParsedEmail(
        path=str(path),
        subject=_first(msg, "Subject"),
        date=_first(msg, "Date"),
        message_id=_first(msg, "Message-ID"),
        from_header=from_header,
        from_name=from_name,
        from_address=from_address.lower(),
        to=_first(msg, "To"),
        reply_to=_first(msg, "Reply-To"),
        return_path=_first(msg, "Return-Path"),
        received=_headers(msg, "Received"),
        authentication_results=_headers(msg, "Authentication-Results"),
        received_spf=_headers(msg, "Received-SPF"),
        dkim_signatures=_headers(msg, "DKIM-Signature"),
    )

    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if _is_attachment(part):
            data = part.get_payload(decode=True) or b""
            parsed.attachments.append(
                Attachment(
                    filename=part.get_filename() or "(sans nom)",
                    content_type=part.get_content_type(),
                    size=len(data),
                    sha256=hashlib.sha256(data).hexdigest(),
                )
            )
        elif part.get_content_type() == "text/plain":
            text_parts.append(_decode_text(part))
        elif part.get_content_type() == "text/html":
            html_parts.append(_decode_text(part))

    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)
    return parsed
