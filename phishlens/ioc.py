"""Extraction des indicateurs de compromission (IOC) : URLs, domaines, IPs, hash, liens trompeurs."""

from __future__ import annotations

import html
import ipaddress
import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

from .domains import is_ip, normalize_host, registered_domain
from .parser import ParsedEmail

# Extensions exécutables ou porteuses de macros/scripts.
DANGEROUS_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "dll", "cpl",
        "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "ps1", "psm1", "jar",
        "lnk", "iso", "img", "vhd", "vhdx", "reg", "chm", "scf", "url",
        "docm", "xlsm", "pptm", "dotm", "xlam", "one", "appx", "msix",
    }
)
# Extensions « rassurantes » utilisées comme leurre dans une double extension.
DECOY_EXTENSIONS: frozenset[str] = frozenset(
    {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv",
        "jpg", "jpeg", "png", "gif", "bmp", "mp3", "mp4", "zip", "rar", "html", "htm",
    }
)
# Suffixes qui ressemblent à des TLD mais désignent des fichiers (évite « facture.pdf » = domaine).
# « com » est à la fois une extension exécutable et le TLD le plus courant : on le garde comme TLD.
_FILE_LIKE_TLDS = (DECOY_EXTENSIONS | DANGEROUS_EXTENSIONS | {"php", "asp", "aspx"}) - {"com"}

_URL_RE = re.compile(r"""https?://[^\s<>"'`]+""", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_IN_TEXT = re.compile(
    r"(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})\b", re.IGNORECASE
)
_TRAILING_PUNCT = ".,;:!?)]}>'\""


class _LinkExtractor(HTMLParser):
    """Collecte les liens <a href> avec leur texte affiché, et les action de formulaires."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []  # (href, texte affiché)
        self.other_urls: list[str] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}
        if tag == "a" and attributes.get("href"):
            self._href = attributes["href"].strip()
            self._text = []
        elif tag == "form" and attributes.get("action"):
            self.other_urls.append(attributes["action"].strip())

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


def _clean_url(url: str) -> str:
    return url.rstrip(_TRAILING_PUNCT)


def _dedupe(items: list[str]) -> list[str]:
    """Supprime les doublons en conservant l'ordre d'apparition."""
    return list(dict.fromkeys(items))


def url_host(url: str) -> str:
    """Renvoie l'hôte d'une URL (chaîne vide si l'URL est invalide)."""
    try:
        return normalize_host(urlsplit(url).hostname or "")
    except ValueError:
        return ""


def extract_links(html_body: str) -> list[tuple[str, str]]:
    """Renvoie les couples (href, texte affiché) des liens HTML."""
    parser = _LinkExtractor()
    try:
        parser.feed(html_body or "")
        parser.close()
    except Exception:  # HTML très malformé : on garde ce qui a pu être lu
        pass
    return parser.links


def extract_urls(email: ParsedEmail) -> list[str]:
    """Extrait les URLs http(s) du corps texte et du HTML (href, action, texte brut)."""
    urls: list[str] = [_clean_url(u) for u in _URL_RE.findall(email.text_body or "")]
    parser = _LinkExtractor()
    try:
        parser.feed(email.html_body or "")
        parser.close()
    except Exception:
        pass
    for href, _ in parser.links:
        if href.lower().startswith(("http://", "https://")):
            urls.append(href)
    for action in parser.other_urls:
        if action.lower().startswith(("http://", "https://")):
            urls.append(action)
    urls += [_clean_url(u) for u in _URL_RE.findall(html.unescape(email.html_body or ""))]
    return _dedupe(urls)


def public_ips(texts: list[str]) -> list[str]:
    """Extrait les IPv4 publiques (routables) présentes dans une liste de textes."""
    found: list[str] = []
    for text in texts:
        for candidate in _IPV4_RE.findall(text or ""):
            try:
                ip = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if ip.is_global:
                found.append(str(ip))
    return _dedupe(found)


def find_deceptive_links(html_body: str) -> list[dict[str, str]]:
    """Repère les liens dont le texte affiche un domaine différent de la cible réelle."""
    deceptive: list[dict[str, str]] = []
    for href, text in extract_links(html_body):
        if not href.lower().startswith(("http://", "https://")):
            continue
        href_host = url_host(href)
        if not href_host:
            continue
        for match in _DOMAIN_IN_TEXT.finditer(text):
            shown = match.group(1).lower()
            if shown.rsplit(".", 1)[-1] in _FILE_LIKE_TLDS:
                continue
            if is_ip(href_host) or registered_domain(shown) != registered_domain(href_host):
                deceptive.append(
                    {"text": text, "href": href, "shown_domain": shown, "real_host": href_host}
                )
                break
    return deceptive


def analyze_attachment_name(filename: str) -> dict[str, bool]:
    """Indique si un nom de fichier porte une extension dangereuse ou une double extension."""
    parts = [p for p in filename.lower().strip().strip(".").split(".")]
    extensions = parts[1:]
    last = extensions[-1].strip() if extensions else ""
    dangerous = last in DANGEROUS_EXTENSIONS
    double = (
        dangerous and len(extensions) >= 2 and extensions[-2].strip() in DECOY_EXTENSIONS
    )
    return {"dangerous_extension": dangerous, "double_extension": double}


def extract_iocs(email: ParsedEmail) -> dict[str, Any]:
    """Regroupe tous les IOC du message dans un dict sérialisable."""
    urls = extract_urls(email)
    hosts = _dedupe([h for h in (url_host(u) for u in urls) if h])
    domains = [h for h in hosts if not is_ip(h)]
    ip_urls = [u for u in urls if is_ip(url_host(u))]

    body_ips = public_ips([email.text_body, html.unescape(email.html_body or "")])
    received_ips = public_ips(email.received)

    attachments = []
    for att in email.attachments:
        attachments.append(
            {
                "filename": att.filename,
                "content_type": att.content_type,
                "size": att.size,
                "sha256": att.sha256,
                **analyze_attachment_name(att.filename),
            }
        )

    return {
        "urls": urls,
        "domains": domains,
        "ips": _dedupe(body_ips + received_ips + [url_host(u) for u in ip_urls]),
        "received_ips": received_ips,
        "ip_urls": ip_urls,
        "deceptive_links": find_deceptive_links(email.html_body),
        "attachments": attachments,
    }
