"""Contrôles d'authentification : SPF, DKIM, DMARC et cohérence des adresses expéditrices."""

from __future__ import annotations

import re
from typing import Any

from .domains import domain_of, same_organization
from .parser import ParsedEmail

# Résultat de mécanisme dans un en-tête Authentication-Results (RFC 8601).
_AR_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
# Domaine signataire dans un en-tête DKIM-Signature.
_DKIM_DOMAIN = re.compile(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", re.IGNORECASE)
# Adresse e-mail glissée dans un nom affiché.
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")

ABSENT = "absent"


def parse_authentication_results(headers: list[str]) -> dict[str, str]:
    """Extrait spf / dkim / dmarc du premier en-tête Authentication-Results.

    Le premier en-tête est celui ajouté par le serveur de réception le plus proche
    de la boîte aux lettres : c'est le plus fiable.
    """
    results = {"spf": ABSENT, "dkim": ABSENT, "dmarc": ABSENT}
    if not headers:
        return results
    dkim_values: list[str] = []
    for mechanism, value in _AR_RESULT.findall(headers[0]):
        mechanism, value = mechanism.lower(), value.lower()
        if mechanism == "dkim":
            dkim_values.append(value)
        elif results[mechanism] == ABSENT:
            results[mechanism] = value
    if dkim_values:
        # Une seule signature DKIM valide suffit.
        results["dkim"] = "pass" if "pass" in dkim_values else dkim_values[0]
    return results


def parse_received_spf(headers: list[str]) -> str:
    """Repli : lit le résultat SPF dans l'en-tête Received-SPF (ex : « Fail (...) »)."""
    if not headers:
        return ABSENT
    match = re.match(r"\s*([a-z]+)", headers[0], re.IGNORECASE)
    return match.group(1).lower() if match else ABSENT


def dkim_domains(headers: list[str]) -> list[str]:
    """Liste les domaines (d=) des signatures DKIM présentes."""
    domains: list[str] = []
    for header in headers:
        match = _DKIM_DOMAIN.search(header)
        if match:
            domains.append(match.group(1).lower())
    return domains


def display_name_spoof(from_name: str, from_domain: str) -> str | None:
    """Détecte une adresse d'un autre domaine cachée dans le nom affiché.

    Exemple : « service@paypal.com » <alerte@paypa1-secure.com>
    Renvoie l'adresse trouvée dans le nom affiché, ou None.
    """
    for match in _EMAIL_IN_TEXT.finditer(from_name or ""):
        if not same_organization(match.group(1).lower(), from_domain):
            return match.group(0)
    return None


def check_authentication(email: ParsedEmail) -> dict[str, Any]:
    """Réalise l'ensemble des contrôles d'authentification et renvoie un dict."""
    results = parse_authentication_results(email.authentication_results)
    spf_source = "Authentication-Results"
    if results["spf"] == ABSENT:
        results["spf"] = parse_received_spf(email.received_spf)
        spf_source = "Received-SPF" if results["spf"] != ABSENT else ""

    from_domain = domain_of(email.from_address)
    reply_to_domain = domain_of(email.reply_to)
    return_path_domain = domain_of(email.return_path)

    return {
        "spf": results["spf"],
        "spf_source": spf_source,
        "dkim": results["dkim"],
        "dmarc": results["dmarc"],
        "dkim_domains": dkim_domains(email.dkim_signatures),
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "return_path_domain": return_path_domain,
        "reply_to_mismatch": bool(reply_to_domain)
        and not same_organization(reply_to_domain, from_domain),
        "return_path_mismatch": bool(return_path_domain)
        and not same_organization(return_path_domain, from_domain),
        "display_name_spoof": display_name_spoof(email.from_name, from_domain),
    }
