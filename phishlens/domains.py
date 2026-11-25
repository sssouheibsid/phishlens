"""Fonctions utilitaires sur les domaines et adresses (partagées par auth, ioc et typosquat)."""

from __future__ import annotations

import ipaddress
from email.utils import parseaddr

# Suffixes publics à deux niveaux les plus courants : pour "impots.gouv.fr",
# le domaine enregistré est "impots.gouv.fr" et non "gouv.fr".
# (Pas de liste publique complète en V1 pour rester hors ligne et sans dépendance.)
MULTI_PART_SUFFIXES: frozenset[str] = frozenset(
    {
        "gouv.fr", "asso.fr", "nom.fr", "com.fr",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "com.br", "com.cn", "co.nz", "co.za", "com.mx", "co.in",
    }
)


def normalize_host(host: str) -> str:
    """Met un nom d'hôte en minuscules, sans point final ni port ni crochets."""
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and "]" in host:
        return host[1 : host.index("]")]
    if host.count(":") == 1:  # hôte:port (une IPv6 contient plusieurs ':')
        host = host.split(":", 1)[0]
    return host


def is_ip(host: str) -> bool:
    """Indique si la chaîne est une adresse IPv4 ou IPv6 littérale."""
    try:
        ipaddress.ip_address(normalize_host(host))
    except ValueError:
        return False
    return True


def registered_domain(host: str) -> str:
    """Renvoie le domaine « enregistrable » approximatif (ex : www.paypal.com -> paypal.com)."""
    host = normalize_host(host)
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_of(address: str) -> str:
    """Extrait le domaine d'une adresse e-mail (accepte « Nom <a@b.c> » ou « <a@b.c> »)."""
    _, addr = parseaddr(address or "")
    if "@" not in addr:
        return ""
    return normalize_host(addr.rsplit("@", 1)[1])


def same_organization(domain_a: str, domain_b: str) -> bool:
    """Compare deux domaines au niveau du domaine enregistré."""
    if not domain_a or not domain_b:
        return True  # rien à comparer : on ne lève pas d'alerte
    return registered_domain(domain_a) == registered_domain(domain_b)
