"""Détection de domaines imitant une marque connue (typosquatting, homoglyphes)."""

from __future__ import annotations

from typing import Iterable

from .domains import is_ip, normalize_host, registered_domain

# Marque (mot-clé recherché) -> domaines officiels. Un domaine officiel, ou l'un de
# ses sous-domaines, n'est jamais signalé.
BRANDS: dict[str, tuple[str, ...]] = {
    "paypal": ("paypal.com", "paypal.fr", "paypal.me", "paypalobjects.com", "paypal-communication.com"),
    "microsoft": ("microsoft.com", "microsoftonline.com", "office.com", "office365.com",
                  "live.com", "outlook.com", "hotmail.com", "windows.net", "azure.com"),
    "office365": ("office365.com", "microsoft.com"),
    "amazon": ("amazon.com", "amazon.fr", "amazon.de", "amazon.co.uk", "amazonaws.com",
               "amazonses.com", "media-amazon.com", "amazon.es", "amazon.it"),
    "netflix": ("netflix.com", "netflix.net", "nflxext.com", "netflixtechblog.com"),
    "apple": ("apple.com", "icloud.com", "me.com"),
    "google": ("google.com", "google.fr", "gmail.com", "googleapis.com", "gstatic.com",
               "googleusercontent.com", "youtube.com"),
    "ameli": ("ameli.fr", "assurance-maladie.fr"),
    "impots": ("impots.gouv.fr",),
    "laposte": ("laposte.fr", "laposte.net", "labanquepostale.fr"),
    "labanquepostale": ("labanquepostale.fr",),
    "chronopost": ("chronopost.fr", "chronopost.com"),
    "colissimo": ("colissimo.fr", "laposte.fr"),
    "creditagricole": ("credit-agricole.fr", "credit-agricole.com", "ca-paris.fr"),
    "societegenerale": ("societegenerale.fr", "societegenerale.com", "sg.fr"),
    "bnpparibas": ("bnpparibas", "bnpparibas.com", "bnpparibas.fr", "mabanque.bnpparibas"),
    "caisseepargne": ("caisse-epargne.fr",),
    "creditmutuel": ("creditmutuel.fr", "creditmutuel.com"),
    "boursorama": ("boursorama.com", "boursobank.com"),
    "banquepopulaire": ("banquepopulaire.fr",),
    "docusign": ("docusign.com", "docusign.net"),
}

# Substitutions visuelles courantes (le chiffre 1 est testé comme « l » et comme « i »).
_SEQUENCE_HOMOGLYPHS: tuple[tuple[str, str], ...] = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_CHAR_HOMOGLYPHS: dict[str, str] = {"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}

# Seuils de longueur pour limiter les faux positifs sur les marques courtes.
MIN_BRAND_LEN_EXACT = 4
MIN_BRAND_LEN_FUZZY = 6


def levenshtein(a: str, b: str) -> int:
    """Distance d'édition classique (insertion, suppression, substitution)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def homoglyph_variants(token: str) -> set[str]:
    """Renvoie les versions « déguisées » d'un mot une fois les homoglyphes remplacés."""
    base = token
    for fake, real in _SEQUENCE_HOMOGLYPHS:
        base = base.replace(fake, real)
    base = "".join(_CHAR_HOMOGLYPHS.get(c, c) for c in base)
    return {base.replace("1", "l"), base.replace("1", "i")}


def is_official(host: str, brand_domains: Iterable[str] | None = None) -> bool:
    """Indique si l'hôte est un domaine officiel (ou un sous-domaine d'un domaine officiel)."""
    host = normalize_host(host)
    domains = brand_domains if brand_domains is not None else (
        d for doms in BRANDS.values() for d in doms
    )
    return any(host == d or host.endswith("." + d) for d in domains)


def _tokens(host: str) -> list[str]:
    """Découpe un hôte en mots à comparer (labels, segments séparés par des tirets, label sans tirets)."""
    tokens: list[str] = []
    for label in host.split("."):
        tokens.append(label)
        if "-" in label:
            tokens.extend(label.split("-"))
            tokens.append(label.replace("-", ""))
    return [t for t in dict.fromkeys(tokens) if t]


def _match_token(token: str, brand: str) -> str | None:
    """Compare un mot à une marque et renvoie la technique d'imitation détectée."""
    if len(brand) >= MIN_BRAND_LEN_EXACT and token == brand:
        return "marque dans un domaine non officiel"
    variants = homoglyph_variants(token) - {token}
    if len(brand) >= MIN_BRAND_LEN_EXACT and any(
        v == brand or (len(brand) >= 5 and brand in v and brand not in token) for v in variants
    ):
        return "homoglyphe"
    if len(brand) >= MIN_BRAND_LEN_FUZZY and len(token) >= MIN_BRAND_LEN_FUZZY - 1:
        if levenshtein(token, brand) == 1:
            return "distance de Levenshtein = 1"
    if len(brand) >= MIN_BRAND_LEN_FUZZY and brand in token:
        return "marque incluse dans un domaine non officiel"
    return None


def check_domain(host: str) -> dict[str, str] | None:
    """Analyse un domaine ; renvoie un dict décrivant l'imitation, ou None s'il est sain."""
    host = normalize_host(host)
    if not host or is_ip(host) or "." not in host or is_official(host):
        return None
    for token in _tokens(host):
        for brand, official in BRANDS.items():
            technique = _match_token(token, brand)
            if technique:
                return {
                    "domain": host,
                    "registered_domain": registered_domain(host),
                    "brand": brand,
                    "technique": technique,
                    "official_domain": official[0],
                }
    return None


def find_typosquats(hosts: Iterable[str]) -> list[dict[str, str]]:
    """Analyse une liste de domaines et renvoie les imitations détectées (sans doublon)."""
    results: list[dict[str, str]] = []
    seen: set[str] = set()
    for host in hosts:
        host = normalize_host(host)
        if not host or host in seen:
            continue
        seen.add(host)
        hit = check_domain(host)
        if hit:
            results.append(hit)
    return results
