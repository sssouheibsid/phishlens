"""Calcul du score de risque (0-100) et du verdict à partir des signaux détectés."""

from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

# Seuils de verdict.
MALICIOUS_THRESHOLD = 60
SUSPICIOUS_THRESHOLD = 25
MAX_SCORE = 100

VERDICT_CLEAN = "sain"
VERDICT_SUSPICIOUS = "suspect"
VERDICT_MALICIOUS = "malveillant"

# Points attribués par signal.
POINTS: dict[str, int] = {
    "spf_fail": 15,
    "spf_softfail": 8,
    "dkim_fail": 10,
    "dmarc_fail": 15,
    "reply_to_mismatch": 10,
    "return_path_mismatch": 5,
    "display_name_spoof": 15,
    "typosquat": 25,
    "deceptive_link": 20,
    "dangerous_attachment": 30,
    "double_extension": 15,
    "ip_url": 10,
    "urgency": 10,
}

# Vocabulaire d'urgence / de pression (comparé sans accents, en minuscules).
URGENCY_TERMS: tuple[str, ...] = (
    "urgent", "immediatement", "sans delai", "sous 24 heures", "sous 24h", "sous 48 heures",
    "dernier rappel", "derniere relance", "action requise", "compte suspendu", "compte bloque",
    "sera suspendu", "sera bloque", "sera supprime", "verifiez votre compte",
    "confirmez votre identite", "mettre a jour vos informations", "activite inhabituelle",
    "acces limite", "facture impayee", "paiement refuse", "mise en demeure", "poursuites",
    "immediately", "action required", "account suspended", "verify your account",
    "within 24 hours", "final notice", "unusual activity", "password expires",
)


def _strip_accents(text: str) -> str:
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(c for c in normalized if not unicodedata.combining(c))


def html_to_text(html_body: str) -> str:
    """Conversion HTML -> texte rudimentaire (suffisante pour la recherche de mots-clés)."""
    without_hidden = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html_body or "")
    return html.unescape(re.sub(r"<[^>]+>", " ", without_hidden))


def find_urgency_terms(*texts: str) -> list[str]:
    """Renvoie les expressions d'urgence trouvées (sans doublon)."""
    haystack = " ".join(_strip_accents(t or "").lower() for t in texts)
    haystack = " ".join(haystack.split())
    return [term for term in URGENCY_TERMS if term in haystack]


def _signal(signal_id: str, label: str, detail: str = "") -> dict[str, Any]:
    return {"id": signal_id, "label": label, "points": POINTS[signal_id], "detail": detail}


def collect_signals(
    auth: dict[str, Any],
    iocs: dict[str, Any],
    typosquats: list[dict[str, str]],
    urgency_terms: list[str],
) -> list[dict[str, Any]]:
    """Transforme les résultats d'analyse en liste de signaux pondérés."""
    signals: list[dict[str, Any]] = []

    if auth["spf"] in ("fail", "permerror"):
        signals.append(_signal("spf_fail", "SPF en échec", f"résultat : {auth['spf']}"))
    elif auth["spf"] == "softfail":
        signals.append(_signal("spf_softfail", "SPF en échec partiel (softfail)"))
    if auth["dkim"] in ("fail", "permerror"):
        signals.append(_signal("dkim_fail", "Signature DKIM invalide", f"résultat : {auth['dkim']}"))
    if auth["dmarc"] in ("fail", "permerror"):
        signals.append(_signal("dmarc_fail", "DMARC en échec", f"résultat : {auth['dmarc']}"))
    if auth["reply_to_mismatch"]:
        signals.append(_signal(
            "reply_to_mismatch", "Reply-To vers un autre domaine",
            f"{auth['reply_to_domain']} ≠ {auth['from_domain']}",
        ))
    if auth["return_path_mismatch"]:
        signals.append(_signal(
            "return_path_mismatch", "Return-Path d'un autre domaine",
            f"{auth['return_path_domain']} ≠ {auth['from_domain']}",
        ))
    if auth["display_name_spoof"]:
        signals.append(_signal(
            "display_name_spoof", "Adresse usurpée dans le nom affiché",
            f"{auth['display_name_spoof']} affiché, envoyé depuis {auth['from_domain']}",
        ))
    if typosquats:
        detail = ", ".join(f"{t['domain']} imite {t['brand']} ({t['technique']})" for t in typosquats)
        signals.append(_signal("typosquat", "Domaine imitant une marque", detail))
    if iocs["deceptive_links"]:
        detail = ", ".join(f"« {d['shown_domain']} » -> {d['real_host']}" for d in iocs["deceptive_links"])
        signals.append(_signal("deceptive_link", "Lien trompeur (texte ≠ destination)", detail))

    dangerous = [a["filename"] for a in iocs["attachments"] if a["dangerous_extension"]]
    if dangerous:
        signals.append(_signal("dangerous_attachment", "Pièce jointe dangereuse", ", ".join(dangerous)))
    doubles = [a["filename"] for a in iocs["attachments"] if a["double_extension"]]
    if doubles:
        signals.append(_signal("double_extension", "Double extension de fichier", ", ".join(doubles)))
    if iocs["ip_urls"]:
        signals.append(_signal("ip_url", "URL pointant vers une adresse IP brute", ", ".join(iocs["ip_urls"])))
    # Un seul mot peut être anodin : on exige au moins deux expressions distinctes.
    if len(urgency_terms) >= 2:
        signals.append(_signal("urgency", "Vocabulaire d'urgence", ", ".join(urgency_terms)))

    return signals


def verdict_for(score: int) -> str:
    """Traduit un score en verdict."""
    if score >= MALICIOUS_THRESHOLD:
        return VERDICT_MALICIOUS
    if score >= SUSPICIOUS_THRESHOLD:
        return VERDICT_SUSPICIOUS
    return VERDICT_CLEAN


def compute_score(signals: list[dict[str, Any]]) -> tuple[int, str]:
    """Additionne les points, plafonne à 100 et renvoie (score, verdict)."""
    score = min(MAX_SCORE, sum(s["points"] for s in signals))
    return score, verdict_for(score)
