"""PhishLens : analyse hors ligne d'e-mails suspects (.eml) pour analystes SOC."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .auth import check_authentication
from .ioc import extract_iocs
from .parser import parse_email
from .scoring import collect_signals, compute_score, find_urgency_terms, html_to_text
from .typosquat import find_typosquats

__version__ = "0.1.0"
__all__ = ["analyze", "__version__"]


def analyze(path: str | Path) -> dict[str, Any]:
    """Analyse un fichier .eml et renvoie un dict complet (sérialisable en JSON).

    Enchaîne : lecture -> authentification -> IOC -> typosquatting -> urgence -> score.
    """
    email = parse_email(path)
    auth = check_authentication(email)
    iocs = extract_iocs(email)

    # Domaines à tester : expéditeur, Reply-To, Return-Path et domaines des URLs.
    candidate_domains = [
        auth["from_domain"],
        auth["reply_to_domain"],
        auth["return_path_domain"],
        *iocs["domains"],
    ]
    typosquats = find_typosquats(d for d in candidate_domains if d)

    urgency_terms = find_urgency_terms(email.subject, email.text_body, html_to_text(email.html_body))
    signals = collect_signals(auth, iocs, typosquats, urgency_terms)
    score, verdict = compute_score(signals)

    return {
        "tool": "phishlens",
        "version": __version__,
        "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "file": Path(path).as_posix(),
        "email": {
            "subject": email.subject,
            "from": email.from_header,
            "to": email.to,
            "reply_to": email.reply_to,
            "return_path": email.return_path,
            "date": email.date,
            "message_id": email.message_id,
            "received_hops": len(email.received),
        },
        "authentication": auth,
        "iocs": iocs,
        "typosquatting": typosquats,
        "urgency_terms": urgency_terms,
        "signals": signals,
        "score": score,
        "verdict": verdict,
    }
