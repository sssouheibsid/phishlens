"""Génération des rapports JSON et HTML (autonome, CSS inline, contenu échappé)."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any, Iterable

VERDICT_COLORS: dict[str, str] = {
    "sain": "#15803d",
    "suspect": "#c2410c",
    "malveillant": "#b91c1c",
}
VERDICT_BACKGROUNDS: dict[str, str] = {
    "sain": "#f0fdf4",
    "suspect": "#fff7ed",
    "malveillant": "#fef2f2",
}
AUTH_COLORS: dict[str, str] = {"pass": "#15803d", "fail": "#b91c1c", "softfail": "#c2410c"}


def to_json(result: dict[str, Any]) -> str:
    """Sérialise le résultat d'analyse en JSON lisible."""
    return json.dumps(result, ensure_ascii=False, indent=2)


def _e(value: Any) -> str:
    """Échappe toute valeur pour une insertion sûre dans le HTML."""
    return escape("" if value is None else str(value), quote=True)


def _rows(pairs: Iterable[tuple[str, Any]]) -> str:
    return "".join(
        f"<tr><th>{_e(k)}</th><td>{_e(v) if v not in ('', None) else '<span class=muted>—</span>'}</td></tr>"
        for k, v in pairs
    )


def _list_section(title: str, items: list[str], mono: bool = True) -> str:
    if not items:
        body = "<p class=muted>Aucun élément.</p>"
    else:
        cls = " class=mono" if mono else ""
        body = "<ul>" + "".join(f"<li{cls}>{_e(i)}</li>" for i in items) + "</ul>"
    return f"<section><h2>{_e(title)} <span class=count>{len(items)}</span></h2>{body}</section>"


def _auth_badge(value: str) -> str:
    color = AUTH_COLORS.get(value, "#6b7280")
    return f'<span class=pill style="background:{color}">{_e(value.upper())}</span>'


_CSS = """
*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:#f3f4f6;color:#111827;line-height:1.5}
.wrap{max-width:980px;margin:0 auto;padding:24px 16px 48px}
header.hero{border-radius:14px;padding:24px 28px;border:2px solid var(--c);background:var(--bg);margin-bottom:20px}
.hero h1{margin:0 0 4px;font-size:22px}
.hero .file{color:#4b5563;font-size:14px;word-break:break-all}
.verdict{display:flex;align-items:center;gap:20px;margin-top:16px;flex-wrap:wrap}
.verdict .label{font-size:28px;font-weight:800;color:var(--c);text-transform:uppercase;letter-spacing:.04em}
.score{font-size:15px;color:#374151}
.bar{flex:1;min-width:200px;height:12px;background:#e5e7eb;border-radius:999px;overflow:hidden}
.bar span{display:block;height:100%;background:var(--c)}
section{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:18px 22px;margin-bottom:16px}
h2{font-size:16px;margin:0 0 12px;color:#1f2937}
.count{display:inline-block;background:#e5e7eb;color:#374151;border-radius:999px;padding:0 8px;font-size:12px;vertical-align:middle}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid #f0f0f0;vertical-align:top;word-break:break-word}
th{color:#4b5563;font-weight:600;width:200px}
thead th{background:#f9fafb;width:auto;white-space:nowrap}
.pill{display:inline-block;color:#fff;border-radius:6px;padding:1px 8px;font-size:12px;font-weight:700}
.pts{font-weight:700;color:#b91c1c;white-space:nowrap}
.mono,code{font-family:ui-monospace,Consolas,"Courier New",monospace;font-size:13px;word-break:break-all}
ul{margin:0;padding-left:20px}
.muted{color:#9ca3af}
footer{color:#6b7280;font-size:12px;text-align:center;margin-top:24px}
"""


def to_html(result: dict[str, Any]) -> str:
    """Construit un rapport HTML autonome à partir du résultat d'analyse."""
    verdict = result["verdict"]
    color = VERDICT_COLORS.get(verdict, "#374151")
    background = VERDICT_BACKGROUNDS.get(verdict, "#ffffff")
    mail, auth, iocs = result["email"], result["authentication"], result["iocs"]

    signals_rows = "".join(
        f"<tr><td class=pts>+{int(s['points'])}</td><td>{_e(s['label'])}</td><td>{_e(s['detail'])}</td></tr>"
        for s in result["signals"]
    ) or "<tr><td colspan=3 class=muted>Aucun signal de risque détecté.</td></tr>"

    auth_rows = (
        f"<tr><th>SPF</th><td>{_auth_badge(auth['spf'])} <span class=muted>{_e(auth['spf_source'])}</span></td></tr>"
        f"<tr><th>DKIM</th><td>{_auth_badge(auth['dkim'])} <span class=muted>{_e(', '.join(auth['dkim_domains']))}</span></td></tr>"
        f"<tr><th>DMARC</th><td>{_auth_badge(auth['dmarc'])}</td></tr>"
        + _rows([
            ("Domaine From", auth["from_domain"]),
            ("Domaine Reply-To", auth["reply_to_domain"]),
            ("Domaine Return-Path", auth["return_path_domain"]),
            ("Reply-To divergent", "oui" if auth["reply_to_mismatch"] else "non"),
            ("Return-Path divergent", "oui" if auth["return_path_mismatch"] else "non"),
            ("Usurpation nom affiché", auth["display_name_spoof"] or "non"),
        ])
    )

    attachments_rows = "".join(
        "<tr>"
        f"<td>{_e(a['filename'])}</td><td>{_e(a['content_type'])}</td><td>{int(a['size'])} o</td>"
        f"<td class=mono>{_e(a['sha256'])}</td>"
        f"<td>{'<span class=pill style=background:#b91c1c>DANGEREUSE</span>' if a['dangerous_extension'] else ''}"
        f"{' <span class=pill style=background:#c2410c>DOUBLE EXT.</span>' if a['double_extension'] else ''}</td>"
        "</tr>"
        for a in iocs["attachments"]
    ) or "<tr><td colspan=5 class=muted>Aucune pièce jointe.</td></tr>"

    deceptive_rows = "".join(
        f"<tr><td>{_e(d['text'])}</td><td class=mono>{_e(d['href'])}</td></tr>"
        for d in iocs["deceptive_links"]
    ) or "<tr><td colspan=2 class=muted>Aucun lien trompeur.</td></tr>"

    typo_rows = "".join(
        f"<tr><td class=mono>{_e(t['domain'])}</td><td>{_e(t['brand'])}</td>"
        f"<td>{_e(t['technique'])}</td><td class=mono>{_e(t['official_domain'])}</td></tr>"
        for t in result["typosquatting"]
    ) or "<tr><td colspan=4 class=muted>Aucune imitation de marque.</td></tr>"

    email_rows = _rows([
        ("Sujet", mail["subject"]), ("De", mail["from"]), ("À", mail["to"]),
        ("Reply-To", mail["reply_to"]), ("Return-Path", mail["return_path"]),
        ("Date", mail["date"]), ("Message-ID", mail["message_id"]),
        ("Sauts Received", mail["received_hops"]),
    ])
    lists = "\n".join([
        _list_section("URLs", iocs["urls"]),
        _list_section("Domaines", iocs["domains"]),
        _list_section("Adresses IP publiques", iocs["ips"]),
        _list_section("Vocabulaire d'urgence", result["urgency_terms"], mono=False),
    ])

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PhishLens – {_e(verdict)} – {_e(mail['subject'])}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
<header class="hero" style="--c:{color};--bg:{background}">
  <h1>Rapport PhishLens</h1>
  <div class="file">{_e(result['file'])}</div>
  <div class="verdict">
    <div class="label">{_e(verdict)}</div>
    <div class="score"><strong>{int(result['score'])}</strong>/100</div>
    <div class="bar"><span style="width:{int(result['score'])}%"></span></div>
  </div>
</header>

<section><h2>E-mail</h2><table>{email_rows}</table></section>

<section><h2>Signaux de risque <span class=count>{len(result['signals'])}</span></h2>
<table><thead><tr><th>Points</th><th>Signal</th><th>Détail</th></tr></thead><tbody>{signals_rows}</tbody></table></section>

<section><h2>Authentification</h2><table>{auth_rows}</table></section>

<section><h2>Typosquatting</h2>
<table><thead><tr><th>Domaine</th><th>Marque</th><th>Technique</th><th>Domaine officiel</th></tr></thead><tbody>{typo_rows}</tbody></table></section>

<section><h2>Liens trompeurs</h2>
<table><thead><tr><th>Texte affiché</th><th>Destination réelle</th></tr></thead><tbody>{deceptive_rows}</tbody></table></section>

<section><h2>Pièces jointes</h2>
<table><thead><tr><th>Nom</th><th>Type</th><th>Taille</th><th>SHA-256</th><th>Alertes</th></tr></thead><tbody>{attachments_rows}</tbody></table></section>

{lists}

<footer>Généré par PhishLens v{_e(result['version'])} le {_e(result['analyzed_at'])} – analyse hors ligne, à confirmer par un analyste.</footer>
</div>
</body>
</html>
"""


def write_reports(result: dict[str, Any], output_dir: str | Path, fmt: str = "both") -> list[Path]:
    """Écrit les rapports demandés (html, json ou both) et renvoie leurs chemins."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(result["file"]).stem
    written: list[Path] = []
    if fmt in ("json", "both"):
        path = output_dir / f"{stem}.json"
        path.write_text(to_json(result), encoding="utf-8")
        written.append(path)
    if fmt in ("html", "both"):
        path = output_dir / f"{stem}.html"
        path.write_text(to_html(result), encoding="utf-8")
        written.append(path)
    return written
