"""Tests de PhishLens (pytest)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from phishlens import analyze
from phishlens.auth import (
    display_name_spoof,
    parse_authentication_results,
    parse_received_spf,
)
from phishlens.cli import main
from phishlens.ioc import analyze_attachment_name, find_deceptive_links, public_ips
from phishlens.report import to_html
from phishlens.scoring import compute_score, find_urgency_terms, verdict_for
from phishlens.typosquat import check_domain, homoglyph_variants, levenshtein

ROOT = Path(__file__).resolve().parent.parent
PHISHING = ROOT / "samples" / "facture_phishing.eml"
LEGIT = ROOT / "samples" / "newsletter_legit.eml"


@pytest.fixture(scope="module")
def phishing() -> dict:
    return analyze(PHISHING)


@pytest.fixture(scope="module")
def legit() -> dict:
    return analyze(LEGIT)


# --- Verdicts des échantillons ----------------------------------------------------------

def test_phishing_sample_is_malicious(phishing: dict) -> None:
    assert phishing["verdict"] == "malveillant"
    assert phishing["score"] >= 60
    assert phishing["score"] <= 100


def test_legit_sample_is_clean(legit: dict) -> None:
    assert legit["verdict"] == "sain"
    assert legit["score"] < 25
    assert legit["signals"] == []


def test_phishing_expected_signals(phishing: dict) -> None:
    ids = {s["id"] for s in phishing["signals"]}
    expected = {
        "spf_fail", "dmarc_fail", "reply_to_mismatch", "display_name_spoof", "typosquat",
        "deceptive_link", "dangerous_attachment", "double_extension", "ip_url", "urgency",
    }
    assert expected <= ids


# --- Authentification -------------------------------------------------------------------

def test_auth_results_phishing(phishing: dict) -> None:
    auth = phishing["authentication"]
    assert auth["spf"] == "fail"
    assert auth["dmarc"] == "fail"
    assert auth["dkim"] == "none"
    assert auth["from_domain"] == "paypa1-secure.com"
    assert auth["reply_to_mismatch"] is True
    assert auth["return_path_mismatch"] is False
    assert auth["display_name_spoof"] == "service@paypal.com"


def test_auth_results_legit(legit: dict) -> None:
    auth = legit["authentication"]
    assert (auth["spf"], auth["dkim"], auth["dmarc"]) == ("pass", "pass", "pass")
    assert auth["dkim_domains"] == ["journaltech.fr"]
    assert auth["reply_to_mismatch"] is False


def test_parse_authentication_results_multiple_dkim() -> None:
    header = "mx.test; spf=softfail smtp.mailfrom=a.com; dkim=fail header.d=x.com; dkim=pass header.d=a.com; dmarc=pass"
    assert parse_authentication_results([header]) == {"spf": "softfail", "dkim": "pass", "dmarc": "pass"}


def test_parse_authentication_results_absent() -> None:
    assert parse_authentication_results([]) == {"spf": "absent", "dkim": "absent", "dmarc": "absent"}


def test_received_spf_fallback() -> None:
    assert parse_received_spf(["SoftFail (domain of x does not designate ...)"]) == "softfail"
    assert parse_received_spf([]) == "absent"


def test_display_name_spoof() -> None:
    assert display_name_spoof("support@amazon.fr", "evil.com") == "support@amazon.fr"
    assert display_name_spoof("Service client", "evil.com") is None
    assert display_name_spoof("contact@www.journaltech.fr", "journaltech.fr") is None


# --- IOC --------------------------------------------------------------------------------

def test_iocs_phishing(phishing: dict) -> None:
    iocs = phishing["iocs"]
    assert "http://185.234.72.19/paypal/login.php" in iocs["urls"]
    assert "185.234.72.19" in iocs["ips"]
    assert "10.0.0.25" not in iocs["ips"]  # IP privée exclue
    assert iocs["ip_urls"] == ["http://185.234.72.19/paypal/login.php"]
    link = iocs["deceptive_links"][0]
    assert link["shown_domain"] == "www.paypal.com"
    assert link["real_host"] == "185.234.72.19"
    att = iocs["attachments"][0]
    assert att["filename"] == "facture.pdf.exe"
    assert len(att["sha256"]) == 64
    assert att["dangerous_extension"] and att["double_extension"]


def test_iocs_legit(legit: dict) -> None:
    iocs = legit["iocs"]
    assert iocs["deceptive_links"] == []
    assert iocs["domains"] == ["www.journaltech.fr"]
    assert "93.184.215.14" in iocs["received_ips"]


@pytest.mark.parametrize(
    ("name", "dangerous", "double"),
    [
        ("facture.pdf.exe", True, True),
        ("photo.jpg.js", True, True),
        ("script.ps1", True, False),
        ("raccourci.lnk", True, False),
        ("image.iso", True, False),
        ("devis.docm", True, False),
        ("rapport.pdf", False, False),
        ("archive.tar.gz", False, False),
        ("README", False, False),
    ],
)
def test_attachment_names(name: str, dangerous: bool, double: bool) -> None:
    assert analyze_attachment_name(name) == {"dangerous_extension": dangerous, "double_extension": double}


def test_deceptive_links() -> None:
    html = (
        '<a href="https://evil.example.net/x">https://www.impots.gouv.fr</a>'
        '<a href="https://www.paypal.com/fr/home">www.paypal.com</a>'
        '<a href="https://shop.example.org/f.pdf">Télécharger facture.pdf</a>'
    )
    links = find_deceptive_links(html)
    assert len(links) == 1
    assert links[0]["real_host"] == "evil.example.net"


def test_public_ips_filters_private() -> None:
    assert public_ips(["from [192.168.1.10] by [8.8.8.8] via 127.0.0.1 and 999.1.1.1"]) == ["8.8.8.8"]


# --- Typosquatting ----------------------------------------------------------------------

@pytest.mark.parametrize(
    ("domain", "brand"),
    [
        ("paypa1-secure.com", "paypal"),
        ("rnicrosoft.com", "microsoft"),
        ("arnazon.fr", "amazon"),
        ("amazom.com", "amazon"),
        ("netf1ix-billing.com", "netflix"),
        ("ameli-remboursement.com", "ameli"),
        ("impots-gouv-fr.info", "impots"),
        ("chronopostt.fr", "chronopost"),
        ("credit-agricole-securite.com", "creditagricole"),
        ("paypal.com.verification.ru", "paypal"),
        ("laposte-colis.net", "laposte"),
    ],
)
def test_typosquat_positive(domain: str, brand: str) -> None:
    hit = check_domain(domain)
    assert hit is not None, domain
    assert hit["brand"] == brand


@pytest.mark.parametrize(
    "domain",
    [
        "paypal.com", "www.paypal.fr", "microsoft.com", "login.microsoftonline.com",
        "amazon.fr", "www.amazon.com", "netflix.com", "ameli.fr", "impots.gouv.fr",
        "www.laposte.fr", "chronopost.fr", "credit-agricole.fr", "boursorama.com",
        "journaltech.fr", "github.com", "lemonde.fr", "amelie-boutique.fr", "example.com",
        "185.234.72.19",
    ],
)
def test_typosquat_negative(domain: str) -> None:
    assert check_domain(domain) is None


def test_levenshtein() -> None:
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypal", "paypall") == 1
    assert levenshtein("amazon", "amazom") == 1
    assert levenshtein("kitten", "sitting") == 3


def test_homoglyph_variants() -> None:
    assert "paypal" in homoglyph_variants("paypa1")
    assert "microsoft" in homoglyph_variants("rnicrosoft")
    assert "google" in homoglyph_variants("g00gle")


# --- Scoring ----------------------------------------------------------------------------

def test_score_thresholds() -> None:
    assert verdict_for(0) == "sain"
    assert verdict_for(24) == "sain"
    assert verdict_for(25) == "suspect"
    assert verdict_for(59) == "suspect"
    assert verdict_for(60) == "malveillant"


def test_score_is_capped() -> None:
    signals = [{"points": 30}] * 10
    assert compute_score(signals) == (100, "malveillant")


def test_urgency_terms_without_accents() -> None:
    terms = find_urgency_terms("Vérifiez votre compte IMMÉDIATEMENT", "sinon il sera suspendu")
    assert {"immediatement", "verifiez votre compte", "sera suspendu"} <= set(terms)
    assert find_urgency_terms("Bonne lecture et à la semaine prochaine") == []


# --- Rapports et CLI --------------------------------------------------------------------

def test_html_report_escapes_content(phishing: dict) -> None:
    result = dict(phishing)
    result["email"] = dict(phishing["email"], subject='<script>alert("x")</script>')
    page = to_html(result)
    assert "<script>alert" not in page
    assert "&lt;script&gt;" in page
    assert "malveillant" in page


def test_cli_writes_reports(tmp_path: Path) -> None:
    code = main(["analyze", str(PHISHING), str(LEGIT), "-o", str(tmp_path), "-q"])
    assert code == 2  # pire verdict : malveillant
    for stem in ("facture_phishing", "newsletter_legit"):
        assert (tmp_path / f"{stem}.html").is_file()
        data = json.loads((tmp_path / f"{stem}.json").read_text(encoding="utf-8"))
        assert data["tool"] == "phishlens"


def test_cli_exit_code_clean_and_format(tmp_path: Path) -> None:
    code = main(["analyze", str(LEGIT), "-o", str(tmp_path), "-f", "json", "-q"])
    assert code == 0
    assert (tmp_path / "newsletter_legit.json").is_file()
    assert not (tmp_path / "newsletter_legit.html").exists()


def test_cli_missing_file(tmp_path: Path) -> None:
    assert main(["analyze", str(tmp_path / "absent.eml"), "-o", str(tmp_path)]) == 3


def test_python_m_entrypoint(tmp_path: Path) -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "phishlens", "analyze", str(PHISHING), "-o", str(tmp_path), "-f", "html"],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    assert proc.returncode == 2, proc.stderr
    assert "MALVEILLANT" in proc.stdout
    assert (tmp_path / "facture_phishing.html").is_file()
