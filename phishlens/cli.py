"""Interface en ligne de commande : phishlens analyze fichiers.eml [-o DIR] [-f FORMAT] [-q]."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from . import __version__, analyze
from .report import write_reports

# Codes de sortie : le pire verdict parmi les fichiers analysés.
EXIT_CODES: dict[str, int] = {"sain": 0, "suspect": 1, "malveillant": 2}
EXIT_ERROR = 3

_ANSI = {"sain": "\033[32m", "suspect": "\033[33m", "malveillant": "\033[31m"}
_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"


def _enable_windows_ansi() -> None:
    """Active les séquences ANSI dans la console Windows (sans effet ailleurs)."""
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _use_color(stream: TextIO) -> bool:
    return stream.isatty() and "NO_COLOR" not in os.environ


class _Printer:
    """Petit utilitaire d'affichage, avec ou sans couleurs."""

    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.color = _use_color(stream)

    def style(self, text: str, *codes: str) -> str:
        return f"{''.join(codes)}{text}{_RESET}" if self.color else text

    def line(self, text: str = "") -> None:
        print(text, file=self.stream)


def _print_result(out: _Printer, result: dict[str, Any], reports: list[Path], quiet: bool) -> None:
    verdict = result["verdict"]
    badge = out.style(f"{verdict.upper()} ({result['score']}/100)", _BOLD, _ANSI[verdict])
    if quiet:
        out.line(f"{badge}  {result['file']}")
        return

    auth = result["authentication"]
    out.line(out.style(f"PhishLens v{__version__} - {result['file']}", _BOLD))
    out.line(f"  Sujet    : {result['email']['subject']}")
    out.line(f"  De       : {result['email']['from']}")
    out.line(f"  Auth     : SPF={auth['spf']}  DKIM={auth['dkim']}  DMARC={auth['dmarc']}")
    out.line(f"  Verdict  : {badge}")
    if result["signals"]:
        out.line("  Signaux  :")
        for signal in result["signals"]:
            points = out.style(f"+{signal['points']:>2}", _ANSI["malveillant"])
            detail = out.style(f"  {signal['detail']}", _DIM) if signal["detail"] else ""
            out.line(f"    {points}  {signal['label']}{detail}")
    else:
        out.line("  Signaux  : aucun")
    iocs = result["iocs"]
    out.line(
        f"  IOC      : {len(iocs['urls'])} URL(s), {len(iocs['domains'])} domaine(s), "
        f"{len(iocs['ips'])} IP(s), {len(iocs['attachments'])} pièce(s) jointe(s)"
    )
    for att in iocs["attachments"]:
        out.line(f"             {att['filename']}  sha256={att['sha256']}")
    if reports:
        out.line("  Rapports : " + ", ".join(str(p) for p in reports))
    out.line()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishlens",
        description="Analyse hors ligne d'e-mails suspects (.eml) : SPF/DKIM/DMARC, IOC, typosquatting.",
        epilog="Codes de sortie : 0 sain, 1 suspect, 2 malveillant, 3 erreur.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_cmd = sub.add_parser("analyze", help="analyser un ou plusieurs fichiers .eml")
    analyze_cmd.add_argument("files", nargs="+", type=Path, help="fichier(s) .eml à analyser")
    analyze_cmd.add_argument("-o", "--output", type=Path, default=Path("reports"),
                             help="dossier des rapports (défaut : reports)")
    analyze_cmd.add_argument("-f", "--format", choices=("html", "json", "both"), default="both",
                             help="format des rapports (défaut : both)")
    analyze_cmd.add_argument("-q", "--quiet", action="store_true",
                             help="une seule ligne par fichier")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Point d'entrée ; renvoie le code de sortie."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    _enable_windows_ansi()

    args = build_parser().parse_args(argv)
    out = _Printer(sys.stdout)
    worst = 0
    had_error = False

    for path in args.files:
        if not path.is_file():
            print(f"Erreur : fichier introuvable : {path}", file=sys.stderr)
            had_error = True
            continue
        try:
            result = analyze(path)
            reports = write_reports(result, args.output, args.format)
        except Exception as exc:  # on continue avec les autres fichiers
            print(f"Erreur lors de l'analyse de {path} : {exc}", file=sys.stderr)
            had_error = True
            continue
        _print_result(out, result, reports, args.quiet)
        worst = max(worst, EXIT_CODES[result["verdict"]])

    if had_error and worst == 0:
        return EXIT_ERROR
    return worst


if __name__ == "__main__":
    sys.exit(main())
