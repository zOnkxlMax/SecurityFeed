#!/usr/bin/env python3
"""Holt die neuesten Schwachstellen-Meldungen von BleepingComputer und heise.de.

Nur Standardbibliothek - keine Installation noetig.

Beispiele:
    py -3 vulnfeed.py                       # letzte 7 Tage, Tabelle
    py -3 vulnfeed.py --since 2 --limit 20  # letzte 2 Tage, max. 20 Eintraege
    py -3 vulnfeed.py --source heise-alerts --format markdown
    py -3 vulnfeed.py --format json > vulns.json
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import re
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

ATOM = "{http://www.w3.org/2005/Atom}"

__version__ = "1.0.0"

# Wichtig: ehrlicher Feedreader-User-Agent. Der urllib-Default ("Python-urllib/x")
# wird von BleepingComputer mit 403 abgewiesen - ein vorgetaeuschter Browser-UA
# uebrigens ebenfalls, die Bot-Erkennung merkt den fehlenden Browser-Fingerprint.
HEADERS = {
    "User-Agent": f"SecurityFeed/{__version__} (RSS reader; +https://github.com/zOnkxlMax)",
    "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.8",
}

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")

# Treffer in Titel/Beschreibung -> Meldung gilt als Schwachstellen-Thema.
VULN_TERMS = (
    "cve-", "vulnerab", "zero-day", "zero day", "0-day", "exploit", "rce",
    "remote code execution", "privilege escalation", "security update",
    "patch tuesday", "patches", "patched", "flaw", "backdoor",
    "sicherheitslueck", "sicherheitslück", "schwachstell", "luecke", "lücke",
    "angreifer", "attacke", "sicherheitspatch", "sicherheitsupdate",
    "jetzt patchen", "verwundbar", "notfall-patch", "exploit-code",
)


@dataclass(frozen=True)
class Source:
    key: str
    label: str
    url: str
    kind: str  # "rss" oder "atom"
    always_vuln: bool = False  # Feed enthaelt ausschliesslich Luecken-Meldungen


SOURCES: tuple[Source, ...] = (
    Source(
        "bleeping", "BleepingComputer",
        "https://www.bleepingcomputer.com/feed/", "rss",
    ),
    Source(
        "heise-alerts", "heise Security Alerts",
        "https://www.heise.de/security/rss/alerts-atom.xml", "atom",
        always_vuln=True,
    ),
    Source(
        "heise-security", "heise Security",
        "https://www.heise.de/security/rss/news-atom.xml", "atom",
    ),
)


@dataclass
class Entry:
    source: str
    title: str
    link: str
    published: datetime | None
    summary: str
    cves: list[str] = field(default_factory=list)
    advisory: bool = False  # stammt aus einem reinen Advisory-Feed

    @property
    def is_vuln(self) -> bool:
        if self.advisory or self.cves:
            return True
        haystack = f"{self.title} {self.summary}".lower()
        return any(term in haystack for term in VULN_TERMS)

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "title": self.title,
            "link": self.link,
            "published": self.published.isoformat() if self.published else None,
            "cves": self.cves,
            "advisory": self.advisory,
            "summary": self.summary,
        }


def clean(raw: str | None) -> str:
    """HTML-Tags und Entities raus, Whitespace normalisieren."""
    if not raw:
        return ""
    return WS_RE.sub(" ", html.unescape(TAG_RE.sub(" ", raw))).strip()


def parse_date(raw: str | None) -> datetime | None:
    if not raw:
        return None
    raw = raw.strip()
    try:  # RFC 822, z.B. "Tue, 28 Jul 2026 17:17:39 -0400"
        return parsedate_to_datetime(raw).astimezone(timezone.utc)
    except (TypeError, ValueError):
        pass
    try:  # ISO 8601, z.B. "2026-07-28T12:15:00.000Z"
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def fetch(url: str, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def parse_rss(root: ET.Element, source: str) -> list[Entry]:
    entries = []
    for item in root.iterfind(".//item"):
        title = clean(item.findtext("title"))
        summary = clean(item.findtext("description"))
        entries.append(Entry(
            source=source,
            title=title,
            link=(item.findtext("link") or "").strip(),
            published=parse_date(item.findtext("pubDate")),
            summary=summary,
            cves=find_cves(title, summary),
        ))
    return entries


def parse_atom(root: ET.Element, source: str) -> list[Entry]:
    entries = []
    for item in root.iterfind(f"{ATOM}entry"):
        title = clean(item.findtext(f"{ATOM}title"))
        summary = clean(item.findtext(f"{ATOM}summary") or item.findtext(f"{ATOM}content"))
        link_el = item.find(f"{ATOM}link")
        entries.append(Entry(
            source=source,
            title=title,
            link=(link_el.get("href") if link_el is not None else "") or "",
            published=parse_date(
                item.findtext(f"{ATOM}published") or item.findtext(f"{ATOM}updated")
            ),
            summary=summary,
            cves=find_cves(title, summary),
        ))
    return entries


def find_cves(*texts: str) -> list[str]:
    seen: dict[str, None] = {}
    for text in texts:
        for match in CVE_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


def load_source(source: Source, timeout: float) -> tuple[Source, list[Entry], str | None]:
    """Liefert (Quelle, Eintraege, Fehlermeldung)."""
    try:
        raw = fetch(source.url, timeout)
        root = ET.fromstring(raw)
    except urllib.error.HTTPError as exc:
        return source, [], f"HTTP {exc.code} {exc.reason}"
    except (urllib.error.URLError, TimeoutError) as exc:
        return source, [], f"Netzwerkfehler: {exc.reason if hasattr(exc, 'reason') else exc}"
    except ET.ParseError as exc:
        return source, [], f"Feed nicht lesbar: {exc}"

    parser = parse_atom if source.kind == "atom" else parse_rss
    entries = parser(root, source.label)
    if source.always_vuln:
        # Feed besteht komplett aus Luecken-Meldungen; der Keyword-Filter waere
        # hier nur eine Fehlerquelle.
        for entry in entries:
            entry.advisory = True
    return source, entries, None


def collect(selected: list[Source], timeout: float, quiet: bool) -> list[Entry]:
    entries: list[Entry] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(selected)) as pool:
        for source, found, error in pool.map(lambda s: load_source(s, timeout), selected):
            if error:
                if not quiet:
                    print(f"! {source.label}: {error}", file=sys.stderr)
                continue
            entries.extend(found)
    return entries


def enrich_with_cves(entries: list[Entry], timeout: float, quiet: bool) -> None:
    """Laedt die Artikelseiten und zieht CVE-Nummern heraus (in-place).

    Die Feeds liefern nur Titel und Anrisstext, konkrete CVE-IDs stehen erst im
    Artikel. Bewusst wenige parallele Requests, um die Seiten nicht zu belasten.
    """
    def load(entry: Entry) -> None:
        if not entry.link:
            return
        try:
            body = fetch(entry.link, timeout).decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            if not quiet:
                print(f"! Artikel nicht ladbar ({exc}): {entry.link}", file=sys.stderr)
            return
        merged = dict.fromkeys(entry.cves)
        for cve in find_cves(body):
            merged.setdefault(cve, None)
        entry.cves = list(merged)

    if not entries:
        return
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(load, entries))


def dedupe(entries: list[Entry]) -> list[Entry]:
    seen: set[str] = set()
    unique = []
    for entry in entries:
        key = entry.link or entry.title
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def render_table(entries: list[Entry]) -> str:
    if not entries:
        return "Keine passenden Meldungen gefunden."
    lines = []
    for entry in entries:
        stamp = entry.published.astimezone().strftime("%Y-%m-%d %H:%M") if entry.published else "?"
        cves = f"  [{', '.join(entry.cves)}]" if entry.cves else ""
        lines.append(f"{stamp}  {entry.source}{cves}")
        lines.append(f"  {entry.title}")
        if entry.summary:
            summary = entry.summary if len(entry.summary) <= 200 else entry.summary[:197] + "..."
            lines.append(f"  {summary}")
        lines.append(f"  {entry.link}")
        lines.append("")
    lines.append(f"{len(entries)} Meldung(en).")
    return "\n".join(lines)


def render_markdown(entries: list[Entry]) -> str:
    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
    lines = ["# Aktuelle Schwachstellen-Meldungen", "", f"_Stand: {generated}_", ""]
    if not entries:
        lines.append("Keine passenden Meldungen gefunden.")
        return "\n".join(lines)
    for entry in entries:
        stamp = entry.published.astimezone().strftime("%Y-%m-%d %H:%M") if entry.published else "?"
        cves = f" — `{'`, `'.join(entry.cves)}`" if entry.cves else ""
        lines.append(f"## [{entry.title}]({entry.link})")
        lines.append("")
        lines.append(f"*{entry.source} · {stamp}*{cves}")
        if entry.summary:
            lines.append("")
            lines.append(entry.summary)
        lines.append("")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Neueste Schwachstellen-Meldungen von BleepingComputer und heise.de.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source", "-s", action="append", choices=[s.key for s in SOURCES],
        help="Nur diese Quelle(n) abfragen (mehrfach angebbar). Default: alle.",
    )
    parser.add_argument("--since", "-d", type=float, default=7,
                        help="Nur Meldungen der letzten N Tage (0 = alle).")
    parser.add_argument("--limit", "-n", type=int, default=0,
                        help="Maximale Anzahl Meldungen (0 = unbegrenzt).")
    parser.add_argument("--format", "-f", choices=("table", "json", "markdown"),
                        default="table", help="Ausgabeformat.")
    parser.add_argument("--all", action="store_true",
                        help="Auch Nicht-Schwachstellen-News ausgeben (kein Themenfilter).")
    parser.add_argument("--details", action="store_true",
                        help="Artikelseiten nachladen, um CVE-Nummern zu ergaenzen (langsamer).")
    parser.add_argument("--cve-only", action="store_true",
                        help="Nur Meldungen mit konkreter CVE-Nummer (impliziert --details).")
    parser.add_argument("--detail-limit", type=int, default=25,
                        help="Maximal so viele Artikelseiten nachladen.")
    parser.add_argument("--timeout", type=float, default=20.0,
                        help="HTTP-Timeout in Sekunden pro Feed.")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Warnungen zu fehlgeschlagenen Feeds unterdruecken.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Umlaute auch in einer cp1252-Konsole nicht crashen lassen.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    selected = [s for s in SOURCES if not args.source or s.key in args.source]
    entries = dedupe(collect(selected, args.timeout, args.quiet))

    if args.since > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.since)
        entries = [e for e in entries if e.published is None or e.published >= cutoff]
    if not args.all:
        entries = [e for e in entries if e.is_vuln]

    entries.sort(key=lambda e: e.published or datetime.min.replace(tzinfo=timezone.utc),
                 reverse=True)

    if args.details or args.cve_only:
        enrich_with_cves(entries[: max(args.detail_limit, 0)], args.timeout, args.quiet)
    if args.cve_only:
        entries = [e for e in entries if e.cves]

    if args.limit > 0:
        entries = entries[: args.limit]

    if args.format == "json":
        print(json.dumps([e.as_dict() for e in entries], indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print(render_markdown(entries))
    else:
        print(render_table(entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
