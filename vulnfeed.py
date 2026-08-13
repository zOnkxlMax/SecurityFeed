#!/usr/bin/env python3
"""Holt die neuesten Schwachstellen-Meldungen von BleepingComputer und heise.de.

Mit --local zusaetzlich: die installierten Debian-Pakete gegen die OSV-Datenbank
halten und Meldungen markieren, die dieses System wirklich betreffen.

Nur Standardbibliothek - keine Installation noetig.

Beispiele:
    python3 vulnfeed.py                       # letzte 7 Tage, Tabelle
    python3 vulnfeed.py --since 2 --limit 20  # letzte 2 Tage, max. 20 Eintraege
    python3 vulnfeed.py --source heise-alerts --format markdown
    python3 vulnfeed.py --format json > vulns.json
    python3 vulnfeed.py --local --since 2     # News plus Paketscan
    python3 vulnfeed.py -s local --since 0    # nur der Paketscan

Geplanter Lauf auf einem Raspberry Pi (siehe docs/RASPBERRY-PI.md):
    python3 vulnfeed.py --email --env-file /etc/securityfeed.env --since 1

Dauerbetrieb im Container, plant selbst (siehe docs/DOCKER.md):
    python3 vulnfeed.py --email --schedule 07:00,18:00 --since 2

Exit-Codes: 0 = ok, 1 = harter Fehler (alle Quellen tot / Mail fehlgeschlagen),
2 = Konfigurationsfehler, 3 = Lauf ok, aber einzelne Quelle ausgefallen.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import html
import json
import os
import re
import signal
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid, parsedate_to_datetime

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
# Teilstring-Treffer, damit Beugungen und Komposita mitgehen ("Schwachstellen",
# "vulnerabilities"). Alles hier muss lang genug sein, um nicht zufaellig in
# harmlosen Woertern zu stecken.
VULN_TERMS = (
    "cve-", "vulnerab", "zero-day", "zero day", "0-day", "exploit",
    "remote code execution", "privilege escalation", "security update",
    "patch tuesday", "flaw", "backdoor",
    "sicherheitslueck", "sicherheitslück", "schwachstell", "luecke", "lücke",
    "angreifer", "attacke", "sicherheitspatch", "sicherheitsupdate",
    "jetzt patchen", "verwundbar", "notfall-patch",
)

# Kurz und mehrdeutig - nur als ganzes Wort. "rce" steckt sonst in "enforced",
# "resources" und "e-commerce", "patched" in "dispatched".
VULN_WORDS_RE = re.compile(r"\b(?:rce|patch|patches|patched|poc)\b", re.IGNORECASE)

# --- Paketscan ------------------------------------------------------------
# Batch-Endpunkt der OSV-Datenbank: eine Anfrage, viele Pakete, Antwort sind
# nur die IDs. Das reicht - die CVE-Nummer steckt schon im OSV-Bezeichner
# ("DEBIAN-CVE-2025-9230"), ein zweiter Request je Luecke waere verschwendet.
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Hoeher als jede reale Debian-Version. Die Antwort auf diese Abfrage sind
# genau die Luecken, gegen die es in der Suite (noch) keinen Fix gibt - sie
# treffen jede Version. Von der echten Abfrage abgezogen bleibt uebrig, was
# ein "apt upgrade" tatsaechlich schliesst. Das ist das Gegenstueck zu
# "debsecan --only-fixed" und kostet nur eine zweite Abfrage je Paket.
OSV_SENTINEL_VERSION = "999999:0-0"

# Die API liefert je Einzelabfrage hoechstens so viele IDs. Wird die Grenze
# erreicht, ist die Liste abgeschnitten und die Differenz oben nicht mehr
# belastbar - solche Pakete werden gesondert gemeldet statt falsch gezaehlt.
OSV_RESULT_CAP = 1000

# Abfragen pro HTTP-Request. Je Paket sind es zwei (echt + Sentinel), ein Pi
# mit ~600 Paketen kommt so mit rund fuenf Requests aus.
OSV_CHUNK = 250

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/source-package/"
DPKG_STATUS_PATH = "/var/lib/dpkg/status"

# Verzeichnis mit den abgelegten Paketlisten der Container, je Container ein
# Unterverzeichnis. Befuellt wird es auf dem Host von
# deploy/dump-container-packages.sh - SecurityFeed selbst bekommt bewusst
# keinen Docker-Zugriff, der Socket waere faktisch Root auf dem Pi.
CONTAINER_STATUS_FILE = "status"
CONTAINER_OS_RELEASE_FILE = "os-release"
CONTAINER_UNSUPPORTED_FILE = "unsupported"  # Grund, falls keine Liste lesbar
CONTAINER_STAMP_FILE = "updated"            # mtime = letzter Lauf des Skripts

# Aelter als das, und die Listen beschreiben womoeglich Container, die es so
# nicht mehr gibt. Ein stehengebliebener Timer darf nicht als "alles ruhig"
# durchgehen - das waere die gefaehrlichste Art, falsch zu liegen.
CONTAINER_STAMP_MAX_AGE = timedelta(hours=48)

# /etc/debian_version nennt nur den Codenamen, OSV will die Nummer.
CODENAME_RELEASES = {
    "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13", "forky": "14",
}

# Nach so vielen Tagen wird ein unveraenderter Fund erneut gemeldet.
#
# Eine Nachricht ist ein Ereignis - einmal melden, fertig. Ein verwundbares
# Paket ist ein Zustand, der bleibt, bis jemand patcht. Ohne Wiedervorlage
# verschwaende der Fund nach der ersten Mail und das System saehe fuer immer
# sauber aus. Woechentlich ist der Kompromiss: haeufig genug, um nicht in
# Vergessenheit zu geraten, selten genug, um nicht weggefiltert zu werden.
LOCAL_REMIND_DAYS = 7.0

# So viele CVE-Nummern werden je Eintrag ausgegeben. Ein lange nicht gepflegtes
# Paket bringt schnell 40 mit - die Liste ist dann keine Information mehr.
CVE_DISPLAY_CAP = 8


@dataclass(frozen=True)
class Source:
    key: str
    label: str
    url: str
    kind: str  # "rss", "atom", "hn" oder "local"
    always_vuln: bool = False  # Feed enthaelt ausschliesslich Luecken-Meldungen
    # Nur fuer kind="hn": Suchbegriffe und Mindestpunktzahl.
    queries: tuple[str, ...] = ()
    min_points: int = 50
    # Ohne --source laufen nur die Quellen mit default_on. Der Paketscan bleibt
    # aussen vor: auf einem Nicht-Debian-System scheitert er zwangslaeufig und
    # wuerde jede Mail mit einer Ausfallwarnung verzieren.
    default_on: bool = True


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
    # Der Frontpage-Feed von HN taugt hierfuer nicht - dort steht meist nichts
    # Sicherheitsrelevantes. Die Algolia-Suche liefert dagegen gezielt, und die
    # Punkteschwelle sortiert unkommentierte Einzeleinreichungen aus.
    #
    # always_vuln, weil hier Suchbegriff und Punkteschwelle den Filter bilden.
    # VULN_TERMS ist auf heise- und BleepingComputer-Formulierungen getrimmt und
    # liesse HN-Ueberschriften wie "Bugtraq is back" oder "My security camera
    # shipped a GitHub admin token" durchfallen.
    Source(
        "hackernews", "Hacker News",
        "https://hn.algolia.com/api/v1/search_by_date", "hn",
        always_vuln=True, queries=("vulnerability", "security"), min_points=50,
    ),
    # Keine Nachrichtenquelle, sondern der Abgleich der installierten Pakete
    # gegen die OSV-Datenbank. Siehe Abschnitt "Paketscan" weiter unten.
    Source(
        "local", "Lokales System", OSV_BATCH_URL, "local",
        always_vuln=True, default_on=False,
    ),
)

# Strukturell keine Sicherheitsmeldungen, matchen aber regelmaessig auf die
# HN-Suchbegriffe ("... deploy agents securely", "security deposit").
HN_TITLE_NOISE = ("launch hn:", "ask hn: who is hiring", "ask hn: who wants to be hired")


@dataclass
class Entry:
    source: str
    title: str
    link: str
    published: datetime | None
    summary: str
    cves: list[str] = field(default_factory=list)
    advisory: bool = False  # stammt aus einem reinen Advisory-Feed
    local: bool = False  # aus dem Paketscan, nicht aus einem Feed
    # Quellpakete, die auf diesem System in einer betroffenen Version stecken.
    affects_local: list[str] = field(default_factory=list)
    # Ueberschreibt den Link als Zustandsschluessel. Der Paketscan verlinkt
    # immer auf dieselbe Tracker-Seite je Paket - ohne eigenen Schluessel
    # bliebe eine neu hinzugekommene Luecke fuer immer ungemeldet.
    key: str | None = None

    @property
    def state_key(self) -> str:
        """Was den Eintrag identifiziert - fuer dedupe() und den Zustand."""
        return self.key or self.link or self.title

    @property
    def is_vuln(self) -> bool:
        if self.advisory or self.cves:
            return True
        haystack = f"{self.title} {self.summary}".lower()
        if any(term in haystack for term in VULN_TERMS):
            return True
        return VULN_WORDS_RE.search(haystack) is not None

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "title": self.title,
            "link": self.link,
            "published": self.published.isoformat() if self.published else None,
            "cves": self.cves,
            "advisory": self.advisory,
            "local": self.local,
            "affects_local": self.affects_local,
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


def parse_hn(payload: dict, source: Source) -> list[Entry]:
    """Algolia-Treffer in Entry-Objekte. Stories ohne eigene URL (Ask HN, Tell
    HN) verweisen auf ihre Diskussion."""
    entries = []
    for hit in payload.get("hits", []):
        title = clean(hit.get("title"))
        if not title or title.lower().startswith(HN_TITLE_NOISE):
            continue
        discussion = f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
        points = hit.get("points") or 0
        story_text = clean(hit.get("story_text"))
        summary = f"{points} Punkte auf Hacker News."
        if story_text:
            summary += " " + (story_text[:300] + "..." if len(story_text) > 300 else story_text)
        if hit.get("url"):
            summary += f" Diskussion: {discussion}"
        entries.append(Entry(
            source=source.label,
            title=title,
            link=hit.get("url") or discussion,
            published=parse_date(hit.get("created_at")),
            summary=summary,
            cves=find_cves(title, story_text),
        ))
    return entries


def hn_urls(source: Source) -> list[str]:
    """Je Suchbegriff eine Abfrage - Algolia kennt kein ODER ueber Begriffe."""
    urls = []
    for query in source.queries:
        params = urllib.parse.urlencode({
            "tags": "story",
            "query": query,
            "numericFilters": f"points>={source.min_points}",
            "hitsPerPage": 50,
        })
        urls.append(f"{source.url}?{params}")
    return urls


def find_cves(*texts: str) -> list[str]:
    seen: dict[str, None] = {}
    for text in texts:
        for match in CVE_RE.findall(text or ""):
            seen.setdefault(match.upper(), None)
    return list(seen)


# --------------------------------------------------------------------------
# Paketscan: was liegt hier installiert, und ist davon etwas verwundbar?
#
# Ablauf: dpkg nach den installierten Quellpaketen fragen, die Liste gegen die
# OSV-Datenbank halten, und je betroffenem Paket einen Eintrag bauen. OSV
# vergleicht dabei selbst die Debian-Versionen - ein gepflegtes System liefert
# darum fast nichts zurueck.
# --------------------------------------------------------------------------

class LocalScanError(Exception):
    """Der Scan ist hier nicht durchfuehrbar -> Quelle gilt als ausgefallen."""


@dataclass(frozen=True)
class LocalOptions:
    status_path: str | None = None  # dpkg-Statusdatei statt dpkg-query
    release: str | None = None      # Debian-Hauptversion, z.B. "12"
    unfixed: bool = False           # auch Luecken ohne verfuegbaren Fix melden
    containers: str | None = None   # Verzeichnis mit Container-Paketlisten
    remind_days: float = 7.0        # unveraenderte Funde nach so vielen Tagen erneut


@dataclass(frozen=True)
class Package:
    """Ein Quellpaket. OSV kennt nur diese - eine Abfrage nach dem
    Binaerpaket 'libssl3' liefert nichts, die nach 'openssl' alles."""
    name: str
    version: str
    binaries: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanTarget:
    """Ein zu pruefendes System: der Host oder einer der Container."""
    name: str  # "" = Host, sonst der Containername
    packages: tuple[Package, ...] = ()
    release: str = ""

    @property
    def label(self) -> str:
        """Was in der Mail als Quelle des Eintrags steht."""
        return f"Container {self.name}" if self.name else "Lokales System"

    def qualify(self, package: str) -> str:
        """Paketname mit Herkunft - 'openssl' steckt auf dem Pi und in drei
        Containern, und das ist nicht dasselbe Problem."""
        return f"{package} ({self.name})" if self.name else package


@dataclass(frozen=True)
class SkippedTarget:
    """Ein System, das sich nicht pruefen liess. Kommt ausdruecklich in die
    Mail: stillschweigend uebergangene Container waeren die schlechtere
    Variante von 'keine Befunde'."""
    name: str
    reason: str


# ${source:Version} faellt automatisch auf die Binaerversion zurueck, wenn das
# Quellpaket keine eigene hat - genau das Verhalten, das OSV erwartet.
DPKG_QUERY_FORMAT = (
    "${db:Status-Status}\t${source:Package}\t${source:Version}\t${binary:Package}\n"
)


def collect_packages(found: dict[tuple[str, str], list[str]]) -> list[Package]:
    return [
        Package(name=name, version=version, binaries=tuple(sorted(set(binaries))))
        for (name, version), binaries in sorted(found.items())
    ]


def parse_dpkg_query(text: str) -> list[Package]:
    found: dict[tuple[str, str], list[str]] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 4:
            continue
        status, name, version, binary = (part.strip() for part in parts)
        if status != "installed" or not name or not version:
            continue
        found.setdefault((name, version), []).append(binary or name)
    return collect_packages(found)


def parse_dpkg_status(text: str) -> list[Package]:
    """Die Statusdatei /var/lib/dpkg/status selbst lesen - noetig, wenn dpkg
    nicht zur Hand ist, etwa im Container mit eingehaengter Hostdatei."""
    found: dict[tuple[str, str], list[str]] = {}
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if not line or line[0] in " \t":  # Fortsetzungszeile, hier egal
                continue
            key, sep, value = line.partition(":")
            if sep:
                fields[key.strip().lower()] = value.strip()

        name, version = fields.get("package"), fields.get("version")
        # Nur "install ok installed". Alles andere - deinstalliert, halb
        # entpackt, nur noch Konfigurationsreste - liegt nicht als
        # angreifbarer Code auf der Platte.
        if not name or not version or fields.get("status", "").split()[-1:] != ["installed"]:
            continue

        source, source_version = name, version
        # "Source: openssl" oder "Source: openssl (3.0.11-1~deb12u2)"; das Feld
        # fehlt ganz, wenn Quell- und Binaerpaket gleich heissen.
        match = re.fullmatch(r"(\S+)(?:\s+\(([^)]+)\))?", fields.get("source", ""))
        if match:
            source = match.group(1)
            source_version = match.group(2) or version
        found.setdefault((source, source_version), []).append(name)
    return collect_packages(found)


def run_dpkg_query(timeout: float) -> str:
    try:
        proc = subprocess.run(
            ["dpkg-query", "-W", "-f", DPKG_QUERY_FORMAT],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise LocalScanError(
            "dpkg-query nicht gefunden - hier laeuft kein Debian. Im Container "
            "stattdessen die Statusdatei des Hosts einhaengen und mit "
            "--dpkg-status /host/var/lib/dpkg/status darauf zeigen."
        ) from None
    except subprocess.TimeoutExpired:
        raise LocalScanError(f"dpkg-query antwortet nicht (Timeout {timeout:.0f}s).") from None
    if proc.returncode != 0:
        raise LocalScanError(
            f"dpkg-query endete mit Code {proc.returncode}: {proc.stderr.strip()[:200]}"
        )
    return proc.stdout


def parse_os_release(text: str) -> dict[str, str]:
    fields = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        fields[key.strip()] = value.strip().strip("\"'")
    return fields


def debian_release(os_release_path: str = "/etc/os-release",
                   debian_version_path: str = "/etc/debian_version") -> str:
    """Debian-Hauptversion als Zahl, z.B. '12'. Raspberry Pi OS meldet sich
    hier als Debian, das passt also auch auf dem Pi."""
    try:
        with open(os_release_path, "r", encoding="utf-8", errors="replace") as fh:
            fields = parse_os_release(fh.read())
    except OSError:
        fields = {}

    ident = fields.get("ID", "").lower()
    if ident and ident != "debian":
        raise LocalScanError(
            f"Das System meldet sich als '{ident}', der Scan kennt aber nur die "
            "Debian-Paketdatenbank. Bei einem Debian-Abkoemmling die passende "
            "Version mit --debian-release erzwingen."
        )
    version_id = fields.get("VERSION_ID", "")
    if version_id.isdigit():
        return version_id
    codename = fields.get("VERSION_CODENAME", "").lower()
    if codename in CODENAME_RELEASES:
        return CODENAME_RELEASES[codename]

    try:
        with open(debian_version_path, "r", encoding="utf-8", errors="replace") as fh:
            raw = fh.read().strip()
    except OSError:
        raw = ""
    if raw.split(".")[0].isdigit():  # "12.5"
        return raw.split(".")[0]
    if raw.split("/")[0].lower() in CODENAME_RELEASES:  # "trixie/sid"
        return CODENAME_RELEASES[raw.split("/")[0].lower()]

    raise LocalScanError(
        "Debian-Version nicht erkennbar. Mit --debian-release 12 nachhelfen "
        "(SECFEED_DEBIAN_RELEASE)."
    )


def installed_packages(opts: LocalOptions, timeout: float) -> list[Package]:
    path = opts.status_path or os.environ.get("SECFEED_DPKG_STATUS")
    if path:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                packages = parse_dpkg_status(fh.read())
        except OSError as exc:
            raise LocalScanError(f"dpkg-Statusdatei nicht lesbar ({path}): {exc}") from None
        if not packages:
            raise LocalScanError(
                f"In {path} steht kein installiertes Paket - ist das wirklich eine "
                "dpkg-Statusdatei?"
            )
        return packages

    packages = parse_dpkg_query(run_dpkg_query(timeout))
    if not packages:
        raise LocalScanError("dpkg-query meldet kein installiertes Paket.")
    return packages


def container_release(os_release_text: str) -> str | None:
    """Debian-Hauptversion eines Containers, oder None. Bewusst ohne Rueckfall
    auf die Version des Hosts: ein bookworm-Host und ein trixie-Container haben
    verschiedene Fixversionen, und ein Vergleich gegen die falsche Suite waere
    schlimmer als gar keiner."""
    fields = parse_os_release(os_release_text)
    if fields.get("ID", "").lower() not in ("", "debian"):
        return None
    version_id = fields.get("VERSION_ID", "")
    if version_id.isdigit():
        return version_id
    return CODENAME_RELEASES.get(fields.get("VERSION_CODENAME", "").lower())


def host_target(opts: LocalOptions, timeout: float) -> ScanTarget:
    packages = installed_packages(opts, timeout)
    release = opts.release or os.environ.get("SECFEED_DEBIAN_RELEASE") or debian_release()
    return ScanTarget(name="", packages=tuple(packages), release=release.strip())


def read_container_list(directory: str, name: str) -> ScanTarget | SkippedTarget:
    """Ein Unterverzeichnis aus dem Ablageordner lesen."""
    base = os.path.join(directory, name)

    # Das Dump-Skript legt diese Datei an, wenn es an einem Container gar nicht
    # erst herankam - so faellt der Container auf, statt zu fehlen.
    try:
        with open(os.path.join(base, CONTAINER_UNSUPPORTED_FILE),
                  "r", encoding="utf-8", errors="replace") as fh:
            return SkippedTarget(name, fh.read().strip() or "keine Paketliste vorhanden")
    except OSError:
        pass

    try:
        with open(os.path.join(base, CONTAINER_STATUS_FILE),
                  "r", encoding="utf-8", errors="replace") as fh:
            packages = parse_dpkg_status(fh.read())
    except OSError as exc:
        return SkippedTarget(name, f"Paketliste nicht lesbar: {exc}")
    if not packages:
        return SkippedTarget(name, "Paketliste enthaelt kein installiertes Paket")

    try:
        with open(os.path.join(base, CONTAINER_OS_RELEASE_FILE),
                  "r", encoding="utf-8", errors="replace") as fh:
            release = container_release(fh.read())
    except OSError:
        release = None
    if not release:
        return SkippedTarget(
            name, "Debian-Version nicht erkennbar - kein Debian-Container?"
        )
    return ScanTarget(name=name, packages=tuple(packages), release=release)


def container_targets(directory: str) -> tuple[list[ScanTarget], list[SkippedTarget]]:
    try:
        names = sorted(
            item for item in os.listdir(directory)
            if os.path.isdir(os.path.join(directory, item))
        )
    except OSError as exc:
        return [], [SkippedTarget("", f"Ablageordner nicht lesbar ({directory}): {exc}")]

    targets: list[ScanTarget] = []
    skipped: list[SkippedTarget] = []
    for name in names:
        result = read_container_list(directory, name)
        (targets if isinstance(result, ScanTarget) else skipped).append(result)
    return targets, skipped


def container_list_age(directory: str) -> timedelta | None:
    """Wie alt der letzte Lauf des Dump-Skripts ist. None = kein Zeitstempel."""
    try:
        stamp = os.path.getmtime(os.path.join(directory, CONTAINER_STAMP_FILE))
    except OSError:
        return None
    return datetime.now(timezone.utc) - datetime.fromtimestamp(stamp, timezone.utc)


def osv_batch(queries: list[tuple[str, str, str]], timeout: float) -> list[list[str]]:
    """[(Paket, Version, Oekosystem)] -> je Abfrage die OSV-IDs, in derselben
    Reihenfolge. Das Oekosystem haengt an der einzelnen Abfrage, damit Host und
    Container mit verschiedenen Debian-Versionen in einen Request passen."""
    results: list[list[str]] = []
    for start in range(0, len(queries), OSV_CHUNK):
        chunk = queries[start:start + OSV_CHUNK]
        body = json.dumps({"queries": [
            {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
            for name, version, ecosystem in chunk
        ]}).encode("utf-8")
        request = urllib.request.Request(
            OSV_BATCH_URL, data=body, method="POST",
            headers={
                "User-Agent": HEADERS["User-Agent"],
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise LocalScanError(f"OSV antwortet mit HTTP {exc.code} {exc.reason}") from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise LocalScanError(f"OSV nicht erreichbar: {exc}") from None
        except json.JSONDecodeError as exc:
            raise LocalScanError(f"OSV-Antwort ist kein gueltiges JSON: {exc}") from None

        answers = payload.get("results")
        if not isinstance(answers, list) or len(answers) != len(chunk):
            raise LocalScanError(
                f"OSV liefert {len(answers or [])} Ergebnisse auf {len(chunk)} Abfragen."
            )
        results.extend(
            [vuln.get("id", "") for vuln in (answer or {}).get("vulns") or []]
            for answer in answers
        )
    return results


def cve_id(osv_id: str) -> str:
    """'DEBIAN-CVE-2025-9230' -> 'CVE-2025-9230'. Alles andere bleibt stehen."""
    stripped = osv_id[7:] if osv_id.startswith("DEBIAN-") else osv_id
    return stripped if CVE_RE.fullmatch(stripped) else osv_id


def reminder_window(now: datetime, days: float) -> str:
    """Kennung des laufenden Wiedervorlage-Fensters.

    Sie steckt im Zustandsschluessel: solange sie gleich bleibt, gilt ein
    unveraenderter Fund als schon gemeldet. Springt sie um, taucht er wieder
    auf. Bei 0 gibt es nur eine Kennung und damit die alte Einmal-Meldung.

    Die Grenzen liegen fest auf dem Zeitstrahl, nicht ab der Erstmeldung. Ein
    Fund kurz vor einer Grenze wiederholt sich deshalb frueher als nach der
    vollen Frist - "hoechstens alle N Tage", nicht "genau alle N Tage". Das
    spart einen Erstmeldungszeitpunkt je Fund im Zustandsspeicher, und
    frueher erinnert zu werden ist der harmlose Fehler."""
    if days <= 0:
        return "einmalig"
    return str(int(now.timestamp() // (days * 86400)))


def local_entry(target: ScanTarget, package: Package, cves: list[str], unfixed: int,
                now: datetime, window: str = "einmalig", *, fixable: bool = True,
                truncated: bool = False) -> Entry:
    binaries = list(package.binaries) or [package.name]
    shown = ", ".join(binaries[:6]) + (" ..." if len(binaries) > 6 else "")

    if truncated:
        title = f"{package.name} {package.version}: sehr viele bekannte Luecken"
        summary = (
            f"OSV schneidet die Trefferliste bei {OSV_RESULT_CAP} Eintraegen ab, "
            "deshalb laesst sich hier nicht auseinanderhalten, was davon ein "
            "Update tatsaechlich schliesst. Bitte auf der verlinkten Seite nachsehen. "
        )
    elif fixable:
        title = f"{package.name} {package.version}: {len(cves)} Luecke(n) mit verfuegbarem Fix"
        summary = (
            f"{len(cves)} bekannte Schwachstelle(n) sind in einer neueren Version "
            "dieses Pakets behoben, die installierte ist aelter. "
        )
        if unfixed:
            summary += (
                f"{unfixed} weitere sind bekannt, aber in dieser Debian-Version "
                "noch nicht behoben. "
            )
    else:
        title = f"{package.name} {package.version}: {len(cves)} Luecke(n) ohne Fix"
        summary = (
            "Fuer diese Schwachstellen gibt es in dieser Debian-Version noch kein "
            "Update. Debian stuft solche Faelle meist als geringfuegig ein und "
            "behebt sie erst mit dem naechsten Release. "
        )

    summary += f"Installiert als: {shown}."
    if fixable and not truncated:
        update = "sudo apt update && sudo apt install --only-upgrade " + " ".join(binaries[:6])
        # Im Container hilft kein apt auf dem Host - dort ist das Image dran.
        summary += (
            f" Beheben ueber ein neues Image: das Basisimage von '{target.name}' "
            "aktualisieren und neu bauen."
            if target.name else f" Beheben mit: {update}"
        )

    return Entry(
        source=target.label,
        title=title,
        link=DEBIAN_TRACKER_URL + urllib.parse.quote(package.name),
        published=now,
        summary=summary,
        cves=cves,
        advisory=True,
        local=True,
        # Beim Scan-Eintrag ist das betroffene Paket er selbst. So kommt
        # mark_local_matches an den Namen, ohne ihn aus dem Titel zu klauben.
        affects_local=[target.qualify(package.name)],
        # Der Link zeigt fuer ein Paket immer auf dieselbe Tracker-Seite. Ohne
        # Ziel, Anzahl und juengste CVE im Schluessel bliebe jede spaeter dazu
        # gekommene Luecke ungemeldet - und dasselbe Paket auf Host und in
        # einem Container waere derselbe Eintrag. Das Fenster am Ende sorgt
        # dafuer, dass ein ungepatchter Fund wiederkommt statt zu verschwinden.
        key=f"local:{target.name or 'host'}:{package.name}:{len(cves)}:"
            f"{max(cves) if cves else package.version}:{window}",
    )


def unscanned_entry(skipped: SkippedTarget, now: datetime,
                    window: str = "einmalig") -> Entry:
    """Ein Ziel, das sich nicht pruefen liess. Ohne diesen Eintrag saehe ein
    unpruefbarer Container aus wie ein unauffaelliger."""
    what = f"Container {skipped.name}" if skipped.name else "Lokales System"
    return Entry(
        source=what,
        title=f"{what}: nicht pruefbar",
        link="",
        published=now,
        summary=f"{skipped.reason}. Dieses System steckt in keiner der obigen "
                "Bewertungen - es wurde nicht geprueft, nicht fuer unauffaellig "
                "befunden.",
        advisory=True,
        local=True,
        # Ein blinder Fleck bleibt einer, bis sich etwas aendert - deshalb
        # dieselbe Wiedervorlage wie bei den Funden.
        key=f"local:{skipped.name or 'host'}:ungeprueft:{skipped.reason}:{window}",
    )


def stale_lists_entry(age: timedelta | None, directory: str, now: datetime) -> Entry:
    alter = "kein Zeitstempel vorhanden" if age is None else f"{int(age.total_seconds() // 3600)} Stunden alt"
    return Entry(
        source="Lokales System",
        title=f"Container-Paketlisten veraltet ({alter})",
        link="",
        published=now,
        summary=f"Die Listen unter {directory} werden nicht mehr aktualisiert - "
                "laeuft der Timer fuer dump-container-packages.sh noch? Bis dahin "
                "beschreiben die Container-Befunde einen alten Stand. "
                "Pruefen mit: systemctl status securityfeed-containers.timer",
        advisory=True,
        local=True,
        # Einmal je Tag melden: ein einmaliger Hinweis geht unter, einer je Lauf
        # ist Laerm.
        key=f"local:containers:veraltet:{now.date().isoformat()}",
    )


def gather_targets(opts: LocalOptions,
                   timeout: float) -> tuple[list[ScanTarget], list[SkippedTarget]]:
    """Host und - falls konfiguriert - die abgelegten Container-Paketlisten.

    Ein gescheitertes Ziel nimmt die anderen nicht mit: laeuft der Host-Scan
    nicht, sollen die Container trotzdem geprueft werden und umgekehrt."""
    targets: list[ScanTarget] = []
    skipped: list[SkippedTarget] = []
    try:
        targets.append(host_target(opts, timeout))
    except LocalScanError as exc:
        skipped.append(SkippedTarget("", str(exc)))

    directory = opts.containers or os.environ.get("SECFEED_CONTAINER_LISTS")
    if directory:
        found, missed = container_targets(directory)
        targets.extend(found)
        skipped.extend(missed)
    return targets, skipped


def scan_local(opts: LocalOptions, timeout: float) -> list[Entry]:
    targets, skipped = gather_targets(opts, timeout)
    if not targets:
        raise LocalScanError(
            "Kein pruefbares System gefunden. "
            + "; ".join(f"{s.name or 'Host'}: {s.reason}" for s in skipped)
        )

    # Je Paket zwei Abfragen: die echte Version und der Sentinel. Was beide
    # melden, ist ungefixt; die Differenz ist das, was ein Update schliesst.
    # Alle Ziele wandern in denselben Stapel - das Oekosystem haengt an der
    # einzelnen Abfrage, ein Request bedient also Host und Container zugleich.
    queries: list[tuple[str, str, str]] = []
    for target in targets:
        ecosystem = f"Debian:{target.release}"
        for package in target.packages:
            queries.append((package.name, package.version, ecosystem))
            queries.append((package.name, OSV_SENTINEL_VERSION, ecosystem))
    # Ein Paket im Feed-Timeout abzufragen ist etwas anderes als 500 Pakete in
    # zwei Dutzend Abfragen - die Antwort braucht hier schlicht laenger.
    answers = osv_batch(queries, max(timeout, 60.0))

    now = datetime.now(timezone.utc)
    window = reminder_window(now, opts.remind_days)
    entries = [unscanned_entry(item, now, window) for item in skipped]

    directory = opts.containers or os.environ.get("SECFEED_CONTAINER_LISTS")
    if directory:
        age = container_list_age(directory)
        if age is None or age > CONTAINER_STAMP_MAX_AGE:
            entries.append(stale_lists_entry(age, directory, now))

    position = 0
    for target in targets:
        for package in target.packages:
            current, sentinel = answers[position], answers[position + 1]
            position += 2
            if not current:
                continue
            if len(current) >= OSV_RESULT_CAP or len(sentinel) >= OSV_RESULT_CAP:
                entries.append(local_entry(
                    target, package, sorted({cve_id(i) for i in current}), 0, now,
                    window, truncated=True,
                ))
                continue

            unfixed = set(sentinel)
            fixable = sorted({cve_id(i) for i in current if i not in unfixed})
            if fixable:
                entries.append(local_entry(
                    target, package, fixable, len(unfixed), now, window
                ))
            elif opts.unfixed:
                entries.append(local_entry(
                    target, package, sorted({cve_id(i) for i in unfixed}), 0, now,
                    window, fixable=False,
                ))
    return entries


def mark_local_matches(entries: list[Entry]) -> None:
    """Meldungen markieren, deren CVE hier tatsaechlich installiert ist.

    Erst nach dem Nachladen der Artikelseiten aufrufen - vorher kennen die
    Feed-Eintraege ihre CVE-Nummern noch gar nicht."""
    affected: dict[str, set[str]] = {}
    for entry in entries:
        if not entry.local:
            continue
        for cve in entry.cves:
            affected.setdefault(cve, set()).update(entry.affects_local)
    if not affected:
        return
    for entry in entries:
        if entry.local:
            continue
        hits = {pkg for cve in entry.cves for pkg in affected.get(cve, ())}
        entry.affects_local = sorted(hits)


def load_source(source: Source, timeout: float,
                local: LocalOptions | None = None) -> tuple[Source, list[Entry], str | None]:
    """Liefert (Quelle, Eintraege, Fehlermeldung)."""
    entries: list[Entry] = []
    root = None
    try:
        if source.kind == "local":
            # Die Quellenbezeichnung kommt hier aus dem Scan selbst: "Lokales
            # System" fuer den Host, "Container <name>" fuer die uebrigen.
            return source, scan_local(local or LocalOptions(), timeout), None
        if source.kind == "hn":
            for url in hn_urls(source):
                entries.extend(parse_hn(json.loads(fetch(url, timeout)), source))
        else:
            root = ET.fromstring(fetch(source.url, timeout))
    except LocalScanError as exc:
        return source, [], str(exc)
    except urllib.error.HTTPError as exc:
        return source, [], f"HTTP {exc.code} {exc.reason}"
    except (urllib.error.URLError, TimeoutError) as exc:
        return source, [], f"Netzwerkfehler: {exc.reason if hasattr(exc, 'reason') else exc}"
    except ET.ParseError as exc:
        return source, [], f"Feed nicht lesbar: {exc}"
    except json.JSONDecodeError as exc:
        return source, [], f"Antwort ist kein gueltiges JSON: {exc}"

    if source.kind != "hn":
        parser = parse_atom if source.kind == "atom" else parse_rss
        entries = parser(root, source.label)

    if source.always_vuln:
        # Quelle liefert bereits nur Relevantes - der Keyword-Filter waere hier
        # nur eine Fehlerquelle. Gilt fuer alle Arten, auch fuer HN.
        for entry in entries:
            entry.advisory = True
    return source, entries, None


def collect(selected: list[Source], timeout: float, quiet: bool,
            local: LocalOptions | None = None) -> tuple[list[Entry], list[str]]:
    """Liefert (Eintraege, Beschreibung der fehlgeschlagenen Quellen)."""
    entries: list[Entry] = []
    failed: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(selected)) as pool:
        for source, found, error in pool.map(
            lambda s: load_source(s, timeout, local), selected
        ):
            if error:
                failed.append(f"{source.label}: {error}")
                if not quiet:
                    print(f"! {source.label}: {error}", file=sys.stderr)
                continue
            entries.extend(found)
    return entries, failed


def enrich_with_cves(entries: list[Entry], timeout: float, quiet: bool) -> None:
    """Laedt die Artikelseiten und zieht CVE-Nummern heraus (in-place).

    Die Feeds liefern nur Titel und Anrisstext, konkrete CVE-IDs stehen erst im
    Artikel. Bewusst wenige parallele Requests, um die Seiten nicht zu belasten.
    """
    def load(entry: Entry) -> None:
        # Eintraege des Paketscans nie nachladen: ihre CVEs stehen schon fest,
        # und die Tracker-Seite eines Pakets nennt Hunderte weitere.
        if not entry.link or entry.local:
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
        key = entry.state_key
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def shown_cves(entry: Entry) -> tuple[list[str], int]:
    """Anzuzeigende CVEs und die Zahl der unterschlagenen. Ein lange nicht
    gepflegtes Paket bringt vierzig mit - das liest dann niemand mehr."""
    shown = entry.cves[:CVE_DISPLAY_CAP]
    return shown, len(entry.cves) - len(shown)


def render_table(entries: list[Entry]) -> str:
    if not entries:
        return "Keine passenden Meldungen gefunden."
    lines = []
    for entry in entries:
        stamp = entry.published.astimezone().strftime("%Y-%m-%d %H:%M") if entry.published else "?"
        listed, rest = shown_cves(entry)
        extra = f" +{rest} weitere" if rest else ""
        cves = f"  [{', '.join(listed)}{extra}]" if listed else ""
        lines.append(f"{stamp}  {entry.source}{cves}")
        lines.append(f"  {entry.title}")
        # Beim Scan-Eintrag selbst waere der Hinweis eine Doppelung - da steht
        # das Paket schon im Titel.
        if entry.affects_local and not entry.local:
            lines.append(f"  >> Betrifft dieses System: {', '.join(entry.affects_local)}")
        if entry.summary:
            summary = entry.summary if len(entry.summary) <= 200 else entry.summary[:197] + "..."
            lines.append(f"  {summary}")
        # Der Paketscan meldet auch Dinge ohne Zielseite, etwa ein System, das
        # sich nicht pruefen liess.
        if entry.link:
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
        listed, rest = shown_cves(entry)
        extra = f" +{rest} weitere" if rest else ""
        cves = f" — `{'`, `'.join(listed)}`{extra}" if listed else ""
        lines.append(f"## [{entry.title}]({entry.link})" if entry.link
                     else f"## {entry.title}")
        lines.append("")
        lines.append(f"*{entry.source} · {stamp}*{cves}")
        if entry.affects_local and not entry.local:
            lines.append("")
            lines.append(f"**Betrifft dieses System:** {', '.join(entry.affects_local)}")
        if entry.summary:
            lines.append("")
            lines.append(entry.summary)
        lines.append("")
    return "\n".join(lines)


def render_html(entries: list[Entry], subtitle: str,
                failed: list[str] | None = None) -> str:
    """Mail-taugliches HTML: Inline-Styles, keine externen Ressourcen."""
    esc = html.escape
    head = (
        '<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
        'max-width:760px;margin:0 auto;color:#1a1a1a">'
        '<h2 style="margin:0 0 4px">Aktuelle Schwachstellen-Meldungen</h2>'
        f'<p style="margin:0 0 20px;color:#666;font-size:13px">{esc(subtitle)}</p>'
    )
    if failed:
        items = "".join(f"<li>{esc(item)}</li>" for item in failed)
        head += (
            '<div style="background:#fff8e1;border-left:3px solid #f0ad4e;'
            'padding:10px 14px;margin:0 0 20px;font-size:14px">'
            '<strong>Warnung:</strong> Diese Quellen waren nicht erreichbar, die '
            'Liste unten ist daher moeglicherweise unvollstaendig.'
            f'<ul style="margin:6px 0 0;padding-left:20px">{items}</ul></div>'
        )
    if not entries:
        return head + '<p>Keine neuen Meldungen.</p></div>'

    blocks = []
    for entry in entries:
        stamp = entry.published.astimezone().strftime("%d.%m.%Y %H:%M") if entry.published else "?"
        meta = f"{esc(entry.source)} &middot; {stamp}"
        listed, rest = shown_cves(entry)
        cves = ""
        if listed:
            tags = "".join(
                '<span style="display:inline-block;background:#fde8e8;color:#9b1c1c;'
                'border-radius:3px;padding:1px 6px;margin:0 4px 4px 0;font-size:12px;'
                f'font-family:monospace">{esc(c)}</span>'
                for c in listed
            )
            if rest:
                tags += (f'<span style="color:#777;font-size:12px">+{rest} weitere</span>')
            cves = f'<div style="margin:6px 0 0">{tags}</div>'
        # Der eigentliche Punkt der Uebung: nicht "es gibt eine Luecke",
        # sondern "sie steckt hier drin".
        affected = (
            '<div style="margin:6px 0 0;background:#fde8e8;color:#9b1c1c;'
            'border-radius:3px;padding:4px 8px;font-size:13px;font-weight:600">'
            f'Betrifft dieses System: {esc(", ".join(entry.affects_local))}</div>'
            if entry.affects_local and not entry.local else ""
        )
        summary = (
            f'<p style="margin:8px 0 0;font-size:14px;line-height:1.5">{esc(entry.summary)}</p>'
            if entry.summary else ""
        )
        border = "#c81e1e" if (entry.local or entry.affects_local) else "#d0d0d0"
        headline = (
            f'<a href="{esc(entry.link)}" style="font-size:16px;font-weight:600;'
            f'color:#1a4fa0;text-decoration:none">{esc(entry.title)}</a>'
            if entry.link else
            f'<div style="font-size:16px;font-weight:600">{esc(entry.title)}</div>'
        )
        blocks.append(
            f'<div style="border-left:3px solid {border};padding:0 0 0 14px;margin:0 0 24px">'
            f'<div style="color:#777;font-size:12px">{meta}</div>'
            f'{headline}{affected}{cves}{summary}</div>'
        )
    footer = (
        f'<p style="color:#888;font-size:12px;border-top:1px solid #e0e0e0;padding-top:10px">'
        f'{len(entries)} Meldung(en) &middot; SecurityFeed {__version__}</p>'
    )
    return head + "".join(blocks) + footer + "</div>"


# --------------------------------------------------------------------------
# Zustand: welche Meldungen wurden schon verschickt?
# --------------------------------------------------------------------------

def default_state_path() -> str:
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "state"
    )
    return os.path.join(base, "securityfeed", "seen.json")


def load_seen(path: str) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return []
    seen = data.get("seen") if isinstance(data, dict) else data
    return [s for s in seen if isinstance(s, str)] if isinstance(seen, list) else []


def save_seen(path: str, seen: list[str], keep: int = 2000) -> None:
    payload = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "seen": seen[:keep],
    }
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    # Erst temporaer schreiben, dann ersetzen - ein Absturz mittendrin darf den
    # bestehenden Zustand nicht zerstoeren.
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Mailversand ueber SMTP-Relay
# --------------------------------------------------------------------------

class ConfigError(Exception):
    """Fehlende oder widerspruechliche Konfiguration -> Exit-Code 2."""


# Werte aus .env.example bzw. deploy/securityfeed.env.example. Bleiben sie
# stehen, ist die Konfiguration garantiert unbrauchbar.
PLACEHOLDER_HOSTS = frozenset({"smtp.firma.de", "relay.intern.example", "relay.example.local"})
PLACEHOLDER_ADDRESSES = frozenset({
    "feed@firma.de", "max@firma.de", "securityfeed@example.com",
    "max@example.com", "pi@example.local", "max@example.local",
})


@dataclass
class MailConfig:
    host: str
    port: int
    sender: str
    recipients: list[str]
    security: str = "starttls"  # none | starttls | ssl
    user: str | None = None
    password: str | None = None
    subject_prefix: str = "[SecurityFeed]"
    timeout: float = 30.0


TRUTHY = frozenset({"1", "true", "yes", "y", "on", "ja"})


def env_flag(name: str) -> bool:
    """Schalter aus der Umgebung. Alles ausser den TRUTHY-Werten gilt als aus."""
    return os.environ.get(name, "").strip().lower() in TRUTHY


def load_env_file(path: str) -> None:
    """Simple KEY=VALUE-Datei ins Environment laden (fuer cron, das kein
    EnvironmentFile wie systemd kennt). Bereits gesetzte Variablen gewinnen."""
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            # Nur ein umschliessendes Paar entfernen. Ein blindes strip("'\"")
            # wuerde ein Passwort, das auf ein Anfuehrungszeichen endet, still
            # beschneiden - der Fehler taucht spaeter nur als "authentication
            # failed" auf.
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            os.environ.setdefault(key, value)


def mail_config_from_env(args: argparse.Namespace) -> MailConfig:
    """CLI-Argumente schlagen Umgebungsvariablen."""
    env = os.environ.get

    def pick(cli_value, env_key, default=None):
        return cli_value if cli_value else env(env_key, default)

    host = pick(args.smtp_host, "SECFEED_SMTP_HOST")
    sender = pick(args.mail_from, "SECFEED_MAIL_FROM")
    raw_to = args.mail_to or env("SECFEED_MAIL_TO", "")
    recipients = [r.strip() for r in re.split(r"[,;]", raw_to) if r.strip()]

    missing = [
        name for name, value in
        (("SMTP-Host (--smtp-host / SECFEED_SMTP_HOST)", host),
         ("Absender (--mail-from / SECFEED_MAIL_FROM)", sender),
         ("Empfaenger (--mail-to / SECFEED_MAIL_TO)", recipients))
        if not value
    ]
    if missing:
        raise ConfigError("Mailversand nicht konfiguriert, es fehlt:\n  - " + "\n  - ".join(missing))

    # Unveraenderte Platzhalter aus .env.example koennen nie funktionieren. Ohne
    # diesen Hinweis aeussert sich das erst spaet als DNS-Fehler beim Versand.
    placeholders = {
        "SECFEED_SMTP_HOST": (host, PLACEHOLDER_HOSTS),
        "SECFEED_MAIL_FROM": (sender, PLACEHOLDER_ADDRESSES),
        "SECFEED_MAIL_TO": (recipients[0] if recipients else "", PLACEHOLDER_ADDRESSES),
    }
    still_example = [
        f"{key} = {value}" for key, (value, known) in placeholders.items()
        if value.lower() in known
    ]
    if still_example:
        raise ConfigError(
            "Es stehen noch Beispielwerte aus .env.example in der Konfiguration:\n  - "
            + "\n  - ".join(still_example)
            + "\nTrage die Daten deines echten Mailservers ein."
        )

    security = (args.smtp_security or env("SECFEED_SMTP_SECURITY") or "starttls").lower()
    if security not in ("none", "starttls", "ssl"):
        raise ConfigError(f"Unbekannter Wert fuer --smtp-security: {security}")

    default_port = {"ssl": 465, "starttls": 587, "none": 25}[security]
    port_raw = args.smtp_port or env("SECFEED_SMTP_PORT") or default_port
    try:
        port = int(port_raw)
    except ValueError:
        raise ConfigError(f"Ungueltiger SMTP-Port: {port_raw}") from None

    return MailConfig(
        host=host,
        port=port,
        sender=sender,
        recipients=recipients,
        security=security,
        user=pick(args.smtp_user, "SECFEED_SMTP_USER"),
        password=env("SECFEED_SMTP_PASSWORD"),
        subject_prefix=pick(args.subject_prefix, "SECFEED_SUBJECT_PREFIX", "[SecurityFeed]"),
        timeout=args.timeout,
    )


def build_message(cfg: MailConfig, entries: list[Entry], subtitle: str,
                  failed: list[str] | None = None) -> EmailMessage:
    failed = failed or []
    count = len(entries)
    # Was dieses System betrifft, gehoert in den Betreff - sonst geht es
    # zwischen zwanzig allgemeinen Meldungen unter. Hinweise des Scans ohne
    # CVE - "nicht pruefbar", "Listen veraltet" - zaehlen hier nicht mit, sie
    # sind Betriebsmeldungen und kein Befund.
    concerned = [e for e in entries if (e.local and e.cves) or e.affects_local]
    headline = (concerned or entries)[0].title if entries else "keine neuen Meldungen"
    if len(headline) > 70:
        headline = headline[:67] + "..."

    if concerned:
        subject = (f"{cfg.subject_prefix} {len(concerned)} von {count} Meldung(en) "
                   f"betreffen dieses System: {headline}")
    elif count:
        subject = f"{cfg.subject_prefix} {count} neue Meldung(en): {headline}"
    else:
        subject = f"{cfg.subject_prefix} keine neuen Meldungen"
    # Eine still ausgefallene Quelle sieht sonst aus wie ein ruhiger Tag.
    if failed:
        subject += f" (Warnung: {len(failed)} Quelle(n) nicht erreichbar)"

    text = [subtitle, ""]
    if failed:
        text.append("WARNUNG - diese Quellen waren nicht erreichbar:")
        text.extend(f"  - {item}" for item in failed)
        text.append("")
    text.append(render_table(entries))

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = make_msgid(domain=cfg.sender.split("@")[-1] or None)
    msg.set_content("\n".join(text))
    msg.add_alternative(render_html(entries, subtitle, failed), subtype="html")
    return msg


def smtp_error_hints(cfg: MailConfig, exc: BaseException) -> list[str]:
    """Konkrete naechste Schritte zum jeweiligen Fehlerbild."""
    if isinstance(exc, socket.gaierror):
        return [
            f"Der Hostname '{cfg.host}' laesst sich nicht aufloesen - das ist ein",
            "DNS-Problem, nicht Anmeldung, Port oder Firewall.",
            "Pruefen:  getent hosts " + cfg.host,
            "Tippfehler im Hostnamen? Interner Name, der nur im Firmennetz",
            "aufloest? Oder steht noch ein Beispielwert in der Konfiguration?",
        ]
    if isinstance(exc, ConnectionRefusedError):
        return [
            f"Port {cfg.port} ist auf {cfg.host} nicht offen.",
            "Pruefen:  nc -vz " + f"{cfg.host} {cfg.port}",
            "Anderer Port noetig? 25 (none), 587 (starttls), 465 (ssl).",
        ]
    if isinstance(exc, TimeoutError) or isinstance(exc, socket.timeout):
        return [
            f"Keine Antwort von {cfg.host}:{cfg.port} innerhalb {cfg.timeout:.0f}s.",
            "Meist eine Firewall, die das Paket verwirft statt es abzulehnen.",
        ]
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return [
            "Anmeldung abgelehnt. Bei Microsoft 365 und Gmail ist ein",
            "App-Passwort noetig, nicht das Kontopasswort - bei M365 muss",
            "SMTP-AUTH fuer das Postfach zusaetzlich freigeschaltet sein.",
        ]
    if isinstance(exc, smtplib.SMTPNotSupportedError):
        return [
            "Das Relay beherrscht die verlangte Erweiterung nicht.",
            "Bei STARTTLS-Fehlern SECFEED_SMTP_SECURITY auf 'none' (Port 25)",
            "oder 'ssl' (Port 465) umstellen.",
        ]
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return [f"Das Relay akzeptiert den Absender '{cfg.sender}' nicht."]
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return ["Das Relay akzeptiert keinen der angegebenen Empfaenger."]
    return []


def send_mail(cfg: MailConfig, msg: EmailMessage) -> None:
    if cfg.security == "ssl":
        server = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=cfg.timeout,
                                  context=ssl.create_default_context())
    else:
        server = smtplib.SMTP(cfg.host, cfg.port, timeout=cfg.timeout)
    with server:
        server.ehlo()
        if cfg.security == "starttls":
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        # Offene Relays im LAN brauchen keine Anmeldung - nur wenn User gesetzt.
        if cfg.user:
            server.login(cfg.user, cfg.password or "")
        server.send_message(msg)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Neueste Schwachstellen-Meldungen von BleepingComputer und heise.de, "
                    "auf Wunsch samt Abgleich mit den hier installierten Paketen.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--source", "-s", action="append", choices=[s.key for s in SOURCES],
        help="Nur diese Quelle(n) abfragen (mehrfach angebbar). Default: alle "
             "Nachrichtenquellen, ohne den Paketscan 'local'.",
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

    scan = parser.add_argument_group(
        "Paketscan", "Installierte Debian-Pakete gegen die OSV-Datenbank halten."
    )
    scan.add_argument("--local", action="store_true",
                      help="Paketscan zusaetzlich zu den Nachrichtenquellen laufen lassen "
                           "(SECFEED_LOCAL=1). '-s local' laesst dagegen nur ihn laufen.")
    scan.add_argument("--dpkg-status", metavar="DATEI",
                      help=f"Statusdatei lesen statt dpkg-query aufzurufen - fuer den "
                           f"Container, in den {DPKG_STATUS_PATH} des Hosts eingehaengt "
                           f"ist (SECFEED_DPKG_STATUS).")
    scan.add_argument("--container-lists", metavar="VERZEICHNIS",
                      help="Zusaetzlich die dort abgelegten Paketlisten der Container "
                           "pruefen, je Container ein Unterverzeichnis. Befuellt wird "
                           "das Verzeichnis auf dem Host von "
                           "deploy/dump-container-packages.sh (SECFEED_CONTAINER_LISTS).")
    scan.add_argument("--debian-release", metavar="N",
                      help="Debian-Hauptversion erzwingen, z.B. 12, falls sie sich nicht "
                           "aus /etc/os-release ergibt (SECFEED_DEBIAN_RELEASE).")
    scan.add_argument("--local-remind", metavar="TAGE", type=float,
                      default=LOCAL_REMIND_DAYS,
                      help="Unveraenderte Funde nach so vielen Tagen erneut melden "
                           "(SECFEED_LOCAL_REMIND). Ein verwundbares Paket ist ein "
                           "Zustand, keine Nachricht - ohne Wiedervorlage verschwaende "
                           "es nach der ersten Mail. 0 = nur einmal melden.")
    scan.add_argument("--local-unfixed", action="store_true",
                      help="Auch Luecken melden, gegen die es noch kein Update gibt "
                           "(SECFEED_LOCAL_UNFIXED=1). Deutlich mehr Rauschen.")

    state = parser.add_argument_group(
        "Zustand", "Fuer geplante Laeufe: bereits gemeldete Eintraege ueberspringen."
    )
    state.add_argument("--state", metavar="DATEI", default=None,
                       help=f"Datei mit bereits gemeldeten Links (Default: {default_state_path()}).")
    state.add_argument("--no-state", action="store_true",
                       help="Zustand ignorieren - immer alle passenden Meldungen ausgeben.")
    state.add_argument("--reset-state", action="store_true",
                       help="Zustand vor dem Lauf leeren.")

    mail = parser.add_argument_group(
        "Mailversand", "Alle Werte auch per Umgebungsvariable SECFEED_* setzbar."
    )
    mail.add_argument("--email", action="store_true", help="Ergebnis per Mail verschicken.")
    mail.add_argument("--env-file", metavar="DATEI",
                      help="KEY=VALUE-Datei mit SMTP-Zugangsdaten laden (fuer cron).")
    mail.add_argument("--smtp-host", help="SMTP-Relay (SECFEED_SMTP_HOST).")
    mail.add_argument("--smtp-port", help="Port; Default je nach Security 25/587/465.")
    mail.add_argument("--smtp-security", choices=("none", "starttls", "ssl"),
                      help="Transportverschluesselung (SECFEED_SMTP_SECURITY). Default starttls.")
    mail.add_argument("--smtp-user", help="Benutzername; leer lassen fuer offene Relays.")
    mail.add_argument("--mail-from", help="Absenderadresse (SECFEED_MAIL_FROM).")
    mail.add_argument("--mail-to", help="Empfaenger, mehrere per Komma (SECFEED_MAIL_TO).")
    mail.add_argument("--subject-prefix", help="Betreff-Prefix. Default '[SecurityFeed]'.")
    mail.add_argument("--send-empty", action="store_true",
                      help="Auch mailen, wenn es nichts Neues gibt - als Lebenszeichen "
                           "(SECFEED_SEND_EMPTY=1).")
    mail.add_argument("--dry-run", action="store_true",
                      help="Mail nur ausgeben statt verschicken (zum Testen).")

    daemon = parser.add_argument_group(
        "Dauerbetrieb", "Fuer Docker: im Vordergrund laufen und selbst planen."
    )
    daemon.add_argument("--schedule", metavar="HH:MM,HH:MM",
                        help="Statt einmalig laufen: zu diesen Uhrzeiten (lokale Zeit, "
                             "SECFEED_SCHEDULE). Beispiel: 07:00,18:00")
    daemon.add_argument("--run-at-start", action="store_true",
                        help="Mit --schedule zusaetzlich sofort beim Start einmal laufen.")
    daemon.add_argument("--once", action="store_true",
                        help="Einen einzelnen Lauf erzwingen und danach beenden, auch wenn "
                             "SECFEED_SCHEDULE gesetzt ist. Fuer 'docker compose run'.")
    return parser


def resolve_state_path(args: argparse.Namespace) -> str | None:
    if args.no_state:
        return None
    return args.state or os.environ.get("SECFEED_STATE") or default_state_path()


def select_sources(args: argparse.Namespace) -> list[Source]:
    """Ohne --source laufen die Standardquellen; der Paketscan kommt nur auf
    ausdrueckliche Ansage dazu."""
    keys = set(args.source) if args.source else {s.key for s in SOURCES if s.default_on}
    if args.local or env_flag("SECFEED_LOCAL"):
        keys.add("local")
    return [s for s in SOURCES if s.key in keys]


def local_options(args: argparse.Namespace) -> LocalOptions:
    # Der Default steckt schon im Parser, die Umgebung zieht also nur, wenn auf
    # der Kommandozeile nichts Abweichendes steht.
    remind = args.local_remind
    if remind == LOCAL_REMIND_DAYS and os.environ.get("SECFEED_LOCAL_REMIND"):
        try:
            remind = float(os.environ["SECFEED_LOCAL_REMIND"])
        except ValueError:
            raise ConfigError(
                "SECFEED_LOCAL_REMIND muss eine Zahl in Tagen sein, z.B. 7 "
                f"(steht dort: {os.environ['SECFEED_LOCAL_REMIND']!r})."
            ) from None

    return LocalOptions(
        status_path=args.dpkg_status,
        release=args.debian_release,
        unfixed=args.local_unfixed or env_flag("SECFEED_LOCAL_UNFIXED"),
        containers=args.container_lists,
        remind_days=remind,
    )


def run_once(args: argparse.Namespace, mail_cfg: MailConfig | None,
             state_path: str | None) -> int:
    """Ein kompletter Durchlauf: abrufen, filtern, ausgeben bzw. mailen."""
    seen = [] if (state_path is None or args.reset_state) else load_seen(state_path)

    selected = select_sources(args)
    entries, failed = collect(selected, args.timeout, args.quiet, local_options(args))
    entries = dedupe(entries)

    if len(failed) == len(selected):
        print("Keine einzige Quelle erreichbar - Abbruch.", file=sys.stderr)
        return 1

    if args.since > 0:
        cutoff = datetime.now(timezone.utc) - timedelta(days=args.since)
        entries = [e for e in entries if e.published is None or e.published >= cutoff]
    if not args.all:
        entries = [e for e in entries if e.is_vuln]

    entries.sort(key=lambda e: e.published or datetime.min.replace(tzinfo=timezone.utc),
                 reverse=True)

    # Schon gemeldete Eintraege raus, bevor Artikelseiten geladen werden.
    known = set(seen)
    fresh = [e for e in entries if e.state_key not in known]

    if args.details or args.cve_only:
        news = [e for e in fresh if not e.local]
        enrich_with_cves(news[: max(args.detail_limit, 0)], args.timeout, args.quiet)
    # Erst jetzt kennen die Meldungen ihre CVE-Nummern - und erst jetzt laesst
    # sich sagen, welche davon dieses System wirklich treffen.
    mark_local_matches(fresh)
    if args.cve_only:
        fresh = [e for e in fresh if e.cves]

    if args.limit > 0:
        fresh = fresh[: args.limit]

    if mail_cfg:
        subtitle = (
            f"Lauf vom {datetime.now().astimezone().strftime('%d.%m.%Y %H:%M')} "
            f"- Quellen: {', '.join(s.label for s in selected)}"
        )
        send_empty = args.send_empty or env_flag("SECFEED_SEND_EMPTY")
        if not fresh and not send_empty:
            if not args.quiet:
                print("Nichts Neues - keine Mail verschickt.", file=sys.stderr)
        else:
            msg = build_message(mail_cfg, fresh, subtitle, failed)
            if args.dry_run:
                print(msg.as_string())
            else:
                try:
                    send_mail(mail_cfg, msg)
                except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
                    print(f"Mailversand an {mail_cfg.host}:{mail_cfg.port} "
                          f"({mail_cfg.security}) fehlgeschlagen: {exc}", file=sys.stderr)
                    for hint in smtp_error_hints(mail_cfg, exc):
                        print(f"  {hint}", file=sys.stderr)
                    return 1
                if not args.quiet:
                    print(f"Mail an {', '.join(mail_cfg.recipients)} verschickt "
                          f"({len(fresh)} Meldung(en)).", file=sys.stderr)
    elif args.format == "json":
        print(json.dumps([e.as_dict() for e in fresh], indent=2, ensure_ascii=False))
    elif args.format == "markdown":
        print(render_markdown(fresh))
    else:
        print(render_table(fresh))

    # Erst nach erfolgreichem Versand merken, sonst gehen Meldungen bei einem
    # SMTP-Fehler verloren.
    if state_path and not args.dry_run:
        try:
            save_seen(state_path, [e.state_key for e in fresh] + seen)
        except OSError as exc:
            print(f"Zustand nicht speicherbar ({state_path}): {exc}", file=sys.stderr)
            return 1

    # Teilausfall einzelner Quellen sichtbar machen, ohne den Lauf zu entwerten.
    return 3 if failed else 0


# --------------------------------------------------------------------------
# Dauerbetrieb: im Container laufen lassen und selbst zu festen Zeiten starten
# --------------------------------------------------------------------------

def parse_schedule(spec: str) -> list[tuple[int, int]]:
    """'07:00,18:00' -> [(7, 0), (18, 0)]"""
    times: list[tuple[int, int]] = []
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        match = re.fullmatch(r"(\d{1,2}):(\d{2})", chunk)
        if not match:
            raise ConfigError(f"Ungueltige Uhrzeit '{chunk}' - erwartet HH:MM, z.B. 07:00,18:00")
        hour, minute = int(match.group(1)), int(match.group(2))
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ConfigError(f"Uhrzeit ausserhalb des gueltigen Bereichs: {chunk}")
        times.append((hour, minute))
    if not times:
        raise ConfigError("--schedule braucht mindestens eine Uhrzeit, z.B. 07:00,18:00")
    return sorted(set(times))


def next_run_at(times: list[tuple[int, int]], now: datetime) -> datetime:
    """Naechster Termin in lokaler Zeit. Alles heute schon vorbei -> morgen."""
    candidates = []
    for hour, minute in times:
        today = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        candidates.append(today if today > now else today + timedelta(days=1))
    return min(candidates)


def log(message: str) -> None:
    """Zeitgestempelte Zeile auf stdout - landet so in `docker logs`."""
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    print(f"[{stamp}] {message}", flush=True)


def run_scheduler(args: argparse.Namespace, mail_cfg: MailConfig | None,
                  state_path: str | None, times: list[tuple[int, int]]) -> int:
    stop = threading.Event()

    def request_stop(signum, _frame):
        log(f"Signal {signal.Signals(signum).name} empfangen - beende nach aktuellem Lauf.")
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, request_stop)

    pretty = ", ".join(f"{h:02d}:{m:02d}" for h, m in times)
    log(f"SecurityFeed {__version__} im Dauerbetrieb. Zeiten: {pretty} "
        f"(Zeitzone {datetime.now().astimezone().tzname()})")

    def execute(reason: str) -> None:
        log(f"Lauf gestartet ({reason}).")
        try:
            code = run_once(args, mail_cfg, state_path)
        except Exception as exc:  # ein Fehlschlag darf den Dienst nicht beenden
            log(f"Lauf abgebrochen: {type(exc).__name__}: {exc}")
            return
        log(f"Lauf beendet, Exit-Code {code}.")

    if args.run_at_start:
        execute("Start")

    while not stop.is_set():
        target = next_run_at(times, datetime.now().astimezone())
        wait = (target - datetime.now().astimezone()).total_seconds()
        log(f"Naechster Lauf {target.strftime('%Y-%m-%d %H:%M:%S %Z')} "
            f"(in {int(wait // 3600)}h {int(wait % 3600 // 60)}min).")
        # Warten in Haeppchen: so wird eine Zeitumstellung oder ein korrigierter
        # Systemtakt spaetestens nach einer Minute neu bewertet.
        while wait > 0 and not stop.is_set():
            if stop.wait(min(wait, 60)):
                break
            wait = (target - datetime.now().astimezone()).total_seconds()
        if stop.is_set():
            break
        execute("Zeitplan")

    log("Beendet.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    # Umlaute auch in einer cp1252-Konsole nicht crashen lassen.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    if args.env_file:
        try:
            load_env_file(args.env_file)
        except OSError as exc:
            print(f"env-file nicht lesbar: {exc}", file=sys.stderr)
            return 2

    # Konfiguration vor dem Netzwerkzugriff pruefen - lieber sofort scheitern als
    # nach 20 Sekunden Feedabruf, und im Dauerbetrieb gar nicht erst starten.
    try:
        mail_cfg = mail_config_from_env(args) if args.email else None
        # Nur zur Pruefung - im Dauerbetrieb soll ein Zahlendreher in der
        # Umgebung sofort auffallen und nicht erst beim ersten Lauf.
        local_options(args)
        # SECFEED_SCHEDULE steckt im Container in der Service-Umgebung und wird
        # daher auch an "docker compose run" durchgereicht. Ohne diese Ausnahme
        # wuerde ein dortiger Einzelaufruf den Scheduler starten und haengen.
        if args.once or args.dry_run:
            schedule_spec = None
        else:
            schedule_spec = args.schedule or os.environ.get("SECFEED_SCHEDULE")
        times = parse_schedule(schedule_spec) if schedule_spec else None
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2

    state_path = resolve_state_path(args)

    if times:
        return run_scheduler(args, mail_cfg, state_path, times)
    return run_once(args, mail_cfg, state_path)


if __name__ == "__main__":
    raise SystemExit(main())
