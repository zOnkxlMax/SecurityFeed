#!/usr/bin/env python3
"""Holt die neuesten Schwachstellen-Meldungen von BleepingComputer und heise.de.

Mit --local zusaetzlich: die installierten Pakete (Debian und Alpine) gegen die
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
import base64
import concurrent.futures
import hmac
import html
import http.client
import json
import os
import re
import secrets
import signal
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

# Hoeher als jede reale Version. Die Antwort auf diese Abfrage sind genau die
# Luecken, gegen die es in der Suite (noch) keinen Fix gibt - sie treffen jede
# Version. Von der echten Abfrage abgezogen bleibt uebrig, was ein Update
# tatsaechlich schliesst. Das ist das Gegenstueck zu "debsecan --only-fixed"
# und kostet nur eine zweite Abfrage je Paket.
#
# Die Schreibweise muss zum Oekosystem passen. Ein Debian-Sentinel liefert bei
# Alpine heute zwar auch nichts - aber nur, weil OSV eine unparsbare Version
# als "kein Treffer" behandelt. Aenderte sich das je zu "trifft alles", wuerde
# die Differenz saemtliche Alpine-Funde stillschweigend ausloeschen.
OSV_SENTINEL_VERSION = "999999:0-0"  # Debian, Ubuntu: Epoche:Version-Revision
OSV_SENTINEL_BY_ECOSYSTEM = {"Alpine": "999999.0-r0"}


def sentinel_version(ecosystem: str) -> str:
    return OSV_SENTINEL_BY_ECOSYSTEM.get(ecosystem.split(":")[0], OSV_SENTINEL_VERSION)

# Die API liefert je Einzelabfrage hoechstens so viele IDs. Wird die Grenze
# erreicht, ist die Liste abgeschnitten und die Differenz oben nicht mehr
# belastbar - solche Pakete werden gesondert gemeldet statt falsch gezaehlt.
OSV_RESULT_CAP = 1000

# Abfragen pro HTTP-Request. Je Paket sind es zwei (echt + Sentinel), ein Pi
# mit ~600 Paketen kommt so mit rund fuenf Requests aus.
OSV_CHUNK = 250

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/source-package/"
OSV_LIST_URL = "https://osv.dev/list?"
DPKG_STATUS_PATH = "/var/lib/dpkg/status"

# Verzeichnis mit den abgelegten Paketlisten der Container, je Container ein
# Unterverzeichnis. Befuellt wird es auf dem Host von
# deploy/dump-container-packages.sh - SecurityFeed selbst bekommt bewusst
# keinen Docker-Zugriff, der Socket waere faktisch Root auf dem Pi.
CONTAINER_STATUS_FILE = "status"          # dpkg, also Debian und Verwandte
CONTAINER_APK_FILE = "apk-installed"      # apk, also Alpine
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
    # Was denselben Fund ueber Laeufe und Wiedervorlage-Fenster hinweg
    # bezeichnet: der Schluessel ohne das Fenster. Daran haengt eine Akzeptanz.
    # Kommt eine neue CVE dazu, aendert sich die Identitaet - und der Fund
    # kommt wieder, denn akzeptiert war ein anderer Zustand.
    identity: str | None = None

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
            "identity": self.identity,
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
    """Alle Einstellungen des Scans, bereits gegen die Umgebung aufgeloest.
    local_options() ist die einzige Stelle, die dafuer os.environ liest - der
    Scan selbst vertraut diesem Objekt."""
    status_path: str | None = None  # dpkg-Statusdatei statt dpkg-query
    release: str | None = None      # Debian-Hauptversion, z.B. "12"
    unfixed: bool = False           # auch Luecken ohne verfuegbaren Fix melden
    containers: str | None = None   # Verzeichnis mit Container-Paketlisten
    remind_days: float = LOCAL_REMIND_DAYS  # unveraenderte Funde nach so vielen Tagen erneut
    # /etc/os-release des Hosts, wenn dessen Paketliste eingehaengt ist. Ohne
    # sie kaeme die Version aus dem Container-Image - und ein Vergleich gegen
    # die falsche Suite ist schlimmer als gar keiner.
    host_os_release: str | None = None


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
    ecosystem: str = ""  # OSV-Oekosystem, z.B. "Debian:12" oder "Alpine:v3.21"

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


def parse_apk_installed(text: str) -> list[Package]:
    """Alpines Paketdatenbank /lib/apk/db/installed.

    Ein Block je Paket, einbuchstabige Feldnamen: P: Name, V: Version,
    o: Ursprungspaket. Wie bei Debian zaehlt fuer OSV das Ursprungspaket -
    eine Abfrage nach 'libssl3' liefert nichts, die nach 'openssl' alles."""
    found: dict[tuple[str, str], list[str]] = {}
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            key, sep, value = line.partition(":")
            # Genau ein Buchstabe vor dem Doppelpunkt, sonst ist es keine
            # Feldzeile - Pruefsummen und Dateilisten sehen aehnlich aus.
            if sep and len(key) == 1:
                fields[key] = value.strip()

        name, version = fields.get("P"), fields.get("V")
        if not name or not version:
            continue
        # Anders als dpkg fuehrt apk nur, was auch installiert ist - es gibt
        # kein Gegenstueck zu "deinstall ok config-files".
        source = fields.get("o") or name
        found.setdefault((source, version), []).append(name)
    return collect_packages(found)


def alpine_ecosystem(version_id: str) -> str | None:
    """'3.21.2' -> 'Alpine:v3.21'. OSV will genau diese Schreibweise: mit
    fuehrendem v und ohne Patchstand. 'edge' und Vorabversionen wie
    '3.23.0_alpha20250612' haben in der Datenbank kein Gegenstueck und liefern
    None - sonst wuerde ein Rolling Release gegen den stabilen Zweig gemessen
    und vor dessen Erscheinen schlicht als sauber gemeldet."""
    match = re.fullmatch(r"(\d+)\.(\d+)(?:\.\d+)?", version_id.strip())
    if not match:
        return None
    return f"Alpine:v{match.group(1)}.{match.group(2)}"


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


def parse_key_values(text: str) -> dict[str, str]:
    """KEY=VALUE-Zeilen, wie in /etc/os-release und in env-Dateien.

    Nur ein umschliessendes Anfuehrungszeichen-Paar wird entfernt. Ein blindes
    strip() wuerde einen Wert, der auf ein Anfuehrungszeichen endet, still
    beschneiden - bei einem Passwort faellt das erst als 'authentication
    failed' am Relay auf."""
    fields: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        fields[key.strip()] = value
    return fields


def parse_os_release(text: str) -> dict[str, str]:
    return parse_key_values(text)


def is_debian_like(fields: dict[str, str]) -> bool:
    """Debian selbst oder Raspbian, das 32-Bit Raspberry Pi OS - es fuehrt
    Debians Versionsnummern und Paketdatenbank. ID_LIKE reicht dafuer nicht:
    Ubuntu hat ebenfalls ID_LIKE=debian, aber eigene Versionen und ein
    eigenes OSV-Oekosystem."""
    return fields.get("ID", "").lower() in ("", "debian", "raspbian")


def debian_major(fields: dict[str, str]) -> str | None:
    """Debian-Hauptversion aus os-release-Feldern, oder None. Eine Regel fuer
    Host und Container, damit beide dieselben Eingaben akzeptieren."""
    version_id = fields.get("VERSION_ID", "")
    if version_id.isdigit():
        return version_id
    return CODENAME_RELEASES.get(fields.get("VERSION_CODENAME", "").lower())


def debian_release(os_release_path: str = "/etc/os-release",
                   debian_version_path: str = "/etc/debian_version") -> str:
    """Debian-Hauptversion als Zahl, z.B. '12'. Raspberry Pi OS meldet sich
    als Debian (64 Bit) oder als raspbian (32 Bit) - beides passt."""
    try:
        with open(os_release_path, "r", encoding="utf-8", errors="replace") as fh:
            fields = parse_os_release(fh.read())
    except OSError:
        fields = {}

    if not is_debian_like(fields):
        raise LocalScanError(
            f"Das System meldet sich als '{fields.get('ID', '').lower()}', der Scan "
            "kennt aber nur die Debian-Paketdatenbank. Bei einem Debian-Abkoemmling "
            "die passende Version mit --debian-release erzwingen."
        )
    release = debian_major(fields)
    if release:
        return release

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
    path = opts.status_path
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


def container_ecosystem(os_release_text: str) -> str | None:
    """OSV-Oekosystem eines Containers aus dessen /etc/os-release, oder None.

    Bewusst ohne Rueckfall auf den Host: ein bookworm-Host und ein
    trixie-Container haben verschiedene Fixversionen, und ein Vergleich gegen
    die falsche Suite waere schlimmer als gar keiner."""
    fields = parse_os_release(os_release_text)
    if fields.get("ID", "").lower() == "alpine":
        return alpine_ecosystem(fields.get("VERSION_ID", ""))
    if is_debian_like(fields):
        release = debian_major(fields)
        return f"Debian:{release}" if release else None
    return None


def host_target(opts: LocalOptions, timeout: float) -> ScanTarget:
    packages = installed_packages(opts, timeout)
    if opts.release:
        release = opts.release
    elif opts.host_os_release:
        # Fremde Paketliste, fremde os-release. /etc/debian_version dieses
        # Containers darf dabei nicht als Rueckfall dienen.
        release = debian_release(opts.host_os_release, debian_version_path="")
    elif opts.status_path:
        raise LocalScanError(
            f"Die Paketliste {opts.status_path} stammt von einem anderen System, "
            "dessen Debian-Version ist aber unbekannt - und die Version dieses "
            "Containers zu nehmen hiesse, gegen die falsche Suite zu vergleichen. "
            "Entweder dessen /etc/os-release einhaengen und mit --host-os-release "
            "darauf zeigen (SECFEED_HOST_OS_RELEASE) oder die Version mit "
            "--debian-release erzwingen (SECFEED_DEBIAN_RELEASE)."
        )
    else:
        release = debian_release()
    return ScanTarget(name="", packages=tuple(packages),
                      ecosystem=f"Debian:{release.strip()}")


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

    # Je nachdem, was das Sammelskript vorgefunden hat: dpkg oder apk.
    packages: list[Package] = []
    for filename, parser in ((CONTAINER_STATUS_FILE, parse_dpkg_status),
                             (CONTAINER_APK_FILE, parse_apk_installed)):
        try:
            with open(os.path.join(base, filename),
                      "r", encoding="utf-8", errors="replace") as fh:
                packages = parser(fh.read())
        except OSError:
            continue
        break
    else:
        return SkippedTarget(name, "keine Paketliste abgelegt")
    if not packages:
        return SkippedTarget(name, "Paketliste enthaelt kein installiertes Paket")

    try:
        with open(os.path.join(base, CONTAINER_OS_RELEASE_FILE),
                  "r", encoding="utf-8", errors="replace") as fh:
            ecosystem = container_ecosystem(fh.read())
    except OSError:
        ecosystem = None
    if not ecosystem:
        return SkippedTarget(
            name, "Distribution oder Version nicht erkennbar - unterstuetzt "
                  "werden Debian und Alpine"
        )
    return ScanTarget(name=name, packages=tuple(packages), ecosystem=ecosystem)


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
        # Fehler beim Lesen des Antwortkoerpers - IncompleteRead ist keine
        # URLError, ConnectionResetError ebenso wenig. Ohne diesen Zweig
        # riss ein Verbindungsabbruch den ganzen Lauf mit, samt der Ergebnisse
        # der anderen Quellen.
        except (OSError, http.client.HTTPException) as exc:
            raise LocalScanError(f"OSV-Verbindung abgebrochen: {exc}") from None

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
    """'DEBIAN-CVE-2025-9230' -> 'CVE-2025-9230', ebenso ALPINE- und UBUNTU-.

    Bleibt nach dem Abschneiden keine gueltige CVE-Nummer uebrig, bleibt die
    OSV-Kennung stehen - eine erfundene Nummer waere schlimmer als eine
    sperrige."""
    _, found, rest = osv_id.partition("CVE-")
    candidate = "CVE-" + rest if found else osv_id
    return candidate if CVE_RE.fullmatch(candidate) else osv_id


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


def tracker_url(ecosystem: str, package: str) -> str:
    """Seite zum Nachlesen. Fuer Debian der Security-Tracker: er zeigt den
    Status je Suite, das kann OSV so nicht. Fuer alles andere die OSV-Liste -
    Alpines Tracker hat keine brauchbare Adresse je Paket."""
    if ecosystem.split(":")[0] == "Debian":
        return DEBIAN_TRACKER_URL + urllib.parse.quote(package)
    return OSV_LIST_URL + urllib.parse.urlencode({"ecosystem": ecosystem, "q": package})


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
                f"{unfixed} weitere sind bekannt, aber in dieser Version der "
                "Distribution noch nicht behoben. "
            )
    else:
        title = f"{package.name} {package.version}: {len(cves)} Luecke(n) ohne Fix"
        summary = (
            "Fuer diese Schwachstellen gibt es in dieser Version der Distribution "
            "noch kein Update. Solche Faelle gelten meist als geringfuegig und "
            "werden erst mit dem naechsten Release behoben. "
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

    # Der Link zeigt fuer ein Paket immer auf dieselbe Tracker-Seite. Ohne
    # Ziel, Anzahl und juengste CVE in der Identitaet bliebe jede spaeter dazu
    # gekommene Luecke ungemeldet - und dasselbe Paket auf Host und in einem
    # Container waere derselbe Eintrag. Das Fenster kommt nur in den
    # Zustandsschluessel: es sorgt dafuer, dass ein ungepatchter Fund
    # wiederkommt statt zu verschwinden.
    identity = (f"local:{target.name or 'host'}:{package.name}:{len(cves)}:"
                f"{max(cves) if cves else package.version}")
    return Entry(
        source=target.label,
        title=title,
        link=tracker_url(target.ecosystem, package.name),
        published=now,
        summary=summary,
        cves=cves,
        advisory=True,
        local=True,
        # Beim Scan-Eintrag ist das betroffene Paket er selbst. So kommt
        # mark_local_matches an den Namen, ohne ihn aus dem Titel zu klauben.
        affects_local=[target.qualify(package.name)],
        key=f"{identity}:{window}",
        identity=identity,
    )


def unscanned_entry(skipped: SkippedTarget, now: datetime,
                    window: str = "einmalig") -> Entry:
    """Ein Ziel, das sich nicht pruefen liess. Ohne diesen Eintrag saehe ein
    unpruefbarer Container aus wie ein unauffaelliger."""
    what = f"Container {skipped.name}" if skipped.name else "Lokales System"
    # Ein blinder Fleck bleibt einer, bis sich etwas aendert - deshalb
    # dieselbe Wiedervorlage wie bei den Funden. Und er laesst sich akzeptieren:
    # ein distroless-Container ohne Paketdatenbank ist eine bewusste Wahl.
    identity = f"local:{skipped.name or 'host'}:ungeprueft:{skipped.reason}"
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
        key=f"{identity}:{window}",
        identity=identity,
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


def gather_targets(opts: LocalOptions, timeout: float
                   ) -> tuple[list[ScanTarget], list[SkippedTarget], str | None]:
    """Host und - falls konfiguriert - die abgelegten Container-Paketlisten.

    Ein gescheitertes Ziel nimmt die anderen nicht mit: laeuft der Host-Scan
    nicht, sollen die Container trotzdem geprueft werden und umgekehrt.

    Der Host-Fehler kommt gesondert zurueck, nicht als SkippedTarget: er soll
    als Ausfall der Quelle zaehlen - Warnung im Betreff jeder Mail, Exit-Code
    3 - und nicht als Betriebsnotiz, die einmal je Wiedervorlage-Fenster
    erscheint. Ein vergessener Mount waere sonst still, solange die Container
    gruen aussehen."""
    targets: list[ScanTarget] = []
    skipped: list[SkippedTarget] = []
    host_error: str | None = None
    try:
        targets.append(host_target(opts, timeout))
    except LocalScanError as exc:
        host_error = str(exc)

    if opts.containers:
        found, missed = container_targets(opts.containers)
        targets.extend(found)
        skipped.extend(missed)
    return targets, skipped, host_error


def scan_local(opts: LocalOptions, timeout: float) -> tuple[list[Entry], str | None]:
    """Liefert (Eintraege, Fehlermeldung). Beides kann zugleich belegt sein:
    Container geprueft, Host nicht."""
    targets, skipped, host_error = gather_targets(opts, timeout)
    if not targets:
        reasons = [f"Host: {host_error}"] if host_error else []
        reasons += [f"{s.name or 'Host'}: {s.reason}" for s in skipped]
        raise LocalScanError("Kein pruefbares System gefunden. " + "; ".join(reasons))

    # Je Paket zwei Abfragen: die echte Version und der Sentinel. Was beide
    # melden, ist ungefixt; die Differenz ist das, was ein Update schliesst.
    # Alle Ziele wandern in denselben Stapel - das Oekosystem haengt an der
    # einzelnen Abfrage, ein Request bedient also Host und Container zugleich.
    queries: list[tuple[str, str, str]] = []
    for target in targets:
        sentinel = sentinel_version(target.ecosystem)
        for package in target.packages:
            queries.append((package.name, package.version, target.ecosystem))
            queries.append((package.name, sentinel, target.ecosystem))
    # Ein Paket im Feed-Timeout abzufragen ist etwas anderes als 500 Pakete in
    # zwei Dutzend Abfragen - die Antwort braucht hier schlicht laenger.
    answers = osv_batch(queries, max(timeout, 60.0))

    now = datetime.now(timezone.utc)
    window = reminder_window(now, opts.remind_days)
    entries = [unscanned_entry(item, now, window) for item in skipped]

    if opts.containers:
        age = container_list_age(opts.containers)
        if age is None or age > CONTAINER_STAMP_MAX_AGE:
            entries.append(stale_lists_entry(age, opts.containers, now))

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
    return entries, host_error


def mark_local_matches(news: list[Entry], scan: list[Entry]) -> None:
    """Meldungen markieren, deren CVE hier tatsaechlich installiert ist.

    `scan` sind ALLE Eintraege des Paketscans aus diesem Lauf - auch die, die
    der Zustandsspeicher schon kennt. Ein Fund bleibt installiert, nachdem er
    gemeldet wurde; nur aus den frischen Eintraegen zu lernen hiesse, die
    Markierung fuer den Rest des Wiedervorlage-Fensters zu verlieren.

    Erst nach dem Nachladen der Artikelseiten aufrufen - vorher kennen die
    Feed-Eintraege ihre CVE-Nummern noch gar nicht."""
    affected: dict[str, set[str]] = {}
    for entry in scan:
        if not entry.local:
            continue
        for cve in entry.cves:
            affected.setdefault(cve, set()).update(entry.affects_local)
    if not affected:
        return
    for entry in news:
        if entry.local:
            continue
        hits = {pkg for cve in entry.cves for pkg in affected.get(cve, ())}
        entry.affects_local = sorted(hits)


def passes_cve_only(entry: Entry) -> bool:
    """Was --cve-only durchlaesst. Betriebsmeldungen des Scans ('nicht
    pruefbar', 'Listen veraltet') haben keine CVE, sind aber genau die Faelle,
    die nie unter den Tisch fallen duerfen."""
    return bool(entry.cves) or entry.local


def load_source(source: Source, timeout: float,
                local: LocalOptions | None = None) -> tuple[Source, list[Entry], str | None]:
    """Liefert (Quelle, Eintraege, Fehlermeldung)."""
    entries: list[Entry] = []
    root = None
    try:
        if source.kind == "local":
            # Die Quellenbezeichnung kommt hier aus dem Scan selbst: "Lokales
            # System" fuer den Host, "Container <name>" fuer die uebrigen.
            # Eintraege UND Fehler koennen zugleich kommen (Container ja,
            # Host nein) - collect() nimmt beides.
            entries, error = scan_local(local or LocalOptions(), timeout)
            return source, entries, error
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
    # Abbruch beim Lesen des Antwortkoerpers (IncompleteRead, Connection
    # reset). Ohne diesen Zweig riss eine Quelle den ganzen Lauf mit.
    except (OSError, http.client.HTTPException) as exc:
        return source, [], f"Verbindung abgebrochen: {exc}"

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
            # Auch bei Fehler uebernehmen: der Paketscan liefert Container-
            # Befunde und einen Host-Fehler zugleich. Feeds geben bei Fehler
            # ohnehin nichts zurueck.
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


def write_json(path: str, payload: dict) -> None:
    """Atomar: erst temporaer schreiben, dann ersetzen. Ein Absturz mittendrin
    darf den bestehenden Stand nicht zerstoeren - und Scanner und Webseite
    teilen sich Dateien, keiner darf einen halben Stand des anderen sehen."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def read_json(path: str) -> dict:
    """Ein JSON-Objekt, oder {} wenn die Datei fehlt oder kaputt ist."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def save_seen(path: str, seen: list[str], keep: int = 2000) -> None:
    write_json(path, {
        "updated": datetime.now(timezone.utc).isoformat(),
        "seen": seen[:keep],
    })


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
        fields = parse_key_values(fh.read())
    for key, value in fields.items():
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
        "Paketscan", "Installierte Pakete gegen die OSV-Datenbank halten - Debian "
                    "auf dem Host, Debian und Alpine in den Containern."
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
    scan.add_argument("--host-os-release", metavar="DATEI",
                      help="Die /etc/os-release des Hosts, wenn dessen Paketliste per "
                           "--dpkg-status eingehaengt ist - daraus kommt die Debian-Version "
                           "(SECFEED_HOST_OS_RELEASE). Ohne sie und ohne --debian-release "
                           "wird nicht geraten, sondern nicht geprueft.")
    # default=None, damit ein ausdrueckliches "--local-remind 7" von einem
    # nicht gesetzten Wert unterscheidbar bleibt - sonst gewaenne die Umgebung.
    scan.add_argument("--local-remind", metavar="TAGE", type=float, default=None,
                      help="Unveraenderte Funde nach so vielen Tagen erneut melden "
                           f"(SECFEED_LOCAL_REMIND, Default {LOCAL_REMIND_DAYS:g}). Ein "
                           "verwundbares Paket ist ein Zustand, keine Nachricht - ohne "
                           "Wiedervorlage verschwaende es nach der ersten Mail. "
                           "0 = nur einmal melden.")
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

    web = parser.add_argument_group(
        "Webseite", "Funde im internen Netz anzeigen und dort akzeptieren."
    )
    web.add_argument("--serve", metavar="HOST:PORT", nargs="?", const="", default=None,
                     help="HTTP-Seite mit den aktuellen Funden anbieten, auf der sich Funde "
                          "akzeptieren lassen (Adresse auch per SECFEED_WEB_LISTEN, Default "
                          "0.0.0.0:8080). Braucht SECFEED_WEB_USER und SECFEED_WEB_PASSWORD. "
                          "Zusammen mit --schedule: ein Prozess fuer beides. Kein TLS - nur "
                          "im eigenen Netz betreiben.")
    web.add_argument("--web-user", help="Benutzername fuer die Anmeldung (SECFEED_WEB_USER). "
                                        "Das Passwort nur ueber SECFEED_WEB_PASSWORD.")
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
    """Die einzige Stelle, die fuer den Scan os.environ liest. Kommandozeile
    schlaegt Umgebung - wie bei mail_config_from_env."""
    env = os.environ.get

    def pick(cli_value: str | None, env_key: str) -> str | None:
        # Leere Umgebungswerte (compose setzt "${VAR:-}") zaehlen als nicht gesetzt.
        return cli_value if cli_value else (env(env_key) or None)

    if args.local_remind is not None:
        remind = args.local_remind
    elif env("SECFEED_LOCAL_REMIND"):
        try:
            remind = float(env("SECFEED_LOCAL_REMIND", ""))
        except ValueError:
            raise ConfigError(
                "SECFEED_LOCAL_REMIND muss eine Zahl in Tagen sein, z.B. 7 "
                f"(steht dort: {env('SECFEED_LOCAL_REMIND')!r})."
            ) from None
    else:
        remind = LOCAL_REMIND_DAYS

    return LocalOptions(
        status_path=pick(args.dpkg_status, "SECFEED_DPKG_STATUS"),
        release=pick(args.debian_release, "SECFEED_DEBIAN_RELEASE"),
        unfixed=args.local_unfixed or env_flag("SECFEED_LOCAL_UNFIXED"),
        containers=pick(args.container_lists, "SECFEED_CONTAINER_LISTS"),
        remind_days=remind,
        host_os_release=pick(args.host_os_release, "SECFEED_HOST_OS_RELEASE"),
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

    # Alle Scan-Eintraege dieses Laufs, bevor Akzeptanzen und Zustand
    # aussortieren: ein akzeptierter oder schon gemeldeter Fund ist trotzdem
    # noch installiert - fuer die Markierung der Nachrichten und fuer die
    # Webseite zaehlt er weiter.
    scan_all = [e for e in entries if e.local]

    # Akzeptanzen: bewusst hingenommene Funde fallen aus Mail und Wiedervorlage,
    # bis ihr Datum ablaeuft. Vor dem Zustandsfilter, damit sie nicht als
    # "gemeldet" gespeichert werden und nach einem Widerruf sofort wiederkommen.
    if state_path:
        decisions = load_decisions(state_sibling(state_path, DECISIONS_FILE))
        entries, accepted = apply_acceptances(entries, decisions, datetime.now(timezone.utc))
        if accepted and not args.quiet:
            print(f"{len(accepted)} akzeptierte(r) Fund(e) uebersprungen.", file=sys.stderr)

    # Schon gemeldete Eintraege raus, bevor Artikelseiten geladen werden.
    known = set(seen)
    fresh = [e for e in entries if e.state_key not in known]

    if args.details or args.cve_only:
        news = [e for e in fresh if not e.local]
        enrich_with_cves(news[: max(args.detail_limit, 0)], args.timeout, args.quiet)
    # Erst jetzt kennen die Meldungen ihre CVE-Nummern - und erst jetzt laesst
    # sich sagen, welche davon dieses System wirklich treffen.
    mark_local_matches(fresh, scan_all)
    if args.cve_only:
        fresh = [e for e in fresh if passes_cve_only(e)]

    if args.limit > 0:
        fresh = fresh[: args.limit]

    subtitle = (
        f"Lauf vom {datetime.now().astimezone().strftime('%d.%m.%Y %H:%M')} "
        f"- Quellen: {', '.join(s.label for s in selected)}"
    )

    if mail_cfg:
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
        # Der Ist-Zustand fuer die Webseite: alle Scan-Funde dieses Laufs -
        # auch akzeptierte und schon gemeldete - plus die Nachrichten, die
        # dieses System betreffen. Nicht kritisch: scheitert das, ist die
        # Mail trotzdem raus.
        try:
            save_findings(state_sibling(state_path, FINDINGS_FILE),
                          scan_all + [e for e in fresh if e.affects_local and not e.local],
                          subtitle, failed)
        except OSError as exc:
            print(f"Ist-Zustand fuer die Webseite nicht speicherbar: {exc}", file=sys.stderr)

    # Teilausfall einzelner Quellen sichtbar machen, ohne den Lauf zu entwerten.
    return 3 if failed else 0


# --------------------------------------------------------------------------
# Akzeptanzen: Funde, die jemand bewusst hingenommen hat - und die Webseite,
# auf der das passiert.
#
# Zwei Dateien neben seen.json. findings.json schreibt der Scanner nach jedem
# Lauf (der Ist-Zustand), decisions.json schreibt die Webseite (die
# Entscheidungen). Beide lesen die jeweils andere. Alle Schreibvorgaenge sind
# atomar, deshalb duerfen beide Prozesse gleichzeitig laufen.
# --------------------------------------------------------------------------

FINDINGS_FILE = "findings.json"
DECISIONS_FILE = "decisions.json"
ACCEPT_DAYS_DEFAULT = 90

# Werte aus den Beispieldateien. Ein Passwort, das in einem oeffentlichen
# Repo steht, ist keins.
PLACEHOLDER_PASSWORDS = frozenset({
    "aendere-mich", "dein-passwort", "geheim", "changeme", "password", "passwort",
})


def state_sibling(state_path: str | None, name: str) -> str:
    """Datei im selben Verzeichnis wie seen.json."""
    return os.path.join(os.path.dirname(state_path or default_state_path()), name)


@dataclass
class Acceptance:
    identity: str
    by: str
    at: datetime
    until: datetime | None  # None = unbefristet
    comment: str = ""
    title: str = ""  # der Fund, wie er hiess - bleibt lesbar, auch wenn er weg ist

    def active(self, now: datetime) -> bool:
        return self.until is None or self.until > now

    def as_dict(self) -> dict:
        return {
            "by": self.by,
            "at": self.at.isoformat(),
            "until": self.until.isoformat() if self.until else None,
            "comment": self.comment,
            "title": self.title,
        }

    @classmethod
    def from_dict(cls, identity: str, raw: dict) -> "Acceptance | None":
        at = parse_date(raw.get("at"))
        if at is None:
            return None
        return cls(identity, str(raw.get("by", "")), at, parse_date(raw.get("until")),
                   str(raw.get("comment", "")), str(raw.get("title", "")))


def load_decisions(path: str) -> dict[str, Acceptance]:
    raw = read_json(path).get("accepted")
    if not isinstance(raw, dict):
        return {}
    decisions: dict[str, Acceptance] = {}
    for identity, item in raw.items():
        if isinstance(item, dict):
            acceptance = Acceptance.from_dict(identity, item)
            if acceptance:
                decisions[identity] = acceptance
    return decisions


def save_decisions(path: str, decisions: dict[str, Acceptance]) -> None:
    write_json(path, {
        "updated": datetime.now(timezone.utc).isoformat(),
        "accepted": {identity: acc.as_dict() for identity, acc in decisions.items()},
    })


def apply_acceptances(entries: list[Entry], decisions: dict[str, Acceptance],
                      now: datetime) -> tuple[list[Entry], list[Entry]]:
    """(weiter zu meldende, akzeptierte). Nur aktive Akzeptanzen zaehlen -
    eine abgelaufene laesst den Fund wieder in die Mail."""
    kept: list[Entry] = []
    accepted: list[Entry] = []
    for entry in entries:
        acceptance = decisions.get(entry.identity) if entry.identity else None
        (accepted if acceptance and acceptance.active(now) else kept).append(entry)
    return kept, accepted


def save_findings(path: str, entries: list[Entry], subtitle: str,
                  failed: list[str]) -> None:
    write_json(path, {
        "updated": datetime.now(timezone.utc).isoformat(),
        "subtitle": subtitle,
        "failed": list(failed),
        "entries": [entry.as_dict() for entry in entries],
    })


@dataclass
class WebConfig:
    host: str
    port: int
    user: str
    password: str
    findings_path: str
    decisions_path: str
    accept_days: int = ACCEPT_DAYS_DEFAULT  # Vorbelegung des Ablaufdatums


def web_config_from_env(args: argparse.Namespace, state_path: str | None) -> WebConfig:
    env = os.environ.get
    listen = args.serve or env("SECFEED_WEB_LISTEN") or "0.0.0.0:8080"
    host, sep, port_raw = listen.rpartition(":")
    if not sep or not port_raw.isdigit():
        raise ConfigError(f"--serve erwartet HOST:PORT, z.B. 0.0.0.0:8080 (steht dort: {listen!r}).")

    user = args.web_user or env("SECFEED_WEB_USER")
    password = env("SECFEED_WEB_PASSWORD")
    if not user or not password:
        raise ConfigError(
            "Die Webseite braucht eine Anmeldung: SECFEED_WEB_USER und "
            "SECFEED_WEB_PASSWORD setzen. Ohne sie koennte jeder im Netz Funde "
            "stumm schalten."
        )
    if password.strip().lower() in PLACEHOLDER_PASSWORDS:
        raise ConfigError("SECFEED_WEB_PASSWORD steht noch auf einem Beispielwert.")

    days_raw = env("SECFEED_ACCEPT_DAYS", "").strip()
    try:
        days = int(days_raw) if days_raw else ACCEPT_DAYS_DEFAULT
    except ValueError:
        raise ConfigError(f"SECFEED_ACCEPT_DAYS muss eine Zahl in Tagen sein (steht dort: {days_raw!r}).") from None

    return WebConfig(
        host=host or "0.0.0.0", port=int(port_raw), user=user, password=password,
        findings_path=state_sibling(state_path, FINDINGS_FILE),
        decisions_path=state_sibling(state_path, DECISIONS_FILE),
        accept_days=days,
    )


class AcceptanceSite:
    """Inhalt und Entscheidungen der Seite - ohne HTTP, damit es sich ohne
    Server testen laesst."""

    def __init__(self, cfg: WebConfig):
        self.cfg = cfg
        self.lock = threading.Lock()
        # Ein Geheimnis je Serverstart in jedem Formular. Basic Auth schickt der
        # Browser bei jeder Anfrage mit - eine fremde Seite im selben Netz
        # koennte ihn sonst Akzeptanzen abschicken lassen.
        self.form_token = secrets.token_urlsafe(24)

    # -- Anmeldung -----------------------------------------------------------

    def authorized(self, header: str | None) -> str | None:
        """Benutzername bei gueltiger Anmeldung, sonst None."""
        if not header or not header.startswith("Basic "):
            return None
        try:
            raw = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
        user, sep, password = raw.partition(":")
        if not sep:
            return None
        # Beide Vergleiche immer ausfuehren - sonst verraet die Antwortzeit,
        # ob der Benutzername stimmt.
        user_ok = hmac.compare_digest(user.encode("utf-8"), self.cfg.user.encode("utf-8"))
        pass_ok = hmac.compare_digest(password.encode("utf-8"), self.cfg.password.encode("utf-8"))
        return user if (user_ok and pass_ok) else None

    # -- Entscheidungen ------------------------------------------------------

    def accept(self, identity: str, by: str, comment: str, until_raw: str) -> str:
        identity = identity.strip()
        if not identity:
            return "Kein Fund angegeben."
        now = datetime.now(timezone.utc)
        until: datetime | None = None
        if until_raw.strip():
            try:
                day = datetime.strptime(until_raw.strip(), "%Y-%m-%d")
            except ValueError:
                return "Ablaufdatum bitte als JJJJ-MM-TT angeben."
            until = day.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
            if until <= now:
                return "Das Ablaufdatum liegt in der Vergangenheit."
        with self.lock:
            decisions = load_decisions(self.cfg.decisions_path)
            title = self.title_for(identity)
            decisions[identity] = Acceptance(identity, by, now, until,
                                             comment.strip()[:500], title)
            save_decisions(self.cfg.decisions_path, decisions)
        log(f"Akzeptiert durch {by}: {identity} "
            f"(bis {until.date().isoformat() if until else 'unbefristet'})")
        return f"Akzeptiert: {title or identity}"

    def revoke(self, identity: str, by: str) -> str:
        with self.lock:
            decisions = load_decisions(self.cfg.decisions_path)
            acceptance = decisions.pop(identity.strip(), None)
            if acceptance is None:
                return "Diese Akzeptanz gibt es nicht (mehr)."
            save_decisions(self.cfg.decisions_path, decisions)
        log(f"Widerrufen durch {by}: {identity}")
        return f"Widerrufen: {acceptance.title or identity}"

    def findings(self) -> dict:
        return read_json(self.cfg.findings_path)

    def title_for(self, identity: str) -> str:
        for item in self.findings().get("entries", []):
            if isinstance(item, dict) and item.get("identity") == identity:
                return str(item.get("title", ""))
        return ""

    # -- Seite ---------------------------------------------------------------

    def page(self, message: str = "") -> str:
        esc = html.escape
        now = datetime.now(timezone.utc)
        data = self.findings()
        decisions = load_decisions(self.cfg.decisions_path)
        entries = [e for e in data.get("entries", []) if isinstance(e, dict)]

        open_findings, accepted_findings, notes, news = [], [], [], []
        for item in entries:
            identity = item.get("identity")
            if not item.get("local"):
                news.append(item)
            elif not identity:
                notes.append(item)
            elif identity in decisions and decisions[identity].active(now):
                accepted_findings.append(item)
            else:
                open_findings.append(item)
        present = {item.get("identity") for item in entries}
        orphaned = [acc for identity, acc in decisions.items() if identity not in present]
        expired = [acc for identity, acc in decisions.items()
                   if identity in present and not acc.active(now)]

        updated = parse_date(data.get("updated"))
        stand = updated.astimezone().strftime("%d.%m.%Y %H:%M") if updated else "noch kein Lauf"
        default_until = (datetime.now() + timedelta(days=self.cfg.accept_days)).strftime("%Y-%m-%d")

        def cves_of(item: dict) -> str:
            cves = [c for c in item.get("cves", []) if isinstance(c, str)]
            shown = cves[:CVE_DISPLAY_CAP]
            tags = "".join(f'<span class="cve">{esc(c)}</span>' for c in shown)
            if len(cves) > len(shown):
                tags += f'<span class="muted">+{len(cves) - len(shown)} weitere</span>'
            return f'<div class="cves">{tags}</div>' if tags else ""

        def headline(item: dict) -> str:
            title, link = esc(str(item.get("title", ""))), str(item.get("link") or "")
            return f'<a href="{esc(link)}">{title}</a>' if link else title

        def accept_form(item: dict) -> str:
            return (
                '<form method="post" action="/accept" class="accept">'
                f'<input type="hidden" name="token" value="{esc(self.form_token)}">'
                f'<input type="hidden" name="identity" value="{esc(str(item.get("identity")))}">'
                '<label>Grund <input name="comment" maxlength="500" '
                'placeholder="z.B. Dienst nicht von aussen erreichbar"></label>'
                f'<label>Bis <input type="date" name="until" value="{default_until}"></label>'
                '<button type="submit">Akzeptieren</button>'
                '<span class="muted">Ablaufdatum leer lassen = unbefristet</span>'
                '</form>'
            )

        def revoke_form(identity: str) -> str:
            return (
                '<form method="post" action="/revoke" class="revoke">'
                f'<input type="hidden" name="token" value="{esc(self.form_token)}">'
                f'<input type="hidden" name="identity" value="{esc(identity)}">'
                '<button type="submit">Widerrufen</button></form>'
            )

        def acceptance_meta(acc: Acceptance) -> str:
            until = acc.until.astimezone().strftime("%d.%m.%Y") if acc.until else "unbefristet"
            at = acc.at.astimezone().strftime("%d.%m.%Y %H:%M")
            comment = f" &middot; {esc(acc.comment)}" if acc.comment else ""
            return (f'<div class="meta">akzeptiert von {esc(acc.by)} am {at}, '
                    f'gueltig bis {until}{comment}</div>')

        parts = [
            "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
            "<title>SecurityFeed</title><style>",
            "body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;",
            "max-width:860px;margin:0 auto;padding:16px 20px;color:#1a1a1a;background:#fafafa}",
            "h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:32px 0 12px;",
            "border-bottom:1px solid #ddd;padding-bottom:4px}",
            ".muted{color:#777;font-size:13px} .meta{color:#666;font-size:13px;margin:4px 0}",
            ".item{background:#fff;border-left:3px solid #c81e1e;padding:10px 14px;",
            "margin:0 0 14px;border-radius:0 4px 4px 0;box-shadow:0 1px 2px rgba(0,0,0,.06)}",
            ".item.ok{border-left-color:#9aa} .item.news{border-left-color:#1a4fa0}",
            ".item a{color:#1a4fa0;text-decoration:none;font-weight:600;font-size:16px}",
            ".item .title{font-weight:600;font-size:16px}",
            ".cves{margin:6px 0} .cve{display:inline-block;background:#fde8e8;color:#9b1c1c;",
            "border-radius:3px;padding:1px 6px;margin:0 4px 4px 0;font-size:12px;font-family:monospace}",
            ".summary{font-size:14px;line-height:1.5;margin:6px 0}",
            "form.accept{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;",
            "margin-top:8px;font-size:13px} form.accept input{margin-left:4px}",
            "form.accept input[name=comment]{width:260px;max-width:100%}",
            "button{background:#1a4fa0;color:#fff;border:0;border-radius:3px;padding:6px 12px;",
            "cursor:pointer} form.revoke button{background:#888}",
            ".message{background:#e6f4ea;border-left:3px solid #2e7d32;padding:8px 14px;margin:12px 0}",
            ".warn{background:#fff8e1;border-left:3px solid #f0ad4e;padding:8px 14px;margin:12px 0}",
            "</style></head><body>",
            "<h1>SecurityFeed</h1>",
            f'<div class="muted">Stand: {esc(stand)} &middot; {esc(str(data.get("subtitle", "")))}</div>',
        ]
        if message:
            parts.append(f'<div class="message">{esc(message)}</div>')
        failed = [f for f in data.get("failed", []) if isinstance(f, str)]
        if failed:
            parts.append('<div class="warn"><strong>Warnung:</strong> Diese Quellen waren '
                         'beim letzten Lauf nicht erreichbar:<ul>'
                         + "".join(f"<li>{esc(f)}</li>" for f in failed) + "</ul></div>")

        parts.append(f"<h2>Offene Funde ({len(open_findings)})</h2>")
        if not open_findings:
            parts.append('<p class="muted">Keine offenen Funde.</p>')
        for item in open_findings:
            parts.append(
                '<div class="item">'
                f'<div class="meta">{esc(str(item.get("source", "")))}</div>'
                f'{headline(item)}{cves_of(item)}'
                f'<div class="summary">{esc(str(item.get("summary", "")))}</div>'
                f'{accept_form(item)}</div>'
            )

        if news:
            parts.append(f"<h2>Meldungen, die dieses System betreffen ({len(news)})</h2>")
            for item in news:
                affects = ", ".join(str(a) for a in item.get("affects_local", []))
                parts.append(
                    '<div class="item news">'
                    f'<div class="meta">{esc(str(item.get("source", "")))} &middot; '
                    f'betrifft: {esc(affects)}</div>'
                    f'{headline(item)}{cves_of(item)}'
                    f'<div class="summary">{esc(str(item.get("summary", "")))}</div></div>'
                )

        if notes:
            parts.append("<h2>Hinweise</h2>")
            for item in notes:
                parts.append(f'<div class="item ok"><div class="title">{esc(str(item.get("title", "")))}'
                             f'</div><div class="summary">{esc(str(item.get("summary", "")))}</div></div>')

        total_accepted = len(accepted_findings) + len(orphaned) + len(expired)
        parts.append(f"<h2>Akzeptiert ({total_accepted})</h2>")
        if not total_accepted:
            parts.append('<p class="muted">Nichts akzeptiert.</p>')
        for item in accepted_findings:
            acc = decisions[item["identity"]]
            parts.append(
                '<div class="item ok">'
                f'<div class="meta">{esc(str(item.get("source", "")))}</div>'
                f'{headline(item)}{cves_of(item)}{acceptance_meta(acc)}'
                f'{revoke_form(acc.identity)}</div>'
            )
        for acc in expired:
            parts.append(
                '<div class="item">'
                f'<div class="title">{esc(acc.title or acc.identity)}</div>'
                f'{acceptance_meta(acc)}<div class="meta"><strong>Abgelaufen</strong> - '
                'der Fund wird wieder gemeldet. Erneut akzeptieren oben, oder hier entfernen.</div>'
                f'{revoke_form(acc.identity)}</div>'
            )
        for acc in orphaned:
            parts.append(
                '<div class="item ok">'
                f'<div class="title">{esc(acc.title or acc.identity)}</div>'
                f'{acceptance_meta(acc)}<div class="meta">Derzeit nicht mehr gemeldet - '
                'gepatcht, oder der Stand hat sich geaendert.</div>'
                f'{revoke_form(acc.identity)}</div>'
            )

        parts.append(f'<p class="muted" style="margin-top:32px">SecurityFeed {__version__} '
                     '&middot; Eine Akzeptanz gilt fuer genau diesen Stand des Funds. '
                     'Kommt eine neue Luecke dazu, wird er wieder gemeldet.</p>')
        parts.append("</body></html>")
        return "".join(parts)


class AcceptanceHandler(BaseHTTPRequestHandler):
    server_version = f"SecurityFeed/{__version__}"
    sys_version = ""

    @property
    def site(self) -> AcceptanceSite:
        return self.server.site  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args) -> None:
        log(f"web {self.client_address[0]} {fmt % args}")

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8",
              extra: dict[str, str] | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _require_user(self) -> str | None:
        user = self.site.authorized(self.headers.get("Authorization"))
        if user is None:
            self._send(401, "Anmeldung erforderlich.", "text/plain; charset=utf-8",
                       {"WWW-Authenticate": 'Basic realm="SecurityFeed", charset="UTF-8"'})
        return user

    def do_GET(self) -> None:
        path, _, query = self.path.partition("?")
        if path == "/health":
            # Ohne Anmeldung, damit ein Healthcheck nicht das Passwort braucht.
            self._send(200, "ok", "text/plain; charset=utf-8")
            return
        if path != "/":
            self._send(404, "Nicht gefunden.", "text/plain; charset=utf-8")
            return
        if self._require_user() is None:
            return
        message = urllib.parse.parse_qs(query).get("m", [""])[0]
        self._send(200, self.site.page(message))

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:
        user = self._require_user()
        if user is None:
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length > 65536:
            self._send(413, "Zu gross.", "text/plain; charset=utf-8")
            return
        form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))

        def field(name: str) -> str:
            return form.get(name, [""])[0]

        if not hmac.compare_digest(field("token"), self.site.form_token):
            self._send(403, "Formular abgelaufen - Seite neu laden und erneut versuchen.",
                       "text/plain; charset=utf-8")
            return
        if self.path == "/accept":
            message = self.site.accept(field("identity"), user, field("comment"), field("until"))
        elif self.path == "/revoke":
            message = self.site.revoke(field("identity"), user)
        else:
            self._send(404, "Nicht gefunden.", "text/plain; charset=utf-8")
            return
        # Post/Redirect/Get: ein Neuladen wiederholt die Entscheidung nicht.
        self._send(303, "", "text/plain; charset=utf-8",
                   {"Location": "/?" + urllib.parse.urlencode({"m": message})})


def start_web(cfg: WebConfig) -> ThreadingHTTPServer:
    """Server im Hintergrund-Thread. Der Aufrufer beendet ihn mit shutdown()."""
    server = ThreadingHTTPServer((cfg.host, cfg.port), AcceptanceHandler)
    server.daemon_threads = True
    server.site = AcceptanceSite(cfg)  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, name="web", daemon=True)
    thread.start()
    log(f"Webseite: http://{cfg.host}:{server.server_address[1]}/ "
        f"(Anmeldung als '{cfg.user}', Akzeptanzen in {cfg.decisions_path}).")
    return server


def run_web_only(cfg: WebConfig) -> int:
    """--serve ohne --schedule: nur die Seite, bis SIGTERM/SIGINT."""
    stop = threading.Event()

    def request_stop(signum, _frame):
        log(f"Signal {signal.Signals(signum).name} empfangen - beende.")
        stop.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, request_stop)

    server = start_web(cfg)
    while not stop.wait(60):
        pass
    server.shutdown()
    server.server_close()
    log("Beendet.")
    return 0


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

    state_path = resolve_state_path(args)

    # Konfiguration vor dem Netzwerkzugriff pruefen - lieber sofort scheitern als
    # nach 20 Sekunden Feedabruf, und im Dauerbetrieb gar nicht erst starten.
    try:
        mail_cfg = mail_config_from_env(args) if args.email else None
        web_cfg = web_config_from_env(args, state_path) if args.serve is not None else None
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

    if times:
        # Seite und Zeitplan in einem Prozess: der Server laeuft nebenher und
        # wird beendet, sobald der Scheduler zurueckkehrt.
        server = start_web(web_cfg) if web_cfg else None
        try:
            return run_scheduler(args, mail_cfg, state_path, times)
        finally:
            if server:
                server.shutdown()
                server.server_close()
    if web_cfg:
        return run_web_only(web_cfg)
    return run_once(args, mail_cfg, state_path)


if __name__ == "__main__":
    raise SystemExit(main())
