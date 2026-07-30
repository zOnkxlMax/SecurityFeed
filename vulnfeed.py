#!/usr/bin/env python3
"""Holt die neuesten Schwachstellen-Meldungen von BleepingComputer und heise.de.

Nur Standardbibliothek - keine Installation noetig.

Beispiele:
    python3 vulnfeed.py                       # letzte 7 Tage, Tabelle
    python3 vulnfeed.py --since 2 --limit 20  # letzte 2 Tage, max. 20 Eintraege
    python3 vulnfeed.py --source heise-alerts --format markdown
    python3 vulnfeed.py --format json > vulns.json

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
import sys
import threading
import urllib.error
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


def collect(selected: list[Source], timeout: float, quiet: bool) -> tuple[list[Entry], int]:
    """Liefert (Eintraege, Anzahl fehlgeschlagener Quellen)."""
    entries: list[Entry] = []
    failures = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(selected)) as pool:
        for source, found, error in pool.map(lambda s: load_source(s, timeout), selected):
            if error:
                failures += 1
                if not quiet:
                    print(f"! {source.label}: {error}", file=sys.stderr)
                continue
            entries.extend(found)
    return entries, failures


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


def render_html(entries: list[Entry], subtitle: str) -> str:
    """Mail-taugliches HTML: Inline-Styles, keine externen Ressourcen."""
    esc = html.escape
    head = (
        '<div style="font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
        'max-width:760px;margin:0 auto;color:#1a1a1a">'
        '<h2 style="margin:0 0 4px">Aktuelle Schwachstellen-Meldungen</h2>'
        f'<p style="margin:0 0 20px;color:#666;font-size:13px">{esc(subtitle)}</p>'
    )
    if not entries:
        return head + '<p>Keine neuen Meldungen.</p></div>'

    blocks = []
    for entry in entries:
        stamp = entry.published.astimezone().strftime("%d.%m.%Y %H:%M") if entry.published else "?"
        meta = f"{esc(entry.source)} &middot; {stamp}"
        cves = ""
        if entry.cves:
            tags = "".join(
                '<span style="display:inline-block;background:#fde8e8;color:#9b1c1c;'
                'border-radius:3px;padding:1px 6px;margin:0 4px 4px 0;font-size:12px;'
                f'font-family:monospace">{esc(c)}</span>'
                for c in entry.cves
            )
            cves = f'<div style="margin:6px 0 0">{tags}</div>'
        summary = (
            f'<p style="margin:8px 0 0;font-size:14px;line-height:1.5">{esc(entry.summary)}</p>'
            if entry.summary else ""
        )
        blocks.append(
            '<div style="border-left:3px solid #d0d0d0;padding:0 0 0 14px;margin:0 0 24px">'
            f'<div style="color:#777;font-size:12px">{meta}</div>'
            f'<a href="{esc(entry.link)}" style="font-size:16px;font-weight:600;'
            f'color:#1a4fa0;text-decoration:none">{esc(entry.title)}</a>'
            f'{cves}{summary}</div>'
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


def build_message(cfg: MailConfig, entries: list[Entry], subtitle: str) -> EmailMessage:
    top = entries[0].title if entries else "keine neuen Meldungen"
    if len(top) > 70:
        top = top[:67] + "..."
    count = len(entries)
    subject = f"{cfg.subject_prefix} {count} neue Meldung(en): {top}" if count else \
              f"{cfg.subject_prefix} keine neuen Meldungen"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = cfg.sender
    msg["To"] = ", ".join(cfg.recipients)
    msg["Date"] = format_datetime(datetime.now(timezone.utc))
    msg["Message-ID"] = make_msgid(domain=cfg.sender.split("@")[-1] or None)
    msg.set_content(render_table(entries))
    msg.add_alternative(render_html(entries, subtitle), subtype="html")
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
                      help="Auch mailen, wenn es nichts Neues gibt.")
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


def run_once(args: argparse.Namespace, mail_cfg: MailConfig | None,
             state_path: str | None) -> int:
    """Ein kompletter Durchlauf: abrufen, filtern, ausgeben bzw. mailen."""
    seen = [] if (state_path is None or args.reset_state) else load_seen(state_path)

    selected = [s for s in SOURCES if not args.source or s.key in args.source]
    entries, failures = collect(selected, args.timeout, args.quiet)
    entries = dedupe(entries)

    if failures == len(selected):
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
    fresh = [e for e in entries if (e.link or e.title) not in known]

    if args.details or args.cve_only:
        enrich_with_cves(fresh[: max(args.detail_limit, 0)], args.timeout, args.quiet)
    if args.cve_only:
        fresh = [e for e in fresh if e.cves]

    if args.limit > 0:
        fresh = fresh[: args.limit]

    if mail_cfg:
        subtitle = (
            f"Lauf vom {datetime.now().astimezone().strftime('%d.%m.%Y %H:%M')} "
            f"- Quellen: {', '.join(s.label for s in selected)}"
        )
        if not fresh and not args.send_empty:
            if not args.quiet:
                print("Nichts Neues - keine Mail verschickt.", file=sys.stderr)
        else:
            msg = build_message(mail_cfg, fresh, subtitle)
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
            save_seen(state_path, [e.link or e.title for e in fresh] + seen)
        except OSError as exc:
            print(f"Zustand nicht speicherbar ({state_path}): {exc}", file=sys.stderr)
            return 1

    # Teilausfall einzelner Quellen sichtbar machen, ohne den Lauf zu entwerten.
    return 3 if failures else 0


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
