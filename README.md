# SecurityFeed

CLI-Tool, das die neuesten Schwachstellen- und Security-Meldungen von
**BleepingComputer** und **heise.de** einsammelt, zusammenführt und als Tabelle,
JSON oder Markdown ausgibt.

Reines Python 3.10+ aus der Standardbibliothek — keine Abhängigkeiten, kein
`pip install`.

## Quellen

| Key              | Feed                          | Inhalt                                   |
| ---------------- | ----------------------------- | ---------------------------------------- |
| `bleeping`       | BleepingComputer (RSS 2.0)    | Security-News allgemein, wird gefiltert   |
| `heise-alerts`   | heise Security Alerts (Atom)  | reine Schwachstellen-/Advisory-Meldungen  |
| `heise-security` | heise Security (Atom)         | Security-News allgemein, wird gefiltert   |

## Nutzung

```bash
py -3 vulnfeed.py
```

Standard: alle drei Quellen, letzte 7 Tage, nur Meldungen mit Schwachstellenbezug.

```bash
py -3 vulnfeed.py --since 2 --limit 20
```

```bash
py -3 vulnfeed.py --source heise-alerts --format markdown > report.md
```

```bash
py -3 vulnfeed.py --cve-only --since 3
```

### Optionen

| Option              | Bedeutung                                                        |
| ------------------- | ---------------------------------------------------------------- |
| `-s, --source`      | Nur bestimmte Quelle(n), mehrfach angebbar (Default: alle)        |
| `-d, --since N`     | Nur Meldungen der letzten N Tage (`0` = alle im Feed), Default 7  |
| `-n, --limit N`     | Maximale Anzahl Meldungen (`0` = unbegrenzt)                      |
| `-f, --format`      | `table` (Default), `json` oder `markdown`                         |
| `--all`             | Themenfilter aus — auch Nicht-Schwachstellen-News                 |
| `--details`         | Artikelseiten nachladen, um CVE-Nummern zu ergänzen               |
| `--cve-only`        | Nur Meldungen mit CVE-Nummer (impliziert `--details`)             |
| `--detail-limit N`  | Höchstens N Artikelseiten nachladen (Default 25)                  |
| `--timeout N`       | HTTP-Timeout pro Feed in Sekunden (Default 20)                    |
| `-q, --quiet`       | Warnungen zu fehlgeschlagenen Feeds unterdrücken                  |

## Wie gefiltert wird

Die RSS/Atom-Feeds liefern nur Titel und Anrisstext. Ein Eintrag gilt als
Schwachstellen-Meldung, wenn einer dieser Punkte zutrifft:

1. Er stammt aus **heise Security Alerts** — dieser Feed enthält ausschließlich
   Advisories.
2. Titel oder Beschreibung enthalten eine CVE-Nummer.
3. Titel oder Beschreibung enthalten einen Begriff aus `VULN_TERMS`
   (`vulnerab`, `exploit`, `zero-day`, `Sicherheitslücke`, `Schwachstelle`, …).

Das ist eine Heuristik: gelegentlich rutscht ein Advertorial durch, und ein sehr
knapp betitelter Artikel kann rausfallen. Mit `--all` bekommst du den
ungefilterten Feed-Inhalt.

CVE-Nummern stehen fast nie im Feed selbst. `--details` bzw. `--cve-only` lädt
darum die Artikelseiten nach (4 parallele Requests, standardmäßig max. 25
Seiten) und extrahiert die IDs aus dem HTML.

## Hinweis zum User-Agent

BleepingComputer beantwortet den urllib-Standard-User-Agent mit `403` — einen
vorgetäuschten Browser-User-Agent übrigens ebenso, weil der Browser-Fingerprint
fehlt. Das Tool identifiziert sich deshalb ehrlich als `SecurityFeed/<version>`,
und genau damit liefert die Seite den Feed sauber aus.

## Exit-Codes

`0` bei Erfolg. Fällt eine einzelne Quelle aus, wird eine Warnung auf stderr
geschrieben und mit den übrigen Quellen weitergearbeitet.
