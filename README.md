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

### Mailversand

| Option              | Umgebungsvariable          | Bedeutung                             |
| ------------------- | -------------------------- | ------------------------------------- |
| `--email`           | —                          | Ergebnis per Mail verschicken          |
| `--env-file DATEI`  | —                          | `KEY=VALUE`-Datei laden (für cron)     |
| `--smtp-host`       | `SECFEED_SMTP_HOST`        | Relay-Hostname                         |
| `--smtp-port`       | `SECFEED_SMTP_PORT`        | Default 25/587/465 je nach Security    |
| `--smtp-security`   | `SECFEED_SMTP_SECURITY`    | `none`, `starttls` (Default), `ssl`    |
| `--smtp-user`       | `SECFEED_SMTP_USER`        | Leer lassen → kein LOGIN-Versuch       |
| —                   | `SECFEED_SMTP_PASSWORD`    | Nur als Env-Variable, nie als Argument |
| `--mail-from`       | `SECFEED_MAIL_FROM`        | Absenderadresse                        |
| `--mail-to`         | `SECFEED_MAIL_TO`          | Empfänger, mehrere per Komma           |
| `--subject-prefix`  | `SECFEED_SUBJECT_PREFIX`   | Default `[SecurityFeed]`               |
| `--send-empty`      | —                          | Auch mailen, wenn nichts Neues da ist  |
| `--dry-run`         | —                          | Mail ausgeben statt verschicken        |

### Dauerbetrieb

| Option              | Umgebungsvariable     | Bedeutung                                  |
| ------------------- | --------------------- | ------------------------------------------ |
| `--schedule`        | `SECFEED_SCHEDULE`    | `07:00,18:00` — läuft dann selbst zu diesen Zeiten |
| `--run-at-start`    | —                     | Zusätzlich sofort beim Start einmal laufen  |

Mit `--schedule` bleibt der Prozess im Vordergrund, schläft bis zur nächsten
Uhrzeit und protokolliert jeden Lauf mit Zeitstempel nach stdout. Ein Fehlschlag
beendet ihn nicht — er wird geloggt, und zur nächsten Zeit geht es weiter.
`SIGTERM` und `SIGINT` beenden sauber, `docker stop` funktioniert also ohne
Wartezeit. Ohne `--schedule` verhält sich das Tool wie bisher: ein Lauf, dann
Ende.

Das Passwort gibt es bewusst **nur** als Umgebungsvariable — als CLI-Argument
stünde es in der Prozessliste und in der Shell-History.

Die Mail geht als `multipart/alternative` raus: HTML mit anklickbaren Titeln und
CVE-Badges, dazu die Tabellenansicht als Plaintext-Alternative.

Erst testen, ohne etwas zu verschicken:

```bash
python3 vulnfeed.py --email --dry-run --smtp-host relay.intern.example --mail-from pi@example.com --mail-to max@example.com
```

### Zustand

Bei geplanten Läufen merkt sich das Tool, was schon gemeldet wurde — sonst käme
jeden Morgen dieselbe Liste. Default ist
`~/.local/state/securityfeed/seen.json` (bzw. `$SECFEED_STATE`), gespeichert
werden die letzten 2000 Links.

| Option           | Bedeutung                                          |
| ---------------- | -------------------------------------------------- |
| `--state DATEI`  | Abweichender Pfad                                   |
| `--no-state`     | Zustand ignorieren, immer alles ausgeben            |
| `--reset-state`  | Zustand vor dem Lauf leeren                         |

Gespeichert wird erst **nach** erfolgreichem Versand. Scheitert das Relay, bleibt
der Zustand unverändert und der nächste Lauf holt die Meldungen nach. `--dry-run`
schreibt den Zustand nie.

## Geplanter Betrieb

Zwei Wege, je nachdem was auf deinem Pi läuft:

| | Docker Compose | systemd-Timer |
| --- | --- | --- |
| Anleitung | [docs/DOCKER.md](docs/DOCKER.md) | [docs/RASPBERRY-PI.md](docs/RASPBERRY-PI.md) |
| Scheduler | im Container (`--schedule`) | systemd |
| Einrichtung | `.env` ausfüllen, `docker compose up -d` | User, env-Datei, Unit-Dateien |
| Wochentagsauswahl | nein, nur Uhrzeiten | ja (`OnCalendar=Mon..Fri`) |
| Voraussetzung | Docker | nichts, Python ist vorinstalliert |

Beide erledigen dasselbe. Nimm Docker, wenn auf dem Pi ohnehin Container laufen,
sonst den systemd-Timer.

**Nur die Befehle zum Einfügen in die SSH-Konsole des Pi:
[docs/PI-SSH-QUICKSTART.md](docs/PI-SSH-QUICKSTART.md)**

### Docker Compose in drei Befehlen

```bash
cp .env.example .env && nano .env
```

```bash
docker compose run --rm securityfeed --email --dry-run --since 2
```

```bash
docker compose up -d
```

Details, Zeitanpassung und Fehlersuche in [docs/DOCKER.md](docs/DOCKER.md).

## Auf dem Raspberry Pi ohne Docker einrichten

**➜ Ausführliche Schritt-für-Schritt-Anleitung: [docs/RASPBERRY-PI.md](docs/RASPBERRY-PI.md)**

Dort steht alles von der Zeitzone über die SMTP-Konfiguration bis zur
Fehlersuche. Die Kurzfassung für Ungeduldige:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin securityfeed
sudo install -d -m 0755 /opt/securityfeed
sudo install -m 0755 vulnfeed.py /opt/securityfeed/vulnfeed.py
sudo install -d -m 0750 -o root -g securityfeed /etc/securityfeed
sudo install -m 0640 -o root -g securityfeed deploy/securityfeed.env.example /etc/securityfeed/securityfeed.env
sudo nano /etc/securityfeed/securityfeed.env
```

Testen, ohne zu verschicken:

```bash
sudo -u securityfeed python3 /opt/securityfeed/vulnfeed.py --env-file /etc/securityfeed/securityfeed.env --email --dry-run --since 2
```

Timer aktivieren:

```bash
sudo install -m 0644 deploy/securityfeed.service deploy/securityfeed.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now securityfeed.timer
```

Voreingestellt sind täglich 07:00 und 18:00 mit bis zu 5 Minuten zufälliger
Verzögerung. `Persistent=true` holt einen Lauf nach, wenn der Pi zum Zeitpunkt
aus war.

### Alternative: cron

Wenn du lieber bei cron bleibst — cron kennt kein `EnvironmentFile`, dafür gibt
es `--env-file`:

```cron
0 7 * * 1-5 securityfeed /usr/bin/python3 /opt/securityfeed/vulnfeed.py --email --env-file /etc/securityfeed/securityfeed.env --since 2 --details --quiet
```

`--quiet` ist hier wichtig: sonst schickt cron dir bei jedem nicht erreichbaren
Feed zusätzlich eine eigene Mail.

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

| Code | Bedeutung                                                            |
| ---- | -------------------------------------------------------------------- |
| `0`  | Erfolg                                                                |
| `1`  | Harter Fehler — keine Quelle erreichbar oder Mailversand gescheitert   |
| `2`  | Konfigurationsfehler (fehlender Relay, ungültiger Port, …)             |
| `3`  | Lauf erfolgreich, aber einzelne Quelle nicht erreichbar               |

Code `3` ist in der systemd-Unit als `SuccessExitStatus` eingetragen — ein
einzelner zickiger Feed soll den Timer nicht auf `failed` setzen. Wer das
strenger will, nimmt die Zeile raus.
