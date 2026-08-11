# SecurityFeed

CLI-Tool, das die neuesten Schwachstellen- und Security-Meldungen von
**BleepingComputer** und **heise.de** einsammelt, zusammenführt und als Tabelle,
JSON oder Markdown ausgibt.

Reines Python 3.10+ aus der Standardbibliothek — keine Abhängigkeiten, kein
`pip install`.

## Quellen

| Key              | Quelle                        | Inhalt                                   |
| ---------------- | ----------------------------- | ---------------------------------------- |
| `bleeping`       | BleepingComputer (RSS 2.0)    | Security-News allgemein, wird gefiltert   |
| `heise-alerts`   | heise Security Alerts (Atom)  | reine Schwachstellen-/Advisory-Meldungen  |
| `heise-security` | heise Security (Atom)         | Security-News allgemein, wird gefiltert   |
| `hackernews`     | Hacker News (Algolia-API)     | Diskutierte Security-Themen ab 50 Punkten |
| `local`          | OSV-Datenbank + `dpkg`        | Verwundbare Pakete **auf diesem System** — nur mit `--local` |

Hacker News läuft anders als die übrigen Quellen. Der Frontpage-Feed taugt
dafür nicht — dort steht meist nichts Sicherheitsrelevantes. Stattdessen wird
die [Algolia-Such-API](https://hn.algolia.com/api) nach `vulnerability` und
`security` abgefragt, beschränkt auf Stories mit mindestens 50 Punkten.

Diese beiden Kriterien **sind** hier der Filter, `VULN_TERMS` wird auf
HN-Einträge nicht angewandt. Grund: die Stichwortliste ist auf heise- und
BleepingComputer-Formulierungen getrimmt und ließe Überschriften wie „Bugtraq is
back" oder „My security camera shipped a GitHub admin token in its login page"
durchfallen. Der Preis dafür ist gelegentliches Rauschen — HN-Einträge sind
Community-Diskussionen, keine Advisories.

Einträge ohne eigene URL (Ask HN, Tell HN) verlinken auf ihre Diskussion, alle
anderen auf den Artikel; die Diskussion steht dann in der Beschreibung.

## Nutzung

```bash
py -3 vulnfeed.py
```

Standard: alle vier Nachrichtenquellen, letzte 7 Tage, nur Meldungen mit
Schwachstellenbezug. Der Paketscan bleibt außen vor, bis du ihn mit `--local`
dazuschaltest.

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
| `-s, --source`      | Nur bestimmte Quelle(n), mehrfach angebbar (Default: alle Nachrichtenquellen) |
| `-d, --since N`     | Nur Meldungen der letzten N Tage (`0` = alle im Feed), Default 7  |
| `-n, --limit N`     | Maximale Anzahl Meldungen (`0` = unbegrenzt)                      |
| `-f, --format`      | `table` (Default), `json` oder `markdown`                         |
| `--all`             | Themenfilter aus — auch Nicht-Schwachstellen-News                 |
| `--details`         | Artikelseiten nachladen, um CVE-Nummern zu ergänzen               |
| `--cve-only`        | Nur Meldungen mit CVE-Nummer (impliziert `--details`)             |
| `--detail-limit N`  | Höchstens N Artikelseiten nachladen (Default 25)                  |
| `--timeout N`       | HTTP-Timeout pro Feed in Sekunden (Default 20)                    |
| `-q, --quiet`       | Warnungen zu fehlgeschlagenen Feeds unterdrücken                  |

### Paketscan

| Option              | Umgebungsvariable        | Bedeutung                              |
| ------------------- | ------------------------ | -------------------------------------- |
| `--local`           | `SECFEED_LOCAL`          | Scan zusätzlich zu den News laufen lassen |
| `--dpkg-status`     | `SECFEED_DPKG_STATUS`    | Statusdatei lesen statt `dpkg-query` aufzurufen |
| `--debian-release`  | `SECFEED_DEBIAN_RELEASE` | Debian-Hauptversion erzwingen, z. B. `12` |
| `--local-unfixed`   | `SECFEED_LOCAL_UNFIXED`  | Auch Lücken ohne verfügbares Update melden |

Siehe Abschnitt [Paketscan](#paketscan-was-steckt-hier-drin) weiter unten.

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
| `--send-empty`      | `SECFEED_SEND_EMPTY`       | Auch mailen, wenn nichts Neues da ist — als Lebenszeichen |
| `--dry-run`         | —                          | Mail ausgeben statt verschicken        |

### Dauerbetrieb

| Option              | Umgebungsvariable     | Bedeutung                                  |
| ------------------- | --------------------- | ------------------------------------------ |
| `--schedule`        | `SECFEED_SCHEDULE`    | `07:00,18:00` — läuft dann selbst zu diesen Zeiten |
| `--run-at-start`    | —                     | Zusätzlich sofort beim Start einmal laufen  |
| `--once`            | —                     | Einzellauf erzwingen, auch wenn `SECFEED_SCHEDULE` gesetzt ist |

`--once` brauchst du bei `docker compose run`: der Aufruf erbt die
Service-Umgebung und damit `SECFEED_SCHEDULE`, würde also sonst in den
Dauerbetrieb gehen statt einmal zu laufen. `--dry-run` impliziert `--once`.

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

## Paketscan: was steckt hier drin?

Die vier Nachrichtenquellen sagen, *was* in der Welt kaputt ist. Der Paketscan
beantwortet die Anschlussfrage: *betrifft mich das?* Er liest die installierten
Pakete, hält sie gegen die [OSV-Datenbank](https://osv.dev) und meldet, was
davon in einer verwundbaren Version vorliegt.

```bash
python3 vulnfeed.py --source local --since 0
```

Zusammen mit den News — so ist es im Dauerbetrieb gedacht:

```bash
python3 vulnfeed.py --local --since 2 --details
```

Meldungen, deren CVE hier tatsächlich installiert ist, tragen dann in Mail und
Ausgabe den Hinweis **„Betrifft dieses System"**, und der Betreff nennt die Zahl
vorweg. Das ist der eigentliche Zweck der Übung.

### Wie die Bewertung zustande kommt

Jedes Paket wird zweimal abgefragt: einmal mit der installierten Version, einmal
mit einer absurd hohen. Die zweite Antwort sind genau die Lücken, gegen die es in
dieser Debian-Version noch **keinen** Fix gibt — die treffen jede Version. Zieht
man sie von der ersten ab, bleibt übrig, was ein `apt upgrade` tatsächlich
schließt. Das entspricht `debsecan --only-fixed`, kostet aber keine zusätzliche
Software auf dem Pi.

Ein gepflegtes System meldet deshalb fast nichts. `openssl 3.0.11` liefert 41
Treffer, davon 39 behebbar; die aktuelle Version liefert 2 — beide ohne Fix und
damit stumm, solange du nicht `--local-unfixed` setzt.

### Grenzen

Drei Dinge, die der Scan **nicht** leistet:

- **Raspberry-Pi-eigene Pakete kennt er nicht.** `raspberrypi-kernel`,
  `raspberrypi-bootloader` und die Firmware-Pakete aus dem RPi-Repo stehen nicht
  in der Debian-Datenbank und kommen als „unauffällig" zurück, obwohl sie nie
  geprüft wurden. Für den Kernel bleibt `sudo apt list --upgradable`.
- **Nur Debian.** Auf einem Abkömmling mit eigener `ID` in `/etc/os-release`
  verweigert er den Dienst, statt gegen die falsche Datenbank zu prüfen. Mit
  `--debian-release` lässt sich das überstimmen, wenn du weißt, was du tust.
- **Nur Systempakete.** Was per `pip`, `npm` oder `docker` danebenliegt, taucht
  in `dpkg` nicht auf. Dafür sind `pip-audit` bzw. `osv-scanner` zuständig.

Und eine Eigenheit, die man kennen sollte: die Markierung **„Betrifft dieses
System"** hinkt den Nachrichten hinterher. Meldet heise eine frische Lücke,
steht deren CVE-Nummer oft erst Stunden bis Tage später in der Debian-Datenbank
— bis dahin bleibt die Meldung unmarkiert, obwohl das Paket installiert ist.
Umgekehrt gibt es keine Fehlalarme: markiert wird nur, was nachweislich in einer
betroffenen Version hier liegt.

Außerdem: der Scan schickt die Liste deiner installierten Pakete samt Versionen
an `api.osv.dev`. Das ist für einen Abgleich unvermeidlich, aber es ist eine
Aussage über dein System an einen Dritten — deshalb ist der Scan standardmäßig
aus und muss mit `--local` bzw. `SECFEED_LOCAL=1` eingeschaltet werden.

### Im Container

Dort gibt es kein `dpkg` des Hosts. Die Statusdatei read-only einhängen und
darauf zeigen — Details in [docs/DOCKER.md](docs/DOCKER.md):

```bash
docker compose run --rm -v /var/lib/dpkg/status:/host/dpkg-status:ro securityfeed --once -s local --dpkg-status /host/dpkg-status --since 0
```

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

1. Er stammt aus **heise Security Alerts** oder **Hacker News** — dort filtert
   bereits die Quelle selbst (reiner Advisory-Feed bzw. Suchbegriff plus
   Punkteschwelle).
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
