# SecurityFeed mit Docker Compose

Der Container läuft dauerhaft und startet seine Läufe selbst — täglich 07:00 und
18:00. Kein cron, kein systemd-Timer, kein Scheduler auf dem Host.

Wenn du es ohne Docker direkt auf dem Pi betreiben willst, nimm stattdessen
[RASPBERRY-PI.md](RASPBERRY-PI.md).

---

## Warum der Container einen eigenen Scheduler hat

SecurityFeed ist von Haus aus ein One-Shot-Programm: abrufen, mailen, beenden.
Genau das ist in Compose ein Problem — ein Container, dessen Prozess endet, gilt
als beendet, und `restart: unless-stopped` würde ihn in einer Endlosschleife neu
starten.

Deshalb gibt es `--schedule`. Damit bleibt der Prozess im Vordergrund, schläft
bis zur nächsten Uhrzeit und protokolliert jeden Lauf nach stdout, wo `docker
logs` ihn abholt. Ein Fehlschlag beendet den Dienst nicht — er wird geloggt, und
zur nächsten Zeit wird es erneut versucht.

---

## Was du vorher brauchst

**Docker auf dem Pi.** Prüfen:

```bash
docker compose version
```

Kommt eine Version, bist du fertig. Andernfalls folge der offiziellen Anleitung
für Debian/Raspberry Pi OS: <https://docs.docker.com/engine/install/debian/> —
du brauchst Docker Engine plus das Compose-Plugin.

**Die Zugangsdaten deines Mailservers.** Fünf Angaben, und falls du unsicher
bist, welcher Fall zutrifft:

| Situation | Port | `SECFEED_SMTP_SECURITY` | Anmeldung |
| --- | --- | --- | --- |
| Internes Relay im Firmen-/Heimnetz | `25` | `none` | keine |
| Provider mit STARTTLS (Standardfall) | `587` | `starttls` | ja |
| Provider mit implizitem TLS | `465` | `ssl` | ja |
| Microsoft 365 | `587` | `starttls` | ja, App-Passwort |
| Gmail | `587` | `starttls` | ja, App-Passwort |

> Bei Microsoft 365 und Gmail funktioniert dein normales Anmeldepasswort **nicht**.
> Beide verlangen ein eigens erzeugtes App-Passwort, und bei M365 muss die
> SMTP-Authentifizierung für das Postfach überhaupt erst freigeschaltet sein.
> Das klärst du im Admin-Portal, bevor du hier weitermachst.

---

## Schritt 1: Projekt auf den Pi bringen

Mit einem GitHub-Token auf dem Pi direkt klonen:

```bash
cd ~ && git clone https://github.com/zOnkxlMax/SecurityFeed.git securityfeed
```

Fragt Git nach Zugangsdaten, ist das Passwort der **Token**, nicht dein
Kontopasswort. Damit gehen spätere Updates per `git pull`.

<details>
<summary>Alternative ohne Git: per <code>scp</code> von Windows aus</summary>

```powershell
$src = "C:\Users\Max.Lang\OneDrive - DATAGROUP SE\Dokumente\VSC\SecurityFeed"
ssh pi@raspberrypi.local "mkdir -p ~/securityfeed"
scp "$src\vulnfeed.py" "$src\Dockerfile" "$src\compose.yaml" "$src\.env.example" pi@raspberrypi.local:~/securityfeed/
```

Updates musst du dann jedes Mal erneut per `scp` schieben.

</details>

---

## Schritt 2: Zugangsdaten eintragen — das musst du anpassen

```bash
cd ~/securityfeed
cp .env.example .env
chmod 600 .env
nano .env
```

`chmod 600` sorgt dafür, dass nur dein Benutzer das Passwort lesen kann.

Trage deine Werte ein:

```bash
SECFEED_SMTP_HOST=smtp.firma.de
SECFEED_SMTP_PORT=587
SECFEED_SMTP_SECURITY=starttls
SECFEED_SMTP_USER=feed@firma.de
SECFEED_SMTP_PASSWORD=dein-app-passwort
SECFEED_MAIL_FROM=feed@firma.de
SECFEED_MAIL_TO=max@firma.de
SECFEED_SUBJECT_PREFIX=[SecurityFeed]
```

**Internes Relay ohne Anmeldung?** `SECFEED_SMTP_USER` und
`SECFEED_SMTP_PASSWORD` auskommentieren. Ohne gesetzten Benutzer versucht das
Tool gar keine Anmeldung — genau das wollen offene Relays.

**Mehrere Empfänger?** Mit Komma trennen: `SECFEED_MAIL_TO=max@firma.de,soc@firma.de`

Die `.env` landet nie im Image — die `.dockerignore` lässt ausschließlich
`vulnfeed.py` in den Build-Kontext. Compose liest sie zur Laufzeit als
Umgebungsvariablen ein.

---

## Schritt 3: Zeitzone prüfen

In der `.env` steht `TZ=Europe/Berlin`. Der Zeitplan gilt in dieser Zeitzone.
Wenn du woanders sitzt, dort anpassen — sonst kommt die Morgenmail zur falschen
Stunde.

Alle anpassbaren Werte liegen bewusst in der `.env` und nicht in der
`compose.yaml`: die ist getrackt, und so kollidiert `git pull` später nicht mit
deinen lokalen Änderungen.

---

## Schritt 4: Bauen und testen, ohne Mail zu verschicken

Erst das Image bauen:

```bash
docker compose build
```

Dann ein Trockenlauf. `docker compose run --rm` startet einen Einweg-Container
mit abweichenden Argumenten, der Dauerbetrieb bleibt davon unberührt:

```bash
docker compose run --rm securityfeed --email --dry-run --since 2
```

Du solltest einen `Subject:`-Header, deine Adressen und darunter die Meldungen
sehen. Kommt `Mailversand nicht konfiguriert`, fehlt ein Wert in der `.env`.

Wenn das passt, ein **echter** Testversand:

```bash
docker compose run --rm securityfeed --email --since 2 --no-state
```

`--no-state` verhindert, dass dieser Test die Meldungen als „schon gemeldet"
markiert. Schau in dein Postfach, auch im Spam-Ordner — die erste Mail einer
neuen Absenderadresse landet gern dort.

Erst weitermachen, wenn diese Mail angekommen ist.

---

## Schritt 5: Dauerbetrieb starten

```bash
docker compose up -d
```

Das war es. Prüfen, ob der Scheduler seinen Plan kennt:

```bash
docker compose logs -f
```

Erwartete Ausgabe:

```
[2026-07-30 10:15:02 CEST] SecurityFeed 1.0.0 im Dauerbetrieb. Zeiten: 07:00, 18:00 (Zeitzone CEST)
[2026-07-30 10:15:02 CEST] Naechster Lauf 2026-07-30 18:00:00 CEST (in 7h 44min).
```

Steht dort `UTC` statt `CEST`, greift die `TZ`-Variable nicht — siehe
Fehlersuche unten.

---

## Zeiten ändern

In der `.env`, nicht in der `compose.yaml`:

```bash
SECFEED_SCHEDULE=07:00,18:00
```

| Wunsch | Wert |
| --- | --- |
| Früh und abends (Standard) | `07:00,18:00` |
| Nur morgens | `07:00` |
| Dreimal täglich | `07:00,13:00,18:00` |
| Alle vier Stunden | `00:00,04:00,08:00,12:00,16:00,20:00` |

Übernehmen:

```bash
docker compose up -d
```

Compose erkennt die geänderte Konfiguration und ersetzt den Container. Das
State-Volume bleibt erhalten, es kommen also keine Wiederholungen.

Anders als beim systemd-Timer gibt es hier **keine Wochentagsauswahl** — der
Zeitplan kennt nur Uhrzeiten. Brauchst du „nur werktags", nimm die
systemd-Variante aus [RASPBERRY-PI.md](RASPBERRY-PI.md).

---

## Weitere Optionen anpassen

Das Zeitfenster geht direkt über die `.env`:

```bash
SECFEED_SINCE=7
```

Für alles Weitere leg eine `compose.override.yaml` neben die `compose.yaml`.
Compose führt beide automatisch zusammen, und die Override-Datei ist per
`.gitignore` ausgeschlossen — `git pull` bleibt damit konfliktfrei:

```yaml
services:
  securityfeed:
    command:
      - --email
      - --since
      - "2"
      - --cve-only
      - --limit
      - "10"
```

`command` wird dabei komplett ersetzt, nicht ergänzt — liste also alle
gewünschten Argumente auf.

| Wunsch | Argumente |
| --- | --- |
| Nur deutsche Advisories | `--source`, `heise-alerts` |
| Nur Meldungen mit CVE-Nummer | `--cve-only` statt `--details` |
| Schneller, ohne CVE-Nummern | `--details` weglassen |
| Höchstens 10 Meldungen pro Mail | `--limit`, `"10"` |
| Auch „nichts los"-Mails | `--send-empty` |
| Beim Start sofort einmal laufen | `--run-at-start` |

Zahlen müssen in YAML als Zeichenkette in Anführungszeichen stehen, sonst
beschwert sich Compose über den Typ. Danach `docker compose up -d`.

Prüfen, was Compose aus beiden Dateien zusammensetzt:

```bash
docker compose config
```

---

## Betrieb

| Zweck | Befehl |
| --- | --- |
| Logs live mitlesen | `docker compose logs -f` |
| Letzte 50 Zeilen | `docker compose logs --tail 50` |
| Läuft der Container? | `docker compose ps` |
| Lauf sofort auslösen | `docker compose run --rm securityfeed --email --since 2` |
| Neu starten | `docker compose restart` |
| Stoppen | `docker compose down` |
| Stoppen samt Zustand | `docker compose down -v` |

`docker compose down -v` löscht das State-Volume. Der nächste Lauf hält dann
alles für neu und schickt eine entsprechend lange Mail.

---

## Wie Wiederholungen verhindert werden

Zwei Dinge greifen ineinander:

**`--since 2`** begrenzt, wie weit zurück geschaut wird — hier zwei Tage. Das ist
der Puffer, falls ein Lauf ausfällt.

**Das State-Volume** merkt sich jeden gemeldeten Link (die letzten 2000).
Deshalb enthält die Abendmail nur, was seit dem Morgen dazugekommen ist, obwohl
das Zeitfenster zwei Tage umfasst.

Gab es nichts Neues, wird **keine** Mail verschickt. Gespeichert wird erst nach
erfolgreichem Versand — ist das Relay morgens kurz weg, kommen die Meldungen
abends mit.

---

## Aktualisieren

```bash
cd ~/securityfeed && git pull && docker compose up -d --build
```

Deine `.env` und eine etwaige `compose.override.yaml` bleiben unangetastet, beide
sind per `.gitignore` ausgeschlossen. Das State-Volume bleibt ebenfalls erhalten,
es kommen also keine Wiederholungen.

---

## Wenn etwas nicht klappt

| Symptom | Ursache und Lösung |
| --- | --- |
| `Mailversand nicht konfiguriert` | Wert fehlt in `.env`. Die Meldung nennt welchen. |
| Container startet immer neu | `SECFEED_SCHEDULE` fehlt oder ist leer. Ohne Zeitplan endet der Prozess nach einem Lauf und `restart: unless-stopped` startet ihn erneut. Prüfen mit `docker compose config`. |
| Log zeigt `UTC` statt `CEST` | `TZ` in `compose.yaml` nicht gesetzt, oder das Image wurde ohne `tzdata` gebaut. Neu bauen mit `docker compose build --no-cache`. |
| `env file .env not found` | Schritt 2 vergessen: `cp .env.example .env` |
| `Connection refused` | Falscher Port oder Relay nicht erreichbar. Test aus dem Container: `docker compose run --rm --entrypoint sh securityfeed -c "python3 -c \"import socket;socket.create_connection(('smtp.firma.de',587),10)\""` |
| `authentication failed` | App-Passwort nötig, nicht das Anmeldepasswort. Bei M365 zusätzlich SMTP-AUTH freischalten. |
| `STARTTLS extension not supported` | Relay will kein STARTTLS. Auf `none` (Port 25) oder `ssl` (465) wechseln. |
| `relay access denied` | Das Relay akzeptiert deine `SECFEED_MAIL_FROM`-Adresse nicht. |
| Keine Mail, aber Log sagt „Lauf beendet" | Meist nichts Neues. Im Log steht dann `Nichts Neues - keine Mail verschickt.` |
| `Read-only file system` | Etwas will außerhalb des State-Volumes schreiben. Zum Eingrenzen `read_only: true` in der `compose.yaml` vorübergehend entfernen und den Fehler melden. |
| `Permission denied` auf seen.json | Tritt bei einem Bind-Mount statt des Named Volumes auf. Dann auf dem Host `sudo chown -R 10001:10001 <verzeichnis>`. |

Was Compose aus deiner Konfiguration wirklich macht, inklusive aller
eingesetzten Variablen:

```bash
docker compose config
```

Die Exit-Codes im Log bedeuten: `0` alles gut, `1` harter Fehler (keine Quelle
erreichbar oder Versand gescheitert), `2` Konfigurationsfehler, `3` Lauf
erfolgreich, aber eine einzelne Quelle war nicht erreichbar.
