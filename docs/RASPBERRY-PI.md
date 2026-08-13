# SecurityFeed auf dem Raspberry Pi: früh und abends eine Mail

Schritt-für-Schritt-Anleitung. Am Ende schickt dir der Pi täglich um 07:00 und
18:00 eine Mail mit den neuen Schwachstellen-Meldungen — ohne Wiederholungen,
weil sich das Tool merkt, was es schon gemeldet hat.

Rechne mit 15–20 Minuten.

---

## Was du vorher brauchst

**Auf dem Pi:** Raspberry Pi OS Bookworm oder neuer. Python 3.11 ist dort
vorinstalliert, weitere Pakete braucht es nicht. Prüfen:

```bash
python3 --version
```

Alles ab 3.10 ist in Ordnung.

**Von deinem Mailserver** — das ist der Teil, den nur du beschaffen kannst.
Leg dir diese fünf Angaben bereit:

| Angabe | Beispiel | Woher |
| --- | --- | --- |
| Relay-Hostname | `smtp.firma.de` | IT / Mailprovider |
| Port | `587` | siehe Tabelle unten |
| Verschlüsselung | `starttls` | siehe Tabelle unten |
| Benutzer + Passwort | `feed@firma.de` | entfällt bei internem Relay |
| Absenderadresse | `pi@firma.de` | muss das Relay akzeptieren |

Falls du unsicher bist, welcher Fall bei dir zutrifft:

| Situation | Port | `SECFEED_SMTP_SECURITY` | Anmeldung |
| --- | --- | --- | --- |
| Internes Relay im Firmen-/Heimnetz | `25` | `none` | keine |
| Provider mit STARTTLS (Standardfall) | `587` | `starttls` | ja |
| Provider mit implizitem TLS | `465` | `ssl` | ja |
| Microsoft 365 | `587` | `starttls` | ja, App-Passwort |
| Gmail | `587` | `starttls` | ja, App-Passwort |

> Bei Microsoft 365 und Gmail funktioniert dein normales Anmeldepasswort **nicht**.
> Beide verlangen ein separat erzeugtes App-Passwort, und bei M365 muss die
> SMTP-Authentifizierung für das Postfach überhaupt erst freigeschaltet sein —
> sie ist bei neuen Tenants standardmäßig aus. Das klärst du im jeweiligen
> Admin-Portal, bevor du hier weitermachst.

---

## Schritt 1: Zeitzone des Pi prüfen

Der Timer feuert in der **lokalen** Zeit des Pi. Steht der auf UTC, kommt die
„Morgenmail" im Sommer um 09:00.

```bash
timedatectl
```

Steht dort nicht `Europe/Berlin`, korrigieren:

```bash
sudo timedatectl set-timezone Europe/Berlin
```

---

## Schritt 2: Programm auf den Pi kopieren

Mit dem GitHub-Token auf dem Pi klonen:

```bash
cd ~ && git clone https://github.com/zOnkxlMax/SecurityFeed.git securityfeed
```

Fragt Git nach Zugangsdaten, ist das Passwort der **Token**, nicht dein
Kontopasswort. Die folgenden Befehle nutzen `~/securityfeed` als Quelle.

<details>
<summary>Alternative ohne Git: per <code>scp</code> von Windows aus</summary>

```powershell
$src = "C:\Users\Max.Lang\OneDrive - DATAGROUP SE\Dokumente\VSC\SecurityFeed"
scp "$src\vulnfeed.py" pi@raspberrypi.local:/tmp/
scp "$src\deploy\*" pi@raspberrypi.local:/tmp/
```

Dann in den folgenden Befehlen `~/securityfeed` und `~/securityfeed/deploy`
jeweils durch `/tmp` ersetzen.

</details>

Jetzt an den endgültigen Platz legen:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin securityfeed
sudo install -d -m 0755 /opt/securityfeed
sudo install -m 0755 ~/securityfeed/vulnfeed.py /opt/securityfeed/vulnfeed.py
```

Der eigene Systembenutzer sorgt dafür, dass der Dienst nicht als `root` läuft
und nur an sein eigenes Zustandsverzeichnis kommt.

---

## Schritt 3: Zugangsdaten eintragen — das musst du anpassen

Vorlage kopieren:

```bash
sudo install -d -m 0750 -o root -g securityfeed /etc/securityfeed
sudo install -m 0640 -o root -g securityfeed ~/securityfeed/deploy/securityfeed.env.example /etc/securityfeed/securityfeed.env
sudo nano /etc/securityfeed/securityfeed.env
```

Die Rechte `0640 root:securityfeed` bedeuten: root darf schreiben, der Dienst
darf lesen, alle anderen Benutzer auf dem Pi kommen nicht an das Passwort.

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

**Hast du ein internes Relay ohne Anmeldung?** Dann `SECFEED_SMTP_USER` und
`SECFEED_SMTP_PASSWORD` auskommentiert lassen. Ohne gesetzten Benutzer versucht
das Tool gar keine Anmeldung — genau das wollen offene Relays.

**Mehrere Empfänger?** Mit Komma trennen:

```bash
SECFEED_MAIL_TO=max@firma.de,security@firma.de
```

---

## Schritt 4: Testen, ohne etwas zu verschicken

Erst der Trockenlauf. Er baut die komplette Mail und gibt sie aus, verschickt
aber nichts und fasst den Zustand nicht an:

```bash
sudo -u securityfeed python3 /opt/securityfeed/vulnfeed.py --env-file /etc/securityfeed/securityfeed.env --email --dry-run --since 2
```

Du solltest einen `Subject:`-Header, deine Adressen und darunter die Meldungen
sehen. Kommt stattdessen `Mailversand nicht konfiguriert`, fehlt ein Wert in der
env-Datei. Kommt `Permission denied`, stimmen die Rechte aus Schritt 3 nicht.

Wenn das passt, ein **echter** Testversand:

```bash
sudo -u securityfeed python3 /opt/securityfeed/vulnfeed.py --env-file /etc/securityfeed/securityfeed.env --email --since 2 --no-state
```

`--no-state` sorgt dafür, dass dieser Test nichts als „schon gemeldet" markiert.
Schau in dein Postfach — inklusive Spam-Ordner, die erste Mail von einer neuen
Absenderadresse landet gern dort.

Erst weitermachen, wenn diese Mail angekommen ist.

---

## Schritt 5: Zeitplan einrichten

```bash
sudo install -m 0644 ~/securityfeed/deploy/securityfeed.service ~/securityfeed/deploy/securityfeed.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now securityfeed.timer
```

Fertig. Voreingestellt sind **täglich 07:00 und 18:00**.

### Zeiten ändern

```bash
sudo systemctl edit --full securityfeed.timer
```

Die `OnCalendar`-Zeilen addieren sich, du kannst also beliebig viele angeben:

| Wunsch | Zeilen |
| --- | --- |
| Früh und abends (Standard) | `OnCalendar=*-*-* 07:00:00`<br>`OnCalendar=*-*-* 18:00:00` |
| Nur werktags | `OnCalendar=Mon..Fri 07:00`<br>`OnCalendar=Mon..Fri 18:00` |
| Nur einmal morgens | `OnCalendar=*-*-* 07:00:00` |
| Stündlich | `OnCalendar=hourly` |

Danach immer:

```bash
sudo systemctl daemon-reload && sudo systemctl restart securityfeed.timer
```

Ob deine Zeitangabe stimmt, verrät dir systemd vorab:

```bash
systemd-analyze calendar "*-*-* 07:00:00" --iterations 3
```

### Zwei Einstellungen, die du kennen solltest

`RandomizedDelaySec=300` in der Timer-Datei verzögert den Start um bis zu fünf
Minuten. Die Mail kommt also zwischen 07:00 und 07:05 — gewollt, damit nicht
alle Installationen gleichzeitig auf die Feeds losgehen. Wer es auf die Minute
genau will, setzt den Wert auf `0`.

`Persistent=true` holt einen verpassten Lauf nach, sobald der Pi wieder läuft.
War er über Nacht aus, bekommst du die Morgenmail beim Hochfahren.

---

## Schritt 6: Kontrollieren

Wann läuft es das nächste Mal?

```bash
systemctl list-timers securityfeed.timer
```

Einen Lauf sofort auslösen, ohne auf 07:00 zu warten:

```bash
sudo systemctl start securityfeed.service
```

Was ist beim letzten Lauf passiert?

```bash
journalctl -u securityfeed.service -n 30 --no-pager
```

---

## Wie das mit den Wiederholungen funktioniert

Zwei Mechanismen greifen ineinander, und es hilft, den Unterschied zu kennen:

**`--since 2`** begrenzt, wie weit zurück überhaupt geschaut wird — hier zwei
Tage. Das ist der Puffer, falls ein Lauf ausfällt.

**Der Zustand** in `/var/lib/securityfeed/seen.json` merkt sich jeden bereits
gemeldeten Link (die letzten 2000). Deshalb bekommst du abends nur, was seit dem
Morgen dazugekommen ist, obwohl das Zeitfenster zwei Tage umfasst.

Gab es nichts Neues, verschickt der Lauf **keine** Mail. Willst du stattdessen
eine „nichts los"-Meldung, hänge `--send-empty` in der Service-Datei an.

Gespeichert wird erst **nach** erfolgreichem Versand. Ist dein Relay morgens
kurz weg, gehen die Meldungen nicht verloren — sie kommen abends mit.

---

## Was du sonst noch anpassen kannst

Alles in der `ExecStart`-Zeile, erreichbar über:

```bash
sudo systemctl edit --full securityfeed.service
```

| Wunsch | Änderung |
| --- | --- |
| Nur deutsche Advisories | `--source heise-alerts` ergänzen |
| Nur Meldungen mit CVE-Nummer | `--details` durch `--cve-only` ersetzen |
| Schneller, ohne CVE-Nummern | `--details` streichen |
| Größeres Zeitfenster | `--since 2` auf `--since 7` |
| Höchstens 10 Meldungen pro Mail | `--limit 10` ergänzen |
| Auch Nicht-Schwachstellen-News | `--all` ergänzen |
| Auch die Pakete des Pi prüfen | siehe nächster Abschnitt — ohne Unit-Änderung |

Nach jeder Änderung:

```bash
sudo systemctl daemon-reload
```

---

## Paketscan: die eigenen Pakete prüfen

Zusätzlich zu den Nachrichtenquellen kann das Tool die installierten Pakete
gegen die OSV-Datenbank halten und melden, was davon in einer verwundbaren
Version vorliegt. Meldungen, die diesen Pi wirklich betreffen, sind in der Mail
dann eigens markiert.

Erst ansehen, was dabei herauskommt:

```bash
sudo -u securityfeed python3 /opt/securityfeed/vulnfeed.py --source local --since 0 --no-state
```

Auf einem gepflegten Pi kommt hier wenig bis nichts zurück — das ist das
erwartete Ergebnis, kein Fehler. Wenn du damit zufrieden bist, dauerhaft
einschalten. Die Unit-Datei bleibt dabei unverändert, es reicht eine Zeile in
der env-Datei:

```bash
sudo nano /etc/securityfeed/securityfeed.env
```

```bash
SECFEED_LOCAL=1
```

Fertig — beim nächsten Timer-Lauf ist der Scan dabei. `dpkg-query` ist auf dem
Pi ohnehin installiert, und die Härtung der Unit steht dem nicht im Weg: sie
macht das Dateisystem nur schreibgeschützt, lesen darf der Dienst.

Zwei Dinge, die du wissen solltest:

- Der Scan schickt die Liste deiner installierten Pakete samt Versionen an
  `api.osv.dev`. Deshalb ist er standardmäßig aus.
- Pakete aus dem Raspberry-Pi-Repo (`raspberrypi-kernel`, `raspberrypi-bootloader`,
  Firmware) stehen nicht in der Debian-Datenbank und werden stillschweigend
  übergangen. Für den Kernel bleibt:

```bash
sudo apt update && apt list --upgradable
```

### Auch die Docker-Container prüfen

Falls auf dem Pi zusätzlich Container laufen: ein Skript legt stündlich die
Paketliste jedes laufenden Containers ab, SecurityFeed liest sie nur lesend.
Bewusst getrennt — den Docker-Socket bekommt SecurityFeed nicht, wer ihn hat,
ist faktisch root auf dem Pi.

```bash
sudo install -m 0755 deploy/dump-container-packages.sh /opt/securityfeed/
sudo install -m 0644 deploy/securityfeed-containers.service deploy/securityfeed-containers.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now securityfeed-containers.timer
```

Einmal von Hand laufen lassen und ansehen, was er einsammelt:

```bash
sudo systemctl start securityfeed-containers.service && ls -R /var/lib/securityfeed/containers
```

Dann in der env-Datei ergänzen:

```bash
SECFEED_CONTAINER_LISTS=/var/lib/securityfeed/containers
```

Jeder Fund nennt danach seine Herkunft — „Lokales System" oder „Container
nextcloud". Debian- und Alpine-Container werden beide geprüft, jeder gegen
seine eigene Distributionsversion. Container ohne Paketdatenbank (distroless,
scratch) erscheinen ausdrücklich
als „nicht prüfbar", und bleibt der Timer stehen, meldet SecurityFeed die
veralteten Listen von sich aus. Behoben werden Container-Funde nicht per `apt`,
sondern über ein neues Image.

Ausführlich zur Funktionsweise und zu den Grenzen: Abschnitt „Paketscan" in der
[README](../README.md#paketscan-was-steckt-hier-drin).

---

## Wenn etwas nicht klappt

| Symptom | Ursache und Lösung |
| --- | --- |
| `Mailversand nicht konfiguriert` | Wert fehlt in der env-Datei. Die Meldung listet auf, welcher. |
| `Connection refused` | Falscher Port oder Relay nicht erreichbar. Test: `nc -vz smtp.firma.de 587` |
| `authentication failed` | Bei M365/Gmail ein App-Passwort nötig, nicht das Anmeldepasswort. Bei M365 zusätzlich SMTP-AUTH fürs Postfach freischalten. |
| `STARTTLS extension not supported` | Relay will kein STARTTLS. Auf `none` (Port 25) oder `ssl` (Port 465) wechseln. |
| `relay access denied` | Das Relay akzeptiert deine `SECFEED_MAIL_FROM`-Adresse nicht. Absender auf eine erlaubte Domain ändern. |
| Timer läuft, aber keine Mail | Meist schlicht: nichts Neues. Prüfen mit `journalctl -u securityfeed.service -n 20` |
| Mail kommt zur falschen Zeit | Zeitzone des Pi, siehe Schritt 1. |
| Erste Mail nie angekommen | Spam-Ordner prüfen, dann `journalctl` lesen. |
| Timer taucht nicht auf | `sudo systemctl enable --now securityfeed.timer` vergessen. |

Detaillierter Blick auf den letzten Lauf, inklusive Exit-Code:

```bash
systemctl status securityfeed.service
```

Die Exit-Codes bedeuten: `0` alles gut, `1` harter Fehler (keine Quelle
erreichbar oder Versand gescheitert), `2` Konfigurationsfehler, `3` Lauf
erfolgreich, aber eine einzelne Quelle war nicht erreichbar.

---

## Später aktualisieren

```bash
cd ~/securityfeed && git pull
```

```bash
sudo install -m 0755 ~/securityfeed/vulnfeed.py /opt/securityfeed/vulnfeed.py
```

Deine Konfiguration liegt in `/etc/securityfeed/securityfeed.env`, also außerhalb
des Repos — `git pull` fasst sie nicht an.

Ein Neustart des Timers ist nicht nötig — der nächste Lauf nimmt automatisch die
neue Datei.

## Wieder abschalten

```bash
sudo systemctl disable --now securityfeed.timer
```

Vollständig entfernen:

```bash
sudo rm /etc/systemd/system/securityfeed.{service,timer}
sudo rm -rf /opt/securityfeed /etc/securityfeed /var/lib/securityfeed
sudo systemctl daemon-reload
sudo userdel securityfeed
```
