# Copy-Paste-Anleitung für die SSH-Konsole

Blöcke der Reihe nach abarbeiten. Achte auf die Kennzeichnung — **A** läuft in
der PowerShell auf deinem Windows-Rechner, **B** bis **G** in der SSH-Sitzung
auf dem Pi.

Erklärungen zu allem hier findest du in [DOCKER.md](DOCKER.md).

Ersetze `pi@raspberrypi.local` überall durch deinen Benutzer und Hostnamen —
falls unbekannt, auf dem Pi mit `whoami` und `hostname -I` nachsehen.

---

## A — Dateien auf den Pi kopieren

**In der Windows-PowerShell**, nicht auf dem Pi:

```powershell
$src = "C:\Users\Max.Lang\OneDrive - DATAGROUP SE\Dokumente\VSC\SecurityFeed"
ssh pi@raspberrypi.local "mkdir -p ~/securityfeed"
scp "$src\vulnfeed.py" "$src\Dockerfile" "$src\compose.yaml" "$src\.env.example" pi@raspberrypi.local:~/securityfeed/
```

Erwartung: vier Zeilen mit `100%`.

Ab hier alles per `ssh pi@raspberrypi.local` auf dem Pi.

---

## B — Docker installieren

Erst prüfen, ob es schon da ist:

```bash
docker compose version
```

Kommt eine Versionsnummer, **überspringe diesen Abschnitt** und mach bei C
weiter. Andernfalls die offizielle Docker-Paketquelle einrichten:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
```

Dann Docker samt Compose-Plugin installieren:

```bash
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Damit du Docker ohne `sudo` benutzen kannst:

```bash
sudo usermod -aG docker $USER
```

**Jetzt die SSH-Sitzung beenden und neu verbinden** — die neue Gruppe gilt erst
in einer neuen Anmeldung:

```bash
exit
```

Nach dem erneuten Verbinden kontrollieren:

```bash
docker compose version && docker run --rm hello-world
```

Erwartung: eine Versionsnummer und `Hello from Docker!`.

---

## C — Zeitzone prüfen

```bash
timedatectl | grep "Time zone"
```

Steht dort nicht `Europe/Berlin`, korrigieren:

```bash
sudo timedatectl set-timezone Europe/Berlin
```

Der Zeitplan im Container gilt in dieser Zeitzone. Ohne diesen Schritt kommt die
Morgenmail im Sommer zwei Stunden zu spät.

---

## D — Zugangsdaten eintragen

Das ist der **einzige Block, den du vor dem Einfügen anpassen musst**. Trage
deine echten Werte ein, dann komplett einfügen:

```bash
cat > ~/securityfeed/.env <<'ENDE'
SECFEED_SMTP_HOST=smtp.firma.de
SECFEED_SMTP_PORT=587
SECFEED_SMTP_SECURITY=starttls
SECFEED_SMTP_USER=feed@firma.de
SECFEED_SMTP_PASSWORD=dein-app-passwort
SECFEED_MAIL_FROM=feed@firma.de
SECFEED_MAIL_TO=max@firma.de
SECFEED_SUBJECT_PREFIX=[SecurityFeed]
ENDE
chmod 600 ~/securityfeed/.env
```

Das `<<'ENDE'` steht in Anführungszeichen — dadurch bleiben `$`, Backticks und
Anführungszeichen in deinem Passwort unverändert. `chmod 600` sorgt dafür, dass
nur dein Benutzer die Datei lesen kann.

Welche Werte für dich gelten:

| Situation | Port | `SECFEED_SMTP_SECURITY` | User/Passwort |
| --- | --- | --- | --- |
| Internes Relay im eigenen Netz | `25` | `none` | Zeilen löschen |
| Provider mit STARTTLS | `587` | `starttls` | nötig |
| Provider mit implizitem TLS | `465` | `ssl` | nötig |
| Microsoft 365 | `587` | `starttls` | App-Passwort |
| Gmail | `587` | `starttls` | App-Passwort |

Bei Microsoft 365 und Gmail funktioniert dein normales Anmeldepasswort nicht —
beide brauchen ein App-Passwort, bei M365 muss SMTP-AUTH fürs Postfach
zusätzlich freigeschaltet sein.

Kontrollieren, ohne das Passwort auf den Bildschirm zu holen:

```bash
grep -v PASSWORD ~/securityfeed/.env
```

---

## E — Bauen und testen, ohne Mail zu verschicken

```bash
cd ~/securityfeed && docker compose build
```

Erwartung: endet mit `naming to docker.io/library/securityfeed:latest` oder
`Successfully built`. Dauert auf einem Pi ein bis drei Minuten.

Jetzt der Trockenlauf — baut die komplette Mail, verschickt sie aber nicht:

```bash
cd ~/securityfeed && docker compose run --rm securityfeed --email --dry-run --since 2
```

Erwartung: ein `Subject:`-Header, deine Adressen und darunter die Meldungen.
Kommt `Mailversand nicht konfiguriert`, fehlt ein Wert in Block D.

Wenn das passt, ein **echter** Testversand:

```bash
cd ~/securityfeed && docker compose run --rm securityfeed --email --since 2 --no-state
```

Erwartung: `Mail an ... verschickt (N Meldung(en)).` Schau in dein Postfach,
auch in den Spam-Ordner. `--no-state` verhindert, dass dieser Test die Meldungen
als „schon gemeldet" markiert.

**Erst weitermachen, wenn diese Mail angekommen ist.**

---

## F — Dauerbetrieb starten

```bash
cd ~/securityfeed && docker compose up -d
```

Kontrollieren:

```bash
cd ~/securityfeed && docker compose logs
```

Erwartete Ausgabe:

```
securityfeed  | [2026-07-30 10:15:02 CEST] SecurityFeed 1.0.0 im Dauerbetrieb. Zeiten: 07:00, 18:00 (Zeitzone CEST)
securityfeed  | [2026-07-30 10:15:02 CEST] Naechster Lauf 2026-07-30 18:00:00 CEST (in 7h 44min).
```

Steht dort `UTC` statt `CEST`, war Block C nicht erfolgreich.

Fertig. Der Container startet nach einem Reboot des Pi automatisch wieder.

---

## G — Merkzettel für den Betrieb

Logs live mitlesen:

```bash
cd ~/securityfeed && docker compose logs -f
```

Läuft es noch?

```bash
cd ~/securityfeed && docker compose ps
```

Lauf sofort auslösen, ohne auf 07:00 zu warten:

```bash
cd ~/securityfeed && docker compose run --rm securityfeed --email --since 2
```

Zeiten ändern — `SECFEED_SCHEDULE` in der `compose.yaml`, danach übernehmen:

```bash
cd ~/securityfeed && nano compose.yaml && docker compose up -d
```

Stoppen:

```bash
cd ~/securityfeed && docker compose down
```

Neue Programmversion einspielen (Datei vorher per `scp` wie in Block A kopieren):

```bash
cd ~/securityfeed && docker compose up -d --build
```

---

## Wenn etwas nicht klappt

| Meldung | Ursache |
| --- | --- |
| `permission denied while trying to connect to the Docker daemon` | Block B nicht abgeschlossen — neu anmelden nach `usermod`. |
| `env file .env not found` | Block D übersprungen. |
| `Mailversand nicht konfiguriert` | Wert fehlt in der `.env`. Die Meldung nennt welchen. |
| `Connection refused` | Falscher Port oder Relay nicht erreichbar. |
| `authentication failed` | App-Passwort nötig, nicht das Anmeldepasswort. |
| `STARTTLS extension not supported` | Relay will kein STARTTLS — auf `none` (25) oder `ssl` (465) wechseln. |
| `relay access denied` | Das Relay akzeptiert deine `SECFEED_MAIL_FROM` nicht. |
| Container startet immer neu | `SECFEED_SCHEDULE` fehlt in der `compose.yaml`. |
| `no such file or directory: compose.yaml` | Du bist nicht in `~/securityfeed`. |

Vollständige Diagnose der Konfiguration, ohne etwas zu starten:

```bash
cd ~/securityfeed && docker compose config
```
