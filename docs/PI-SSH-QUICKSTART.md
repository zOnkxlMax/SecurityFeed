# Copy-Paste-Anleitung für die SSH-Konsole

Alle Blöcke der Reihe nach in der SSH-Sitzung auf dem Pi einfügen. Ein
Windows-Zwischenschritt ist nicht nötig, weil der Pi einen GitHub-Token für das
private Repo hat.

Erklärungen zu allem hier findest du in [DOCKER.md](DOCKER.md).

---

## A — Repo klonen

```bash
cd ~ && git clone https://github.com/zOnkxlMax/SecurityFeed.git securityfeed
```

Fragt Git nach Zugangsdaten, gib deinen GitHub-Benutzernamen und als **Passwort
den Token** ein — nicht dein Kontopasswort.

Kontrollieren:

```bash
cd ~/securityfeed && ls -a
```

Erwartung: unter anderem `Dockerfile`, `compose.yaml`, `vulnfeed.py`,
`.env.example`, `deploy`, `docs`, `tests`. Das `-a` ist nötig, weil
`.env.example` mit einem Punkt beginnt und ein blankes `ls` sie verschweigt.

<details>
<summary>Token dauerhaft hinterlegen, falls Git jedes Mal fragt</summary>

```bash
git config --global credential.helper store
```

Beim nächsten `git pull` einmal eingeben, danach merkt Git ihn sich. Der Token
liegt dann im Klartext in `~/.git-credentials` — auf einem Pi, der nur diese
Aufgabe hat, ein üblicher Kompromiss. Rechte einschränken:

```bash
chmod 600 ~/.git-credentials
```

Alternativ ohne gespeicherten Token: Token in die Remote-URL setzen mit
`git remote set-url origin https://<TOKEN>@github.com/zOnkxlMax/SecurityFeed.git`.
Er steht dann in `.git/config` — dieselbe Klartext-Abwägung, nur an anderer
Stelle.

</details>

<details>
<summary>Alternative ohne Git: Dateien per scp kopieren</summary>

**In der Windows-PowerShell**, nicht auf dem Pi:

```powershell
$src = "C:\Users\Max.Lang\OneDrive - DATAGROUP SE\Dokumente\VSC\SecurityFeed"
ssh pi@raspberrypi.local "mkdir -p ~/securityfeed"
scp "$src\vulnfeed.py" "$src\Dockerfile" "$src\compose.yaml" "$src\.env.example" pi@raspberrypi.local:~/securityfeed/
```

Ersetze `pi@raspberrypi.local` durch deinen Benutzer und Hostnamen. Damit
entfällt später aber `git pull` — Updates musst du dann jedes Mal erneut per
`scp` schieben.

</details>

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

## C — Zeitzone

Maßgeblich für den Zeitplan ist **`TZ` in der `.env`**, die du im nächsten Block
anlegst — nicht die Zeitzone des Pi. Der Container bringt seine eigene mit.
Steht dort `Europe/Berlin`, kommt die Morgenmail um 07:00 deutscher Zeit, auch
wenn der Pi auf UTC läuft.

Trotzdem sinnvoll, den Pi passend zu stellen, damit Zeitstempel auf dem Host und
im Container übereinstimmen:

```bash
timedatectl | grep "Time zone"
```

Steht dort nicht `Europe/Berlin`:

```bash
sudo timedatectl set-timezone Europe/Berlin
```

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
SECFEED_SCHEDULE=07:00,18:00
TZ=Europe/Berlin
SECFEED_SINCE=2
ENDE
chmod 600 ~/securityfeed/.env
```

Die unteren drei Zeilen steuern Zeitplan, Zeitzone und Zeitfenster. Sie stehen
absichtlich hier und nicht in der `compose.yaml` — so bleibt die getrackte Datei
unverändert und `git pull` konfliktfrei.

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
cd ~/securityfeed && docker compose run --rm securityfeed --once --email --since 2 --no-state
```

Das `--once` ist hier nötig: `docker compose run` erbt die Service-Umgebung und
damit `SECFEED_SCHEDULE`. Ohne das Flag würde der Aufruf in den Dauerbetrieb
gehen und warten, statt einmal zu laufen. Bei `--dry-run` oben ist es nicht
nötig, das impliziert den Einzellauf.

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

Steht dort `UTC` statt `CEST`, fehlt `TZ=Europe/Berlin` in der `.env` aus
Block D — die Zeitzone des Pi spielt dafür keine Rolle.

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
cd ~/securityfeed && docker compose run --rm securityfeed --once --email --since 2
```

Zeiten ändern — `SECFEED_SCHEDULE` in der `.env`, danach übernehmen:

```bash
cd ~/securityfeed && nano .env && docker compose up -d
```

Die `compose.yaml` musst du dafür **nicht** anfassen. Sie liest Zeitplan,
Zeitzone und Zeitfenster aus der `.env`, die per `.gitignore` ausgeschlossen ist —
so bleibt `git pull` konfliktfrei.

Stoppen:

```bash
cd ~/securityfeed && docker compose down
```

Neue Programmversion einspielen — holt den aktuellen Stand aus GitHub, baut neu
und ersetzt den Container:

```bash
cd ~/securityfeed && git pull && docker compose up -d --build
```

Deine `.env` bleibt dabei unangetastet: sie ist per `.gitignore` ausgeschlossen,
`git pull` überschreibt sie also nicht. Das State-Volume bleibt ebenfalls
erhalten, es kommen keine Wiederholungen.

---

## Wenn etwas nicht klappt

| Meldung | Ursache |
| --- | --- |
| `permission denied while trying to connect to the Docker daemon` | Block B nicht abgeschlossen — neu anmelden nach `usermod`. |
| `env file .env not found` | Block D übersprungen. |
| `Mailversand nicht konfiguriert` | Wert fehlt in der `.env`. Die Meldung nennt welchen. |
| `No address associated with hostname` / `Name or service not known` | DNS: der Hostname löst nicht auf. Siehe Abschnitt unten. |
| `Es stehen noch Beispielwerte` | Die `.env` enthält unveränderte Werte aus der Vorlage. |
| `Connection refused` | Falscher Port oder Relay nicht erreichbar. |
| `authentication failed` | App-Passwort nötig, nicht das Anmeldepasswort. |
| `STARTTLS extension not supported` | Relay will kein STARTTLS — auf `none` (25) oder `ssl` (465) wechseln. |
| `relay access denied` | Das Relay akzeptiert deine `SECFEED_MAIL_FROM` nicht. |
| Container startet immer neu | `SECFEED_SCHEDULE` ist in der `.env` auf einen leeren Wert gesetzt. Zeile entweder korrekt füllen oder ganz löschen — dann greift der Standardwert `07:00,18:00` aus der `compose.yaml`. |
| `no such file or directory: compose.yaml` | Du bist nicht in `~/securityfeed`. |
| `compose run` läuft nicht durch, meldet „im Dauerbetrieb" | `--once` fehlt. `compose run` erbt `SECFEED_SCHEDULE` aus der Service-Umgebung. |
| `Authentication failed` beim `git clone` | Als Passwort den Token eingeben, nicht das Kontopasswort. Token abgelaufen? Auf GitHub unter Settings → Developer settings prüfen. |
| `git pull` meldet lokale Änderungen | Du hast eine getrackte Datei bearbeitet. Zeitplan und Zeitzone gehören in die `.env`, nicht in die `compose.yaml`. Mit `git stash` beiseitelegen, `git pull`, dann `git stash pop`. |

Vollständige Diagnose der Konfiguration, ohne etwas zu starten:

```bash
cd ~/securityfeed && docker compose config
```

### Hostname löst nicht auf

`No address associated with hostname` bedeutet: DNS liefert keine IP. Anmeldung,
Port und Firewall sind daran unbeteiligt.

Erst schauen, was überhaupt konfiguriert ist:

```bash
grep -v PASSWORD ~/securityfeed/.env
```

Steht dort noch `smtp.firma.de` aus der Vorlage, ist das die Ursache — dieser
Name existiert nicht. Sonst prüfen, ob der Pi ihn auflösen kann:

```bash
getent hosts DEIN-RELAY-HOSTNAME
```

Kommt nichts, liegt es nicht am Container. Dann ist der Name falsch geschrieben,
oder er löst nur im Firmennetz auf und der Pi hängt woanders.

Löst der Pi ihn auf, der Container aber nicht, teste dort direkt:

```bash
cd ~/securityfeed && docker compose run --rm --entrypoint getent securityfeed hosts DEIN-RELAY-HOSTNAME
```

Der typische Grund für „Host ja, Container nein" ist ein **kurzer Hostname**, der
auf dem Pi nur über eine Suchdomain funktioniert. Zwei Auswege — entweder den
vollqualifizierten Namen verwenden:

```bash
SECFEED_SMTP_HOST=relay.intern.firma.de
```

oder die Suchdomain in einer `compose.override.yaml` nachreichen:

```yaml
services:
  securityfeed:
    dns_search:
      - intern.firma.de
```

Wenn der Relay überhaupt keinen DNS-Namen hat, geht auch die IP direkt:

```bash
SECFEED_SMTP_HOST=192.168.1.25
```

Bei `starttls` oder `ssl` schlägt dann allerdings die Zertifikatsprüfung fehl,
weil das Zertifikat auf den Namen ausgestellt ist und nicht auf die IP. Für ein
Relay im eigenen Netz ist in dem Fall `SECFEED_SMTP_SECURITY=none` mit Port `25`
der übliche Weg.
