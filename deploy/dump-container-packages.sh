#!/bin/sh
# Legt die Paketliste jedes laufenden Containers in einem Verzeichnis ab, das
# SecurityFeed nur lesend eingehaengt bekommt.
#
# Warum der Umweg: SecurityFeed selbst bekommt bewusst keinen Zugriff auf den
# Docker-Socket. Wer den Socket hat, ist faktisch root auf dem Pi - das waere
# ausgerechnet beim Dienst, der die Sicherheit ueberwachen soll, ein schlechter
# Tausch. Stattdessen holt dieses Skript auf dem Host die Listen ab, und der
# Container sieht nur noch Textdateien.
#
# Aufruf:
#   sudo ./dump-container-packages.sh [ZIELVERZEICHNIS] [EIGENTUEMER]
#
# Default-Ziel: /var/lib/securityfeed/containers
# Default-Eigentuemer: der Dienstbenutzer "securityfeed", falls es ihn gibt
#   (systemd-Variante), sonst 10001:10001 - die UID im SecurityFeed-Container.
# Geplant laeuft es ueber deploy/securityfeed-containers.timer.
#
# Die Ablage ist fuer niemanden sonst lesbar (0750/0640). Sie ist das
# Paketinventar aller Container samt Versionen - eine fertige Zielliste, die
# nicht jeder Benutzer auf dem Pi einsehen sollte. Der Leser braucht nur
# Leserechte.
#
# Ablage je Container:
#   <ziel>/<name>/status       dpkg-Statusdatei aus dem Container
#   <ziel>/<name>/os-release   /etc/os-release, fuer die Debian-Version
#   <ziel>/<name>/unsupported  Grund, falls keine Paketliste zu holen war
#   <ziel>/updated             Zeitstempel dieses Laufs

set -eu

ZIEL="${1:-/var/lib/securityfeed/containers}"
EIGENTUEMER="${2:-}"
if [ -z "$EIGENTUEMER" ]; then
    if getent passwd securityfeed >/dev/null 2>&1; then
        EIGENTUEMER="securityfeed:securityfeed"
    else
        EIGENTUEMER="10001:10001"
    fi
fi

# Datei an ihren endgueltigen Platz schieben und die Rechte setzen. docker cp
# legt sie als root und 0644 ab - beides wird hier korrigiert.
ablegen() {
    mv "$1" "$2"
    chmod 0640 "$2"
    chown "$EIGENTUEMER" "$2"
}

if ! command -v docker >/dev/null 2>&1; then
    echo "docker nicht gefunden - laeuft dieses Skript auf dem richtigen Host?" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Kein Zugriff auf Docker. Als root ausfuehren oder in der Gruppe 'docker' sein." >&2
    exit 1
fi

mkdir -p "$ZIEL"
chmod 0750 "$ZIEL"
chown "$EIGENTUEMER" "$ZIEL"

# Das Verzeichnis wird in den SecurityFeed-Container gemountet - es darf hier
# nicht ersetzt werden, sonst zeigt der Mount ins Leere. Deshalb wird alles an
# Ort und Stelle aktualisiert.

LAUFEND=$(docker ps --format '{{.Names}}' | sort)

for NAME in $LAUFEND; do
    VERZ="$ZIEL/$NAME"
    mkdir -p "$VERZ"
    chmod 0750 "$VERZ"
    chown "$EIGENTUEMER" "$VERZ"
    rm -f "$VERZ/unsupported"

    # docker cp braucht keine Shell im Container und funktioniert deshalb auch
    # bei schlanken Images.
    ART=""
    if docker cp -L "$NAME:/var/lib/dpkg/status" "$VERZ/status.neu" >/dev/null 2>&1; then
        ART="dpkg"
        rm -f "$VERZ/apk-installed"
        ablegen "$VERZ/status.neu" "$VERZ/status"
    elif docker cp -L "$NAME:/lib/apk/db/installed" "$VERZ/apk-installed.neu" >/dev/null 2>&1; then
        ART="apk"
        rm -f "$VERZ/status"
        ablegen "$VERZ/apk-installed.neu" "$VERZ/apk-installed"
    fi
    rm -f "$VERZ/status.neu" "$VERZ/apk-installed.neu"

    if [ -n "$ART" ]; then
        # Ohne os-release fehlt die Distributionsversion, und ohne die wird
        # nicht geraten, sondern nicht geprueft.
        if docker cp -L "$NAME:/etc/os-release" "$VERZ/os-release.neu" >/dev/null 2>&1; then
            ablegen "$VERZ/os-release.neu" "$VERZ/os-release"
        else
            rm -f "$VERZ/os-release.neu" "$VERZ/os-release"
        fi
        echo "$NAME: Paketliste abgelegt ($ART)"
    else
        rm -f "$VERZ/os-release"
        # Weder dpkg noch apk: distroless, scratch oder eine andere Basis. Der
        # Vermerk sorgt dafuer, dass der Container in der Mail als "nicht
        # pruefbar" auftaucht, statt stillschweigend als unauffaellig
        # durchzugehen.
        IMAGE=$(docker inspect -f '{{.Config.Image}}' "$NAME" 2>/dev/null || echo "unbekannt")
        printf 'keine Paketliste im Container gefunden, weder dpkg noch apk (Image: %s)\n' \
            "$IMAGE" > "$VERZ/unsupported.neu"
        ablegen "$VERZ/unsupported.neu" "$VERZ/unsupported"
        echo "$NAME: weder dpkg noch apk, als nicht pruefbar vermerkt"
    fi
done

# Container, die es nicht mehr gibt, sonst meldet SecurityFeed ewig Befunde zu
# etwas, das laengst weggeraeumt ist.
for VERZ in "$ZIEL"/*/; do
    [ -d "$VERZ" ] || continue
    NAME=$(basename "$VERZ")
    # -F, weil Containernamen Punkte enthalten duerfen und die sonst als
    # Regex-Platzhalter durchgingen.
    if ! echo "$LAUFEND" | grep -Fqx "$NAME"; then
        rm -rf "$VERZ"
        echo "$NAME: laeuft nicht mehr, Eintrag entfernt"
    fi
done

# Zeitstempel zum Schluss: SecurityFeed warnt, wenn er zu alt wird - ein
# stehengebliebener Timer darf nicht als "alles ruhig" durchgehen.
: > "$ZIEL/updated.neu"
ablegen "$ZIEL/updated.neu" "$ZIEL/updated"

echo "Fertig. Ablage: $ZIEL (Eigentuemer $EIGENTUEMER)"
