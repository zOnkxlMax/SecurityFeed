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
#   sudo ./dump-container-packages.sh [ZIELVERZEICHNIS]
#
# Default-Ziel: /var/lib/securityfeed/containers
# Geplant laeuft es ueber deploy/securityfeed-containers.timer.
#
# Ablage je Container:
#   <ziel>/<name>/status       dpkg-Statusdatei aus dem Container
#   <ziel>/<name>/os-release   /etc/os-release, fuer die Debian-Version
#   <ziel>/<name>/unsupported  Grund, falls keine Paketliste zu holen war
#   <ziel>/updated             Zeitstempel dieses Laufs

set -eu

ZIEL="${1:-/var/lib/securityfeed/containers}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker nicht gefunden - laeuft dieses Skript auf dem richtigen Host?" >&2
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "Kein Zugriff auf Docker. Als root ausfuehren oder in der Gruppe 'docker' sein." >&2
    exit 1
fi

mkdir -p "$ZIEL"
chmod 0755 "$ZIEL"

# Das Verzeichnis wird in den SecurityFeed-Container gemountet - es darf hier
# nicht ersetzt werden, sonst zeigt der Mount ins Leere. Deshalb wird alles an
# Ort und Stelle aktualisiert.

LAUFEND=$(docker ps --format '{{.Names}}' | sort)

for NAME in $LAUFEND; do
    VERZ="$ZIEL/$NAME"
    mkdir -p "$VERZ"
    chmod 0755 "$VERZ"
    rm -f "$VERZ/unsupported"

    # docker cp braucht keine Shell im Container und funktioniert deshalb auch
    # bei schlanken Images. Bei distroless und scratch fehlt dpkg trotzdem.
    if docker cp -L "$NAME:/var/lib/dpkg/status" "$VERZ/status.neu" >/dev/null 2>&1; then
        mv "$VERZ/status.neu" "$VERZ/status"
        chmod 0644 "$VERZ/status"
        if docker cp -L "$NAME:/etc/os-release" "$VERZ/os-release.neu" >/dev/null 2>&1; then
            mv "$VERZ/os-release.neu" "$VERZ/os-release"
            chmod 0644 "$VERZ/os-release"
        else
            rm -f "$VERZ/os-release.neu" "$VERZ/os-release"
        fi
        echo "$NAME: Paketliste abgelegt"
    else
        rm -f "$VERZ/status.neu" "$VERZ/status" "$VERZ/os-release"
        # Kein dpkg: Alpine, distroless oder scratch. Der Vermerk sorgt dafuer,
        # dass der Container in der Mail als "nicht pruefbar" auftaucht, statt
        # stillschweigend als unauffaellig durchzugehen.
        IMAGE=$(docker inspect -f '{{.Config.Image}}' "$NAME" 2>/dev/null || echo "unbekannt")
        printf 'keine dpkg-Paketliste im Container (Image: %s) - Alpine, distroless oder scratch?\n' \
            "$IMAGE" > "$VERZ/unsupported"
        chmod 0644 "$VERZ/unsupported"
        echo "$NAME: kein dpkg, als nicht pruefbar vermerkt"
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
: > "$ZIEL/updated"
chmod 0644 "$ZIEL/updated"

echo "Fertig. Ablage: $ZIEL"
