#!/bin/sh
# Agent fuer einen weiteren Server: sammelt die Paketlisten des Servers und
# seiner Container in einem Bericht, den SecurityFeed per SSH abholt.
#
# Der Agent schickt nichts selbst los. Er legt den Bericht nur ab - der Rechner
# mit SecurityFeed holt ihn mit einem Schluessel ab, der hier genau einen
# Befehl darf: den Bericht ausgeben (siehe install-agent.sh). So braucht der
# Server keinen Weg ins Netz von SecurityFeed, und SecurityFeed keinen Zugang
# zu diesem Server ausser zu diesem einen Bericht.
#
# Aufruf (als root, geplant ueber securityfeed-agent.timer):
#   securityfeed-agent.sh [AUSGABEVERZEICHNIS] [LESEGRUPPE]
#
# Bericht: <ausgabe>/report.tar.gz mit
#   host/status | host/apk-installed   Paketliste des Servers
#   host/os-release                     fuer die Distributionsversion
#   containers/...                      wie von dump-container-packages.sh
#   created                             Zeitpunkt des Berichts

set -eu

AUSGABE="${1:-/var/lib/securityfeed-agent}"
GRUPPE="${2:-securityfeed-agent}"
HIER=$(cd "$(dirname "$0")" && pwd)
# Installiert liegt das Sammelskript daneben, im Repo eine Ebene hoeher.
DUMP="$HIER/dump-container-packages.sh"
[ -f "$DUMP" ] || DUMP="$HIER/../dump-container-packages.sh"

ARBEIT=$(mktemp -d)
trap 'rm -rf "$ARBEIT"' EXIT INT TERM
mkdir "$ARBEIT/host"

if [ -r /var/lib/dpkg/status ]; then
    cp /var/lib/dpkg/status "$ARBEIT/host/status"
elif [ -r /lib/apk/db/installed ]; then
    cp /lib/apk/db/installed "$ARBEIT/host/apk-installed"
else
    echo "keine Paketliste gefunden, weder dpkg noch apk" > "$ARBEIT/host/unsupported"
fi
cp -L /etc/os-release "$ARBEIT/host/os-release"

# Container nur, wenn es Docker gibt und es antwortet. Ohne Docker ist das
# kein Fehler - dann ist der Server eben nur der Server.
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    sh "$DUMP" "$ARBEIT/containers" "$(id -u):$(id -g)" >/dev/null
    echo "Container erfasst: $(find "$ARBEIT/containers" -mindepth 1 -maxdepth 1 -type d | wc -l)"
fi

date -u +%Y-%m-%dT%H:%M:%SZ > "$ARBEIT/created"

mkdir -p "$AUSGABE"
chmod 0750 "$AUSGABE"
chgrp "$GRUPPE" "$AUSGABE" 2>/dev/null || true
# Erst fertig schreiben, dann umbenennen: wer gerade abholt, bekommt den
# alten oder den neuen Bericht, nie einen halben.
tar -czf "$AUSGABE/report.tar.gz.neu" -C "$ARBEIT" .
chmod 0640 "$AUSGABE/report.tar.gz.neu"
chgrp "$GRUPPE" "$AUSGABE/report.tar.gz.neu" 2>/dev/null || true
mv "$AUSGABE/report.tar.gz.neu" "$AUSGABE/report.tar.gz"
echo "Bericht abgelegt: $AUSGABE/report.tar.gz ($(wc -c < "$AUSGABE/report.tar.gz") Bytes)"
