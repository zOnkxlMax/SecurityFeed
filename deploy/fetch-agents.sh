#!/bin/sh
# Holt die Berichte der SecurityFeed-Agenten auf anderen Servern ab und legt
# sie so ab, wie SecurityFeed sie liest (SECFEED_AGENTS_DIR).
#
# Der Agent auf dem Server erlaubt diesem Schluessel nur einen Befehl: den
# Bericht ausgeben. Alles, was zurueckkommt, wird trotzdem wie fremde Daten
# behandelt - nur bekannte Dateinamen, keine Links, keine Pfade nach draussen,
# eine Groessengrenze.
#
# Aufruf (als root, geplant ueber securityfeed-agents.timer):
#   fetch-agents.sh [ZIEL] [EIGENTUEMER]
#   fetch-agents.sh --ingest NAME BERICHT.tar.gz [ZIEL] [EIGENTUEMER]   (ohne SSH, fuer Tests)
#
# Konfiguration in /etc/securityfeed:
#   agents             je Zeile: NAME BENUTZER@HOST [PORT]
#   agent_key          privater Schluessel (ssh-keygen -t ed25519 -N "")
#   agent_known_hosts  Host-Schluessel der Server - ohne Eintrag kein Abruf

set -eu

KONFIG=/etc/securityfeed
MAX_BYTES=52428800   # 50 MiB

ingest_modus=""
if [ "${1:-}" = "--ingest" ]; then
    ingest_modus=1
    I_NAME="${2:?Name fehlt}"; I_DATEI="${3:?Bericht fehlt}"
    shift 3
fi
ZIEL="${1:-/var/lib/securityfeed/agents}"
EIGENTUEMER="${2:-}"
if [ -z "$EIGENTUEMER" ]; then
    if getent passwd securityfeed >/dev/null 2>&1; then
        EIGENTUEMER="securityfeed:securityfeed"
    else
        EIGENTUEMER="10001:10001"
    fi
fi

# Erlaubte Eintraege im Bericht. Alles andere - ein Link, ein "..", eine
# unbekannte Datei - verwirft den ganzen Bericht.
ERLAUBT='^\./$|^\./created$|^\./host/$|^\./host/(status|apk-installed|os-release|unsupported)$|^\./containers/$|^\./containers/updated$|^\./containers/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/$|^\./containers/[A-Za-z0-9][A-Za-z0-9_.-]{0,127}/(status|apk-installed|os-release|unsupported|image-status)$'

pruefe_name() {
    case "$1" in
        *[!a-z0-9-]*|"") echo "Ungueltiger Agent-Name '$1' - erlaubt sind a-z, 0-9 und -." >&2; return 1 ;;
    esac
}

ingest() {
    NAME="$1"; BERICHT="$2"
    pruefe_name "$NAME" || return 1
    if [ "$(wc -c < "$BERICHT")" -gt "$MAX_BYTES" ]; then
        echo "$NAME: Bericht groesser als $MAX_BYTES Bytes, verworfen" >&2; return 1
    fi
    # Erst die Liste pruefen, dann auspacken. -tv zeigt den Typ: nur normale
    # Dateien (-) und Verzeichnisse (d), keine Links oder Geraete.
    if ! LISTE=$(tar -tvzf "$BERICHT" 2>/dev/null); then
        echo "$NAME: Bericht ist kein lesbares tar.gz, verworfen" >&2; return 1
    fi
    if printf '%s\n' "$LISTE" | cut -c1 | grep -qv '^[-d]$'; then
        echo "$NAME: Bericht enthaelt Links oder Sonderdateien, verworfen" >&2; return 1
    fi
    NAMEN=$(tar -tzf "$BERICHT")
    FALSCH=$(printf '%s\n' "$NAMEN" | grep -Ev "$ERLAUBT" || true)
    if [ -n "$FALSCH" ]; then
        echo "$NAME: unerwartete Eintraege im Bericht, verworfen:" >&2
        printf '  %s\n' "$FALSCH" | head -5 >&2
        return 1
    fi

    mkdir -p "$ZIEL"
    chmod 0750 "$ZIEL"
    chown "$EIGENTUEMER" "$ZIEL"
    NEU="$ZIEL/.$NAME.neu"; ALT="$ZIEL/.$NAME.alt"
    rm -rf "$NEU" "$ALT"
    mkdir "$NEU"
    tar -xzf "$BERICHT" -C "$NEU" --no-same-owner --no-same-permissions
    find "$NEU" -type d -exec chmod 0750 {} +
    find "$NEU" -type f -exec chmod 0640 {} +
    : > "$NEU/received"
    chmod 0640 "$NEU/received"
    chown -R "$EIGENTUEMER" "$NEU"
    # Tauschen statt ueberschreiben: SecurityFeed liest den alten oder den
    # neuen Stand, nie eine Mischung.
    if [ -d "$ZIEL/$NAME" ]; then mv "$ZIEL/$NAME" "$ALT"; fi
    mv "$NEU" "$ZIEL/$NAME"
    rm -rf "$ALT"
    echo "$NAME: Bericht abgelegt ($(find "$ZIEL/$NAME/containers" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l) Container)"
}

if [ -n "$ingest_modus" ]; then
    ingest "$I_NAME" "$I_DATEI"
    exit $?
fi

if [ ! -f "$KONFIG/agents" ]; then
    echo "Keine Agenten konfiguriert ($KONFIG/agents fehlt)."
    exit 0
fi

ARBEIT=$(mktemp -d)
trap 'rm -rf "$ARBEIT"' EXIT INT TERM
FEHLER=0
BEKANNT=""

while read -r NAME ZIELHOST PORT _REST; do
    case "$NAME" in ""|\#*) continue ;; esac
    pruefe_name "$NAME" || { FEHLER=1; continue; }
    BEKANNT="$BEKANNT $NAME"
    # -F /dev/null: keine ~/.ssh/config, die etwas umlenkt. StrictHostKeyChecking
    # =yes: ein unbekannter oder geaenderter Host-Schluessel bricht ab.
    if ssh -F /dev/null -i "$KONFIG/agent_key" -p "${PORT:-22}" \
           -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=20 \
           -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$KONFIG/agent_known_hosts" \
           -o LogLevel=ERROR "$ZIELHOST" < /dev/null \
           | head -c $((MAX_BYTES + 1)) > "$ARBEIT/$NAME.tar.gz" \
       && [ -s "$ARBEIT/$NAME.tar.gz" ]; then
        ingest "$NAME" "$ARBEIT/$NAME.tar.gz" || FEHLER=1
    else
        echo "$NAME: Abruf von $ZIELHOST fehlgeschlagen" >&2
        FEHLER=1
    fi
done < "$KONFIG/agents"

# Server, die nicht mehr konfiguriert sind, verschwinden aus der Ablage -
# sonst meldete SecurityFeed ewig einen alten Stand.
if [ -d "$ZIEL" ]; then
    for VERZ in "$ZIEL"/*/; do
        [ -d "$VERZ" ] || continue
        N=$(basename "$VERZ")
        case " $BEKANNT " in *" $N "*) ;; *) rm -rf "$VERZ"; echo "$N: nicht mehr konfiguriert, entfernt" ;; esac
    done
fi
exit $FEHLER
