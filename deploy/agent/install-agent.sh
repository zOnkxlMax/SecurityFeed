#!/bin/sh
# Richtet den SecurityFeed-Agenten auf diesem Server ein. Einmal als root:
#
#   sudo sh install-agent.sh SCHLUESSEL.pub
#
# SCHLUESSEL.pub ist der oeffentliche Schluessel, mit dem SecurityFeed den
# Bericht abholt. Er bekommt in authorized_keys einen festen Befehl: Was die
# Gegenseite auch verlangt, ausgefuehrt wird nur "Bericht ausgeben". restrict
# nimmt ihm Terminal, Weiterleitungen und Agent-Forwarding.
#
# Wieder entfernen:
#   systemctl disable --now securityfeed-agent.timer
#   rm /etc/systemd/system/securityfeed-agent.* && systemctl daemon-reload
#   userdel -r securityfeed-agent; rm -rf /opt/securityfeed-agent

set -eu

if [ "$(id -u)" != 0 ]; then
    echo "Bitte als root ausfuehren: sudo sh $0 SCHLUESSEL.pub" >&2
    exit 1
fi
SCHLUESSEL="${1:?Pfad zum oeffentlichen Schluessel von SecurityFeed fehlt}"
HIER=$(cd "$(dirname "$0")" && pwd)
# Im Repo liegt das Sammelskript eine Ebene hoeher, im Paket daneben.
DUMP="$HIER/dump-container-packages.sh"
[ -f "$DUMP" ] || DUMP="$HIER/../dump-container-packages.sh"
BENUTZER=securityfeed-agent
AUSGABE=/var/lib/securityfeed-agent

# Genau ein Schluessel, und er muss wie einer aussehen - keine Optionen,
# die jemand vorne angehaengt hat.
ZEILE=$(grep -E '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp[0-9]+) [A-Za-z0-9+/=]+( [^ ]+)?$' "$SCHLUESSEL" | head -n 1)
if [ -z "$ZEILE" ] || [ "$(grep -c . "$SCHLUESSEL")" != 1 ]; then
    echo "$SCHLUESSEL enthaelt nicht genau einen oeffentlichen SSH-Schluessel." >&2
    exit 1
fi

if ! id "$BENUTZER" >/dev/null 2>&1; then
    # Eine Shell braucht er: sshd fuehrt den festen Befehl ueber sie aus.
    # Ein Passwort bekommt er nie - Anmeldung nur mit dem Schluessel.
    useradd --system --home-dir "$AUSGABE" --create-home --shell /bin/sh "$BENUTZER"
    passwd -l "$BENUTZER" >/dev/null
fi

install -d -m 0755 /opt/securityfeed-agent
install -m 0755 "$HIER/securityfeed-agent.sh" "$DUMP" /opt/securityfeed-agent/

install -d -m 0750 -o root -g "$BENUTZER" "$AUSGABE"
install -d -m 0750 -o root -g "$BENUTZER" "$AUSGABE/.ssh"
printf 'command="cat %s/report.tar.gz",restrict %s\n' "$AUSGABE" "$ZEILE" > "$AUSGABE/.ssh/authorized_keys"
chown root:"$BENUTZER" "$AUSGABE/.ssh/authorized_keys"
chmod 0640 "$AUSGABE/.ssh/authorized_keys"

install -m 0644 "$HIER/securityfeed-agent.service" "$HIER/securityfeed-agent.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now securityfeed-agent.timer
systemctl start securityfeed-agent.service

echo
echo "Eingerichtet. Bericht: $(ls -la "$AUSGABE/report.tar.gz")"
echo "Abholen von SecurityFeed aus mit: ssh -i <schluessel> $BENUTZER@<dieser-server>"
