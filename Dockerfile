# SecurityFeed - laeuft im Dauerbetrieb und plant seine Laeufe selbst.
#
# Bauen:   docker compose build
# Starten: docker compose up -d
FROM python:3.13-slim-bookworm

# tzdata ist in den slim-Images nicht enthalten. Ohne die Datenbank kann
# TZ=Europe/Berlin nicht aufgeloest werden und der Zeitplan liefe in UTC.
# ca-certificates braucht urllib fuer die HTTPS-Feeds.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Feste UID/GID, damit die Rechte auch bei einem gemounteten Host-Verzeichnis
# vorhersagbar sind.
RUN groupadd --gid 10001 securityfeed \
    && useradd --uid 10001 --gid 10001 --no-create-home \
       --shell /usr/sbin/nologin securityfeed

# Zustandsverzeichnis schon im Image anlegen: ein frisch erzeugtes Named Volume
# uebernimmt Besitzer und Rechte des Mountpunkts aus dem Image.
RUN install -d -m 0755 -o securityfeed -g securityfeed /var/lib/securityfeed

COPY vulnfeed.py /app/vulnfeed.py

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECFEED_STATE=/var/lib/securityfeed/seen.json

USER securityfeed
WORKDIR /app

# Kein Shell-Wrapper: so kommt SIGTERM von "docker stop" direkt bei Python an
# und der Scheduler beendet sich sauber.
ENTRYPOINT ["python3", "/app/vulnfeed.py"]

# Wird von "command:" in der compose.yaml ueberschrieben. Der Zeitplan kommt
# dort aus SECFEED_SCHEDULE.
CMD ["--email", "--schedule", "07:00,18:00", "--since", "2", "--details"]
