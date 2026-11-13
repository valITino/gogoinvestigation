#!/usr/bin/env bash
# Richtet den OSINT-Ermittlungsarbeitsplatz ein. Ohne Rückfragen, beliebig oft wiederholbar.
#
#   ./setup.sh                 alles einrichten
#   ./setup.sh --ohne-docker   Web-Check und Robin auslassen
#   ./setup.sh --ohne-robin    nur Robin (Dark Web) auslassen
#
# Was geschieht:
#   1. Python prüfen, .venv anlegen, Pakete installieren
#   2. .env aus .env.example anlegen (vorhandene .env bleibt unberührt)
#   3. Web-Check per Docker starten, Robin-Abbild laden (wenn Docker läuft)
#   4. MCP-Server für Claude Code freischalten (.claude/settings.local.json)
#   5. Musterfall bauen und Einrichtung prüfen
set -uo pipefail
cd "$(dirname "$0")"

MIT_DOCKER=1; MIT_ROBIN=1
for arg in "$@"; do
  case "$arg" in
    --ohne-docker) MIT_DOCKER=0; MIT_ROBIN=0 ;;
    --ohne-robin)  MIT_ROBIN=0 ;;
    -h|--help|--hilfe) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unbekannte Option: $arg (Hilfe: ./setup.sh --hilfe)"; exit 2 ;;
  esac
done

schritt() { printf '\n\033[1m[%s/5] %s\033[0m\n' "$1" "$2"; }
gut()     { printf '  \033[32m✓\033[0m %s\n' "$1"; }
aus()     { printf '  – %s\n' "$1"; }
abbruch() { printf '\n\033[31mFEHLER:\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '        %s\n' "$2"; exit 1; }

# ------------------------------------------------------------------ 1 Python
schritt 1 "Python-Umgebung"
command -v python3 >/dev/null 2>&1 || abbruch "python3 wurde nicht gefunden." \
  "Installieren: Debian/Ubuntu 'sudo apt install python3 python3-venv', macOS 'brew install python'."
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || abbruch \
  "Python $(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))') ist zu alt. Nötig ist 3.10 oder neuer."
gut "Python $(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv 2>/tmp/osint-venv.log || abbruch "Die Python-Umgebung .venv liess sich nicht anlegen." \
    "Meist fehlt das Paket python3-venv: 'sudo apt install python3-venv'. Details: /tmp/osint-venv.log"
  gut ".venv angelegt"
else
  gut ".venv vorhanden"
fi
if ! .venv/bin/python -m pip install --quiet --disable-pip-version-check -r requirements.txt 2>/tmp/osint-pip.log; then
  tail -n 5 /tmp/osint-pip.log
  abbruch "Die Python-Pakete liessen sich nicht installieren." \
    "Internetzugang und Proxy prüfen (HTTPS_PROXY). Vollständige Meldung: /tmp/osint-pip.log"
fi
gut "Pakete installiert (mcp, httpx, pydantic)"
chmod +x .claude/hooks/*.py tools/*.py gateway/start.py 2>/dev/null || true

# ------------------------------------------------------------------ 2 .env
schritt 2 "Schlüsseldatei"
if [ -f .env ]; then
  gut ".env vorhanden, bleibt unverändert"
else
  cp .env.example .env && chmod 600 .env
  gut ".env aus .env.example angelegt. Schlüssel dort eintragen."
fi
mkdir -p faelle protokoll/sitzungen

# ------------------------------------------------------------------ 3 Docker
schritt 3 "Web-Check und Robin (Docker)"
DOCKER_OK=0; ROBIN_OK=0
if [ "$MIT_DOCKER" = 0 ]; then
  aus "übersprungen (--ohne-docker)"
elif ! command -v docker >/dev/null 2>&1; then
  aus "Docker ist nicht installiert. Web-Check und Robin bleiben aus, alles andere läuft."
elif ! docker info >/dev/null 2>&1; then
  aus "Docker ist installiert, aber der Dienst läuft nicht oder ihr habt keinen Zugriff darauf."
  aus "Docker starten und ./setup.sh erneut ausführen, um Web-Check und Robin zu aktivieren."
else
  DOCKER_OK=1
  if docker compose up -d webcheck >/tmp/osint-docker.log 2>&1; then
    gut "Web-Check läuft auf 127.0.0.1:${WEBCHECK_PORT:-3000}"
  else
    aus "Web-Check liess sich nicht starten (Port belegt? WEBCHECK_PORT setzen). Details: /tmp/osint-docker.log"
  fi
  if [ "$MIT_ROBIN" = 1 ]; then
    ROBIN_IMAGE="${ROBIN_IMAGE:-$(grep -E '^ROBIN_IMAGE=' .env 2>/dev/null | tail -n1 | cut -d= -f2-)}"
    ROBIN_IMAGE="${ROBIN_IMAGE:-apurvsg/robin:latest}"
    if docker image inspect "$ROBIN_IMAGE" >/dev/null 2>&1 || docker pull "$ROBIN_IMAGE" >>/tmp/osint-docker.log 2>&1; then
      ROBIN_OK=1; gut "Robin-Abbild bereit ($ROBIN_IMAGE)"
    else
      aus "Robin-Abbild $ROBIN_IMAGE liess sich nicht laden. Dark-Web-Suche bleibt aus. Details: /tmp/osint-docker.log"
    fi
  else
    aus "Robin übersprungen (--ohne-robin)"
  fi
fi

# ------------------------------------------------------------------ 4 Claude Code
schritt 4 "Claude Code"
ROBIN_OK="$ROBIN_OK" python3 - <<'PY'
import json, os, pathlib
datei = pathlib.Path(".claude/settings.local.json")
try:
    daten = json.loads(datei.read_text()) if datei.is_file() else {}
except json.JSONDecodeError:
    daten = {}
robin = os.environ.get("ROBIN_OK") == "1"
an = [s for s in daten.get("enabledMcpjsonServers", []) if s not in ("osint", "robin")] + ["osint"] + (["robin"] if robin else [])
ab = [s for s in daten.get("disabledMcpjsonServers", []) if s not in ("osint", "robin")] + ([] if robin else ["robin"])
daten["enabledMcpjsonServers"] = an
daten["disabledMcpjsonServers"] = ab
datei.write_text(json.dumps(daten, indent=2) + "\n")
print("  \033[32m✓\033[0m MCP-Server freigeschaltet: " + ", ".join(an) + ("" if robin else "  (robin aus: kein Docker oder kein Abbild)"))
PY
if command -v claude >/dev/null 2>&1; then
  gut "Claude Code gefunden: $(claude --version 2>/dev/null | head -n1)"
else
  aus "Claude Code ist nicht installiert. Anleitung: https://code.claude.com/docs"
fi

# ------------------------------------------------------------------ 5 Musterfall und Prüfung
schritt 5 "Musterfall und Prüfung"
if .venv/bin/python tools/musterfall.py >/tmp/osint-muster.log 2>&1; then
  gut "Musterfall gebaut: faelle/MUSTER-2026-001/rapport/Abschlussrapport.html"
else
  tail -n 5 /tmp/osint-muster.log
  abbruch "Der Musterfall liess sich nicht bauen." "Vollständige Meldung: /tmp/osint-muster.log"
fi
python3 tools/pruefen.py
STAND=$?

printf '\n\033[1mSo geht es weiter\033[0m\n'
cat <<'TEXT'
  1. Schlüssel in .env eintragen (jede Quelle ist für sich optional). Stand: python3 tools/pruefen.py --live
  2. Musterfall ansehen:  faelle/MUSTER-2026-001/rapport/Abschlussrapport.html
  3. Fall anlegen:        python3 tools/fall.py neu 2026-0001 --titel "…" --rapport <pseudonymisiertes Dokument>
  4. Ermitteln:           claude      und dort      /ermittlung 2026-0001
TEXT
exit $STAND
