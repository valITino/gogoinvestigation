#!/bin/sh
# Startet einen Hook mit einem passenden Python. Aufruf aus .claude/settings.json:
#
#     sh "$CLAUDE_PROJECT_DIR/.claude/hooks/start.sh" waechter
#
# Reihenfolge: das Python der .venv des Projekts (die Einrichtung legt sie an, dort stimmt die Version),
# dann das aus der Variablen OSINT_PYTHON, dann python3 aus dem PATH.
# Unter Windows (Git Bash) wird python3 nicht versucht: Der gleichnamige Platzhalter von Windows
# öffnet nur den Microsoft Store.
#
# Findet sich kein Python, läuft der Wächter nicht. Dann endet der Starter mit Code 2, und Claude Code
# sperrt den Werkzeugaufruf. Beim Sitzungsprotokoll endet er mit Code 1: Die Arbeit geht weiter,
# die Meldung erscheint in Claude Code.
case "${1:-}" in
  waechter|protokoll_hook) ;;
  *) echo "start.sh: unbekannter Hook '${1:-}'" >&2; exit 2 ;;
esac
wurzel="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
hook="$wurzel/.claude/hooks/$1.py"

if [ -x "$wurzel/.venv/Scripts/python.exe" ]; then exec "$wurzel/.venv/Scripts/python.exe" "$hook"; fi
if [ -x "$wurzel/.venv/bin/python" ]; then exec "$wurzel/.venv/bin/python" "$hook"; fi
if [ -n "${OSINT_PYTHON:-}" ] && [ -x "$OSINT_PYTHON" ]; then exec "$OSINT_PYTHON" "$hook"; fi
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) ;;
  *) if command -v python3 >/dev/null 2>&1; then exec python3 "$hook"; fi ;;
esac

echo "Kein Python für die Hooks gefunden. Bitte die Einrichtung ausführen: ./setup.sh, unter Windows .\\setup.cmd" >&2
[ "$1" = waechter ] && exit 2
exit 1
