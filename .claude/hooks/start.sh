#!/bin/sh
# Startet einen Hook mit einem passenden Python. Aufruf aus .claude/settings.json:
#
#     sh "$CLAUDE_PROJECT_DIR/.claude/hooks/start.sh" protokoll_hook
#
# Reihenfolge: das Python der .venv des Projekts (die Einrichtung legt sie an, dort stimmt die Version),
# dann das aus der Variablen OSINT_PYTHON, dann python3 aus dem PATH.
# Unter Windows (Git Bash) wird python3 nicht versucht: Der gleichnamige Platzhalter von Windows
# öffnet nur den Microsoft Store.
#
# Findet sich kein Python, endet der Starter mit Code 1: Die Arbeit geht weiter, die Meldung erscheint
# in Claude Code. Das Sitzungsprotokoll fehlt dann für diesen Aufruf.
#
# Der Hook schreibt nur mit, er lehnt nie etwas ab. Claude Code liest den Code 2 als Absage: Vor der
# Ausführung liefe der Aufruf dann nicht, und am Ende einer Antwort endete sie nicht. Seit dem 20.11.2026
# läuft der Hook auch an diesen beiden Stellen. Python endet von sich aus mit 2, wenn es die Datei des
# Hooks nicht öffnen kann. Deshalb gibt der Starter eine 2 des Hooks nie weiter: Er macht 1 daraus.
case "${1:-}" in
  protokoll_hook) ;;
  *) echo "start.sh: unbekannter Hook '${1:-}'" >&2; exit 2 ;;
esac
wurzel="${CLAUDE_PROJECT_DIR:-$(cd "$(dirname "$0")/../.." && pwd)}"
hook="$wurzel/.claude/hooks/$1.py"

if [ ! -f "$hook" ]; then
  echo "Der Hook $hook fehlt. Das Sitzungsprotokoll wird nicht geschrieben. Bitte die Einrichtung ausführen: ./setup.sh, unter Windows .\\setup.cmd" >&2
  exit 1
fi

laufen() {
  "$@"
  code=$?
  if [ "$code" -eq 2 ]; then code=1; fi
  exit "$code"
}

if [ -x "$wurzel/.venv/Scripts/python.exe" ]; then laufen "$wurzel/.venv/Scripts/python.exe" "$hook"; fi
if [ -x "$wurzel/.venv/bin/python" ]; then laufen "$wurzel/.venv/bin/python" "$hook"; fi
if [ -n "${OSINT_PYTHON:-}" ] && [ -x "$OSINT_PYTHON" ]; then laufen "$OSINT_PYTHON" "$hook"; fi
case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*) ;;
  *) if command -v python3 >/dev/null 2>&1; then laufen python3 "$hook"; fi ;;
esac

echo "Kein Python für die Hooks gefunden. Bitte die Einrichtung ausführen: ./setup.sh, unter Windows .\\setup.cmd" >&2
exit 1
