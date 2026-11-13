#!/usr/bin/env bash
# Richtet den OSINT-Ermittlungsarbeitsplatz ein (Linux, macOS, WSL). Ohne Rückfragen, beliebig oft wiederholbar.
#
#   ./setup.sh                              alles einrichten
#   ./setup.sh --nur-pruefen                nur zeigen, was vorhanden ist und was fehlt
#   ./setup.sh --mythos                     erklären, dass dieses Konto Claude Mythos 5.2 hat
#   ./setup.sh --hilfe                      alle Optionen
#
# Dieses Skript sorgt nur für ein brauchbares Python (3.10 oder neuer) und übergibt dann an
# tools/einrichten.py. Dort steht alles Weitere, für Linux, macOS und Windows gemeinsam.
# Unter Windows ohne WSL: setup.cmd
set -u
cd "$(dirname "$0")" || exit 1

fehler() {
  printf '\nFEHLER: %s\n' "$1" >&2
  shift
  for zeile in "$@"; do printf '        %s\n' "$zeile" >&2; done
  exit 1
}

case "$(uname -s 2>/dev/null)" in
  MINGW*|MSYS*|CYGWIN*)
    fehler "Das ist Git Bash unter Windows." \
      "Bitte in PowerShell oder der Eingabeaufforderung starten:  .\\setup.cmd" \
      "Oder in einem WSL-Terminal:  ./setup.sh" ;;
esac

DARF=1      # darf dieses Skript Python nachinstallieren?
for arg in "$@"; do
  case "$arg" in --nur-pruefen|--nichts-installieren|--hilfe|--help|-h) DARF=0 ;; esac
done

python_ok() { "$1" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; }

PYTHON=""
finde_python() {
  for p in python3 python3.13 python3.12 python3.11 python3.10 python; do
    command -v "$p" >/dev/null 2>&1 || continue
    # macOS: /usr/bin/python3 ist ohne die Command Line Tools ein Platzhalter, der nur ein Installationsfenster öffnet
    if [ "$(uname -s)" = Darwin ] && [ "$(command -v "$p")" = /usr/bin/python3 ] && ! xcode-select -p >/dev/null 2>&1; then
      continue
    fi
    if python_ok "$p"; then PYTHON="$p"; return 0; fi
  done
  return 1
}

als_root() {
  if [ "$(id -u)" = 0 ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  else return 127
  fi
}

python_installieren() {
  LOG="${TMPDIR:-/tmp}/osint-setup"
  mkdir -p "$LOG" 2>/dev/null
  LOG="$LOG/python.log"
  printf '  + Python 3.10 oder neuer fehlt. Es wird über die Paketverwaltung installiert'
  [ "$(id -u)" = 0 ] || command -v brew >/dev/null 2>&1 || printf ' (sudo fragt dafür einmal nach eurem Passwort)'
  printf ' ...\n'
  if command -v apt-get >/dev/null 2>&1; then
    als_root apt-get update -qq >>"$LOG" 2>&1
    als_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 python3-venv >>"$LOG" 2>&1
  elif command -v dnf >/dev/null 2>&1; then als_root dnf install -y python3 >>"$LOG" 2>&1
  elif command -v yum >/dev/null 2>&1; then als_root yum install -y python3 >>"$LOG" 2>&1
  elif command -v pacman >/dev/null 2>&1; then als_root pacman -S --noconfirm --needed python >>"$LOG" 2>&1
  elif command -v zypper >/dev/null 2>&1; then als_root zypper --non-interactive install python3 >>"$LOG" 2>&1
  elif command -v apk >/dev/null 2>&1; then als_root apk add python3 >>"$LOG" 2>&1
  elif command -v brew >/dev/null 2>&1; then brew install python >>"$LOG" 2>&1
  else return 1
  fi
}

if ! finde_python && [ "$DARF" = 1 ]; then
  python_installieren
  hash -r 2>/dev/null
  finde_python
fi

if [ -z "$PYTHON" ]; then
  gefunden=""
  if command -v python3 >/dev/null 2>&1; then
    gefunden="$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))' 2>/dev/null)"
  fi
  fehler "Python 3.10 oder neuer wird gebraucht${gefunden:+, gefunden wurde nur $gefunden}." \
    "Debian, Ubuntu, Kali:  sudo apt install python3 python3-venv" \
    "Fedora:                sudo dnf install python3" \
    "macOS:                 brew install python     (Homebrew: https://brew.sh)" \
    "Bringt die Distribution nur ein älteres Python mit, hilft eine neuere Version der Distribution." \
    "Danach ./setup.sh erneut starten.${LOG:+ Meldungen der Paketverwaltung: $LOG}"
fi

exec "$PYTHON" tools/einrichten.py "$@"
