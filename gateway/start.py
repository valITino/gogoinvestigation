#!/usr/bin/env python3
"""Startet das OSINT-Gateway als MCP-Server (stdio). Wird von .mcp.json aufgerufen.

.mcp.json ruft "${OSINT_PYTHON:-python3}" auf: unter Linux und macOS das python3 des Systems, unter
Windows das Python aus der Umgebungsvariablen OSINT_PYTHON (die Einrichtung setzt sie für das Benutzerkonto).
Dieser Starter wechselt von dort in das Python der .venv, wo die Pakete des Gateways liegen. So braucht
.mcp.json keinen Pfad, der nur auf einem Betriebssystem stimmt.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start(venv=True)

try:
    from gateway.server import main
except ModuleNotFoundError as e:  # klare Meldung statt Traceback im MCP-Log
    sys.stderr.write(
        f"OSINT-Gateway kann nicht starten: Python-Paket '{e.name}' fehlt.\n"
        f"Bitte im Projektordner '{plattform.SETUP}' ausführen. Das legt .venv an und installiert alles.\n")
    sys.exit(1)

if __name__ == "__main__":
    main()
