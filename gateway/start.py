#!/usr/bin/env python3
"""Startet das OSINT-Gateway als MCP-Server (stdio). Wird von .mcp.json aufgerufen."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from gateway.server import main
except ModuleNotFoundError as e:  # klare Meldung statt Traceback im MCP-Log
    sys.stderr.write(
        f"OSINT-Gateway kann nicht starten: Python-Paket '{e.name}' fehlt.\n"
        "Bitte im Projektordner './setup.sh' ausführen. Das legt .venv an und installiert alles.\n")
    sys.exit(1)

if __name__ == "__main__":
    main()
