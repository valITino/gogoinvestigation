#!/usr/bin/env python3
"""MCP-Server «oberflaeche»: reicht Rückfragen von Claude Code an die Oberfläche weiter.

Claude Code startet ihn, wenn die Ermittlung aus der Oberfläche läuft (tools/ui/sitzung.py, --permission-prompt-tool).
Will Claude Code ein Werkzeug ausführen, für das die Einstellungen eine Rückfrage verlangen (aktive Massnahmen), ruft es
das Werkzeug `rueckfrage` auf. Der Server gibt die Frage an die Oberfläche weiter und wartet, bis der Sachbearbeiter im
Browser erlaubt oder ablehnt. Ohne Antwort gilt: abgelehnt.

Die Karte in der Umgebung dieses Servers taugt nur zum Fragen. Erlauben kann nur der Browser mit dem Geheimnis der Oberfläche.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

WARTEZEIT = 32 * 60
GROSSE_EINGABE = 20_000         # Zeichen. Darüber geht die Eingabe bei «erlauben» nicht als Kopie zurück


def fragen(tool_name: str, eingabe: object, tool_use_id: str = "") -> dict:
    """Schickt die Frage an die Oberfläche und liefert die Entscheidung in der Form, die Claude Code erwartet."""
    port, karte, fall = (os.environ.get(n, "") for n in ("OSINT_RUECKFRAGE_PORT", "OSINT_RUECKFRAGE_KARTE", "OSINT_RUECKFRAGE_FALL"))
    ablehnung = {"behavior": "deny", "message": "Die Oberfläche ist nicht erreichbar. Der Aufruf wurde nicht ausgeführt."}
    if not (port.isdigit() and karte and fall):
        return ablehnung
    koerper = json.dumps({"fall": fall, "karte": karte, "werkzeug": tool_name, "eingabe": eingabe, "tool_use_id": tool_use_id}, ensure_ascii=False).encode("utf-8")
    anfrage = urllib.request.Request(f"http://127.0.0.1:{port}/api/rueckfrage", data=koerper, method="POST",
                                     headers={"Content-Type": "application/json", "Host": f"127.0.0.1:{port}"})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(anfrage, timeout=WARTEZEIT) as r:      # nie über einen Proxy
            antwort = json.loads(r.read())
    except (OSError, ValueError, urllib.error.URLError):
        return ablehnung
    if antwort.get("erlauben") is True:
        antworten = antwort.get("antworten")
        if isinstance(antworten, dict) and antworten and isinstance(eingabe, dict):
            # Eine Frage der Ermittlung an den Sachbearbeiter (AskUserQuestion): Die Antworten gehen in der Eingabe zurück, je Frage
            # ihr Wortlaut als Schlüssel. So beschreibt es die Dokumentation von Claude Code (gelesen am 19.11.2026).
            return {"behavior": "allow", "updatedInput": {**eingabe, "answers": {str(k): str(v) for k, v in antworten.items()}}}
        # Die Eingabe geht unverändert zurück. Ältere Fassungen von Claude Code verlangen das Feld, bei sehr grossen Eingaben
        # sprengt die Kopie die Grenze für Werkzeugausgaben (Dokumentation: ab etwa 40 KB weglassen).
        klein = isinstance(eingabe, dict) and len(json.dumps(eingabe, ensure_ascii=False)) < GROSSE_EINGABE
        return {"behavior": "allow", "updatedInput": eingabe} if klein else {"behavior": "allow"}
    return {"behavior": "deny", "message": str(antwort.get("grund") or "Der Sachbearbeiter hat den Aufruf abgelehnt.")}


def bauen():
    """Der MCP-Server mit dem einen Werkzeug `rueckfrage`.

    Claude Code nimmt als Antwort genau einen Textblock mit JSON an und nichts daneben. Das MCP-SDK hängt einer Antwort
    sonst von sich aus ein Feld `structuredContent` an, und Claude Code verwirft sie dann («Permission prompt tool returned
    an invalid result»). Deshalb `structured_output=False`."""
    try:
        from mcp.server.mcpserver import MCPServer            # MCP-SDK ab 2.0
    except ImportError:  # pragma: no cover
        from mcp.server.fastmcp import FastMCP as MCPServer   # MCP-SDK 1.x
    server = MCPServer("oberflaeche", instructions="Reicht Rückfragen an den Sachbearbeiter weiter. Nur für Claude Code selbst, nicht für Agenten.")

    def rueckfrage(tool_name: str, input: dict, tool_use_id: str = "") -> str:      # noqa: A002  (Claude Code nennt das Feld so)
        """Fragt den Sachbearbeiter in der Oberfläche, ob ein Werkzeugaufruf erlaubt ist. Antwort als JSON: behavior allow oder deny."""
        return json.dumps(fragen(tool_name, input, tool_use_id), ensure_ascii=False)
    try:
        server.tool(structured_output=False)(rueckfrage)
    except TypeError:  # pragma: no cover  (ältere SDK kennen den Schalter nicht und hängen auch nichts an)
        server.tool()(rueckfrage)
    return server


def main() -> None:
    bauen().run("stdio")


if __name__ == "__main__":
    main()
