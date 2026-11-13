#!/usr/bin/env python3
"""Selbsttest ohne Netz und ohne Schlüssel. Wird von tools/pruefen.py und setup.sh aufgerufen.

Prüft in einem Wegwerf-Projektordner, dass die Schutzmechanismen tatsächlich greifen:
Gateway über echtes MCP-stdio, Protokollkette samt Manipulationserkennung, Fall-Cache, Freigaben,
Wächter-Hook, Sitzungs-Hook (inklusive Belege für Robin), PII-Prüfung, Rapport-Prüfregeln und die
Übereinstimmung der Agenten-Definitionen mit den vorhandenen Werkzeugen.

    python3 tools/selbsttest.py          Ausgabe: eine Zeile je Test, Rückgabewert 1 bei Fehlern
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ECHT = Path(__file__).resolve().parents[1]
VENV = ECHT / ".venv" / "bin" / "python"
if "OSINT_SELBSTTEST" not in os.environ:
    # In einem Wegwerf-Ordner neu starten, damit kein echter Fall berührt wird.
    tmp = Path(tempfile.mkdtemp(prefix="osint-selbsttest-"))
    for name in ("gateway", "tools", ".claude", ".mcp.json"):
        quelle = ECHT / name
        (shutil.copytree(quelle, tmp / name, ignore=shutil.ignore_patterns("__pycache__", "settings.local.json"))
         if quelle.is_dir() else shutil.copy2(quelle, tmp / name))
    (tmp / "faelle").mkdir()
    python = str(VENV) if VENV.is_file() else sys.executable
    umgebung = {k: v for k, v in os.environ.items() if not k.endswith(("_API_KEY", "_TOKEN")) and k != "OSINT_PROXY"}
    code = subprocess.run([python, str(tmp / "tools" / "selbsttest.py")],
                          env={**umgebung, "OSINT_SELBSTTEST": "1", "OSINT_PROJEKT": str(tmp),
                               "CLAUDE_PROJECT_DIR": str(tmp), "OSINT_ECHT": str(ECHT)}).returncode
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(code)

PROJEKT = Path(os.environ["OSINT_PROJEKT"])
sys.path.insert(0, str(PROJEKT))

try:
    import asyncio

    import httpx

    from gateway import kern, quellen_infrastruktur as infra, quellen_web as web
    from gateway.akte import kette_pruefen
    from gateway.quellen import ROBIN_WERKZEUGE, alle_werkzeuge
    from tools import fall as fallwerkzeug, rapport
    from tools.pii_pruefung import pruefen as pii_pruefen
except ModuleNotFoundError as e:
    print(f"✗ Python-Paket '{e.name}' fehlt. Bitte ./setup.sh ausführen.")
    sys.exit(1)

FALL = "TEST-0001"
ergebnisse: list[tuple[bool, str, str]] = []


def test(name: str):
    def huelle(fn):
        try:
            fn()
            ergebnisse.append((True, name, ""))
        except AssertionError as e:
            ergebnisse.append((False, name, str(e) or "Erwartung nicht erfüllt"))
        except Exception as e:  # ein abgestürzter Test ist ein fehlgeschlagener Test
            ergebnisse.append((False, name, f"{type(e).__name__}: {e}"))
        return fn
    return huelle


def hook(skript: str, ereignis: dict) -> tuple[int, dict]:
    r = subprocess.run([sys.executable, str(PROJEKT / ".claude" / "hooks" / skript)],
                       input=json.dumps({"session_id": "test-sitzung", "cwd": str(PROJEKT), **ereignis}),
                       text=True, capture_output=True, env={**os.environ, "CLAUDE_PROJECT_DIR": str(PROJEKT)})
    try:
        ausgabe = json.loads(r.stdout) if r.stdout.strip() else {}
    except json.JSONDecodeError:
        ausgabe = {"roh": r.stdout}
    return r.returncode, ausgabe


def abgelehnt(ausgabe: dict) -> bool:
    return (ausgabe.get("hookSpecificOutput") or {}).get("permissionDecision") == "deny"


def antwort(anfrage: httpx.Request) -> httpx.Response:
    if anfrage.url.host == "internetdb.shodan.io":
        return httpx.Response(200, json={"ip": anfrage.url.path.strip("/"), "ports": [443], "hostnames": [], "tags": [], "vulns": [], "cpes": []})
    if anfrage.url.host == "api.abuseipdb.com":
        return httpx.Response(200, json={"data": {"ipAddress": "8.8.8.8", "abuseConfidenceScore": 0, "totalReports": 0}})
    if anfrage.url.host == "api.shodan.io":
        return httpx.Response(401, text="Invalid API key")
    return httpx.Response(404, json={})


def aufruf(fn, **argumente) -> dict:
    return asyncio.run(fn(FALL, **argumente))


# --------------------------------------------------------------------------- Vorbereitung

pfad = PROJEKT / "faelle" / FALL
for ordner in fallwerkzeug.UNTERORDNER:
    (pfad / ordner).mkdir(parents=True)
fallwerkzeug.schreiben(pfad / "fall.json", {"fall_id": FALL, "titel": "Selbsttest", "freigaben": {}})
kern.transport = httpx.MockTransport(antwort)
os.environ["ABUSEIPDB_API_KEY"] = os.environ["SHODAN_API_KEY"] = "GEHEIMER-TESTSCHLUESSEL-123"
ZWECK = "Selbsttest der Einrichtung, keine echte Abfrage"


# --------------------------------------------------------------------------- Tests

@test("Gateway startet als MCP-Server und meldet alle Werkzeuge")
def _():
    p = subprocess.Popen([sys.executable, str(PROJEKT / "gateway" / "start.py")], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        def senden(nachricht: dict) -> None:
            p.stdin.write(json.dumps(nachricht) + "\n")
            p.stdin.flush()

        def lesen(kennung: int) -> dict:
            while True:
                zeile = p.stdout.readline()
                assert zeile, f"Server hat die Verbindung beendet: {p.stderr.read()[:300]}"
                nachricht = json.loads(zeile)
                if nachricht.get("id") == kennung:
                    return nachricht
        senden({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "selbsttest", "version": "1"}}})
        assert "result" in lesen(1), "keine Antwort auf initialize"
        senden({"jsonrpc": "2.0", "method": "notifications/initialized"})
        senden({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        namen = {t["name"] for t in lesen(2)["result"]["tools"]}
        erwartet = alle_werkzeuge() | {"fall_status"}
        assert namen == erwartet, f"Abweichung: fehlt {sorted(erwartet - namen)}, zu viel {sorted(namen - erwartet)}"
        senden({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "fall_status", "arguments": {"fall": FALL}}})
        text = json.dumps(lesen(3)["result"])
        assert FALL in text and "freigaben" in text, "fall_status liefert nicht den erwarteten Inhalt"
    finally:
        p.kill()


@test("Abfrage wird protokolliert, Rohdaten werden abgelegt, Schlüssel bleiben draussen")
def _():
    r = aufruf(infra.abuseipdb_pruefen, zweck=ZWECK, ip="8.8.8.8")
    assert r["ergebnis"] == "ok" and r["protokoll_id"] == "P-0001", r
    assert (PROJEKT / r["rohdaten"]).is_file(), "Rohdatei fehlt"
    inhalt = (pfad / "protokoll" / "abfragen.jsonl").read_text()
    assert "GEHEIMER-TESTSCHLUESSEL" not in inhalt, "API-Schlüssel steht im Protokoll"
    r = aufruf(infra.shodan_host, zweck=ZWECK, ip="8.8.8.8")
    assert r["ergebnis"] == "fehler" and "Schlüssel" in r["fehler"], r
    inhalt = (pfad / "protokoll" / "abfragen.jsonl").read_text()
    assert "GEHEIMER-TESTSCHLUESSEL" not in inhalt and "key=***" in inhalt, "Shodan-Schlüssel nicht maskiert"


@test("Abfrage ohne Zweck oder ohne Fall wird abgewiesen")
def _():
    assert aufruf(infra.shodan_internetdb, zweck="x", ip="8.8.8.8")["ergebnis"] == "nicht_ausgefuehrt"
    assert asyncio.run(infra.shodan_internetdb("GIBT-ES-NICHT", ZWECK, "8.8.8.8"))["ergebnis"] == "nicht_ausgefuehrt"
    assert aufruf(infra.shodan_internetdb, zweck=ZWECK, ip="192.168.1.1")["ergebnis"] == "nicht_ausgefuehrt"


@test("Wiederholte Abfrage kommt aus dem Fall-Cache und wird trotzdem protokolliert")
def _():
    erste = aufruf(infra.shodan_internetdb, zweck=ZWECK, ip="8.8.8.8")
    zweite = aufruf(infra.shodan_internetdb, zweck=ZWECK, ip="8.8.8.8")
    assert zweite.get("aus_cache") == erste["protokoll_id"] and zweite["protokoll_id"] != erste["protokoll_id"], zweite


@test("Aktive Massnahme ohne Freigabe wird abgelehnt und der Versuch protokolliert")
def _():
    r = aufruf(web.urlquery_einreichen, zweck=ZWECK, url="https://example.com/")
    assert r["ergebnis"] == "nicht_ausgefuehrt", r   # Schlüssel fehlt: gar nicht erst versucht
    os.environ["URLQUERY_API_KEY"] = "x" * 12
    r = aufruf(web.urlquery_einreichen, zweck=ZWECK, url="https://example.com/")
    assert r["ergebnis"] == "nicht_ausgefuehrt" and r.get("protokoll_id"), r
    letzte = json.loads((pfad / "protokoll" / "abfragen.jsonl").read_text().splitlines()[-1])
    assert letzte["ergebnis"] == "abgelehnt" and letzte["freigabe"] == "aktiv", letzte


@test("Protokollkette ist stimmig und erkennt Manipulation")
def _():
    assert kette_pruefen(FALL)["ok"], kette_pruefen(FALL)["fehler"]
    datei = pfad / "protokoll" / "abfragen.jsonl"
    original = datei.read_text()
    datei.write_text(original.replace("8.8.8.8", "9.9.9.9", 1))
    assert not kette_pruefen(FALL)["ok"], "veränderter Eintrag blieb unbemerkt"
    datei.write_text("\n".join(original.splitlines()[1:]) + "\n")
    assert not kette_pruefen(FALL)["ok"], "gelöschter Eintrag blieb unbemerkt"
    datei.write_text(original)
    roh = next((pfad / "rohdaten").glob("P-0001_*"))
    alt = roh.read_bytes()
    roh.chmod(0o644)
    roh.write_bytes(alt + b" ")
    assert not kette_pruefen(FALL)["ok"], "veränderte Rohdatei blieb unbemerkt"
    roh.write_bytes(alt)
    assert kette_pruefen(FALL)["ok"]


@test("PII-Prüfung sperrt AHV-Nummer, IBAN, Telefon und lässt Indikatoren durch")
def _():
    funde, platzhalter = pii_pruefen("[PERSON_01], AHV 756.1234.5678.97, Tel. 079 123 45 67, IBAN CH93 0076 2011 6238 5295 7")
    arten = {f.art for f in funde if f.stufe == "sperre"}
    assert {"AHV-Nummer", "Telefonnummer", "IBAN"} <= arten, arten
    assert platzhalter == {"PERSON": 1}
    funde, _ = pii_pruefen("IP 203.0.113.7, Hash " + "a1" * 32 + ", Zeit 20260928101500, hxxps://boese[.]example/login")
    assert not [f for f in funde if f.stufe == "sperre"], [(f.art, f.maske) for f in funde]


@test("Wächter: ungeprüftes Dokument im Eingang ist nicht lesbar, geprüftes schon")
def _():
    fremd = pfad / "eingang" / "von_hand_kopiert.md"
    fremd.write_text("Hans Muster, 079 123 45 67")
    _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": str(fremd)}})
    assert abgelehnt(a), "Lesen eines ungeprüften Dokuments wurde nicht verhindert"
    _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Grep", "tool_input": {"pattern": "Muster", "path": "faelle"}})
    assert abgelehnt(a), "Grep über ungeprüfte Dokumente wurde nicht verhindert"
    _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"cat faelle/{FALL}/eingang/von_hand_kopiert.md"}})
    assert abgelehnt(a), "cat auf ein ungeprüftes Dokument wurde nicht verhindert"
    fremd.unlink()
    sauber = PROJEKT / "sauber.md"
    sauber.write_text("[PERSON_01] meldet einen Zugriff von 203.0.113.7.")
    with contextlib.redirect_stdout(io.StringIO()):
        assert fallwerkzeug.aufnehmen(FALL, [str(sauber)], None, None)
    _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": str(pfad / "eingang" / "sauber.md")}})
    assert not abgelehnt(a), f"geprüftes Dokument wurde gesperrt: {a}"
    (pfad / "eingang" / "sauber.md").write_text("nachträglich verändert")
    _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": str(pfad / "eingang" / "sauber.md")}})
    assert abgelehnt(a), "nachträglich verändertes Dokument blieb lesbar"


@test("Wächter: Stammdaten, Protokoll, Gateway und Hooks sind schreibgeschützt")
def _():
    for ziel in (f"faelle/{FALL}/fall.json", f"faelle/{FALL}/protokoll/abfragen.jsonl", f"faelle/{FALL}/rohdaten/x.json",
                 "gateway/kern.py", ".claude/settings.json", ".claude/hooks/waechter.py", ".mcp.json", ".env"):
        _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": {"file_path": ziel, "content": "x"}})
        assert abgelehnt(a), f"Schreiben nach {ziel} wurde nicht verhindert"
    _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Write",
                                "tool_input": {"file_path": f"faelle/{FALL}/befunde.json", "content": "{}"}})
    assert not abgelehnt(a), "befunde.json muss schreibbar sein"


@test("Wächter: keine Selbstfreigabe, kein Netzwerk an der Protokollierung vorbei")
def _():
    for befehl in (f"python3 tools/fall.py freigabe {FALL} darkweb --durch ich --vermerk x", "curl https://example.com",
                   "cd /tmp && wget http://example.com/x", f"python3 tools/fall.py aufnehmen {FALL} x.md --trotzdem egal"):
        _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": befehl}})
        assert abgelehnt(a), f"nicht verhindert: {befehl}"
    _, a = hook("waechter.py", {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": f"python3 tools/rapport.py {FALL}"}})
    assert not abgelehnt(a), "rapport.py muss ausführbar sein"
    r = subprocess.run([sys.executable, str(PROJEKT / "tools" / "fall.py"), "freigabe", FALL, "aktiv", "--durch", "x", "--vermerk", "y"],
                       capture_output=True, text=True, stdin=subprocess.DEVNULL)
    assert r.returncode != 0 and "Terminal" in r.stderr, "Freigabe ohne Terminal wurde angenommen"


@test("Robin läuft nur mit Freigabe darkweb, Antworten werden als Beleg X-… gesichert")
def _():
    robin = {"hook_event_name": "PreToolUse", "tool_name": "mcp__robin__robin_search", "tool_input": {"query": "musterlocker"}}
    _, a = hook("waechter.py", robin)
    assert abgelehnt(a), "Robin ohne erkannten Fall wurde nicht verhindert"
    hook("protokoll_hook.py", {"hook_event_name": "PostToolUse", "tool_name": "mcp__osint__fall_status",
                               "tool_input": {"fall": FALL}, "tool_response": {"fall": FALL}})
    _, a = hook("waechter.py", robin)
    assert abgelehnt(a), "Robin ohne Freigabe darkweb wurde nicht verhindert"
    daten = json.loads((pfad / "fall.json").read_text())
    daten["freigaben"] = {"darkweb": {"erteilt": True, "durch": "Selbsttest", "am": "2026-01-01T00:00:00+00:00", "vermerk": "Test"}}
    fallwerkzeug.schreiben(pfad / "fall.json", daten)
    _, a = hook("waechter.py", robin)
    assert not abgelehnt(a), f"Robin trotz Freigabe gesperrt: {a}"
    code, a = hook("protokoll_hook.py", {"hook_event_name": "PostToolUse", "tool_name": "mcp__robin__robin_search",
                                         "agent_type": "darkweb-analyst", "tool_use_id": "toolu_1",
                                         "tool_input": {"query": "musterlocker"}, "tool_response": [{"type": "text", "text": "Treffer …"}]})
    assert code == 0 and "X-0001" in json.dumps(a), f"keine Belegnummer zurückgemeldet: {a}"
    stand = kette_pruefen(FALL)
    assert stand["ok"] and stand["anzahl_extern"] == 1, stand
    assert (pfad / "rohdaten" / "extern" / "X-0001_robin_search.json").is_file()


@test("Sitzungs-Hook ordnet Abfragen dem Agenten zu")
def _():
    hook("protokoll_hook.py", {"hook_event_name": "UserPromptSubmit", "prompt": f"/ermittlung {FALL}"})
    hook("protokoll_hook.py", {"hook_event_name": "PostToolUse", "tool_name": "mcp__osint__shodan_internetdb", "agent_type": "infrastruktur-analyst",
                               "tool_input": {"fall": FALL, "ip": "8.8.8.8"},
                               "tool_response": [{"type": "text", "text": json.dumps({"protokoll_id": "P-0003", "ergebnis": "ok"})}]})
    zeilen = [json.loads(z) for z in (PROJEKT / "protokoll" / "sitzungen" / "test-sitzung.jsonl").read_text().splitlines()]
    assert any(z.get("protokoll_id") == "P-0003" and z.get("agent") == "infrastruktur-analyst" for z in zeilen)
    assert any(z.get("ereignis") == "UserPromptSubmit" and z.get("fall") == FALL for z in zeilen)


@test("Rapport wird ohne Belege, bei erfundenen Belegen und bei überhöhter Sicherheit verweigert")
def _():
    protokoll = {e["id"]: e for e in kern.protokoll_lesen(pfad / "protokoll" / "abfragen.jsonl")}
    basis = {"zusammenfassung": ["x"], "luecken": ["x"],
             "indikatoren": [{"id": "I-01", "typ": "ip", "wert": "8.8.8.8", "herkunft": "Test", "bewertung": "unauffaellig", "belege": ["P-0001"]}]}

    def maengel(befund: dict) -> list[str]:
        voll = {"id": "B-01", "titel": "t", "text": "t", "erlaeuterung": "Eine Erklärung in einfachen Worten, lang genug.",
                "indikatoren": ["I-01"], "gegenpruefung": "bestaetigt", **befund}
        return rapport.pruefen({**basis, "befunde": [voll]}, protokoll, entwurf=False)[0]

    assert not maengel({"art": "feststellung", "sicherheit": "mittel", "belege": ["P-0001"]})
    assert any("mindestens einen Beleg" in m for m in maengel({"art": "feststellung", "sicherheit": "mittel", "belege": []}))
    assert any("steht nicht im" in m for m in maengel({"art": "feststellung", "sicherheit": "mittel", "belege": ["P-0999"]}))
    assert any("zwei verschiedenen Quellen" in m for m in maengel({"art": "feststellung", "sicherheit": "hoch", "belege": ["P-0001"]}))
    assert any("belegt nichts" in m for m in maengel({"art": "feststellung", "sicherheit": "mittel", "belege": ["P-0002"]}))
    assert any("gegengeprüft" in m for m in maengel({"art": "feststellung", "sicherheit": "mittel", "belege": ["P-0001"], "gegenpruefung": "offen"}))
    assert any("Hypothese" in m for m in maengel({"art": "hypothese", "sicherheit": "hoch", "belege": []}))


@test("Agenten und Einstellungen nennen nur Werkzeuge, die es gibt")
def _():
    bekannt = {f"mcp__osint__{w}" for w in alle_werkzeuge() | {"fall_status"}} | {f"mcp__robin__{w}" for w in ROBIN_WERKZEUGE}
    eingebaut = {"Read", "Grep", "Glob", "Write", "Edit", "Bash"}
    agenten = sorted((PROJEKT / ".claude" / "agents").glob("*.md"))
    assert len(agenten) >= 6, "Agenten-Definitionen fehlen"
    skills = {p.parent.name for p in (PROJEKT / ".claude" / "skills").glob("*/SKILL.md")}
    for datei in agenten:
        kopf = datei.read_text().split("---")[1]
        werkzeuge = [w.strip() for w in re.search(r"^tools:\s*(.+)$", kopf, re.M).group(1).split(",")]
        unbekannt = [w for w in werkzeuge if w not in bekannt | eingebaut]
        assert not unbekannt, f"{datei.name}: unbekannte Werkzeuge {unbekannt}"
        assert re.search(r"^model:\s*inherit$", kopf, re.M), f"{datei.name}: model ist nicht 'inherit'"
        for skill in re.findall(r"^\s+-\s+(\S+)$", kopf, re.M):
            assert skill in skills, f"{datei.name}: Skill '{skill}' gibt es nicht"
    regeln = json.loads((PROJEKT / ".claude" / "settings.json").read_text())["permissions"]
    for regel in regeln["allow"] + regeln["ask"]:
        if regel.startswith("mcp__osint__"):
            muster = re.escape(regel).replace(r"\*", ".*")
            assert any(re.fullmatch(muster, b) for b in bekannt), f"settings.json: Regel '{regel}' trifft kein Werkzeug"
    json.loads((PROJEKT / ".mcp.json").read_text())
    aktiv = {"mcp__osint__urlquery_einreichen", "mcp__osint__wayback_sichern", "mcp__osint__webcheck_aktiv"}
    assert aktiv <= set(regeln["ask"]), "aktive Werkzeuge müssen unter 'ask' stehen"
    for datei in agenten:
        assert not aktiv & set(re.findall(r"mcp__osint__\w+", datei.read_text().split("---")[1])), f"{datei.name} darf keine aktiven Werkzeuge haben"


# --------------------------------------------------------------------------- Ausgabe

for ok, name, grund in ergebnisse:
    print(f"{'✓' if ok else '✗'} {name}" + (f"\n    {grund}" if grund else ""))
fehler = sum(1 for ok, _, _ in ergebnisse if not ok)
print(f"\n{len(ergebnisse) - fehler} von {len(ergebnisse)} Selbsttests bestanden.")
sys.exit(1 if fehler else 0)
