"""Der lokale Server der Oberfläche. Nur Standardbibliothek.

Schutz, nicht verhandelbar:
  - Der Server hört nur auf 127.0.0.1. Anfragen mit fremdem Host-Kopf weist er ab (Schutz vor DNS-Rebinding),
    ebenso Anfragen, die eine fremde Seite auslöst (Origin, Sec-Fetch-Site).
  - Lesen geht mit GET und HEAD. Ändern geht nur mit POST und nur mit dem Geheimnis, das beim Start entsteht
    (tools/ui/bedienung.py). Läuft die Oberfläche im Modus «nur lesen», gibt es keinen Weg, über sie etwas zu ändern.
  - Was echte Angaben zeigen kann (der Akten-Eingang mit den Namen hochgeladener Dateien, der Bildschirm der
    Pseudonymisierung), gibt der Server nur per POST und nur gegen das Geheimnis heraus. Eine hochgeladene Datei liest
    er erst ein, wenn die Anfrage das Geheimnis trägt.
  - Die Seite lädt nichts von aussen (Content-Security-Policy). Skripte kommen nur aus der eigenen Datei app.js.
  - Rohdateien liefert er als Text oder als Bild aus, nie als HTML. Was aus einer Quelle stammt, wird nicht ausgeführt.
  - Gespeicherte Dokumente der Akte (Abschlussrapport.html) laufen in einem Rahmen ohne Skripte.
"""
from __future__ import annotations

import json
import mimetypes
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from tools._html import STIL
from tools.ui import bedienung as bedienung_modul, daten, formulare, paket, seiten, sitzung as sitzung_modul

ORT = Path(__file__).resolve().parent
STATISCH = {"/app.js": ("app.js", "text/javascript; charset=utf-8"), "/app.css": ("app.css", "text/css; charset=utf-8"),
            "/bedienung.css": ("bedienung.css", "text/css; charset=utf-8")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; connect-src 'self'; frame-src 'self'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'self'")
CSP_DOKUMENT = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox; base-uri 'none'; form-action 'none'"
SEITE = """<!DOCTYPE html>
<html lang="de-CH"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT-Arbeitsplatz</title><link rel="stylesheet" href="/basis.css"><link rel="stylesheet" href="/app.css"><link rel="stylesheet" href="/bedienung.css"></head>
<body><a class="sprung" href="#mitte">Zum Inhalt</a>
<div id="rahmen">
<nav id="nav" aria-label="Navigation"></nav>
<div id="haupt"><header id="kopf"></header><div id="mitte" tabindex="-1" aria-live="polite"><p class="klein">Die Oberfläche wird geladen …</p></div></div>
<aside id="rand" aria-label="Arbeitsspur und Chat" hidden><section id="spur" aria-label="Arbeitsspur"></section><section id="chatrand" aria-label="Chat" hidden></section></aside>
</div>
<div id="rueckfrage-ebene" hidden></div>
<noscript><p class="banner">Die Oberfläche braucht JavaScript. Es wird nur die eigene Datei app.js geladen, nichts von aussen.</p></noscript>
<script src="/app.js"></script></body></html>
"""
ANSICHTEN = {"uebersicht": ("Fallübersicht", lambda f, a: seiten.uebersicht(f)), "rapport": ("Rapport", lambda f, a: seiten.rapport_seite(f)),
             "indikatoren": ("Indikatoren", lambda f, a: seiten.indikatoren_seite(f)), "indikator": ("Datenblatt", lambda f, a: seiten.datenblatt(f, a)),
             "beleg": ("Beleg", lambda f, a: seiten.beleg_seite(f, a)), "roh": ("Rohdatei", lambda f, a: seiten.roh_seite(f, a)),
             "rohdaten": ("Rohdaten", lambda f, a: seiten.rohdaten_seite(f)), "suche": ("Suche", lambda f, a: seiten.suche_seite(f, a)),
             "dokumente": ("Dokumente", lambda f, a: seiten.dokumente_seite(f)), "dokument": ("Dokument", lambda f, a: seiten.dokument_seite(f, a)),
             "ergebnisse": ("Ergebnisse", lambda f, a: seiten.ergebnisse_seite(f))}
OHNE_GEHEIMNIS = ("Diese Anfrage trägt das Geheimnis der Oberfläche nicht. Es wurde nichts geändert. "
                  "Bedienen lässt sich die Oberfläche nur aus dem Browserfenster, das sie beim Start geöffnet hat.")


class Zustand:
    """Die geöffneten Fälle. Eine Sperre hält gleichzeitige Anfragen auseinander."""

    def __init__(self) -> None:
        self.faelle: dict[str, daten.Fall] = {}
        self.sperre = threading.Lock()

    def fall(self, fall_id: str) -> daten.Fall:
        fall = self.faelle.get(fall_id)
        if fall is None or not (fall.pfad / "fall.json").is_file():      # ein Fall kann gelöscht worden sein
            self.faelle.pop(fall_id, None)
            fall = self.faelle[fall_id] = daten.Fall(fall_id)
        return fall


KOERPER = 8 * 1024 * 1024       # grösste Anfrage in JSON. Dateien kommen nicht als JSON, sondern einzeln über /api/hochladen


class Bearbeiter(BaseHTTPRequestHandler):
    server_version = "OSINT-Oberflaeche"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    zustand: Zustand
    erlaubt: set
    bedienung: "bedienung_modul.Bedienung | None" = None

    def log_message(self, *args) -> None:       # keine Zugriffszeilen im Terminal
        pass

    # ---- Antworten
    def senden(self, status: int, inhalt: bytes, typ: str, csp: str = CSP, weitere: dict | None = None) -> None:
        self.send_response(status)
        for name, wert in {"Content-Type": typ, "Content-Length": str(len(inhalt)), "Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff",
                           "Referrer-Policy": "no-referrer", "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "same-origin",
                           "X-Frame-Options": "SAMEORIGIN", **(weitere or {})}.items():
            self.send_header(name, wert)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(inhalt)

    def json(self, daten_: object, status: int = 200) -> None:
        self.senden(status, json.dumps(daten_, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def fehler(self, status: int, text: str) -> None:
        if self.path.startswith("/api/"):
            self.json({"fehler": text}, status)
        else:
            self.senden(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    # ---- Schutz
    def zulaessig(self) -> bool:
        if (self.headers.get("Host") or "").strip().lower() not in self.erlaubt:
            self.fehler(403, "Abgewiesen: Diese Oberfläche antwortet nur unter 127.0.0.1 und localhost.")
            return False
        herkunft = self.headers.get("Origin")
        if herkunft and urlsplit(herkunft).netloc.lower() not in self.erlaubt:
            self.fehler(403, "Abgewiesen: Die Anfrage kommt von einer fremden Seite.")
            return False
        if (self.headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
            self.fehler(403, "Abgewiesen: Die Anfrage kommt von einer fremden Seite.")
            return False
        return True

    def do_GET(self) -> None:
        if not self.zulaessig():
            return
        try:
            with self.zustand.sperre:
                self.verteilen()
        except daten.NichtGefunden as e:
            self.fehler(404, str(e))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:      # eine Ansicht darf scheitern, der Server läuft weiter
            traceback.print_exc(file=sys.stderr)
            self.fehler(500, f"Die Ansicht konnte nicht aufgebaut werden ({type(e).__name__}). Einzelheiten stehen im Terminal, in dem die Oberfläche läuft.")

    do_HEAD = do_GET

    def nicht_erlaubt(self) -> None:
        self.send_response(405)
        self.send_header("Allow", "GET, HEAD, POST" if self.bedienung is not None else "GET, HEAD")
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = nicht_erlaubt

    # ---- Ändern: nur mit POST, nur mit dem Geheimnis des Starts. Angaben kommen als JSON, eine Datei als Rohinhalt
    def do_POST(self) -> None:
        if self.bedienung is None:
            return self.nicht_erlaubt()
        if not self.zulaessig():
            self.close_connection = True
            return
        url = urlsplit(self.path)
        weg = [unquote(t) for t in url.path.split("/") if t]
        try:
            laenge = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            laenge = -1
        typ = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        b = self.bedienung
        try:
            if weg == ["api", "hochladen"]:
                return self.hochladen(parse_qs(url.query), laenge, typ)
            if laenge < 0 or laenge > KOERPER or typ != "application/json":
                self.close_connection = True
                return self.fehler_json(400, "Die Anfrage hat nicht die erwartete Form.")
            try:
                angaben = json.loads(self.rfile.read(laenge) or b"{}")
                if not isinstance(angaben, dict):
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                return self.fehler_json(400, "Die Anfrage hat nicht die erwartete Form.")
            if weg == ["api", "anmelden"]:      # der eine Weg ohne Geheimnis: Er gibt es heraus, genau einmal, gegen den Startcode
                return self.json({"geheimnis": b.anmelden(str(angaben.get("startcode") or ""))})
            if weg == ["api", "rueckfrage"]:    # die Frage einer gesteuerten Sitzung: Ihre Karte taugt nur zum Fragen, nie zum Erlauben
                return self.json(sitzung_modul.rueckfrage(b, angaben))
            if not b.berechtigt(self.headers.get("X-OSINT-Geheimnis")):
                return self.fehler_json(403, OHNE_GEHEIMNIS)
            if len(weg) == 3 and weg[:2] == ["api", "aktion"]:
                return self.json(self.aktion(weg[2], angaben))
            # Ansichten, die echte Angaben zeigen können: nur per POST und nur mit Geheimnis
            if weg == ["api", "klartext", "pseudo"]:
                pseudo = b.pseudo_holen(angaben.get("vorgang"))
                with b.sperre:
                    seite = formulare.klartext_seite(pseudo, str(angaben.get("vorgang")))
                return self.json({"titel": "Pseudonymisieren (lokal, Klartext)", "html": seite, "ziel": pseudo.ziel})
            if weg == ["api", "klartext", "korb"]:
                ziel = str(angaben.get("ziel") or "").strip()
                with b.sperre:
                    seite = formulare.akten_seite(b, ziel)
                return self.json({"titel": f"Akten · {ziel}" if ziel else "Neuer Fall", "html": seite})
            return self.fehler_json(404, "Diese Aktion gibt es nicht.")
        except bedienung_modul.Fehler as e:
            return self.fehler_json(e.status, str(e))
        except (daten.NichtGefunden, FileNotFoundError) as e:
            return self.fehler_json(404, str(e))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as e:      # eine Aktion darf scheitern, der Server läuft weiter. Die Meldung nennt nie Inhalte
            traceback.print_exc(file=sys.stderr)
            return self.fehler_json(500, f"Die Aktion ist gescheitert ({type(e).__name__}). Einzelheiten stehen im Terminal, in dem die Oberfläche läuft.")

    def fehler_json(self, status: int, text: str) -> None:
        self.json({"fehler": text}, status)

    def hochladen(self, frage: dict, laenge: int, typ: str) -> None:
        """Eine Datei für den Akten-Eingang: der Rohinhalt im Körper der Anfrage, ihr Name (mit Ordnern) im Kopf X-OSINT-Name.
        Erst das Geheimnis, dann der Inhalt: Ohne Geheimnis liest der Server nichts ein."""
        b = self.bedienung
        if not b.berechtigt(self.headers.get("X-OSINT-Geheimnis")):
            self.close_connection = True
            return self.fehler_json(403, OHNE_GEHEIMNIS)
        name = unquote(self.headers.get("X-OSINT-Name") or "")
        if typ != "application/octet-stream" or laenge < 0 or not name.strip():
            self.close_connection = True
            return self.fehler_json(400, "Die Anfrage hat nicht die erwartete Form.")
        if laenge > bedienung_modul.DATEI_GROESSE:
            self.close_connection = True
            return self.fehler_json(413, f"{bedienung_modul.sauberer_name(name)[0]}: grösser als {bedienung_modul.DATEI_GROESSE // (1024 * 1024)} MB, nicht angenommen.")
        inhalt = self.rfile.read(laenge)
        if len(inhalt) != laenge:
            self.close_connection = True
            return self.fehler_json(400, "Die Datei ist nicht vollständig angekommen.")
        return self.json(b.hochladen((frage.get("ziel") or [""])[0], name, inhalt))

    def aktion(self, name: str, angaben: dict) -> dict:
        b = self.bedienung
        if name in bedienung_modul.AKTIONEN:
            return getattr(b, name)(angaben)
        if name in sitzung_modul.AKTIONEN:
            return getattr(sitzung_modul, name)(b, {**angaben, "_port": self.server.server_address[1]})
        raise bedienung_modul.Fehler("Diese Aktion gibt es nicht.", 404)

    # ---- Wege
    def verteilen(self) -> None:
        url = urlsplit(self.path)
        weg = [unquote(t) for t in url.path.split("/") if t]
        frage = parse_qs(url.query)
        if url.path == "/":
            return self.senden(200, SEITE.encode("utf-8"), "text/html; charset=utf-8")
        if len(weg) == 2 and weg[0] == "klartext" and self.bedienung is not None:
            # Eine Datei aus der Ablage ausserhalb des Projekts, gegen eine Karte für genau einen Abruf. Skripte laufen darin nicht.
            try:
                pfad = self.bedienung.ticket_einloesen(weg[1])
            except bedienung_modul.Fehler as e:
                raise daten.NichtGefunden(str(e)) from e
            typ = "text/html; charset=utf-8" if pfad.suffix == ".html" else "text/plain; charset=utf-8"
            return self.senden(200, pfad.read_bytes(), typ, CSP_DOKUMENT)
        if url.path == "/basis.css":
            return self.senden(200, STIL.encode("utf-8"), "text/css; charset=utf-8")
        if url.path in STATISCH:
            name, typ = STATISCH[url.path]
            return self.senden(200, (ORT / name).read_bytes(), typ)
        if weg[:1] == ["api"]:
            return self.api(weg[1:], frage)
        if len(weg) >= 4 and weg[0] == "fall" and weg[2] in ("datei", "rohdaten"):
            fall = self.zustand.fall(weg[1])
            name = "/".join(weg[3:]) if weg[2] == "datei" else "rohdaten/" + "/".join(weg[3:])
            roh = fall.rohdatei(name)
            if roh.form == "fehlt":
                raise daten.NichtGefunden("Diese Rohdatei fehlt in der Fallakte.")
            typ = daten.BILD.get(roh.pfad.suffix.lower(), "text/plain; charset=utf-8")      # nie text/html: Fremdes wird nicht ausgeführt
            return self.senden(200, roh.pfad.read_bytes(), typ, "default-src 'none'; sandbox")
        if len(weg) == 4 and weg[0] == "fall" and weg[2] == "dokument":
            pfad = self.zustand.fall(weg[1]).dokument(weg[3])
            holen = {"Content-Disposition": f'attachment; filename="{weg[1]}_{pfad.name}"'}
            if pfad.suffix == ".html":      # zum Ansehen im Rahmen ohne Skripte, mit ?holen als Datei zum Mitnehmen
                return self.senden(200, pfad.read_bytes(), "text/html; charset=utf-8", CSP_DOKUMENT, holen if "holen" in frage else None)
            typ = "application/pdf" if pfad.suffix == ".pdf" else "text/csv; charset=utf-8"
            return self.senden(200, pfad.read_bytes(), typ, "default-src 'none'; sandbox", holen)
        if len(weg) == 3 and weg[0] == "fall" and weg[2] == "befunde.json":
            pfad = self.zustand.fall(weg[1]).pfad / "befunde.json"
            if not pfad.is_file():
                raise daten.NichtGefunden("befunde.json gibt es in diesem Fall noch nicht.")
            return self.senden(200, pfad.read_bytes(), "application/json; charset=utf-8", "default-src 'none'; sandbox",
                               {"Content-Disposition": f'attachment; filename="{weg[1]}_befunde.json"'})
        if len(weg) == 3 and weg[0] == "fall" and weg[2] == "paket.zip":
            # Alles zum Mitnehmen als ein Archiv. Es entsteht im Speicher und liest die Fallakte nur
            fall = self.zustand.fall(weg[1])
            teile = {t for t in ",".join(frage.get("teile") or []).split(",") if t in paket.TEILE}
            sitzung = self.bedienung.ermittlungen.get(fall.id) if self.bedienung is not None else None
            verlauf = [dict(z) for z in sitzung.verlauf] if sitzung is not None else None
            inhalt, _ = paket.bauen(fall, teile, verlauf, sitzung_modul.verlauf_datei(self.bedienung) if verlauf else "")
            return self.senden(200, inhalt, "application/zip", "default-src 'none'; sandbox",
                               {"Content-Disposition": f'attachment; filename="{weg[1]}_{paket.dateiname(teile)}.zip"'})
        raise daten.NichtGefunden("Diese Adresse gibt es in der Oberfläche nicht.")

    def api(self, weg: list[str], frage: dict) -> None:
        if weg == ["faelle"]:
            return self.json({"titel": "Fälle", "html": seiten.faelle_seite(self.bedienung is not None), "faelle": daten.faelle()})
        if weg == ["rueckfragen"]:      # Rückfragen, die gerade auf den Sachbearbeiter warten, über alle Fälle: für den Dialog in jeder Ansicht
            fragen = sitzung_modul.offene_fragen(self.bedienung)
            return self.json({"anzahl": len(fragen), "html": formulare.rueckfrage_dialog(fragen)})
        if weg == ["quellen"]:
            return self.json({"titel": "Quellen", "html": seiten.quellen_seite() + formulare.quellen_bedienung(self.bedienung) + "<h2>Begriffe</h2>" + seiten.begriffe()})
        if weg == ["bedienung"]:        # ob sich die Oberfläche bedienen lässt. Das Geheimnis steht hier nie
            return self.json({"aktiv": self.bedienung is not None, "claude": sitzung_modul.verfuegbar() if self.bedienung is not None else ""})
        if weg == ["neu"]:
            return self.json({"titel": "Neuer Fall", "html": formulare.neu_seite(self.bedienung)})
        if len(weg) >= 3 and weg[0] == "fall":
            fall = self.zustand.fall(weg[1])
            ansicht, arg = weg[2], "/".join(weg[3:])
            if ansicht == "spur":
                try:
                    ab = max(0, int((frage.get("ab") or ["0"])[0]))
                except ValueError:
                    ab = 0
                return self.json(seiten.spur_daten(fall, ab))
            if ansicht == "bedienen":
                return self.json({"titel": f"Bedienen · {fall.id}", "html": formulare.bedienen_seite(fall, self.bedienung)})
            if ansicht == "akten":      # ohne Geheimnis: nur, was im Eingang des Falls liegt. Den Akten-Eingang gibt es per POST
                return self.json({"titel": f"Akten · {fall.id}", "html": formulare.akten_lesen(fall.id, self.bedienung is not None)})
            if ansicht == "ermittlung":
                bedienbar = self.bedienung is not None
                stand = sitzung_modul.verlauf(self.bedienung, fall.id) if bedienbar else None
                return self.json({"titel": f"Ermittlung · {fall.id}", "html": formulare.ermittlung_seite(
                    fall, self.bedienung, stand, sitzung_modul.verfuegbar() if bedienbar else "", sitzung_modul.abrechnung()["text"] if bedienbar else "")})
            if ansicht == "verlauf":    # der Chat: Stand der gesteuerten Sitzung und, was seit der genannten Version dazukam
                try:
                    version = max(0, int((frage.get("v") or ["0"])[0]))
                except ValueError:
                    version = 0
                stand = sitzung_modul.verlauf(self.bedienung, fall.id, version)
                bereit = sitzung_modul.verfuegbar() if self.bedienung is not None else ""
                return self.json({**stand, "bedienbar": self.bedienung is not None, "claude": bereit,
                                  "feld": formulare.ermittlung_feld(fall.id, stand, bereit) if self.bedienung is not None else "",
                                  "tafel": formulare.wer_tafel(stand) if self.bedienung is not None else "",
                                  "pflicht": seiten.pflichtquellen_html(fall, formulare.PFLICHT_STAND_KOPF), "pflicht_kurz": seiten.pflichtquellen_kurz(fall)})
            if ansicht == "ergebnisse":
                return self.json({"titel": f"Ergebnisse · {fall.id}", "html": seiten.ergebnisse_seite(fall, self.bedienung is not None)})
            if ansicht == "zurueck":
                return self.json({"titel": f"Zurückführen · {fall.id}", "html": formulare.zurueck_seite(fall, self.bedienung)})
            if ansicht == "kopf":
                return self.json({"html": seiten.kopf(fall), "titel": fall.daten.get("titel") or "", "indikatoren": [{"id": i.get("id"), "wert": i.get("wert"), "typ": i.get("typ")} for i in fall.indikatoren()]})
            if ansicht in ANSICHTEN:
                titel, bauen = ANSICHTEN[ansicht]
                return self.json({"titel": f"{titel}{' ' + arg if arg and ansicht != 'suche' else ''} · {fall.id}", "html": bauen(fall, arg)})
        raise daten.NichtGefunden("Diese Ansicht gibt es nicht.")


def starten(port: int = 8765, versuche: int = 20, bedienung: "bedienung_modul.Bedienung | None" = None) -> ThreadingHTTPServer:
    """Startet den Server auf 127.0.0.1. Ist der Port belegt, nimmt er den nächsten freien. Port 0: irgendeinen freien.
    Ohne `bedienung` läuft er im Modus «nur lesen»: Dann gibt es kein POST und nichts, was sich ändern liesse."""
    mimetypes.init()
    letzter: OSError | None = None
    for p in ([0] if port == 0 else range(port, port + versuche)):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", p), Bearbeiter)
        except OSError as e:
            letzter = e
            continue
        echt = server.server_address[1]
        bearbeiter = type("Bearbeiter", (Bearbeiter,), {"zustand": Zustand(), "erlaubt": {f"127.0.0.1:{echt}", f"localhost:{echt}"}, "bedienung": bedienung})
        server.RequestHandlerClass = bearbeiter
        server.daemon_threads = True
        return server
    raise OSError(f"Kein freier Port zwischen {port} und {port + versuche - 1}: {letzter}")
