"""Datenschicht der Oberfläche. Liest fall.json, die Protokolle, die Rohdaten und befunde.json und liefert sie in einer
einheitlichen Form. Sie schreibt nie: Es gibt in diesem Modul keinen Aufruf, der eine Datei anlegt oder verändert.

Kennzahlen kommen aus denselben Funktionen wie im Abschlussrapport (tools/rapport.py, kennzahlen) und im
Ermittlungsprotokoll (tools/protokoll.py, kennzahlen). Hier wird nichts ein zweites Mal gerechnet.

    fall = Fall("MUSTER-2026-001")
    fall.eintraege()            alle Protokolleinträge (P-… und X-…)
    fall.blatt("P-0001")        die Rohantwort, vom Darsteller geordnet
    fall.datenblatt("I-03")     alles zu einem Indikator, in festen Abschnitten
    fall.abdeckung()            Indikator × Quelle
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from gateway import pflichtquellen as pq, plattform  # noqa: E402
from gateway.akte import FAELLE, FREIGABEN, fall_pfad, freigabe_erteilt, jsonl_lesen, kette_pruefen, sha256_datei  # noqa: E402
from gateway.quellen import EINSTELLUNG_AUS, NICHT_SCHALTBAR, QUELLEN, aus_namen, schaltbar  # noqa: E402
from tools import protokoll as protokollwerkzeug, rapport  # noqa: E402
from tools.ui import blaetter, darsteller as ds  # noqa: E402

ds.ZONE = rapport.ZONE
BILD = {".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif", ".webp": "image/webp"}
GROSS = 3 * 1024 * 1024         # Rohdateien bis zu dieser Grösse werden als Baum gezeigt und durchsucht
SCHRITTE = ("Fall angelegt", "Indikatoren", "Plan", "Abfragen", "Gegenprüfung", "Rapport")
ZUSTAND = {"ok": "Treffer", "kein_treffer": "kein Treffer", "fehler": "Fehlschlag", "abgelehnt": "abgelehnt"}


class NichtGefunden(Exception):
    pass


@dataclass
class Rohdatei:
    pfad: Path
    name: str               # Pfad innerhalb der Fallakte, wie er im Protokoll steht
    form: str               # json | text | csv | bild | fehlt
    inhalt: object = None   # json: das gelesene Objekt. text, csv: der Text. bild, fehlt: None
    bytes: int = 0
    sha256: str = ""
    zu_gross: bool = False


@dataclass
class Wert:
    """Eine Angabe im Datenblatt: was eine Quelle zu einem Feld sagt."""
    quelle: str
    beleg: str
    zeit: str
    angabe: ds.Angabe | ds.Liste
    aus_cache: str = ""


@dataclass
class Feld:
    schluessel: str
    name: str
    werte: list = field(default_factory=list)
    widerspruch: bool = False


def faelle() -> list[dict]:
    """Alle Fallakten, die neueste zuerst."""
    aus = []
    for ordner in sorted(FAELLE.iterdir()) if FAELLE.is_dir() else []:
        datei = ordner / "fall.json"
        if not datei.is_file():
            continue
        try:
            d = json.loads(datei.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            d = {"titel": "fall.json ist nicht lesbar"}
        aus.append({"id": ordner.name, "titel": d.get("titel") or "", "muster": bool(d.get("muster")), "eroeffnet": d.get("eroeffnet") or "",
                    "sachbearbeiter": d.get("sachbearbeiter") or "", "klassifizierung": d.get("klassifizierung") or ""})
    return sorted(aus, key=lambda f: f["eroeffnet"], reverse=True)


def quellen() -> list[dict]:
    """Das Verzeichnis der Quellen mit dem Stand der Einrichtung. Von Schlüsseln zeigt die Oberfläche nur, ob einer gesetzt ist."""
    aus = []
    abgeschaltet = aus_namen(plattform.einstellung(EINSTELLUNG_AUS))        # vom Sachbearbeiter ausgeschaltet (Seite «Quellen»)
    for q in QUELLEN:
        gesetzt = bool(plattform.einstellung(q.env)) if q.env else None
        ist_aus = q.name in abgeschaltet
        stand = "ausgeschaltet" if ist_aus else "kein Schlüssel nötig" if q.env is None else (
            "eingerichtet" if gesetzt else ("läuft ohne Schlüssel, gedrosselt" if q.auch_ohne else "nicht eingerichtet"))
        aus.append({"name": q.name, "zweck": q.zweck, "werkzeuge": list(q.werkzeuge), "schluessel": q.env or "", "stand": stand,
                    "eingerichtet": not ist_aus and bool(q.env is None or gesetzt or q.auch_ohne), "hinweis": q.hinweis, "woher": q.woher if q.env else "",
                    "freigabe": dict(q.freigabe), "gesetzt": bool(gesetzt), "auch_ohne": q.auch_ohne, "aus": ist_aus,
                    # Ein Schlüssel aus der Umgebung des Terminals gilt vor der Schlüsseldatei: Die Oberfläche kann ihn nicht ändern
                    "aus_umgebung": bool(q.env and os.environ.get(q.env, "").strip()),
                    "schaltbar": schaltbar(q.name), "ohne_schalter": NICHT_SCHALTBAR.get(q.name, "")})
    return aus


class Fall:
    def __init__(self, fall_id: str):
        try:
            self.pfad = fall_pfad(fall_id)
        except ValueError as e:
            raise NichtGefunden(str(e)) from e
        if not (self.pfad / "fall.json").is_file():
            raise NichtGefunden(f"Den Fall «{fall_id}» gibt es nicht.")
        self.id = fall_id
        self._merker: dict = {}

    # ---- Grundlagen
    def _gemerkt(self, name: str, dateien: list[Path], lesen):
        """Liest nur neu, wenn sich Grösse oder Änderungszeit einer Datei geändert hat."""
        stand = tuple((d.stat().st_size, d.stat().st_mtime_ns) if d.is_file() else None for d in dateien)
        alt = self._merker.get(name)
        if alt is None or alt[0] != stand:
            self._merker[name] = (stand, lesen())
        return self._merker[name][1]

    @property
    def daten(self) -> dict:
        return self._gemerkt("fall", [self.pfad / "fall.json"], lambda: json.loads((self.pfad / "fall.json").read_text(encoding="utf-8")))

    def eintraege(self) -> list[dict]:
        a, x = self.pfad / "protokoll" / "abfragen.jsonl", self.pfad / "protokoll" / "extern.jsonl"
        return self._gemerkt("eintraege", [a, x], lambda: jsonl_lesen(a) + jsonl_lesen(x))

    def eintrag(self, beleg: str) -> dict:
        for e in self.eintraege():
            if e.get("id") == beleg:
                return e
        raise NichtGefunden(f"Den Beleg «{beleg}» gibt es in diesem Fall nicht.")

    def kette(self) -> dict:
        """Stand der Protokollkette samt Prüfsummen aller Rohdateien. Höchstens alle 20 Sekunden neu geprüft, ausser das Protokoll wuchs."""
        a, x = self.pfad / "protokoll" / "abfragen.jsonl", self.pfad / "protokoll" / "extern.jsonl"
        stand = tuple((d.stat().st_size, d.stat().st_mtime_ns) if d.is_file() else None for d in (a, x))
        alt = self._merker.get("kette")
        if alt is None or alt[0] != stand or time.monotonic() - alt[2] > 20:
            self._merker["kette"] = (stand, kette_pruefen(self.id), time.monotonic())
        return self._merker["kette"][1]

    def befunde(self) -> dict | None:
        datei = self.pfad / "befunde.json"

        def lesen():
            if not datei.is_file():
                return None
            roh = datei.read_bytes()
            try:
                b = json.loads(roh)
            except json.JSONDecodeError as e:
                return {"_fehler": f"befunde.json ist kein gültiges JSON: Zeile {e.lineno}, Spalte {e.colno}."}
            b["_sha256"] = hashlib.sha256(roh).hexdigest()
            return b
        return self._gemerkt("befunde", [datei], lesen)

    def klartext_stellen(self) -> list[dict]:
        """Stellen, an denen laut der Ermittlung eine geschützte Angabe noch im Klartext steht (arbeitsstand/klartext.json): je Stelle
        Dokument, Zeile und die Art der Angabe. Die Angabe selbst steht dort nie. Genannt werden nur Dokumente, die noch im Eingang
        des Falls liegen: Ist ein Dokument nachgebessert und ersetzt, entfällt seine Meldung."""
        datei = self.pfad / "arbeitsstand" / "klartext.json"
        eingang = self.pfad / "eingang"

        def lesen():
            try:
                roh = json.loads(datei.read_text(encoding="utf-8")) if datei.is_file() else {}
            except (OSError, ValueError):
                return []
            aus = []
            for s in (roh.get("stellen") if isinstance(roh, dict) else None) or []:
                name = Path(str(s.get("dokument") or "")).name if isinstance(s, dict) else ""
                if name:
                    zeile = s.get("zeile")
                    aus.append({"dokument": name, "zeile": zeile if isinstance(zeile, int) and not isinstance(zeile, bool) and zeile > 0 else None,
                                "was": " ".join(str(s.get("was") or "").split())[:200]})
            return aus[:200]
        return [s for s in self._gemerkt("klartext", [datei], lesen) if (eingang / s["dokument"]).is_file()]

    def indikatoren(self) -> list[dict]:
        """Die Indikatoren des Falls: aus befunde.json, sonst aus der Indikatorliste des Arbeitsstands."""
        b = self.befunde() or {}
        if b.get("indikatoren"):
            return b["indikatoren"]
        datei = self.pfad / "arbeitsstand" / "indikatoren.json"
        if datei.is_file():
            try:
                roh = json.loads(datei.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return []
            liste = roh.get("indikatoren") if isinstance(roh, dict) else roh
            return [i for i in liste or [] if isinstance(i, dict) and i.get("wert")]
        return []

    def indikator(self, kennung: str) -> dict:
        for i in self.indikatoren():
            if i.get("id") == kennung:
                return i
        raise NichtGefunden(f"Den Indikator «{kennung}» gibt es in diesem Fall nicht.")

    # ---- Rohdaten
    def rohdatei(self, name: str) -> Rohdatei:
        """Eine Rohdatei der Fallakte. Der Pfad muss unter rohdaten/ liegen, alles andere wird abgewiesen."""
        basis = (self.pfad / "rohdaten").resolve()
        pfad = (self.pfad / name).resolve()
        if basis != pfad and basis not in pfad.parents:
            raise NichtGefunden("Diese Datei liegt nicht in den Rohdaten des Falls.")
        if not pfad.is_file():
            return Rohdatei(pfad, name, "fehlt")
        groesse = pfad.stat().st_size
        r = Rohdatei(pfad, name, "text", bytes=groesse)
        endung = pfad.suffix.lower()
        if endung in BILD:
            r.form = "bild"
            return r
        if groesse > GROSS:
            r.zu_gross = True
            r.inhalt = pfad.open("rb").read(200_000).decode("utf-8", "replace")
            return r
        text = pfad.read_bytes().decode("utf-8", "replace")
        r.inhalt = text
        if endung == ".json":
            try:
                r.inhalt, r.form = json.loads(text), "json"
            except json.JSONDecodeError:
                pass
        elif endung == ".csv":
            r.form = "csv"
        return r

    def roh_zu(self, e: dict) -> Rohdatei | None:
        name = (e.get("antwort") or {}).get("rohdaten")
        return self.rohdatei(name) if name else None

    def passt_zur_kette(self, e: dict) -> tuple[bool | None, str]:
        """Stimmt die Rohdatei noch mit der Prüfsumme im Protokolleintrag überein?"""
        antwort = e.get("antwort") or {}
        if not antwort.get("rohdaten"):
            return None, "Zu diesem Eintrag gibt es keine Rohdatei."
        roh = self.rohdatei(antwort["rohdaten"])
        if roh.form == "fehlt":
            return False, "Die Rohdatei fehlt in der Fallakte."
        ist = sha256_datei(roh.pfad)
        if ist != antwort.get("sha256"):
            return False, "Die Rohdatei wurde nach der Abfrage verändert: Ihre Prüfsumme stimmt nicht mit dem Protokoll überein."
        return True, "Die Prüfsumme der Rohdatei stimmt mit dem Protokolleintrag überein."

    def blatt(self, beleg: str) -> tuple[dict, Rohdatei | None, ds.Blatt]:
        e = self.eintrag(beleg)
        roh = self.roh_zu(e)
        if roh is None or roh.form == "fehlt" or roh.zu_gross:
            return e, roh, ds.darstellen(e, None, "leer")
        return e, roh, ds.darstellen(e, roh.inhalt, roh.form)

    # ---- Kennzahlen: aus den Funktionen von Rapport und Protokoll
    def kennzahlen(self) -> dict:
        eintraege = self.eintraege()
        abfragen = [e for e in eintraege if str(e.get("id", "")).startswith("P-")]
        return {"rapport": rapport.kennzahlen(self.befunde() or {}, eintraege), "protokoll": protokollwerkzeug.kennzahlen(abfragen)}

    def schritte(self) -> list[dict]:
        """Wo der Fall steht. Jeder Schritt nennt, woran die Oberfläche das erkennt."""
        b = self.befunde() or {}
        arbeit = self.pfad / "arbeitsstand"
        eintraege = self.eintraege()
        geprueft = sum(1 for f in b.get("befunde") or [] if f.get("gegenpruefung"))
        rapport_da = (self.pfad / "rapport" / "Abschlussrapport.html").is_file()
        stand = [
            (True, "fall.json vorhanden"),
            (bool(self.indikatoren()), f"{len(self.indikatoren())} Indikatoren" if self.indikatoren() else "noch keine Indikatorliste"),
            ((arbeit / "plan.md").is_file(), "arbeitsstand/plan.md vorhanden" if (arbeit / "plan.md").is_file() else "kein Plan in der Fallakte abgelegt"),
            (bool(eintraege), f"{len(eintraege)} Einträge im Protokoll" if eintraege else "noch keine Abfragen"),
            (geprueft > 0, f"{geprueft} von {len(b.get('befunde') or [])} Befunden gegengeprüft" if b.get("befunde") else "noch keine Befunde"),
            (rapport_da, "Abschlussrapport erzeugt" if rapport_da else "noch kein Abschlussrapport"),
        ]
        letzter = max((i for i, (ok, _) in enumerate(stand) if ok), default=0)
        return [{"name": SCHRITTE[i], "erledigt": ok, "aktuell": i == letzter, "uebersprungen": not ok and i < letzter, "woran": woran}
                for i, (ok, woran) in enumerate(stand)]

    def freigaben(self) -> list[dict]:
        aus = []
        for name in FREIGABEN:
            e = (self.daten.get("freigaben") or {}).get(name) or {}
            aus.append({"name": name, "erteilt": freigabe_erteilt(self.daten, name), "durch": e.get("durch") or "", "am": e.get("am") or "", "vermerk": e.get("vermerk") or ""})
        return aus

    def pflichtquellen(self) -> dict | None:
        """Der Stand der Pflichtquellen: was der Sachbearbeiter vorgegeben hat und was das Protokoll dazu zeigt. None ohne Vorgabe."""
        if not pq.vorgabe(self.daten):
            return None
        dateien = [self.pfad / "fall.json", self.pfad / "protokoll" / "abfragen.jsonl", self.pfad / "protokoll" / "extern.jsonl",
                   self.pfad / "arbeitsstand" / "indikatoren.json", self.pfad / "befunde.json"]
        return self._gemerkt("pflicht", dateien, lambda: pq.stand_fuer(self.daten, self.pfad, self.eintraege()))

    # ---- Indikator und seine Belege
    def zu_indikator(self, ind: dict) -> list[dict]:
        """Die Protokolleinträge, die zu einem Indikator gehören: Abfragen auf seinen Wert, die genannten Belege und
        die Teilabfragen hinter einer Auswertung."""
        wert = " ".join(str(ind.get("wert") or "").split()).casefold()
        genannt = set(ind.get("belege") or [])
        eintraege = self.eintraege()
        gewaehlt: dict[str, dict] = {}
        for e in eintraege:
            ziel = " ".join(str(e.get("ziel") or "").split()).casefold()
            if e.get("id") in genannt or (wert and (ziel == wert or ziel.startswith(wert + " "))) or (wert and wert in self.bezug(e)):
                gewaehlt[e["id"]] = e
        je_id = {e["id"]: e for e in eintraege}
        for e in list(gewaehlt.values()):
            for teil in e.get("grundlage") or []:
                if teil in je_id:
                    gewaehlt.setdefault(teil, je_id[teil])
        return sorted(gewaehlt.values(), key=lambda e: (str(e.get("zeit_utc") or ""), e.get("nr") or 0))

    def bezug(self, e: dict) -> set[str]:
        """Worum es in einem Beleg geht, wenn sein Ziel im Protokoll nur eine Kennung ist (Scan, Bericht): laut Rohantwort."""
        stellen = ds.BEZUG.get(str(e.get("werkzeug")))
        if not stellen or e.get("ergebnis") != "ok":
            return set()
        merker = self._merker.setdefault("bezug", {})
        if e["id"] not in merker:
            roh = self.roh_zu(e)
            werte = [w for s in stellen for _, w in ds.aufloesen(roh.inhalt, s)] if roh is not None and roh.form == "json" else []
            merker[e["id"]] = {" ".join(str(w).split()).casefold() for w in werte if isinstance(w, str) and w}
        return merker[e["id"]]

    def datenblatt(self, kennung: str) -> dict:
        """Alles, was irgendeine Quelle zu einem Indikator geliefert hat, in den festen Abschnitten seines Typs."""
        ind = self.indikator(kennung)
        typ = ind.get("typ") if ind.get("typ") in blaetter.ABSCHNITTE else "sonstiges"
        eintraege = self.zu_indikator(ind)
        wert = " ".join(str(ind.get("wert") or "").split()).casefold()
        direkt = {e["id"] for e in eintraege if " ".join(str(e.get("ziel") or "").split()).casefold().startswith(wert) or wert in self.bezug(e)}
        felder: dict[str, dict[str, Feld]] = {titel: {} for titel, _ in blaetter.ABSCHNITTE[typ]}
        for e in eintraege:
            if e.get("ergebnis") not in ("ok", "kein_treffer") or e["id"] not in direkt and e.get("art") != "auswertung" and e["id"] not in (ind.get("belege") or []):
                continue        # Teilabfragen zu anderen Zielen (Stationen eines Geldflusses) gehören zum Beleg, nicht ins Datenblatt
            if (e.get("antwort") or {}).get("aus_cache"):
                continue        # dieselbe Rohdatei wie die ursprüngliche Abfrage: Sie steht unter «Befragte Quellen», die Werte nicht doppelt
            roh = self.roh_zu(e)
            if roh is None or roh.form != "json":
                continue
            blatt = ds.darstellen(e, roh.inhalt)
            for _, teile in blatt.abschnitte:
                for teil in teile:
                    if not teil.schluessel:
                        continue
                    titel = blaetter.abschnitt_fuer(typ, teil.schluessel)
                    if titel is None:
                        continue
                    feld_ = felder[titel].setdefault(teil.schluessel, Feld(teil.schluessel, teil.name))
                    feld_.werte.append(Wert(str(e.get("quelle") or ""), e["id"], str(e.get("zeit_utc") or ""), teil, (e.get("antwort") or {}).get("aus_cache") or ""))
        for abschnitt in felder.values():
            for f in abschnitt.values():
                einzel = [w for w in f.werte if isinstance(w.angabe, ds.Angabe)]
                f.widerspruch = blaetter.widerspruch(f.schluessel, [(w.quelle, w.angabe.wert, w.angabe.art) for w in einzel])
        befragt = [{"beleg": e["id"], "quelle": e.get("quelle"), "werkzeug": e.get("werkzeug"), "ergebnis": e.get("ergebnis"), "zeit": e.get("zeit_utc"),
                    "aus_cache": (e.get("antwort") or {}).get("aus_cache") or "", "art": e.get("art"), "fehler": e.get("fehler") or "", "ziel": e.get("ziel")}
                   for e in eintraege]
        b = self.befunde() or {}
        return {"indikator": ind, "typ": typ, "abschnitte": [(titel, sorted(felder[titel].values(), key=lambda f: f.schluessel)) for titel, _ in blaetter.ABSCHNITTE[typ]],
                "befragt": befragt, "befunde": [f for f in b.get("befunde") or [] if kennung in (f.get("indikatoren") or [])],
                "beziehungen": [r for r in b.get("beziehungen") or [] if kennung in (r.get("von"), r.get("nach"))]}

    def abdeckung(self) -> dict:
        """Indikator × Quelle. Je Zelle: Treffer, kein Treffer, Fehlschlag, abgelehnt, nicht abgefragt, Quelle nicht eingerichtet
        oder «passt nicht» (die Quelle sagt zu diesem Typ nichts)."""
        indikatoren = self.indikatoren()
        verzeichnis = {q["name"]: q for q in quellen()}
        zellen: dict[tuple[str, str], dict] = {}
        spalten: list[str] = []
        rang = {"ok": 0, "kein_treffer": 1, "fehler": 2, "abgelehnt": 3}
        for ind in indikatoren:
            for e in self.zu_indikator(ind):
                if e.get("art") in ("auswertung",):
                    continue
                name = blaetter.QUELLE_GLEICH.get(str(e.get("quelle")), str(e.get("quelle")))
                if name not in spalten:
                    spalten.append(name)
                alt = zellen.get((ind["id"], name))
                if alt is None or rang.get(e.get("ergebnis"), 9) < rang.get(alt["ergebnis"], 9):
                    zellen[(ind["id"], name)] = {"ergebnis": e.get("ergebnis"), "beleg": e["id"], "anzahl": (alt or {}).get("anzahl", 0) + 1}
                else:
                    alt["anzahl"] += 1
        typen = {i.get("typ") for i in indikatoren}
        for name in verzeichnis:        # Quellen, die zu einem vorhandenen Typ passen, aber nie gefragt wurden
            if name not in spalten and typen & set(blaetter.QUELLE_TYPEN.get(name, ())):
                spalten.append(name)
        reihenfolge = [q.name for q in QUELLEN]
        spalten.sort(key=lambda n: (reihenfolge.index(n) if n in reihenfolge else len(reihenfolge), n))
        zeilen = []
        for ind in indikatoren:
            zeile = []
            for name in spalten:
                z = zellen.get((ind["id"], name))
                if z:
                    zeile.append({"zustand": ZUSTAND.get(z["ergebnis"], str(z["ergebnis"])), "beleg": z["beleg"], "anzahl": z["anzahl"]})
                elif ind.get("typ") not in blaetter.QUELLE_TYPEN.get(name, (ind.get("typ"),)):
                    zeile.append({"zustand": "passt nicht"})
                elif name in verzeichnis and not verzeichnis[name]["eingerichtet"]:
                    zeile.append({"zustand": "Quelle nicht eingerichtet"})
                else:
                    zeile.append({"zustand": "nicht abgefragt"})
            zeilen.append({"indikator": ind, "zellen": zeile})
        return {"spalten": spalten, "zeilen": zeilen}

    # ---- Dokumente
    def dokumente(self) -> list[dict]:
        """Abschlussrapport und Ermittlungsprotokoll, als HTML und PDF, mit dem Vermerk, ob sie dem Stand der Daten entsprechen."""
        ordner = self.pfad / "rapport"
        b = self.befunde() or {}
        kette = self.kette()
        aus = []
        for name, titel in (("Abschlussrapport", "Abschlussrapport"), ("Ermittlungsprotokoll", "Ermittlungsprotokoll"), ("Datenblaetter", "Datenblätter (Anhang)")):
            html_datei = ordner / f"{name}.html"
            eintrag = {"name": name, "titel": titel, "html": html_datei.is_file(), "pdf": (ordner / f"{name}.pdf").is_file(), "aktuell": None, "vermerk": ""}
            if html_datei.is_file():
                text = html_datei.read_text(encoding="utf-8", errors="replace")
                eintrag["geaendert"] = html_datei.stat().st_mtime
                m = re.search(r"Letzter Kettenwert: <span class='mono'>([0-9a-f]{64})</span>", text)
                alt_kette = m.group(1) if m else None
                gruende = []
                if alt_kette and kette.get("letzter_hash") and alt_kette != kette["letzter_hash"]:
                    neuer = [e["id"] for e in self.eintraege() if str(e.get("id", "")).startswith("P-")]
                    ketten = [e.get("kette") for e in self.eintraege()]
                    seither = len(neuer) - (ketten.index(alt_kette) + 1) if alt_kette in ketten else None
                    gruende.append(f"seit der Erzeugung kamen {seither} Protokolleinträge dazu" if seither else "das Protokoll hat sich seit der Erzeugung geändert")
                if name in ("Abschlussrapport", "Datenblaetter"):
                    m = re.search(r"Prüfsumme befunde.json: <span class='mono'>([0-9a-f]{64})</span>", text)
                    if m and b.get("_sha256") and m.group(1) != b["_sha256"]:
                        gruende.append("befunde.json wurde seit der Erzeugung geändert")
                eintrag["aktuell"] = not gruende
                eintrag["vermerk"] = "entspricht dem Stand der Daten" if not gruende else "älter als die Daten: " + ", ".join(gruende)
                if not gruende and not alt_kette and kette.get("letzter_hash"):
                    # Ohne Kettenwert im Dokument lässt sich sein Stand nicht mit dem Protokoll vergleichen: Dann behauptet die Oberfläche nichts
                    eintrag["aktuell"] = None
                    eintrag["vermerk"] = "Stand nicht feststellbar: Das Dokument nennt keinen Kettenwert. Neu erzeugen."
            aus.append(eintrag)
        return aus

    def dokument(self, datei: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_-]+\.(html|pdf|csv)", datei):
            raise NichtGefunden("Dieses Dokument gibt es nicht.")
        pfad = self.pfad / "rapport" / datei
        if not pfad.is_file():
            raise NichtGefunden(f"«{datei}» ist noch nicht erzeugt.")
        return pfad

    def rapport_html(self) -> dict:
        """Der Abschlussrapport, frisch aus befunde.json und dem Protokoll: derselbe Generator, also derselbe Wortlaut."""
        b = self.befunde()
        if b is None:
            return {"fehlt": "befunde.json fehlt. Die Befunde schreibt der Rapportführer."}
        if b.get("_fehler"):
            return {"fehlt": b["_fehler"]}
        eintraege = self.eintraege()
        kette = self.kette()
        maengel, hinweise = rapport.pruefen(b, {e["id"]: e for e in eintraege}, True, self.pfad)
        if not kette["ok"]:
            maengel = [f"Abfrageprotokoll: {f}" for f in kette["fehler"]] + maengel
        fall = dict(self.daten)
        register = self.pfad / "eingang" / ".freigabe.json"
        if register.is_file():
            fall["_eingang"] = json.loads(register.read_text(encoding="utf-8")).get("dateien", {})
        seite = rapport.bauen(self.id, fall, b, eintraege, kette, maengel, hinweise, bool(maengel or hinweise))
        koerper = re.search(r"<main>\n(.*)\n</main>", seite, re.S).group(1)
        koerper = re.sub(r"<div class='fuss'>.*?</div>\s*$", "", koerper, flags=re.S)
        return {"html": koerper, "maengel": maengel, "hinweise": hinweise}

    def akteure(self) -> dict[str, str]:
        """Welcher Analyst (Subagent) welche Abfrage ausgelöst hat, laut den Sitzungsprotokollen."""
        nur = set(self.daten["sitzungen"]) if self.daten.get("muster") and self.daten.get("sitzungen") else None
        sitzung, _ = protokollwerkzeug.sitzungen_laden(self.id, nur)
        wer = {z["protokoll_id"]: str(z.get("agent") or "hauptsitzung") for z in sitzung if z.get("protokoll_id") and z.get("fall") == self.id}
        for e in self.eintraege():
            if e.get("art") == "auswertung" and e["id"] in wer:
                for teil in e.get("grundlage") or []:
                    wer.setdefault(teil, wer[e["id"]])
        return wer

    # ---- Arbeitsspur und Suche
    def spur(self, ab: int = 0) -> dict:
        """Die Einträge des Protokolls für die Arbeitsspur, ab einer Stelle. Dazu Zahl und Stand der Kette."""
        eintraege = self.eintraege()
        aus = []
        for nr, e in enumerate(eintraege[ab:], ab + 1):
            antwort = e.get("antwort") or {}
            klasse = "auswertung" if e.get("art") in ("auswertung", "lokal") else {"kein_treffer": "kein_treffer", "fehler": "fehlschlag", "abgelehnt": "fehlschlag"}.get(e.get("ergebnis"), "abfrage")
            aus.append({"id": e.get("id"), "zeit": e.get("zeit_utc"), "zeit_anzeige": ds.zeit(e.get("zeit_utc"))[0] if e.get("zeit_utc") else "", "art": e.get("art"), "klasse": klasse, "quelle": e.get("quelle"), "werkzeug": e.get("werkzeug"),
                        "ziel": e.get("ziel"), "ergebnis": e.get("ergebnis"), "freigabe": e.get("freigabe"), "aus_cache": antwort.get("aus_cache") or "",
                        "fehler": e.get("fehler") or "", "stelle": nr})
        kette = self.kette()
        return {"eintraege": aus, "anzahl": len(eintraege), "kette_ok": kette["ok"], "kette_fehler": kette["fehler"][:3],
                "freigaben": [f for f in self.freigaben() if f["erteilt"]]}

    def suche(self, frage: str, hoechstens: int = 200) -> list[dict]:
        """Sucht im ganzen Fall: Indikatoren, Befunde, Protokoll und Rohdaten. Gross- und Kleinschreibung spielen keine Rolle."""
        q = frage.strip().casefold()
        if len(q) < 2:
            return []
        treffer: list[dict] = []

        def auszug(text: str) -> str:
            stelle = text.casefold().find(q)
            return " ".join(text[max(0, stelle - 60):stelle + len(q) + 80].split())

        for i in self.indikatoren():
            text = " ".join(str(i.get(k) or "") for k in ("id", "wert", "rolle", "herkunft", "typ"))
            if q in text.casefold():
                treffer.append({"wo": "Indikator", "ziel": f"indikator/{i.get('id')}", "titel": f"{i.get('id')} · {i.get('wert')}", "auszug": auszug(text)})
        b = self.befunde() or {}
        for f in b.get("befunde") or []:
            text = " ".join(str(f.get(k) or "") for k in ("id", "titel", "text", "erlaeuterung"))
            if q in text.casefold():
                treffer.append({"wo": "Befund", "ziel": f"rapport/{f.get('id')}", "titel": f"{f.get('id')} · {f.get('titel')}", "auszug": auszug(text)})
        for e in self.eintraege():
            text = " ".join(str(e.get(k) or "") for k in ("id", "quelle", "werkzeug", "ziel", "zweck", "fehler"))
            if q in text.casefold():
                treffer.append({"wo": "Protokoll", "ziel": f"beleg/{e.get('id')}", "titel": f"{e.get('id')} · {e.get('quelle')} · {e.get('ziel')}", "auszug": auszug(text)})
        gesehen: set[str] = set()
        for e in self.eintraege():
            name = (e.get("antwort") or {}).get("rohdaten")
            if not name or name in gesehen or len(treffer) >= hoechstens:
                continue
            gesehen.add(name)
            pfad = self.pfad / name
            if not pfad.is_file() or pfad.suffix.lower() in BILD or pfad.stat().st_size > GROSS:
                continue
            text = pfad.read_bytes().decode("utf-8", "replace")
            if q in text.casefold():
                treffer.append({"wo": "Rohdaten", "ziel": f"beleg/{e.get('id')}", "titel": f"{e.get('id')} · {name}", "auszug": auszug(text)})
        return treffer[:hoechstens]


def csv_lesen(text: str, hoechstens: int = 2000) -> list[list[str]]:
    trenner = ";" if text[:2000].count(";") > text[:2000].count(",") else ","
    zeilen = []
    for nr, zeile in enumerate(csv.reader(io.StringIO(text), delimiter=trenner)):
        if nr >= hoechstens:
            break
        zeilen.append(zeile)
    return zeilen
