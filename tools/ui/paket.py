"""Alles zu einem Fall als ein Archiv zum Mitnehmen. Liest nur, schreibt nichts in die Fallakte.

Drei Teile, einzeln wählbar:
  unterlagen   Abschlussrapport, Ermittlungsprotokoll und Datenblätter (HTML und PDF), Indikatorliste, Befunde
  sitzung      das Sitzungsprotokoll (was der Hook mitgeschrieben hat, je Sitzung eine Datei, nur die Zeilen dieses Falls)
               und der Verlauf aus dem Chat der Oberfläche (eine Lesehilfe, kein Beleg)
  akte         die Fallakte: fall.json, Eingang, Protokollkette, Arbeitsstand und Rohdaten

Die Datei INHALT.txt nennt jede Datei mit Grösse und Prüfsumme, dazu den Stand der Protokollkette.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import datetime

from gateway import plattform
from tools import protokoll as protokollwerkzeug
from tools.ui import daten

TEILE = {"unterlagen": "Unterlagen (Rapport, Protokoll, Datenblätter, Indikatorliste, Befunde)",
         "sitzung": "Sitzungsprotokoll und Verlauf der Ermittlung",
         "akte": "Fallakte mit Eingang, Protokollkette und Rohdaten"}
GRENZE = 400 * 1024 * 1024      # so viel packt die Oberfläche höchstens in ein Archiv
VERLAUF_MUSTER = "verlauf-oberflaeche-*.txt"       # so heissen die Verläufe, die die Oberfläche im Arbeitsstand eines Falls ablegt
VERLAUF_KOPF = ("Verlauf der Ermittlung aus dem Chat der Oberfläche. Eine Lesehilfe, kein Beleg: Belegt ist, was im Sitzungsprotokoll und in der "
                "Protokollkette des Falls steht.\n\n")


def gewaehlt(teile: set[str] | None) -> set[str]:
    return {t for t in teile or () if t in TEILE} or {"unterlagen", "sitzung"}


def dateiname(teile: set[str] | None) -> str:
    """Der Name des Archivs sagt, was darin ist."""
    teile = gewaehlt(teile)
    return "Fallakte" if "akte" in teile else "Unterlagen_und_Sitzungsprotokoll" if teile == {"unterlagen", "sitzung"} else \
        "Sitzungsprotokoll" if teile == {"sitzung"} else "Unterlagen"


def verlauf_text(verlauf: list[dict]) -> str:
    """Der Verlauf aus dem Chat als Text: eine Zeile je Eintrag, Nachrichten mit ihrem ganzen Wortlaut. Ein Schritt steht in Worten
    da, wie im Chat. Bei einer Abfrage folgt in Klammern der Name des Werkzeugs, wie er im Protokoll steht, darunter ihr Zweck."""
    zeilen = []
    for z in verlauf:
        zusatz = "".join(f" [{z[k]}]" for k in ("beleg", "ergebnis", "entscheid") if z.get(k))
        text = str(z.get("text", "")).replace("\n", "\n" + " " * 36)
        werkzeug = f" ({z['technik']})" if z.get("technik") and z.get("quelle") else ""
        zweck = "\n" + " " * 36 + "Zweck: " + str(z["zweck"]) if z.get("zweck") else ""
        zeilen.append(f"{z.get('zeit', ''):<10}{z.get('wer', ''):<26}{text}{werkzeug}{zusatz}" + (" [wartet]" if z.get("wartet") else "")
                      + (" [zurückgenommen]" if z.get("zurueck") else "") + zweck)
    return VERLAUF_KOPF + "\n".join(zeilen) + "\n"


def bauen(fall: daten.Fall, teile: set[str] | None, verlauf: list[dict] | None = None, verlauf_name: str = "") -> tuple[bytes, list[str]]:
    """Baut das Archiv im Speicher. Rückgabe: Inhalt und, was fehlt oder weggelassen wurde.
    `verlauf`: der Verlauf des Chats, wie er gerade im Speicher der Oberfläche steht. Er geht unter `verlauf_name` ins Archiv
    und ersetzt die Datei gleichen Namens aus dem Arbeitsstand, die einen älteren Stand desselben Verlaufs zeigt."""
    teile = gewaehlt(teile)
    eintraege: list[tuple[str, bytes]] = []
    hinweise: list[str] = []
    summe = 0

    def nehmen(name: str, inhalt: bytes) -> bool:
        nonlocal summe
        if summe + len(inhalt) > GRENZE:
            hinweise.append(f"{name}: weggelassen, das Archiv würde grösser als {GRENZE // (1024 * 1024)} MB. Die Datei liegt in der Fallakte.")
            return False
        summe += len(inhalt)
        eintraege.append((name, inhalt))
        return True

    if "unterlagen" in teile:
        ordner = fall.pfad / "rapport"
        dateien = sorted(p for p in ordner.glob("*") if p.is_file() and p.suffix.lower() in (".html", ".pdf", ".csv")) if ordner.is_dir() else []
        for p in dateien:
            nehmen(f"unterlagen/{p.name}", p.read_bytes())
        if (fall.pfad / "befunde.json").is_file():
            nehmen("unterlagen/befunde.json", (fall.pfad / "befunde.json").read_bytes())
        for d in fall.dokumente():
            if not d["html"]:
                hinweise.append(f"{d['titel']}: noch nicht erzeugt.")
            elif d["aktuell"] is False:
                hinweise.append(f"{d['titel']}: {d['vermerk']}.")
            if d["html"] and not d["pdf"]:
                hinweise.append(f"{d['titel']}: kein PDF vorhanden.")
    if "sitzung" in teile:
        zeilen, meldungen = protokollwerkzeug.sitzungen_laden(fall.id)
        je_sitzung: dict[str, list[dict]] = {}
        for z in zeilen:
            if z.get("fall") == fall.id:
                je_sitzung.setdefault(str(z.get("sitzung") or "unbekannt"), []).append(z)
        for sitzung, liste in sorted(je_sitzung.items()):
            nehmen(f"sitzung/{sitzung}.jsonl", ("\n".join(json.dumps(z, ensure_ascii=False) for z in liste) + "\n").encode("utf-8"))
        hinweise += meldungen
        if not je_sitzung:
            hinweise.append("Sitzungsprotokoll: Zu diesem Fall liegt auf diesem Rechner keines.")
        verlaeufe = {p.name: p.read_bytes() for p in sorted((fall.pfad / "arbeitsstand").glob(VERLAUF_MUSTER))} if (fall.pfad / "arbeitsstand").is_dir() else {}
        if verlauf:
            verlaeufe[verlauf_name or "verlauf-oberflaeche.txt"] = verlauf_text(verlauf).encode("utf-8")
        for name, inhalt in sorted(verlaeufe.items()):
            nehmen(f"sitzung/{name}", inhalt)
        if not verlaeufe:
            hinweise.append("Verlauf aus dem Chat: Es gibt keinen. Über die Oberfläche wurde zu diesem Fall nicht ermittelt. "
                            "Was geschah, steht im Sitzungsprotokoll und im Ermittlungsprotokoll.")
    if "akte" in teile:
        for unter in ("fall.json", "eingang", "protokoll", "arbeitsstand", "rohdaten"):
            quelle = fall.pfad / unter
            dateien = [quelle] if quelle.is_file() else sorted(p for p in quelle.rglob("*") if p.is_file()) if quelle.is_dir() else []
            for p in dateien:
                if "sitzung" in teile and p.parent.name == "arbeitsstand" and p.match(VERLAUF_MUSTER):
                    continue        # steht schon im Teil «sitzung», dort im neuesten Stand
                nehmen("akte/" + p.relative_to(fall.pfad).as_posix(), p.read_bytes())
    kette = fall.kette()
    kopf = [f"Fall {fall.id}: {fall.daten.get('titel') or ''}",
            f"Erzeugt von der Oberfläche am {datetime.now(plattform.zeitzone()).strftime('%d.%m.%Y %H:%M:%S %Z')}",
            "Teile: " + ", ".join(TEILE[t] for t in TEILE if t in teile),
            f"Protokollkette: {'unversehrt' if kette.get('ok') else 'GEBROCHEN: ' + '; '.join(kette.get('fehler') or [])}"
            + (f". Letzter Kettenwert {kette.get('letzter_hash')}" if kette.get("letzter_hash") else ""),
            "Im Teil «sitzung» stehen je Sitzung nur die Zeilen dieses Falls: ein Auszug. Die vollständigen, verketteten Dateien liegen unter protokoll/sitzungen.",
            ""]
    if hinweise:
        kopf += ["Hinweise:"] + [f"  - {h}" for h in hinweise] + [""]
    kopf += ["Dateien (SHA-256, Bytes, Name):"] + [f"  {hashlib.sha256(inhalt).hexdigest()}  {len(inhalt):>10}  {name}" for name, inhalt in eintraege]
    puffer = io.BytesIO()
    with zipfile.ZipFile(puffer, "w", zipfile.ZIP_DEFLATED) as archiv:
        archiv.writestr("INHALT.txt", "\n".join(kopf) + "\n")
        for name, inhalt in eintraege:
            archiv.writestr(name, inhalt)
    return puffer.getvalue(), hinweise
