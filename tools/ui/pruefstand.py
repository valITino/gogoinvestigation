"""Prüfstand der Darsteller.

Unter `tools/ui/vorlagen/` liegt je Werkzeug des Gateways eine Rohantwort als Vorlage: eine echte Antwort (gekürzt,
ohne Angaben zu Personen) oder, wo keine echte Antwort vorliegt, eine erfundene in der Form der Quelle. Welche es ist,
steht in `verzeichnis.json` und in der Tabelle, die dieses Modul ausgibt.

Der Prüfstand rechnet für jede Vorlage aus, wie viele Angaben die Rohantwort enthält, wie viele davon der Darsteller
einem benannten Feld zuordnet und wie viele unter «Weitere Angaben der Quelle» stehen. Die Selbsttests bauen darauf auf:
Keine Angabe darf verloren gehen, und jeder gezeigte Wert muss an der genannten Stelle der Rohdatei stehen.

    python3 tools/ui/pruefstand.py            Tabelle je Vorlage
    python3 tools/ui/pruefstand.py --kurz     Tabelle je Werkzeug. Sie steht in docs/OBERFLAECHE.md zwischen den Marken
                                              «darsteller:anfang» und «darsteller:ende». Ein Selbsttest prüft, dass sie dort aktuell ist.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):      # direkt gestartet
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "tools.ui"

from . import darsteller as ds  # noqa: E402

ORT = Path(__file__).resolve().parent / "vorlagen"
ZEIT = "2026-11-16T10:00:00Z"
ANFANG, ENDE = "<!-- darsteller:anfang -->", "<!-- darsteller:ende -->"
ARTEN = {"echt": "echte Antwort", "form": "Inhalt erfunden, Form der echten Antwort", "erfunden": "erfunden nach Dokumentation"}


def vorlagen() -> list[dict]:
    return json.loads((ORT / "verzeichnis.json").read_text(encoding="utf-8"))


def form_von(datei: str) -> str:
    if datei.endswith(".json"):
        return "json"
    return "csv" if datei.endswith(".csv") else "bild" if datei.endswith((".png", ".jpg", ".jpeg", ".gif", ".webp")) else "text"


def lesen(v: dict) -> tuple[object, str]:
    """Inhalt der Vorlage und ihre Form (json, text, csv)."""
    text = (ORT / v["datei"]).read_text(encoding="utf-8")
    form = form_von(v["datei"])
    return (json.loads(text) if form == "json" else text), form


def eintrag(v: dict, nr: int = 1, **mehr) -> dict:
    """Ein Protokolleintrag in der Form des Gateways, wie er zu dieser Rohantwort gehören würde."""
    aktiv = v["werkzeug"] in ("webcheck_aktiv", "urlquery_einreichen", "urlscan_einreichen", "wayback_sichern")
    art = "tor" if "robin" in v["werkzeug"] else "von_hand" if v["werkzeug"] == "abklaerung_von_hand" else "aktiv" if aktiv else \
        "auswertung" if v["quelle"] == "Gateway" else "passiv"
    return {"nr": nr, "id": f"P-{nr:04d}", "zeit_utc": ZEIT, "zeit_lokal": "2026-11-16T11:00:00+01:00", "fall": "VORLAGEN", "werkzeug": v["werkzeug"],
            "quelle": v["quelle"], "art": art, "freigabe": None, "ziel": v["ziel"], "ziel_typ": "sonstiges", "zweck": "Vorlage für den Prüfstand der Darsteller",
            "anfrage": {"methode": "GET", "url": "", "proxy": False},
            "antwort": {"status": 200, "bytes": (ORT / v["datei"]).stat().st_size, "sha256": "", "rohdaten": f"rohdaten/P-{nr:04d}_{v['datei']}", "dauer_ms": 1, "aus_cache": False},
            "ergebnis": "ok", "fehler": None, **mehr}


def blatt(v: dict) -> ds.Blatt:
    roh, form = lesen(v)
    return ds.darstellen(eintrag(v), roh, form)


def messen() -> list[dict]:
    zeilen = []
    for v in vorlagen():
        roh, form = lesen(v)
        b = ds.darstellen(eintrag(v), roh, form)
        # Robin antwortet als Text, gezeigt wird seine Zerlegung: Gezählt werden deren Angaben
        zeilen.append({"name": v["name"], "werkzeug": v["werkzeug"], "quelle": v["quelle"], "form": "json" if b.zerlegt else form, "eigen": b.eigen, "titel": b.titel, "gesamt": b.gesamt,
                       "zugeordnet": b.zugeordnet, "weitere": len(b.weitere), "art": v["art"], "herkunft": v["herkunft"]})
    return zeilen


def je_werkzeug() -> list[dict]:
    """Die Messung zusammengefasst: eine Zeile je Werkzeug (Web-Check: passiv und aktiv, Teilabfragen je Quelle)."""
    gruppen: dict[str, dict] = {}
    for z in messen():
        teil = z["werkzeug"] in ("ip_abruf", "krypto_abruf", "urlscan_abruf")
        name = f"{z['werkzeug']} ({z['quelle']})" if teil else z["werkzeug"].rsplit("__", 1)[-1]
        g = gruppen.setdefault(name, {"werkzeug": name, "vorlagen": 0, "eigen": 0, "gesamt": 0, "zugeordnet": 0, "weitere": 0, "arten": set(), "formen": set()})
        g["vorlagen"] += 1
        g["eigen"] += 1 if z["eigen"] else 0
        g["arten"].add(z["art"])
        g["formen"].add(z["form"])
        for k in ("gesamt", "zugeordnet", "weitere"):
            g[k] += z[k]
    return [gruppen[k] for k in sorted(gruppen)]


def tabelle(kurz: bool = False) -> str:
    aus = []
    if kurz:
        aus += ["| Werkzeug | Eigener Darsteller | Angaben in der Vorlage | zugeordnet | unter «Weitere Angaben» | Vorlage |", "|---|---|---:|---:|---:|---|"]
        for g in je_werkzeug():
            eigen = "ja" if g["eigen"] == g["vorlagen"] else "nein (allgemeiner)" if not g["eigen"] else f"{g['eigen']} von {g['vorlagen']}"
            zahlen = (g["gesamt"], g["zugeordnet"], g["weitere"]) if g["formen"] == {"json"} else ("Text", "–", "–")
            vorlage = ", ".join(ARTEN[a] for a in sorted(g["arten"])) + (f" ({g['vorlagen']} Prüfungen)" if g["vorlagen"] > 1 else "")
            aus.append(f"| `{g['werkzeug']}` | {eigen} | {zahlen[0]} | {zahlen[1]} | {zahlen[2]} | {vorlage} |")
    else:
        aus += ["| Vorlage | Darsteller | Angaben | zugeordnet | weitere | Art |", "|---|---|---:|---:|---:|---|"]
        for z in messen():
            zahlen = (z["gesamt"], z["zugeordnet"], z["weitere"]) if z["form"] == "json" else ("Text", "–", "–")
            aus.append(f"| `{z['name']}` | {'eigener' if z['eigen'] else 'allgemeiner'} | {zahlen[0]} | {zahlen[1]} | {zahlen[2]} | {ARTEN[z['art']]} |")
    return "\n".join(aus)


if __name__ == "__main__":
    print(tabelle("--kurz" in sys.argv))
