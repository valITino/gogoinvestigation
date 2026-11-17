"""Pflichtquellen: Quellen, die der Sachbearbeiter für einen Fall vorgibt. Nur Standardbibliothek.

Ohne Vorgabe wählen die Analysten die Quellen selbst, nach den Indikatoren und den Fragen des Auftrags. Mit Vorgabe gilt:

- Jede Pflichtquelle wird für jeden Indikator aus den Eingangsdokumenten abgefragt, zu dem sie passt.
- Suchquellen und Quellen, deren Indikatoren Namen sind (Gruppen, Konten), werden mindestens einmal im Fall gefragt.
- Weitere Quellen darf das Team zusätzlich fragen. Die Vorgabe ist ein Mindestmass, keine Beschränkung.
- Eine Pflichtquelle ersetzt keine Freigabe und keinen Zweck. Abgefragt werden nur Indikatoren des Falls.

Was «passt» heisst, steht je Quelle in gateway/quellen.py (VORGABEN). Ob eine Pflicht erfüllt ist, liest dieses Modul aus
dem Protokoll. Eine Abfrage gehört zu einem Indikator, wenn sie seinen Wert zum Ziel hatte, wenn sie Grundlage einer
Auswertung zu ihm ist oder wenn der Indikator sie unter seinen Belegen führt. Gefragt ist eine Quelle, wenn die Anfrage
hinausging: mit Treffer, ohne Treffer oder mit einem Fehlschlag. Was das Gateway selbst abgelehnt hat (fehlende Freigabe,
Schranke), hat die Quelle nie erreicht und zählt nicht.

    waehlbar(fall)                               was sich vorgeben lässt, mit Bereitschaft
    stand(fall, indikatoren, eintraege, pfad)    was fällig ist, was erfüllt, was fehlgeschlagen, was offen
    maengel(stand), hinweise(stand)              für die Prüfung des Rapports
    kurz(stand)                                  für fall_status: die offenen Paare als Arbeitsliste

Die Vorgabe selbst steht in fall.json unter «pflichtquellen» und wird nur von tools/fall.py geschrieben: am Terminal mit
Bestätigung oder aus der Oberfläche des Sachbearbeiters. Ein Agent kann sie weder setzen noch aufheben.
"""
from __future__ import annotations

import json
import re
import socket
from pathlib import Path
from urllib.parse import urlsplit

from . import plattform
from .akte import PROJEKT, freigabe_erteilt
from .krypto_adressen import erkennen
from .quellen import QUELLEN, ROBIN, VORGABEN, Vorgabe

SCHLUESSEL = "pflichtquellen"
BRAUCHBAR = ("ok", "kein_treffer")
NIE_GESENDET = ("abgelehnt",)           # das Gateway liess die Anfrage nicht hinaus (fehlende Freigabe, Schranke): Die Quelle wurde nie gefragt
ABGELEITET = ("pivot", "geldfluss")     # so beginnt die Herkunft eines Indikators, der nicht aus einem Eingangsdokument stammt
FAMILIEN = ("bitcoin", "evm", "tron")
TYP_NAME = {"ip": "IP-Adressen", "domain": "Domains", "url": "URLs", "hash": "Datei-Hashes", "wallet": "Wallets", "transaktion": "Zahlungen",
            "onion": "Onion-Adressen", "gruppe": "Gruppen", "konto": "Konten"}
STAND_WORT = {"erfuellt": "erfüllt", "offen": "offen", "fehlgeschlagen": "Fehlschlag", "entfaellt": "entfällt", "wartet": "noch nicht fällig",
              "unbekannt": "unbekannt"}
REGEL = ("Vom Sachbearbeiter vorgegeben. Jede dieser Quellen ist für jeden Indikator aus den Eingangsdokumenten abzufragen, zu dem sie passt. "
         "Suchquellen und Quellen für Gruppen und Konten mindestens einmal im Fall. Weitere Quellen sind zusätzlich erlaubt. Die Vorgabe ersetzt "
         "keine Freigabe und keinen Zweck: Abgefragt werden nur Indikatoren des Falls, und der Zweck nennt die Vorgabe und die Fundstelle.")
# Namen der Block-Explorer je Familie im Protokoll: Wo eine Zahlung gefunden wurde, steht damit fest, auf welcher Kette sie liegt
_KETTEN = {f: {n for name, v in VORGABEN.items() if v.familie == f for n in (name, *v.im_protokoll)} for f in FAMILIEN}


def _norm(text: object) -> str:
    return " ".join(str(text or "").split()).casefold()


def reihenfolge() -> list[str]:
    """Alle Namen, die sich vorgeben lassen, in der Reihenfolge des Verzeichnisses. Robin steht am Schluss."""
    return [q.name for q in QUELLEN] + [ROBIN]


def vorgabe(fall: dict) -> list[str]:
    """Die Pflichtquellen eines Falls. Bekannte Namen in der Reihenfolge des Verzeichnisses, unbekannte dahinter: Sie fallen
    nicht still weg, sondern bleiben sichtbar."""
    roh = (fall.get(SCHLUESSEL) or {}).get("quellen") if isinstance(fall.get(SCHLUESSEL), dict) else None
    namen = [str(n) for n in roh] if isinstance(roh, list) else []
    ordnung = reihenfolge()
    return [n for n in ordnung if n in namen] + [n for n in dict.fromkeys(namen) if n not in ordnung]


def faellig_text(v: Vorgabe) -> str:
    """In Worten, wofür eine Quelle als Pflichtquelle fällig wird."""
    typen = ", ".join(TYP_NAME.get(t, t) for t in v.typen)
    if v.einmal:
        return f"einmal im Fall, wenn er {typen} enthält" if typen else "einmal im Fall"
    return f"für jeden Indikator: {typen}"


def faellig_kurz(v: Vorgabe) -> str:
    """Dasselbe in wenigen Worten, für die Auswahl in der Oberfläche: Dort steht die Regel schon über der Liste."""
    typen = ", ".join(TYP_NAME.get(t, t) for t in v.typen)
    if v.einmal:
        return f"einmal im Fall, bei {typen}" if typen else "einmal im Fall"
    return typen


def _erreichbar(url: str) -> bool:
    teile = urlsplit(url)
    try:
        with socket.create_connection((teile.hostname or "127.0.0.1", teile.port or 80), timeout=0.5):
            return True
    except (OSError, ValueError):
        return False


def _robin_bereit() -> tuple[bool, str]:
    """Robin läuft als eigener MCP-Server. Ob er an diesem Arbeitsplatz eingeschaltet ist, hält die Einrichtung in den
    lokalen Einstellungen von Claude Code fest."""
    datei = PROJEKT / ".claude" / "settings.local.json"
    try:
        d = json.loads(datei.read_text(encoding="utf-8")) if datei.is_file() else {}
    except (OSError, ValueError):
        d = {}
    if not isinstance(d, dict):
        d = {}
    if "robin" in (d.get("disabledMcpjsonServers") or []):
        return False, "an diesem Arbeitsplatz abgeschaltet (ohne Robin eingerichtet)"
    if "robin" in (d.get("enabledMcpjsonServers") or []) or d.get("enableAllProjectMcpServers") is True:
        return True, ""
    return False, "an diesem Arbeitsplatz nicht eingeschaltet (braucht Docker und das Abbild, siehe Einrichtung)"


def waehlbar(fall: dict | None = None, nur: set[str] | None = None) -> list[dict]:
    """Was sich als Pflichtquelle vorgeben lässt: je Eintrag Name, Gruppe, ob die Quelle bereit ist und wofür sie fällig würde.
    `nur`: bloss diese Namen (die Erreichbarkeit von Web-Check kostet eine Verbindung, die sonst niemand braucht)."""
    aus = []
    for q in QUELLEN:
        if nur is not None and q.name not in nur:
            continue
        v = VORGABEN[q.name]
        if q.name == "ransomware.live":
            bereit = bool(plattform.einstellung(q.env)) or plattform.einstellung("RANSOMWARE_LIVE_V2") == "1"
        elif q.name == "Web-Check":
            bereit = _erreichbar(plattform.einstellung("WEBCHECK_URL", "http://127.0.0.1:3000"))
        else:
            bereit = q.env is None or q.auch_ohne or bool(plattform.einstellung(q.env))
        grund = "" if bereit else ("die Instanz läuft nicht" if q.name == "Web-Check" else f"der Schlüssel {q.env} fehlt")
        aus.append({"name": q.name, "gruppe": "mit Schlüssel" if q.env else "ohne Schlüssel", "bereit": bereit, "grund": grund, "zweck": q.zweck,
                    "faellig": faellig_text(v), "kurz": faellig_kurz(v), "freigabe": "", "freigabe_fehlt": False})
    if nur is None or ROBIN in nur:
        v = VORGABEN[ROBIN]
        bereit, grund = _robin_bereit()
        aus.append({"name": ROBIN, "gruppe": "Dark Web", "bereit": bereit, "grund": grund,
                    "zweck": "Suche und Lektüre von Onion-Seiten über Tor. Vor dem Öffnen einer Seite steht immer die Prüfung gegen die Sperrliste.",
                    "faellig": faellig_text(v), "kurz": faellig_kurz(v), "freigabe": v.freigabe,
                    "freigabe_fehlt": fall is not None and not freigabe_erteilt(fall, v.freigabe)})
    return aus


def indikatoren_laden(pfad: Path, befunde: dict | None = None) -> list[dict]:
    """Die Indikatoren eines Falls: die Liste aus der Extraktion (arbeitsstand/indikatoren.json), ergänzt um befunde.json.
    Beide zusammen, damit ein Indikator aus dem Eingangsdokument nicht aus der Pflicht fällt, weil er im Rapport fehlt.
    Was die Extraktion von der Abfrage ausnimmt (`abfragen: false`), bleibt ausgenommen.
    `befunde`: der schon gelesene Inhalt von befunde.json, sonst liest die Funktion die Datei."""
    liste: dict[tuple[str, str], dict] = {}
    for datei in (pfad / "arbeitsstand" / "indikatoren.json", pfad / "befunde.json"):
        if befunde is not None and datei.name == "befunde.json":
            roh = befunde
        else:
            try:
                roh = json.loads(datei.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
        eintraege = roh.get("indikatoren") if isinstance(roh, dict) else roh
        for i in eintraege if isinstance(eintraege, list) else []:
            if not isinstance(i, dict) or not i.get("wert") or not i.get("typ"):
                continue
            k = (str(i["typ"]), _norm(i["wert"]))
            alt = liste.get(k, {})
            neu = {**alt, **i}
            if alt.get("abfragen") is False:
                neu["abfragen"] = False
            neu["belege"] = list(dict.fromkeys([*(alt.get("belege") or []), *(i.get("belege") or [])]))
            liste[k] = neu
    return list(liste.values())


def aus_eingang(ind: dict) -> bool:
    """Gilt die Pflicht für diesen Indikator? Ja, wenn er aus einem Eingangsdokument stammt und abgefragt werden darf.
    Nein für die Seite der Geschädigten und für alles, was erst die Ermittlung ergeben hat (Pivot, Station eines Geldflusses)."""
    return (ind.get("abfragen") is not False and "nicht abfragen" not in _norm(ind.get("rolle"))
            and not _norm(ind.get("herkunft")).startswith(ABGELEITET))


def _familien(ind: dict) -> set[str]:
    """Auf welchen Ketten-Familien ein Wallet oder eine Zahlung liegen kann. Leer: nicht verfolgbar (Monero) oder kein bekanntes Format."""
    e = erkennen(str(ind.get("wert") or ""))
    if e.familie in FAMILIEN:
        return {e.familie}
    if e.art == "transaktion":      # 64 Hex-Zeichen: Bitcoin und TRON schreiben gleich. Was das Dokument sagt, steht in Rolle und Anmerkung
        text = _norm(f"{ind.get('rolle') or ''} {ind.get('anmerkung') or ''}")
        if re.search(r"\b(tron|trx|trc-?20)\b", text):
            return {"tron"}
        if re.search(r"\b(bitcoin|btc)\b", text):
            return {"bitcoin"}
        return {"bitcoin", "tron"}
    return set()


def _formen(ind: dict) -> set[str]:
    """Die Schreibweisen, unter denen der Wert eines Indikators als Ziel einer Abfrage im Protokoll stehen kann: der Wert selbst,
    bei einer URL auch mit oder ohne Schrägstrich am Ende."""
    wert = _norm(ind.get("wert"))
    if not wert:
        return set()
    if ind.get("typ") == "url":
        return {wert, wert.rstrip("/"), wert.rstrip("/") + "/"}
    return {wert}


def _zu_indikator(ind: dict, eintraege: list[dict], je_id: dict) -> list[dict]:
    formen = _formen(ind)
    genannt = set(ind.get("belege") or [])
    aus: dict[str, dict] = {}
    for e in eintraege:
        ziel = _norm(e.get("ziel"))
        if e.get("id") in genannt or ziel in formen or any(ziel.startswith(f + " ") for f in formen):
            aus[e["id"]] = e
    for e in list(aus.values()):
        if e.get("art") == "auswertung":
            for teil in e.get("grundlage") or []:
                if teil in je_id:
                    aus.setdefault(teil, je_id[teil])
    return list(aus.values())


def _gelungen(e: dict, pfad: Path | None) -> bool:
    """Hat die Quelle auf diese Abfrage geantwortet? Robin meldet auch dann eine Antwort, wenn Tor noch startet: Das zählt nicht."""
    if e.get("ergebnis") not in BRAUCHBAR:
        return False
    roh = (e.get("antwort") or {}).get("rohdaten")
    if e.get("art") == "tor" and pfad is not None and roh:
        try:
            with open(pfad / roh, "rb") as f:
                if b"tor_bootstrapping" in f.read(200_000):
                    return False
        except OSError:
            pass
    return True


def stand(fall: dict, indikatoren: list[dict], eintraege: list[dict], pfad: Path | None = None) -> dict | None:
    """Der Stand der Pflichtquellen eines Falls, oder None ohne Vorgabe.

    Je Quelle eine Zeile mit `stand`: erfuellt, offen, fehlgeschlagen (gefragt, die Quelle hat nicht geantwortet), entfaellt (kein
    passender Indikator im Fall), wartet (die Indikatoren stehen noch nicht fest) oder unbekannt (Name nicht im Verzeichnis)."""
    quellen = vorgabe(fall)
    if not quellen:
        return None
    eintrag = fall.get(SCHLUESSEL) or {}
    je_id = {e.get("id"): e for e in eintraege}
    eingang = [i for i in indikatoren if isinstance(i, dict) and i.get("id") and aus_eingang(i)]
    bekannt = bool(indikatoren)
    bereit = {w["name"]: w for w in waehlbar(fall, set(quellen))}
    gemerkt: dict[str, list[dict]] = {}

    def zu(i: dict) -> list[dict]:
        if i["id"] not in gemerkt:
            gemerkt[i["id"]] = _zu_indikator(i, eintraege, je_id)
        return gemerkt[i["id"]]

    def passt(v: Vorgabe, i: dict) -> bool:
        if i.get("typ") not in v.typen:
            return False
        if i.get("typ") not in ("wallet", "transaktion"):
            return True
        familien = _familien(i)
        if not familien:                    # nicht verfolgbar: Dafür gibt es keine Abfrage, also auch keine Pflicht
            return False
        if not v.familie:
            return True
        if v.familie not in familien:
            return False
        if len(familien) > 1:               # die Kette steht nicht fest. Ist die Zahlung auf einer andern gefunden, entfällt diese hier
            gefunden = {f for f in FAMILIEN if any(e.get("quelle") in _KETTEN[f] and e.get("ergebnis") == "ok" for e in zu(i))}
            return not gefunden or v.familie in gefunden
        return True

    zeilen, offen = [], []
    zahlen = {"faellig": 0, "erfuellt": 0, "fehlgeschlagen": 0, "offen": 0}
    for name in quellen:
        v = VORGABEN.get(name)
        if v is None:
            zeilen.append({"quelle": name, "stand": "unbekannt", "einmal": False, "faellig": [], "erfuellt": [], "fehlgeschlagen": [], "offen": [], "belege": {},
                           "grund": "Diese Quelle steht nicht im Verzeichnis. Der Sachbearbeiter nimmt sie aus der Vorgabe."})
            continue
        namen = {name, *v.im_protokoll}
        gilt = lambda e: (e.get("quelle") in namen and e.get("art") != "auswertung" and e.get("ergebnis") not in NIE_GESENDET  # noqa: E731
                          and (not v.werkzeuge or e.get("werkzeug") in v.werkzeuge))
        passend = [i for i in eingang if passt(v, i)]
        zeile = {"quelle": name, "einmal": v.einmal, "faellig": [], "erfuellt": [], "fehlgeschlagen": [], "offen": [], "belege": {}, "grund": ""}
        w = bereit.get(name) or {}
        hindernis = (f"Die Freigabe {v.freigabe} fehlt." if v.freigabe and not freigabe_erteilt(fall, v.freigabe)
                     else f"Die Quelle ist nicht bereit: {w.get('grund')}." if w and not w.get("bereit") else "")
        if v.einmal:
            if v.typen and not passend:
                zeile.update(stand="entfaellt" if bekannt else "wartet",
                             grund=(f"Der Fall enthält keine {' oder '.join(TYP_NAME.get(t, t) for t in v.typen)} aus den Eingangsdokumenten."
                                    if bekannt else "Die Indikatoren des Falls stehen noch nicht fest."))
                zeilen.append(zeile)
                continue
            gefragt = [e for e in eintraege if gilt(e)]
            gut = [e["id"] for e in gefragt if _gelungen(e, pfad)]
            zeile["faellig"] = ["Fall"]
            zahlen["faellig"] += 1
            if gut:
                zeile.update(stand="erfuellt", erfuellt=["Fall"], belege={"Fall": gut[:3]})
                zahlen["erfuellt"] += 1
            elif gefragt:
                zeile.update(stand="fehlgeschlagen", fehlgeschlagen=["Fall"], belege={"Fall": [e["id"] for e in gefragt][-3:]},
                             grund="Gefragt, aber ohne verwertbare Antwort.")
                zahlen["fehlgeschlagen"] += 1
            else:
                zeile.update(stand="offen", offen=["Fall"], grund=hindernis)
                zahlen["offen"] += 1
                offen.append({"quelle": name, "indikator": None, "typ": None, "wert": None})
            zeilen.append(zeile)
            continue
        if not passend:
            zeile.update(stand="entfaellt" if bekannt else "wartet",
                         grund=(f"Der Fall enthält keine {' oder '.join(TYP_NAME.get(t, t) for t in v.typen)} aus den Eingangsdokumenten, zu denen diese Quelle passt."
                                if bekannt else "Die Indikatoren des Falls stehen noch nicht fest."))
            zeilen.append(zeile)
            continue
        for i in passend:
            gefragt = [e for e in zu(i) if gilt(e)]
            gut = [e["id"] for e in gefragt if _gelungen(e, pfad)]
            zeile["faellig"].append(i["id"])
            if gut:
                zeile["erfuellt"].append(i["id"])
                zeile["belege"][i["id"]] = gut[:3]
            elif gefragt:
                zeile["fehlgeschlagen"].append(i["id"])
                zeile["belege"][i["id"]] = [e["id"] for e in gefragt][-3:]
            else:
                zeile["offen"].append(i["id"])
                offen.append({"quelle": name, "indikator": i["id"], "typ": i.get("typ"), "wert": i.get("wert")})
        for k in ("faellig", "erfuellt", "fehlgeschlagen", "offen"):
            zahlen[k] += len(zeile[k])
        zeile["stand"] = "offen" if zeile["offen"] else "fehlgeschlagen" if zeile["fehlgeschlagen"] else "erfuellt"
        if zeile["offen"]:
            zeile["grund"] = hindernis
        zeilen.append(zeile)
    return {"quellen": quellen, "am": eintrag.get("am") or "", "durch": eintrag.get("durch") or "", "weg": eintrag.get("weg") or "",
            "bekannt": bekannt, "zeilen": zeilen, "offen": offen, "zahlen": zahlen}


def stand_fuer(fall: dict, pfad: Path, eintraege: list[dict]) -> dict | None:
    """Wie `stand`, mit den Indikatoren aus der Fallakte."""
    if not vorgabe(fall):
        return None
    return stand(fall, indikatoren_laden(pfad), eintraege, pfad)


def _ids(liste: list[str], hoechstens: int = 12) -> str:
    return ", ".join(liste[:hoechstens]) + (f" und {len(liste) - hoechstens} weitere" if len(liste) > hoechstens else "")


def maengel(s: dict | None) -> list[str]:
    """Was den Rapport verhindert: jede Pflichtquelle, die für einen passenden Indikator nie gefragt wurde."""
    aus = []
    for z in (s or {}).get("zeilen") or []:
        if z["stand"] != "offen":
            continue
        wo = "im Fall nie abgefragt" if z["einmal"] else f"nicht abgefragt für {_ids(z['offen'])}"
        aus.append(f"Pflichtquelle {z['quelle']}: {wo}. Der Sachbearbeiter hat sie vorgegeben. " + (f"{z['grund']} " if z["grund"] else "")
                   + "Die Abfrage nachholen. Ob die Quelle aus der Vorgabe fällt, entscheidet nur der Sachbearbeiter.")
    return aus


def hinweise(s: dict | None) -> list[str]:
    """Was der Rapport nennen muss, ohne dass es ihn verhindert: Pflichtquellen, die gefragt wurden und nicht geantwortet haben."""
    aus = []
    for z in (s or {}).get("zeilen") or []:
        if z["stand"] == "unbekannt":
            aus.append(f"Pflichtquelle {z['quelle']}: {z['grund']}")
        elif z["fehlgeschlagen"]:
            wo = "die Abfrage" if z["einmal"] else f"die Abfrage für {_ids(z['fehlgeschlagen'])}"
            belege = ", ".join(dict.fromkeys(b for i in z["fehlgeschlagen"] for b in z["belege"].get(i, [])))
            aus.append(f"Pflichtquelle {z['quelle']}: {wo} ist fehlgeschlagen ({belege}). Das gehört unter 'luecken'.")
    return aus


def kurz(s: dict | None, hoechstens: int = 40) -> dict | None:
    """Der Stand für die Agenten (fall_status): die Vorgabe, die Regel und die offenen Paare als Arbeitsliste."""
    if s is None:
        return None
    aus = {"quellen": s["quellen"], "regel": REGEL, "stand": dict(s["zahlen"]),
           "offen": [o if o["indikator"] else {"quelle": o["quelle"], "faellig": "einmal im Fall, womit, wählt der Analyst"} for o in s["offen"][:hoechstens]]}
    if len(s["offen"]) > hoechstens:
        aus["offen_weitere"] = len(s["offen"]) - hoechstens
    if not s["bekannt"]:
        aus["hinweis"] = "Die Indikatoren des Falls stehen noch nicht fest. Nach der Extraktion fall_status erneut aufrufen: Dann steht hier, was offen ist."
    sonst = [{"quelle": z["quelle"], "stand": STAND_WORT.get(z["stand"], z["stand"]), "grund": z["grund"]} for z in s["zeilen"]
             if z["stand"] in ("entfaellt", "fehlgeschlagen", "unbekannt") or (z["stand"] == "offen" and z["grund"])]
    if sonst:
        aus["anmerkungen"] = sonst
    return aus
