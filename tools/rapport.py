#!/usr/bin/env python3
"""Erzeugt den Abschlussrapport eines Falls aus befunde.json.

    python3 tools/rapport.py <Fall-ID>             prüft und erzeugt den Rapport
    python3 tools/rapport.py <Fall-ID> --entwurf   erzeugt trotz Mängeln, als Entwurf gekennzeichnet
    python3 tools/rapport.py <Fall-ID> --nur-pruefen

Ergebnis: faelle/<Fall-ID>/rapport/Abschlussrapport.html (in sich geschlossen, druckbar als PDF)
          faelle/<Fall-ID>/rapport/indikatoren.csv

Der Rapport wird nur erzeugt, wenn jede Aussage belegt ist. Geprüft wird unter anderem:
  - Jeder Beleg (P-0001 … vom Gateway, X-0001 … von weiteren Werkzeugen wie Robin) existiert im
    Protokoll der Fallakte und war keine fehlgeschlagene Abfrage.
  - Feststellungen und Bewertungen haben mindestens einen Beleg.
  - Sicherheit 'hoch' stützt sich auf mindestens zwei verschiedene Quellen. Bei einer Auswertung des Gateways
    (Geldfluss, Zuordnung) zählen die Quellen, aus denen ihre Tatsachen stammen.
  - Ein Geldfluss-Diagramm verweist auf eine Auswertung von krypto_geldfluss in der Fallakte.
  - Jeder Befund hat eine Erklärung in einfachen Worten und ist gegengeprüft.
  - Das Abfrageprotokoll ist unverändert (Hash-Kette).
Rückgabewert 0: erzeugt. 1: Mängel, nichts erzeugt. 2: Fall oder befunde.json fehlt.
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import FREIGABE_TEXT, FREIGABEN, belege_lesen, fall_daten, fall_pfad, freigabe_erteilt, kette_pruefen  # noqa: E402
from tools._html import (FLUSS_KLASSEN, STATUS, TYPEN, _FLUSS_ART, _FLUSS_WORT, balken, esc, geldfluss, graf, graf_legende,  # noqa: E402
                         kachel, kuerzen, kurz_adresse, seite, verteilung, zahl_ch)

try:
    ZONE = plattform.zeitzone()
except plattform.Zeitzonenfehler as e:
    sys.exit(f"FEHLER: {e}")


def erstellt() -> datetime:
    """Erstellzeit des Dokuments. Für den Musterfall gestellt, damit er bei jedem Lauf gleich ausfällt."""
    if os.environ.get("OSINT_TESTZEIT"):
        return datetime.strptime(os.environ["OSINT_TESTZEIT"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)
SICHERHEIT = {"hoch": "●●● hoch", "mittel": "●●○ mittel", "tief": "●○○ tief"}
ARTEN = {"feststellung": "Feststellung", "bewertung": "Bewertung", "hypothese": "Hypothese"}
PRUEFUNG = {"bestaetigt": ("✓ Gegenprüfung: bestätigt", "var(--gut)"),
            "eingeschraenkt": ("✓ Gegenprüfung: bestätigt mit Einschränkung", "var(--warnung)"),
            "widerlegt": ("✕ Gegenprüfung: widerlegt", "var(--kritisch)"),
            "offen": ("○ Gegenprüfung: offen", "var(--neutral)")}
BRAUCHBAR = ("ok", "kein_treffer")


# --------------------------------------------------------------------------- Prüfung

def pruefen(b: dict, protokoll: dict[str, dict], entwurf: bool) -> tuple[list[str], list[str]]:
    """Gibt (Mängel, Hinweise) zurück. Mängel verhindern den Rapport."""
    maengel: list[str] = []
    hinweise: list[str] = []
    indikatoren = {i.get("id"): i for i in b.get("indikatoren") or []}
    befunde = b.get("befunde") or []

    def belege_pruefen(wo: str, belege: list | None) -> set[str]:
        quellen = set()
        for pid in belege or []:
            e = protokoll.get(pid)
            if not e:
                maengel.append(f"{wo}: Beleg {pid} steht nicht im Abfrageprotokoll.")
            elif e.get("ergebnis") not in BRAUCHBAR:
                maengel.append(f"{wo}: Beleg {pid} war eine {e.get('ergebnis')}e Abfrage und belegt nichts.")
            elif e.get("art") == "auswertung":      # das Gateway hat gerechnet: Es zählen die Quellen der Tatsachen
                quellen.update(e.get("quellen") or [])
            else:
                quellen.add(e.get("quelle"))
        return quellen

    if not [a for a in b.get("zusammenfassung") or [] if str(a).strip()]:
        maengel.append("zusammenfassung fehlt (mindestens ein Absatz).")
    for name, liste in (("Indikator", b.get("indikatoren") or []), ("Befund", befunde)):
        ids = [x.get("id") for x in liste]
        for doppelt in {i for i in ids if ids.count(i) > 1}:
            maengel.append(f"{name}-ID {doppelt} ist mehrfach vergeben.")

    for i in b.get("indikatoren") or []:
        wo = f"Indikator {i.get('id')}"
        if not i.get("wert") or i.get("typ") not in TYPEN:
            maengel.append(f"{wo}: 'wert' fehlt oder 'typ' unbekannt (erlaubt: {', '.join(TYPEN)}).")
        if i.get("bewertung") not in STATUS:
            maengel.append(f"{wo}: 'bewertung' muss eines sein von {', '.join(STATUS)}.")
        if not str(i.get("herkunft") or "").strip():
            maengel.append(f"{wo}: 'herkunft' fehlt (Fundstelle im Eingangsdokument oder Pivot aus welchem Beleg).")
        belege_pruefen(wo, i.get("belege"))
        if i.get("bewertung") in ("boesartig", "verdaechtig") and not i.get("belege"):
            maengel.append(f"{wo}: Bewertung '{i.get('bewertung')}' ohne Beleg.")

    for f in befunde:
        wo = f"Befund {f.get('id')}"
        art = f.get("art")
        if art not in ARTEN:
            maengel.append(f"{wo}: 'art' muss feststellung, bewertung oder hypothese sein.")
        if f.get("sicherheit") not in SICHERHEIT:
            maengel.append(f"{wo}: 'sicherheit' muss hoch, mittel oder tief sein.")
        for feld in ("titel", "text"):
            if not str(f.get(feld) or "").strip():
                maengel.append(f"{wo}: '{feld}' fehlt.")
        if len(str(f.get("erlaeuterung") or "").strip()) < 30:
            maengel.append(f"{wo}: 'erlaeuterung' fehlt. Jeder Befund braucht eine Erklärung in einfachen Worten.")
        quellen = belege_pruefen(wo, f.get("belege"))
        if art in ("feststellung", "bewertung") and not f.get("belege"):
            maengel.append(f"{wo}: Eine {ARTEN[art]} braucht mindestens einen Beleg. Ohne Beleg ist es eine Hypothese.")
        if f.get("sicherheit") == "hoch" and len(quellen) < 2:
            maengel.append(f"{wo}: Sicherheit 'hoch' verlangt Belege aus mindestens zwei verschiedenen Quellen "
                           f"(vorhanden: {', '.join(sorted(q for q in quellen if q)) or 'keine'}). Sonst 'mittel'.")
        if art == "hypothese" and f.get("sicherheit") == "hoch":
            maengel.append(f"{wo}: Eine Hypothese kann nicht Sicherheit 'hoch' haben.")
        for iid in f.get("indikatoren") or []:
            if iid not in indikatoren:
                maengel.append(f"{wo}: verweist auf unbekannten Indikator {iid}.")
        stand = f.get("gegenpruefung") or "offen"
        if stand not in PRUEFUNG:
            maengel.append(f"{wo}: 'gegenpruefung' muss bestaetigt, eingeschraenkt, widerlegt oder offen sein.")
        elif stand == "widerlegt":
            maengel.append(f"{wo}: Die Gegenprüfung hat den Befund widerlegt. Befund streichen oder überarbeiten.")
        elif stand == "offen":
            (hinweise if entwurf else maengel).append(f"{wo}: noch nicht gegengeprüft.")
        elif stand == "eingeschraenkt" and not str(f.get("gegenpruefung_notiz") or "").strip():
            maengel.append(f"{wo}: Gegenprüfung 'eingeschraenkt' braucht 'gegenpruefung_notiz' (worin die Einschränkung besteht).")

    befund_ids = {f.get("id") for f in befunde}
    for n, k in enumerate(b.get("kernaussagen") or [], 1):
        wo = f"Kernaussage {n}"
        belege_pruefen(wo, k.get("belege"))
        for bid in k.get("befunde") or []:
            if bid not in befund_ids:
                maengel.append(f"{wo}: verweist auf unbekannten Befund {bid}.")
        if not k.get("belege") and not k.get("befunde"):
            maengel.append(f"{wo}: braucht einen Verweis auf Befunde oder Belege.")
    for n, r in enumerate(b.get("beziehungen") or [], 1):
        wo = f"Beziehung {n} ({r.get('von')} → {r.get('nach')})"
        for seite_ in ("von", "nach"):
            if r.get(seite_) not in indikatoren:
                maengel.append(f"{wo}: unbekannter Indikator {r.get(seite_)}.")
        belege_pruefen(wo, r.get("belege"))
        if not r.get("belege") and not str(r.get("quelle") or "").strip() and r.get("sicherheit") != "tief":
            maengel.append(f"{wo}: ohne 'belege' oder 'quelle' (Fundstelle im Eingangsdokument) nur mit Sicherheit 'tief' zulässig.")
    for n, z in enumerate(b.get("zeitachse") or [], 1):
        belege_pruefen(f"Zeitachse {n}", z.get("belege"))
        if not zeit_lesen(z.get("zeit")):
            maengel.append(f"Zeitachse {n}: 'zeit' nicht lesbar ({z.get('zeit')}). Format: 2026-10-02 oder 2026-10-02T14:10:00Z.")
        if not z.get("belege") and not str(z.get("quelle") or "").strip():
            maengel.append(f"Zeitachse {n}: braucht 'belege' oder 'quelle' (z. B. 'Rapport Ziff. 2').")
    for n, g in enumerate(b.get("geldfluesse") or [], 1):
        wo = f"Geldfluss {n}"
        e = protokoll.get(g.get("beleg"))
        if not str(g.get("titel") or "").strip():
            maengel.append(f"{wo}: 'titel' fehlt (was wird verfolgt, in einem Satz).")
        if not e:
            maengel.append(f"{wo}: Beleg {g.get('beleg')} steht nicht im Abfrageprotokoll.")
        elif e.get("werkzeug") != "krypto_geldfluss" or e.get("art") != "auswertung" or e.get("ergebnis") != "ok":
            maengel.append(f"{wo}: Beleg {g.get('beleg')} ist keine Auswertung von krypto_geldfluss. Als 'beleg' gilt die "
                           "protokoll_id, die das Werkzeug zurückgegeben hat.")
        for bid in g.get("befunde") or []:
            if bid not in {f.get("id") for f in befunde}:
                maengel.append(f"{wo}: verweist auf unbekannten Befund {bid}.")
    if not b.get("luecken"):
        hinweise.append("'luecken' ist leer. Wirklich alles geklärt? Offene Punkte und Grenzen gehören in den Rapport.")
    genutzt = verwendete_belege(b, protokoll)
    ungenutzt = [p for p, e in protokoll.items() if p not in genutzt and e.get("ergebnis") in BRAUCHBAR
                 and not (e.get("antwort") or {}).get("aus_cache")]
    if ungenutzt:
        hinweise.append(f"{len(ungenutzt)} Abfrage(n) tauchen im Rapport nicht auf: {', '.join(ungenutzt[:12])}"
                        f"{' …' if len(ungenutzt) > 12 else ''}. Auch Abfragen ohne Treffer sind ein Ergebnis.")
    return maengel, hinweise


def verwendete_belege(b: dict, protokoll: dict[str, dict] | None = None) -> set[str]:
    """Belege, auf die der Rapport verweist. Wer eine Auswertung zitiert, hat auch die Abfragen dahinter verwendet."""
    genutzt: set[str] = set()
    for liste in ("indikatoren", "befunde", "kernaussagen", "beziehungen", "zeitachse"):
        for x in b.get(liste) or []:
            genutzt.update(x.get("belege") or [])
    genutzt.update(g.get("beleg") for g in b.get("geldfluesse") or [] if g.get("beleg"))
    for pid in list(genutzt):
        genutzt.update((protokoll or {}).get(pid, {}).get("grundlage") or [])
    return genutzt


# --------------------------------------------------------------------------- Darstellung

def zeit_lesen(wert: object) -> datetime | None:
    if not isinstance(wert, str) or not wert.strip():
        return None
    w = wert.strip().replace("Z", "+00:00")
    for versuch in (w, w + "T00:00:00+00:00" if len(w) == 10 else w):
        try:
            d = datetime.fromisoformat(versuch)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def zeit_zeigen(wert: object) -> str:
    d = zeit_lesen(wert)
    if not d:
        return str(wert or "")
    if isinstance(wert, str) and len(wert.strip()) == 10:
        return d.strftime("%d.%m.%Y")
    return d.astimezone(ZONE).strftime("%d.%m.%Y, %H:%M")


def beleg_links(belege: list | None, protokoll: dict[str, dict]) -> str:
    teile = []
    for pid in belege or []:
        e = protokoll.get(pid) or {}
        titel = f"{e.get('quelle', '?')} · {e.get('werkzeug', '?')} · {e.get('ziel', '?')} · {zeit_zeigen(e.get('zeit_utc'))}"
        teile.append(f'<a class="beleg" href="Ermittlungsprotokoll.html#{esc(pid)}" title="{esc(titel)}">{esc(pid)}</a>')
    return " ".join(teile) or '<span class="klein">–</span>'


def marke(text: str, farbe: str | None = None) -> str:
    punkt = f'<span class="punkt" style="background:{farbe}"></span>' if farbe else ""
    return f'<span class="marke">{punkt}{esc(text)}</span>'


def absaetze(texte: list | str | None) -> str:
    if isinstance(texte, str):
        texte = [texte]
    return "".join(f"<p>{esc(str(t))}</p>" for t in texte or [] if str(t).strip())


def kennzahlen_text(k: dict | None) -> str:
    if not k:
        return ""
    teile = []
    if "abuse_score" in k:
        teile.append(f"AbuseIPDB {k['abuse_score']}/100")
    if "vt_boesartig" in k:
        teile.append(f"VirusTotal {k['vt_boesartig']}" + (f"/{k['vt_gesamt']}" if k.get("vt_gesamt") else ""))
    if k.get("offene_ports"):
        teile.append("Ports " + ", ".join(str(p) for p in k["offene_ports"][:8]))
    for name, wert in k.items():
        if name not in ("abuse_score", "vt_boesartig", "vt_gesamt", "offene_ports"):
            teile.append(f"{name}: {wert}")
    return "; ".join(teile)


_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


def ortszeit(text: str) -> str:
    """Zeitangaben in UTC, wie sie die Werkzeuge schreiben, in die Ortszeit des Rapports."""
    return _UTC.sub(lambda m: zeit_zeigen(m.group(0)), text or "")


def geldfluss_abschnitt(g: dict, protokoll: dict[str, dict], pfad: Path) -> str:
    """Ein Geldfluss: Kopf, Verbleib als Balken, Flussbild, Tabellen, Ansatzpunkte und Verfahren.
    Alles stammt aus der Rohdatei der Auswertung, nichts aus der Erinnerung."""
    e = protokoll.get(g.get("beleg")) or {}
    h = [f"<h3>Geldfluss: {esc(g.get('titel') or '')}</h3>" + absaetze(g.get("text"))]
    try:
        d = json.loads((pfad / e["antwort"]["rohdaten"]).read_text(encoding="utf-8"))["details"]
    except (KeyError, OSError, ValueError, TypeError):
        return h[0] + f"<p class='klein'>Die Auswertung {esc(str(g.get('beleg')))} liegt nicht lesbar in der Fallakte.</p>"
    start, einheit = d.get("start") or {}, (d.get("wert") or {}).get("symbol") or ""
    wert = start.get("gegenwert") or {}
    womit = (f"Zahlung {start.get('tx', '')} an {start.get('adresse', '')}" if start.get("art") == "zahlung"
             else f"alle Abgänge der Adresse {start.get('adresse', '')}")
    h.append('<div class="kopf">'
             f"<div style='grid-column:1/-1'><b>Verfolgt</b><span class='mono'>{esc(womit)}</span></div>"
             f"<div><b>Startbetrag</b>{esc(zahl_ch(d.get('startbetrag', '')))} {esc(einheit)}"
             + (f" (CHF {esc(zahl_ch(wert['chf']))})" if wert.get("chf") else "") + "</div>"
             f"<div><b>Zeitpunkt</b>{esc(zeit_zeigen(start.get('zeit')) or '–')}</div>"
             f"<div><b>Kette</b>{esc(d.get('kette_anzeige') or d.get('kette') or '')}</div>"
             f"<div><b>Beleg</b>{beleg_links([g.get('beleg')], protokoll)}</div></div>")
    if wert.get("chf"):
        kurs = start.get("kurs") or {}
        h.append(f"<p class='klein'>Gegenwerte zum Kurs am Tag der Startzahlung ({esc(' und '.join(kurs.get('quellen') or []))}"
                 + (f", Wechselkurs vom {esc(zeit_zeigen(kurs['wechselkurs_vom']))}" if kurs.get("wechselkurs_vom") else "")
                 + "). Ein Gegenwert ist eine Bewertung zum Tageskurs, kein ausbezahlter Betrag.</p>")
    balken_ = verteilung(d)
    if balken_:
        h.append(f"<figure>{balken_}<figcaption>Verbleib des Startbetrags nach dem Ende der Verfolgung.</figcaption></figure>")
    bild = geldfluss(d)
    if bild:
        h.append(f"<figure>{bild}<figcaption>Weg des Geldes von links nach rechts. Die Breite der Bänder entspricht dem Betrag, "
                 "die Nummern verweisen auf die Tabelle der Stationen. Jede einzelne Zahlung ist eine Feststellung aus der "
                 "Blockchain. Die Zuordnung über mehrere Stationen ist eine Bewertung nach dem unten genannten Verfahren.</figcaption></figure>")
    enden = d.get("enden") or []
    if enden:
        h.append('<div class="tabelle-breit"><table><tr><th>Verbleib</th><th>Station</th><th class="zahl">Betrag</th>'
                 '<th class="zahl">Anteil</th><th>Begründung</th></tr>')
        for x in enden[:30]:
            farbe = FLUSS_KLASSEN[_FLUSS_ART.get(x.get("art"), "offen")][1]
            wer = f"{x['station']} · <span class='mono'>{esc(kurz_adresse(str(x.get('adresse', ''))))}</span>" if x.get("station") else "–"
            h.append(f"<tr><td class='nw'>{marke(x.get('bezeichnung', ''), farbe)}" + (f"<div class='klein'>{esc(x['name'])}</div>" if x.get("name") else "")
                     + f"</td><td class='nw'>{wer}</td><td class='zahl nw'>{esc(zahl_ch(x.get('betrag', '')))} {esc(einheit)}</td>"
                     f"<td class='zahl nw'>{esc(str(x.get('anteil', '')))} %</td><td class='klein'>{esc(ortszeit(x.get('grund') or ''))}"
                     + (f". Transaktion <span class='mono'>{esc(x['tx'])}</span>" if x.get("tx") else "") + "</td></tr>")
        h.append("</table></div>")
        if len(enden) > 30:
            h.append(f"<p class='klein'>{len(enden) - 30} weitere, kleinere Enden stehen in der Rohdatei der Auswertung.</p>")
    stationen = d.get("stationen") or []
    if stationen:
        h.append('<div class="tabelle-breit"><table><tr><th>Nr.</th><th>Adresse</th><th>Rolle</th><th class="zahl">Betrag</th><th>Etiketten und Hinweise</th></tr>')
        for x in stationen[:60]:
            zusatz = ortszeit("; ".join((x.get("etiketten") or []) + (x.get("hinweise") or [])))
            h.append(f"<tr><td class='nw'>{x.get('nr')}</td><td class='mono'>{esc(str(x.get('adresse', '')))}</td>"
                     f"<td class='nw'>{esc(_FLUSS_WORT.get(x.get('art'), str(x.get('art'))))}" + (f"<div class='klein'>{esc(x['name'])}</div>" if x.get("name") else "")
                     + f"</td><td class='zahl nw'>{esc(zahl_ch(x.get('betrag', '')))} {esc(einheit)}</td><td class='klein'>{esc(zusatz)}</td></tr>")
        h.append("</table></div>")
    if d.get("ansatzpunkte"):
        h.append("<p><b>Ansatzpunkte aus der Auswertung</b> <span class='klein'>(vom Werkzeug aus dem Geldfluss abgeleitet, durch die "
                 "fallführende Stelle zu würdigen)</span></p><ul>" + "".join(f"<li>{esc(ortszeit(a))}</li>" for a in d["ansatzpunkte"]) + "</ul>")
    if d.get("methode"):
        h.append(f"<p class='klein'><b>Verfahren:</b> {esc(d['methode'])}</p>")
    return "".join(h)


def bauen(fall_id: str, fall: dict, b: dict, eintraege: list[dict], kettenstand: dict,
          maengel: list[str], hinweise: list[str], entwurf: bool) -> str:
    protokoll = {e["id"]: e for e in eintraege}
    indikatoren = b.get("indikatoren") or []
    befunde = b.get("befunde") or []
    h: list[str] = []

    # ---- Kopf
    if fall.get("muster"):
        h.append('<div class="banner">MUSTER – fiktiver Fall mit erfundenen Daten. Dient nur zur Veranschaulichung.</div>')
    if entwurf:
        h.append(f'<div class="banner">ENTWURF – {len(maengel)} Mangel/Mängel und {len(hinweise)} Hinweis(e) offen. '
                 'Nicht zur Weitergabe. Liste am Ende des Dokuments.</div>')
    h.append(f"<h1>Abschlussrapport OSINT-Ermittlung</h1><p class='unter'>{esc(fall.get('titel') or fall_id)}</p>")
    h.append('<div class="kopf">'
             f"<div><b>Fall</b>{esc(fall_id)}</div>"
             f"<div><b>Stand</b>{esc(zeit_zeigen(b.get('stand') or erstellt().isoformat()))}</div>"
             f"<div><b>Sachbearbeitung</b>{esc(fall.get('sachbearbeiter') or '–')}</div>"
             f"<div><b>Klassifizierung</b>{esc(fall.get('klassifizierung') or '–')}</div>"
             f"<div><b>Fassung</b>pseudonymisiert</div></div>")
    h.append('<p class="klein">Personen und Organisationen erscheinen als Platzhalter in eckigen Klammern, zum Beispiel '
             '[PERSON_01]. Die Zuordnung liegt ausschliesslich bei der fallführenden Stelle. Zeiten in Ortszeit '
             f'({esc(str(ZONE))}). Verweise wie <span class="beleg">P-0007</span> führen zum Eintrag im Ermittlungsprotokoll.</p>')

    # ---- 1 Das Wichtigste
    h.append("<h2>1 Das Wichtigste in Kürze</h2>" + absaetze(b.get("zusammenfassung")))
    if b.get("kernaussagen"):
        h.append("<ul>")
        for k in b["kernaussagen"]:
            verweise = " ".join(f'<a class="beleg" href="#{esc(x)}">{esc(x)}</a>' for x in k.get("befunde") or [])
            h.append(f"<li>{esc(k.get('text', ''))} {marke(SICHERHEIT.get(k.get('sicherheit'), '?'))} "
                     f"{verweise} {beleg_links(k.get('belege'), protokoll) if k.get('belege') else ''}</li>")
        h.append("</ul>")

    # ---- 2 Auftrag
    h.append("<h2>2 Auftrag und Ausgangslage</h2>")
    h.append(absaetze(fall.get("auftrag")) or '<p class="klein">Kein Auftrag in der Fallakte vermerkt.</p>')
    h.append(absaetze(b.get("ausgangslage")))
    register = fall.get("_eingang") or {}
    if register:
        h.append('<table><tr><th>Eingangsdokument</th><th>PII-Prüfung</th><th>SHA-256</th></tr>')
        for name, e in sorted(register.items()):
            h.append(f"<tr><td>{esc(name)}</td><td>{esc(e.get('ergebnis', ''))}</td><td class='mono'>{esc(e.get('sha256', ''))}</td></tr>")
        h.append("</table>")

    # ---- 3 Überblick in Zahlen
    zaehler = Counter((i.get("bewertung") or "unbekannt") for i in indikatoren)
    auswertungen = [e for e in eintraege if e.get("art") == "auswertung"]
    eintraege = [e for e in eintraege if e.get("art") != "auswertung"]       # ab hier: nur Abfragen bei Quellen
    quellen = Counter(e.get("quelle") for e in eintraege if e.get("ergebnis") in BRAUCHBAR)
    ohne_treffer = sum(1 for e in eintraege if e.get("ergebnis") == "kein_treffer")
    fehlgeschlagen = sum(1 for e in eintraege if e.get("ergebnis") in ("fehler", "abgelehnt"))
    geprueft = sum(1 for f in befunde if f.get("gegenpruefung") in ("bestaetigt", "eingeschraenkt"))
    h.append("<h2>3 Überblick in Zahlen</h2><div class='kacheln'>")
    h.append(kachel(len(indikatoren), "Indikatoren", f"{zaehler['boesartig']} bösartig, {zaehler['verdaechtig']} verdächtig"))
    h.append(kachel(len(eintraege), "Abfragen", f"{ohne_treffer} ohne Treffer, {fehlgeschlagen} nicht ausgeführt"))
    h.append(kachel(len(quellen), "Quellen genutzt", f"{len(auswertungen)} Auswertungen daraus" if auswertungen else ""))
    h.append(kachel(len(befunde), "Befunde", f"{geprueft} gegengeprüft"))
    h.append("</div>")
    if indikatoren:
        zeilen = [{"name": f"{STATUS[s][2]} {STATUS[s][0]}", "wert": zaehler[s], "anzeige": str(zaehler[s]), "farbe": STATUS[s][1]}
                  for s in ("boesartig", "verdaechtig", "unauffaellig", "unbekannt") if zaehler[s]]
        h.append("<figure>" + balken(zeilen, beschriftung="Indikatoren nach Bewertung", namensspalte=150) +
                 "<figcaption>Indikatoren nach Bewertung. Die Bewertung jedes einzelnen Indikators steht in Abschnitt 5.</figcaption></figure>")

    # ---- 4 Vorgehen
    h.append("<h2>4 Vorgehen</h2>")
    h.append(absaetze(b.get("vorgehen")) or
             "<p>Die Indikatoren aus den Eingangsdokumenten wurden über das OSINT-Gateway bei den unten aufgeführten "
             "Quellen abgefragt. Jede Abfrage ist mit Zeitpunkt, Ziel, Zweck und Prüfsumme der Antwort protokolliert, "
             "die Antworten liegen unverändert in der Fallakte. Die Befunde wurden von einer zweiten, unabhängigen "
             "Instanz anhand der Rohdaten gegengeprüft.</p>")
    if quellen:
        zeilen = [{"name": q or "?", "wert": n, "anzeige": str(n)} for q, n in quellen.most_common()]
        h.append("<figure>" + balken(zeilen, beschriftung="Abfragen je Quelle") +
                 "<figcaption>Verwertbare Abfragen je Quelle (mit und ohne Treffer). Einzelnachweis im Ermittlungsprotokoll.</figcaption></figure>")
    h.append("<table><tr><th>Freigabe</th><th>Stand</th><th>Bedeutung</th></tr>")
    for name in FREIGABEN:
        e = (fall.get("freigaben") or {}).get(name) or {}
        stand = f"erteilt durch {e.get('durch')} am {zeit_zeigen(e.get('am'))}" if freigabe_erteilt(fall, name) else "nicht erteilt"
        h.append(f"<tr><td>{esc(name)}</td><td>{esc(stand)}</td><td>{esc(FREIGABE_TEXT[name])}</td></tr>")
    h.append("</table>")

    # ---- 5 Indikatoren
    h.append("<h2>5 Indikatoren</h2>")
    if indikatoren:
        h.append('<div class="tabelle-breit"><table><tr><th>Nr.</th><th>Typ</th><th>Wert</th><th>Rolle und Herkunft</th>'
                 "<th>Bewertung</th><th>Belege</th></tr>")
        for i in indikatoren:
            name, farbe, zeichen, _ = STATUS.get(i.get("bewertung"), STATUS["unbekannt"])
            zahlen = kennzahlen_text(i.get("kennzahlen"))
            h.append(f"<tr id='{esc(i.get('id', ''))}'><td class='nw'>{esc(i.get('id', ''))}</td>"
                     f"<td class='nw'>{esc(TYPEN.get(i.get('typ'), ('?',))[0])}</td>"
                     f"<td class='mono wert'>{esc(i.get('wert', ''))}</td>"
                     f"<td>{esc(i.get('rolle') or '')}<div class='klein'>Herkunft: {esc(i.get('herkunft') or '')}</div></td>"
                     f"<td>{marke(f'{zeichen} {name}', farbe)}" + (f"<div class='klein'>{esc(zahlen)}</div>" if zahlen else "") + "</td>"
                     f"<td>{beleg_links(i.get('belege'), protokoll)}</td></tr>")
        h.append("</table></div>")
        abuse = [{"name": f"{i['id']} · {i['wert']}", "wert": i["kennzahlen"]["abuse_score"], "anzeige": f"{i['kennzahlen']['abuse_score']} von 100"}
                 for i in indikatoren if isinstance((i.get("kennzahlen") or {}).get("abuse_score"), (int, float))]
        if abuse:
            h.append("<figure>" + balken(abuse, maximum=100, beschriftung="AbuseIPDB-Score je IP-Adresse") +
                     "<figcaption>AbuseIPDB-Score je IP-Adresse (0 bis 100). Der Score beruht auf Missbrauchsmeldungen Dritter. "
                     "Er zeigt, wie oft eine Adresse negativ auffiel, und ist ein Hinweis, kein Beweis.</figcaption></figure>")
        vt = [{"name": f"{i['id']} · {kuerzen(i['wert'], 22)}", "wert": i["kennzahlen"]["vt_boesartig"],
               "anzeige": f"{i['kennzahlen']['vt_boesartig']} von {i['kennzahlen'].get('vt_gesamt', '?')}",
               "_gesamt": i["kennzahlen"].get("vt_gesamt") or 0}
              for i in indikatoren if isinstance((i.get("kennzahlen") or {}).get("vt_boesartig"), (int, float))]
        if vt:
            h.append("<figure>" + balken(vt, maximum=max([z["_gesamt"] for z in vt] + [z["wert"] for z in vt] + [1]),
                                         beschriftung="VirusTotal: Scanner mit Befund je Indikator") +
                     "<figcaption>VirusTotal: Zahl der Sicherheitsprodukte, die den Indikator als bösartig einstufen, von allen "
                     "beteiligten Produkten. Wenige Treffer können Fehlalarme sein, viele übereinstimmende sind ein starkes Indiz.</figcaption></figure>")
    else:
        h.append('<p class="klein">Keine Indikatoren erfasst.</p>')

    # ---- 6 Befunde
    h.append("<h2>6 Befunde im Einzelnen</h2>")
    for f in befunde:
        art = f.get("art")
        text, farbe = PRUEFUNG.get(f.get("gegenpruefung") or "offen", PRUEFUNG["offen"])
        verweise = " ".join(f'<a class="beleg" href="#{esc(x)}">{esc(x)}</a>' for x in f.get("indikatoren") or [])
        h.append(f"<div class='karte{' hypothese' if art == 'hypothese' else ''}' id='{esc(f.get('id', ''))}'>"
                 f"<h3>{esc(f.get('id', ''))} · {esc(f.get('titel', ''))}</h3>{absaetze(f.get('text'))}"
                 f"<div class='einfach'><b>Einfach erklärt:</b> {esc(f.get('erlaeuterung') or '')}</div>"
                 f"<div class='zeile'>{marke(ARTEN.get(art, '?'))}{marke('Sicherheit ' + SICHERHEIT.get(f.get('sicherheit'), '?'))}"
                 + (marke('Quelle/Information ' + str(f["quellenbewertung"])) if f.get("quellenbewertung") else "")
                 + marke(text, farbe) + "</div>"
                 + (f"<p class='klein'>Zur Gegenprüfung: {esc(f['gegenpruefung_notiz'])}</p>" if f.get("gegenpruefung_notiz") else "")
                 + f"<div class='zeile klein'>Indikatoren: {verweise or '–'} &nbsp; Belege: {beleg_links(f.get('belege'), protokoll)}</div></div>")
    if not befunde:
        h.append('<p class="klein">Keine Befunde erfasst.</p>')

    # ---- 7 Zusammenhänge
    beziehungen = b.get("beziehungen") or []
    h.append("<h2>7 Zusammenhänge</h2>")
    if beziehungen:
        beteiligt = {r.get("von") for r in beziehungen} | {r.get("nach") for r in beziehungen}
        knoten = [i for i in indikatoren if i.get("id") in beteiligt]
        h.append("<figure>" + graf(knoten, beziehungen) + graf_legende(knoten, beziehungen) +
                 "<figcaption>Beziehungen zwischen den Indikatoren. Farbe und Zeichen zeigen die Bewertung, die Form den Typ. "
                 "Jede Verbindung steht mit Beleg in der Tabelle darunter.</figcaption></figure>")
        werte = {i.get("id"): i.get("wert") for i in indikatoren}
        h.append("<table><tr><th>Von</th><th>Beziehung</th><th>Nach</th><th>Sicherheit</th><th>Belege</th></tr>")
        for r in beziehungen:
            h.append(f"<tr><td><a class='beleg' href='#{esc(r['von'])}'>{esc(r['von'])}</a> <span class='mono'>{esc(kuerzen(werte.get(r['von'], ''), 34))}</span></td>"
                     f"<td>{esc(r.get('art', ''))}</td>"
                     f"<td><a class='beleg' href='#{esc(r['nach'])}'>{esc(r['nach'])}</a> <span class='mono'>{esc(kuerzen(werte.get(r['nach'], ''), 34))}</span></td>"
                     f"<td class='nw'>{esc(SICHERHEIT.get(r.get('sicherheit'), '?'))}</td>"
                     f"<td>{beleg_links(r.get('belege'), protokoll) if r.get('belege') else esc(r.get('quelle') or 'ohne Beleg (Hypothese)')}</td></tr>")
        h.append("</table>")
    elif not b.get("geldfluesse"):
        h.append('<p class="klein">Keine Beziehungen zwischen Indikatoren festgestellt.</p>')
    for g in b.get("geldfluesse") or []:
        h.append(geldfluss_abschnitt(g, protokoll, fall_pfad(fall_id)))

    # ---- 8 Zeitachse
    h.append("<h2>8 Zeitachse</h2>")
    ereignisse = sorted(b.get("zeitachse") or [], key=lambda z: zeit_lesen(z.get("zeit")) or datetime.max.replace(tzinfo=timezone.utc))
    if ereignisse:
        h.append('<ol class="zeitachse">')
        for z in ereignisse:
            nachweis = beleg_links(z.get("belege"), protokoll) if z.get("belege") else f"<span class='klein'>{esc(z.get('quelle') or '')}</span>"
            h.append(f"<li><time>{esc(zeit_zeigen(z.get('zeit')))}</time><span class='spur'></span>"
                     f"<div class='text'>{esc(z.get('ereignis', ''))} {nachweis}</div></li>")
        h.append("</ol>")
    else:
        h.append('<p class="klein">Keine zeitlich einordenbaren Ereignisse.</p>')

    # ---- 9 Lücken, 10 Empfehlungen
    h.append("<h2>9 Lücken und Grenzen</h2>")
    h.append("<ul>" + "".join(f"<li>{esc(str(x))}</li>" for x in b.get("luecken") or []) + "</ul>" if b.get("luecken")
             else '<p class="klein">Keine Lücken vermerkt.</p>')
    h.append("<p class='klein'>Allgemein gilt: Offene Quellen zeigen, was Dritte beobachtet und gespeichert haben. Sie können "
             "veraltet, unvollständig oder falsch sein. Eine IP-Adresse oder ein Konto identifiziert für sich allein keine Person.</p>")
    h.append("<h2>10 Empfehlungen</h2>")
    if b.get("empfehlungen"):
        rang = {"hoch": 0, "mittel": 1, "tief": 2}
        h.append("<table><tr><th>Priorität</th><th>Empfehlung</th></tr>")
        for e in sorted(b["empfehlungen"], key=lambda e: rang.get(e.get("prioritaet"), 3)):
            h.append(f"<tr><td>{esc(e.get('prioritaet') or '–')}</td><td>{esc(e.get('text', ''))}</td></tr>")
        h.append("</table>")
    else:
        h.append('<p class="klein">Keine Empfehlungen.</p>')

    # ---- Anhang
    h.append("<h2>Anhang A: Lesehilfe</h2>"
             "<table><tr><th>Begriff</th><th>Bedeutung in diesem Rapport</th></tr>"
             "<tr><td>Feststellung</td><td>Was eine Quelle unmittelbar zeigt. Beispiel: «Auf der IP ist Port 443 offen.»</td></tr>"
             "<tr><td>Bewertung</td><td>Schluss aus einer oder mehreren Feststellungen. Beispiel: «Die Domain wurde eigens für die Tat registriert.»</td></tr>"
             "<tr><td>Hypothese</td><td>Mögliche Erklärung, die noch nicht belegt ist. Gestrichelt umrandet.</td></tr>"
             "<tr><td>Sicherheit hoch</td><td>Mindestens zwei voneinander unabhängige Quellen stimmen überein.</td></tr>"
             "<tr><td>Sicherheit mittel</td><td>Eine zuverlässige Quelle, kein Widerspruch.</td></tr>"
             "<tr><td>Sicherheit tief</td><td>Einzelhinweis, unbestätigt oder mit Widersprüchen.</td></tr>"
             "<tr><td>Quelle/Information (z. B. B2)</td><td>Buchstabe: Zuverlässigkeit der Quelle von A (zuverlässig) bis F (nicht beurteilbar). "
             "Ziffer: Glaubhaftigkeit der Information von 1 (bestätigt) bis 6 (nicht beurteilbar).</td></tr>"
             "<tr><td>Gegenprüfung</td><td>Eine zweite Instanz ohne Kenntnis des Ermittlungsverlaufs hat den Befund anhand der Rohdaten nachvollzogen.</td></tr>"
             "<tr><td>Auswertung</td><td>Ergebnis, das das Gateway aus mehreren Abfragen errechnet hat, zum Beispiel ein Geldfluss. "
             "Der Eintrag im Ermittlungsprotokoll nennt die Abfragen, auf denen es beruht.</td></tr>"
             "</table>")
    if b.get("glossar"):
        h.append("<h2>Anhang B: Glossar</h2><table><tr><th>Begriff</th><th>Erklärung</th></tr>")
        for g in sorted(b["glossar"], key=lambda g: str(g.get("begriff", "")).lower()):
            h.append(f"<tr><td>{esc(g.get('begriff', ''))}</td><td>{esc(g.get('erklaerung', ''))}</td></tr>")
        h.append("</table>")
    h.append("<h2>Anhang C: Nachvollziehbarkeit</h2>"
             f"<p>Das Abfrageprotokoll umfasst {kettenstand['anzahl']} Einträge des Gateways"
             + (f" und {kettenstand['anzahl_extern']} gesicherte Antworten weiterer Werkzeuge" if kettenstand["anzahl_extern"] else "") + ". "
             + ("Verkettung und Rohdaten wurden bei der Erstellung dieses Rapports geprüft und sind unverändert."
                if kettenstand["ok"] else "<b>Die Prüfung der Verkettung hat Abweichungen ergeben.</b>")
             + f"</p><p class='klein'>Letzter Kettenwert: <span class='mono'>{esc(kettenstand.get('letzter_hash') or '–')}</span><br>"
             + (f"Letzter Kettenwert der weiteren Werkzeuge: <span class='mono'>{esc(kettenstand['letzter_hash_extern'])}</span><br>"
                if kettenstand.get("letzter_hash_extern") else "") +
             f"Prüfsumme befunde.json: <span class='mono'>{esc(b.get('_sha256', ''))}</span><br>"
             "Einzelnachweis aller Abfragen: <a href='Ermittlungsprotokoll.html'>Ermittlungsprotokoll.html</a>. "
             f"Prüfung jederzeit wiederholbar mit <code>python3 tools/audit_pruefen.py {esc(fall_id)}</code>.</p>")
    if entwurf and (maengel or hinweise):
        h.append("<h2>Offene Mängel und Hinweise (Entwurf)</h2><ul>"
                 + "".join(f"<li><b>Mangel:</b> {esc(m)}</li>" for m in maengel)
                 + "".join(f"<li>Hinweis: {esc(x)}</li>" for x in hinweise) + "</ul>")
    h.append(f"<div class='fuss'>Erstellt am {esc(zeit_zeigen(erstellt().isoformat()))} aus befunde.json und dem "
             "Abfrageprotokoll der Fallakte. Die Aussagen stützen sich auf offene Quellen und sind vor einer Verwendung "
             "im Verfahren durch die fallführende Stelle zu würdigen.</div>")
    return seite(f"Abschlussrapport {fall_id}", "\n".join(h))


# --------------------------------------------------------------------------- Ablauf

def main(argv: list[str]) -> int:
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or "--help" in argv or "-h" in argv:
        print(__doc__)
        return 0 if ("--help" in argv or "-h" in argv) else 2
    fall_id = args[0]
    entwurf, nur_pruefen = "--entwurf" in argv, "--nur-pruefen" in argv
    try:
        fall = fall_daten(fall_id)
        pfad = fall_pfad(fall_id)
    except (ValueError, FileNotFoundError) as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 2
    datei = pfad / "befunde.json"
    if not datei.is_file():
        print(f"FEHLER: {datei} fehlt. Die Befunde schreibt der Rapportführer (Skill /abschlussrapport).", file=sys.stderr)
        return 2
    roh = datei.read_bytes()
    try:
        b = json.loads(roh)
    except json.JSONDecodeError as e:
        print(f"FEHLER: befunde.json ist kein gültiges JSON: Zeile {e.lineno}, Spalte {e.colno}: {e.msg}", file=sys.stderr)
        return 2
    b["_sha256"] = hashlib.sha256(roh).hexdigest()
    eintraege = belege_lesen(fall_id)
    kettenstand = kette_pruefen(fall_id)
    maengel, hinweise = pruefen(b, {e["id"]: e for e in eintraege}, entwurf)
    if not kettenstand["ok"]:
        maengel = [f"Abfrageprotokoll: {f}" for f in kettenstand["fehler"]] + maengel

    for h in hinweise:
        print(f"Hinweis: {h}")
    if maengel:
        print(f"\n{len(maengel)} Mangel/Mängel in befunde.json:")
        for m in maengel:
            print(f"  - {m}")
    if nur_pruefen:
        print("\nPrüfung " + ("bestanden." if not maengel else "nicht bestanden."))
        return 1 if maengel else 0
    if maengel and not entwurf:
        print("\nKein Rapport erzeugt. Mängel in befunde.json beheben und erneut ausführen. "
              "Die Prüfregeln werden nicht umgangen: Wo ein Beleg fehlt, wird die Aussage herabgestuft oder gestrichen.")
        return 1

    register = pfad / "eingang" / ".freigabe.json"
    if register.is_file():
        fall["_eingang"] = json.loads(register.read_text(encoding="utf-8")).get("dateien", {})
    ziel = pfad / "rapport"
    ziel.mkdir(exist_ok=True)
    plattform.text_schreiben(
        ziel / "Abschlussrapport.html",
        bauen(fall_id, fall, b, eintraege, kettenstand, maengel, hinweise, entwurf and bool(maengel or hinweise)))
    with open(ziel / "indikatoren.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["id", "typ", "wert", "bewertung", "rolle", "herkunft", "belege"])
        for i in b.get("indikatoren") or []:
            w.writerow([i.get("id"), i.get("typ"), i.get("wert"), i.get("bewertung"), i.get("rolle") or "",
                        i.get("herkunft") or "", " ".join(i.get("belege") or [])])
    print(f"\nRapport erzeugt: faelle/{fall_id}/rapport/Abschlussrapport.html"
          + (" (ENTWURF)" if entwurf and maengel else ""))
    print(f"Indikatorliste:  faelle/{fall_id}/rapport/indikatoren.csv")
    if not (ziel / "Ermittlungsprotokoll.html").is_file():
        print(f"Noch offen:      {plattform.PY} tools/protokoll.py {fall_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
