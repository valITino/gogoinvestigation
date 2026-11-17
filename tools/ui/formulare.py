"""Die Bildschirme der Bedienung: Akten-Eingang, der lokale Bildschirm der Pseudonymisierung, Ermittlung mit Chat, Bedienen, Zurückführen.

Formulare sind schlichtes HTML. Das Skript der Oberfläche schickt sie ab: `data-aktion` nennt die Funktion in
tools/ui/bedienung.py oder tools/ui/sitzung.py, die Felder werden ihre Angaben. Ohne das Geheimnis des Starts nimmt der
Server nichts davon an.

Drei Bildschirme können echte Angaben zeigen: der Akten-Eingang (Dateinamen), die Pseudonymisierung und das Zurückführen.
Alle drei tragen das Band «lokal, Klartext». Ihren Inhalt gibt der Server nur an den Browser, der das Geheimnis hat.
"""
from __future__ import annotations

import json

from gateway.akte import FAELLE, eingang_stand
from tools import _pseudo as ps
from tools._html import TYPEN as INDIKATOR_TYPEN
from tools.ui import daten
from tools.ui.seiten import esc, pfad, tabelle

KLARTEXT_BAND = ('<div class="klartext-band" role="note"><b>lokal, Klartext</b> Dieser Bildschirm zeigt echte Angaben. Sie bleiben auf diesem Rechner: '
                 "im Speicher der Oberfläche und in der Ablage ausserhalb des Projektordners. Kein Sprachmodell sieht sie, und sie stehen in keinem Protokoll.</div>")
NUR_LESEN = ('<p class="banner">Die Oberfläche läuft im Modus «nur lesen». Bedienen lässt sie sich, wenn der Sachbearbeiter sie selbst an einem Terminal '
             "startet (<code>python3 tools/oberflaeche.py</code>) und das Browserfenster benutzt, das sich dabei öffnet.</p>")
OHNE_GEHEIMNIS = ('<p class="banner">Dieses Fenster kann nur lesen. Hochladen, ordnen und entfernen lässt sich aus dem Browserfenster, das die Oberfläche '
                  "beim Start geöffnet hat.</p>")
FREIGABE_NAME = {"aktiv": "Aktive Massnahmen", "darkweb": "Dark Web", "personenbezug": "Kontoabfragen"}
STAND_MARKE = {"sauber": ("gut", "✓ bereit"), "personendaten": ("kritisch", "✕ Personendaten"), "nicht_lesbar": ("leer", "– nicht lesbar")}
STATUS_WORT = {"aus": "nicht gestartet", "laeuft": "läuft", "wartet": "wartet auf eine Antwort", "angehalten": "angehalten", "beendet": "beendet", "fehler": "abgebrochen"}
STATUS_FARBE = {"laeuft": "gut", "wartet": "warnung", "fehler": "kritisch"}


def feld(name: str, text: str, *, art: str = "text", pflicht: bool = False, wert: str = "", hilfe: str = "", platzhalter: str = "", breit: bool = False) -> str:
    kennung = f"f-{name}"
    eingabe = (f'<textarea id="{kennung}" name="{esc(name)}" rows="4"{" required" if pflicht else ""} placeholder="{esc(platzhalter)}">{esc(wert)}</textarea>'
               if art == "mehrzeilig" else
               f'<input id="{kennung}" name="{esc(name)}" type="{esc(art)}" value="{esc(wert)}"{" required" if pflicht else ""} placeholder="{esc(platzhalter)}" autocomplete="off">')
    return (f'<div class="feld{" breit" if breit else ""}"><label for="{kennung}">{esc(text)}{"" if pflicht else " <span class=klein>(freiwillig)</span>"}</label>{eingabe}'
            + (f'<div class="klein">{esc(hilfe)}</div>' if hilfe else "") + "</div>")


def wahl(name: str, text: str, werte: list[tuple[str, str]], gewaehlt: str = "") -> str:
    return (f'<div class="feld"><label for="f-{esc(name)}">{esc(text)}</label><select id="f-{esc(name)}" name="{esc(name)}">'
            + "".join(f'<option value="{esc(w)}"{" selected" if w == gewaehlt else ""}>{esc(t)}</option>' for w, t in werte) + "</select></div>")


def formular(aktion: str, inhalt: str, knopf: str, *, verborgen: dict | None = None, danach: str = "", klasse: str = "", frage: str = "") -> str:
    """Ein Formular der Bedienung. `danach`: Adresse, die nach Erfolg geöffnet wird. `frage`: Rückfrage vor dem Absenden."""
    fest = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">' for k, v in (verborgen or {}).items())
    return (f'<form class="aktion {esc(klasse)}" data-aktion="{esc(aktion)}"{f" data-danach={chr(34)}{esc(danach)}{chr(34)}" if danach else ""}'
            f'{f" data-frage={chr(34)}{esc(frage)}{chr(34)}" if frage else ""}>{fest}{inhalt}<div class="knoepfe"><button type="submit">{esc(knopf)}</button></div>'
            '<div class="ergebnis" aria-live="polite"></div></form>')


def ablage_zeile(bedienung) -> str:
    return (f'<p class="klein">Ablage für Klartext und Zuordnungstabellen: <span class="mono">{esc(bedienung.ablage)}</span> (ausserhalb des Projektordners). '
            "Ändern: Oberfläche mit <code>--ablage &lt;Ordner&gt;</code> starten.</p>")


def groesse(n: int) -> str:
    return f"{n} B" if n < 1024 else f"{n / 1024:.0f} KB" if n < 1024 * 1024 else f"{n / (1024 * 1024):.1f} MB".replace(".", ",")


def haken(wert: str, was: str, stand: str = "") -> str:
    return f'<input type="checkbox" name="auswahl" value="{esc(wert)}" data-stand="{esc(stand)}" aria-label="{esc(was)} auswählen">'


AUFNEHMEN_HINWEIS = '<p class="klein" data-aufnehmen-hinweis>Aufgenommen wird, was gewählt und bereit ist. Ist nichts gewählt: alles, was bereit ist.</p>'


ALLE = '<input type="checkbox" data-alle aria-label="Alle auswählen" title="Alle auswählen">'


# --------------------------------------------------------------------------- Akten-Eingang: neuer Fall und weitere Dokumente

def neu_seite(bedienung) -> str:
    """Die Hülle von «Neuer Fall» für den Modus «nur lesen». Bedienbar holt der Browser den Akten-Eingang mit dem Geheimnis."""
    return "<h1>Neuer Fall</h1><p class='unter'>Akten hineinziehen, prüfen, wo nötig nochmals pseudonymisieren, Fall anlegen.</p>" + NUR_LESEN


def akten_seite(bedienung, ziel: str) -> str:
    """Der Akten-Eingang zu einem neuen Fall (ziel leer) oder zu einem bestehenden: hochladen, prüfen, ordnen, pseudonymisieren,
    aufnehmen. Zu einem bestehenden Fall zeigt die Seite auch, was schon in seinem Eingang liegt."""
    korb = bedienung.korb(ziel)
    eintraege = list(korb.eintraege.values())
    kopf = (f"<h1>Akten · {esc(ziel)}</h1><p class='unter'>Weitere Dokumente nachziehen, und was im Eingang des Falls liegt.</p>" if ziel else
            "<h1>Neuer Fall</h1><p class='unter'>Akten hineinziehen, prüfen, wo nötig nochmals pseudonymisieren, Fall anlegen.</p>")
    h = [kopf, KLARTEXT_BAND,
         f'<div class="ablegen gross" data-hochladen data-ziel="{esc(ziel)}"><p><b>Dateien, Ordner oder ZIP hierher ziehen</b></p>'
         '<p><label class="knopf">Dateien wählen<input type="file" multiple data-dateien></label> '
         '<label class="knopf">Ordner wählen<input type="file" webkitdirectory multiple data-ordner></label></p>'
         '<p class="klein">Rapport und Beilagen, auch gemischt: Text, Word, PDF, OpenDocument, Excel, PowerPoint, RTF, E-Mail (.eml), CSV, JSON. Ein ZIP wird entpackt, '
         "die Anhänge einer E-Mail werden eigene Dokumente. Jede Datei wird sofort gelesen und auf Personendaten geprüft. In den Fall kommt hier noch nichts.</p>"
         '<ul class="hochladen-stand" aria-live="polite"></ul></div>']
    if eintraege:
        zeilen = []
        for e in eintraege:
            farbe, wort = STAND_MARKE[e.stand]
            pruefung = f'<span class="marke z-{farbe}">{wort}</span>'
            if e.stand == "personendaten":
                pruefung += f' <span class="klein">{e.sperren} Fundstelle{"n" if e.sperren != 1 else ""}</span>'
            elif e.stand == "nicht_lesbar":
                pruefung += f'<div class="klein">{esc(e.grund)}</div>'
            elif e.platzhalter:
                pruefung += f' <span class="klein">{e.platzhalter} Platzhalter{", " + str(e.hinweise) + " Hinweise" if e.hinweise else ""}</span>'
            else:
                pruefung += ' <span class="klein">keine Platzhalter gefunden</span>'
            if e.bericht:
                pruefung += f'<details><summary class="klein">Bericht der Prüfung</summary><pre class="rohtext">{esc(e.bericht)}</pre></details>'
            if e.vorgang:
                pseudo = f'<a href="#/klartext/{esc(e.vorgang)}">in Arbeit: weiter</a>'
            elif e.text is None:
                pseudo = '<span class="klein">nicht möglich</span>'
            else:
                pseudo = (f'<span class="marke z-gut">✓ übernommen</span> <span class="klein">{e.ersetzt} ersetzt</span> ' if e.ersetzt is not None else "") + \
                    f'<button type="button" class="klein-knopf" data-korb="pseudo" data-id="{esc(e.id)}">{"nochmals" if e.ersetzt is not None else "pseudonymisieren"}</button>'
            andere = "beilage" if e.rolle == "rapport" else "rapport"
            rolle = (f'<span class="marke">{esc(e.rolle.capitalize())}</span> '
                     f'<button type="button" class="verweis klein" data-korb="rolle" data-id="{esc(e.id)}" data-rolle="{andere}">zu {andere.capitalize()}</button>')
            name = (f'<span class="mono">{esc(e.name)}</span> <button type="button" class="verweis klein" data-korb="umbenennen" data-id="{esc(e.id)}" '
                    f'data-name="{esc(e.name)}">umbenennen</button>' + (f'<div class="klein">aus {esc(e.ordner)}</div>' if e.ordner else ""))
            zeilen.append([haken(e.id, e.name, e.stand), name, esc(e.endung or "–"), f'<span data-roh="{e.groesse}">{groesse(e.groesse)}</span>', pruefung, pseudo, rolle])
        andere = ([("", "neuer Fall")] if ziel else []) + [(f, f) for f in andere_faelle(ziel)]
        verschieben = (' <span class="trenner"></span><button type="button" data-korb="verschieben" title="Legt die gewählten Dateien in den Akten-Eingang eines anderen Falls">'
                       'Verschieben</button> <label class="klein" for="korb-nach">nach</label> <select id="korb-nach" data-korb-nach>'
                       + "".join(f'<option value="{esc(w)}">{esc(t)}</option>' for w, t in andere) + "</select>") if andere else ""
        bereit = sum(1 for e in eintraege if e.stand == "sauber")
        pii = sum(1 for e in eintraege if e.stand == "personendaten")
        unlesbar = sum(1 for e in eintraege if e.stand == "nicht_lesbar")
        h.append(f'<h2>Im Akten-Eingang ({len(eintraege)})</h2><p class="klein">{bereit} bereit, {pii} mit Personendaten, {unlesbar} nicht lesbar.</p>'
                 f'<div class="auswahl" data-auswahl="korb" data-ziel="{esc(ziel)}">'
                 '<div class="auswahlleiste" role="group" aria-label="Mit der Auswahl"><span class="klein" data-gewaehlt>nichts gewählt</span> '
                 '<button type="button" data-korb="pseudo-auswahl">Nochmals pseudonymisieren</button> '
                 '<button type="button" data-korb="rolle-auswahl" data-rolle="rapport">Als Rapport</button> '
                 '<button type="button" data-korb="rolle-auswahl" data-rolle="beilage">Als Beilage</button> '
                 '<button type="button" data-korb="entfernen" data-frage="Die gewählten Dateien aus dem Akten-Eingang entfernen? Sie werden aus dem Speicher der Oberfläche gelöscht.">Entfernen</button>'
                 + verschieben + "</div>"
                 + tabelle([ALLE, "Datei", "Art", "Grösse", "PII-Prüfung", "Pseudonymisierung", "Rolle"], zeilen, "Akten-Eingang", klasse="daten auswahltabelle")
                 + '<div class="ergebnis" data-korb-ergebnis aria-live="polite"></div></div>')
        hinweise = []
        if pii:
            hinweise.append("<b>Personendaten:</b> «pseudonymisieren» öffnet das Dokument auf dem lokalen Bildschirm. Dort sind die Fundstellen markiert: annehmen, verwerfen, "
                            "ergänzen. Namen erkennt die Prüfung nicht von selbst, deshalb lohnt der Blick auch bei Dokumenten, die als bereit gelten.")
        if unlesbar:
            hinweise.append("<b>Nicht lesbar:</b> Bilder, Ton, alte Formate. Was sich nicht lesen lässt, lässt sich nicht prüfen. Diese Dateien gehen nicht in den Fall "
                            "und nicht an das Sprachmodell. Sie bleiben bei dir.")
        hinweise.append("In den Fall kommt von jedem Dokument die Textfassung, nicht das Original: In einem Original können Angaben stecken, die niemand sieht "
                        "(Verfasser, eingebettete Bilder, Änderungsverlauf).")
        h.append("<ul class='klein'>" + "".join(f"<li>{x}</li>" for x in hinweise) + "</ul>")
        namen = ('<div class="feld breit"><label><input type="checkbox" name="neutral" value="1" checked> Neutrale Dateinamen verwenden (empfohlen): '
                 "<span class='mono'>rapport-01.txt</span>, <span class='mono'>beilage-01.txt</span>. Ein Dateiname nennt leicht eine Person, und er steht in jedem Protokoll.</label></div>")
        if ziel:
            h.append("<h2>In den Fall aufnehmen</h2>" + AUFNEHMEN_HINWEIS
                     + formular("korb_aufnehmen", f'<div class="felder-raster">{namen}</div>', f"In den Fall {ziel} aufnehmen", verborgen={"ziel": ziel, "ids": ""}, danach="neu-laden",
                                klasse="aufnehmen"))
        else:
            stamm = (feld("fall", "Fall-ID", pflicht=True, platzhalter="2026-0412", hilfe="Buchstaben, Ziffern, Punkt, Strich, Unterstrich. Keine Namen.")
                     + feld("titel", "Titel", pflicht=True, platzhalter="Phishing Kundenportal", hilfe="Ohne Personendaten: Der Titel steht in jedem Dokument der Akte.")
                     + feld("kuerzel", "Kürzel des Sachbearbeiters") + feld("auftrag", "Auftrag in ein bis zwei Sätzen", art="mehrzeilig", breit=True, hilfe="Ohne Personendaten."))
            h.append("<h2>Fall anlegen</h2>" + AUFNEHMEN_HINWEIS
                     + formular("korb_aufnehmen", f'<div class="felder-raster">{stamm}{namen}</div>', "Fall anlegen und Akten aufnehmen", verborgen={"ziel": "", "ids": ""}, danach="fall",
                                klasse="aufnehmen"))
    else:
        h.append('<p class="klein">Der Akten-Eingang ist leer.</p>')
    h.append(ablage_zeile(bedienung))
    if ziel:
        h.append(eingang_teil(ziel))
    return "\n".join(h)


def andere_faelle(fall_id: str) -> list[str]:
    """Die Fälle, in die sich etwas verschieben lässt: alle ausser diesem und dem Musterfall, der zum Projekt gehört."""
    return sorted(f["id"] for f in daten.faelle() if f["id"] != fall_id and not f["muster"])


def akten_lesen(fall_id: str, bedienbar: bool) -> str:
    """Die Akten eines Falls für ein Fenster ohne Geheimnis: was in seinem Eingang liegt, nur zum Ansehen. Der Akten-Eingang mit
    den hochgeladenen Dateien erscheint hier nicht: Ihre Namen können echte Angaben nennen."""
    return (f"<h1>Akten · {esc(fall_id)}</h1><p class='unter'>Was im Eingang des Falls liegt.</p>" + (OHNE_GEHEIMNIS if bedienbar else NUR_LESEN)
            + eingang_teil(fall_id, bedienbar=False))


def eingang_teil(fall_id: str, bedienbar: bool = True) -> str:
    """Was im Eingang eines Falls liegt: geprüfte Dokumente und, was jemand von Hand hineinkopiert hat. Auswählen, entfernen, verschieben."""
    pfad_ = FAELLE / fall_id
    geprueft, ungeprueft = eingang_stand(pfad_)
    register = {}
    try:
        register = json.loads((pfad_ / "eingang" / ".freigabe.json").read_text(encoding="utf-8")).get("dateien", {})
    except (OSError, ValueError):
        pass
    h = [f"<h2>Im Fall ({len(geprueft) + len(ungeprueft)})</h2>"]
    if not geprueft and not ungeprueft:
        return h[0] + '<p class="klein">Im Eingang des Falls liegt noch kein Dokument.</p>'
    zeilen = []
    for name in geprueft + ungeprueft:
        datei = pfad_ / "eingang" / name
        e = register.get(name) or {}
        if name in ungeprueft:
            stand = '<span class="marke z-kritisch">✕ nicht geprüft</span> <span class="klein">von Hand kopiert oder nachträglich verändert</span>'
        else:
            stand = (f'<span class="marke z-{"gut" if e.get("ergebnis") == "sauber" else "warnung"}">{"✓ geprüft" if e.get("ergebnis") == "sauber" else "! übersteuert"}</span> '
                     f'<span class="klein">{esc(str(e.get("geprueft") or "")[:16].replace("T", " "))}</span>')
        zeilen.append([haken(name, name), f'<span class="mono">{esc(name)}</span>', stand, f'<span data-roh="{datei.stat().st_size}">{groesse(datei.stat().st_size)}</span>'])
    if not bedienbar:
        return h[0] + tabelle(["Dokument", "Stand", "Grösse"], [z[1:] for z in zeilen], "Eingang")
    andere = andere_faelle(fall_id)
    h.append(f'<div class="auswahl" data-auswahl="eingang" data-fall="{esc(fall_id)}">'
             + tabelle([ALLE, "Dokument", "Stand", "Grösse"], zeilen, "Eingang", klasse="daten auswahltabelle")
             + '<p class="klein" data-gewaehlt>nichts gewählt</p>'
             + (formular("eingang_pruefen", "", "Gewählte nachträglich prüfen", verborgen={"fall": fall_id, "namen": ""}, danach="neu-laden", klasse="klein-form mit-auswahl") if ungeprueft else "")
             + "<details><summary>Gewählte entfernen</summary><p class='klein'>Nimmt die Dokumente aus dem Eingang. Das Register der PII-Prüfung hält fest, was wann von wem und warum "
               "entfernt wurde. Was ein Agent schon gelesen hat, bleibt im Protokoll belegt.</p>"
             + formular("eingang_entfernen", '<div class="felder-raster">' + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True) + feld("grund", "Grund", pflicht=True, platzhalter="falsches Dokument")
                        + "</div>", "Entfernen", verborgen={"fall": fall_id, "namen": ""}, danach="neu-laden", klasse="mit-auswahl",
                        frage="Die gewählten Dokumente aus dem Eingang des Falls entfernen?") + "</details>"
             + ("<details><summary>Gewählte in einen anderen Fall verschieben</summary><p class='klein'>Das Dokument wird im anderen Fall aufgenommen (mit PII-Prüfung) und hier entfernt.</p>"
                + formular("eingang_verschieben", '<div class="felder-raster">' + wahl("nach", "Nach Fall", [(f, f) for f in andere]) + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True)
                           + "</div>", "Verschieben", verborgen={"fall": fall_id, "namen": ""}, danach="neu-laden", klasse="mit-auswahl") + "</details>" if andere else "")
             + "</div>")
    return "\n".join(h)


# --------------------------------------------------------------------------- Der lokale Bildschirm der Pseudonymisierung

STAND = {True: ("ersetzen", "wird ersetzt"), False: ("lassen", "bleibt stehen"), None: ("offen", "noch offen")}


def text_markiert(v: ps.Vorgang) -> str:
    """Der Klartext mit markierten Fundstellen. Technische Indikatoren sind eigens gekennzeichnet: Sie bleiben immer stehen."""
    text = v.erk.text
    marken = [(f.start, f.ende, "fund", f) for f in v.erk.funde]
    belegt = [(a, e) for a, e, _, _ in marken]
    marken += [(s.start, s.ende, "technik", s) for s in v.erk.geschuetzt if not any(a < s.ende and s.start < e for a, e in belegt)]
    aus, pos = [], 0
    for start, ende, art, ding in sorted(marken, key=lambda m: m[0]):
        if start < pos:
            continue
        aus.append(esc(text[pos:start]))
        if art == "technik":
            aus.append(f'<span class="technik" title="technischer Indikator ({esc(ding.art)}): bleibt stehen, nach ihm wird ermittelt">{esc(text[start:ende])}</span>')
        else:
            klasse, wort = STAND[ps.stand(ding, v.ent)]
            aus.append(f'<mark class="fund s-{klasse}" id="fund-{esc(ding.id)}" title="{esc(ding.typ)} · {wort}'
                       f'{" · " + esc(ding.grund) if ding.grund else ""}">{esc(text[start:ende])}</mark>')
        pos = ende
    aus.append(esc(text[pos:]))
    return "".join(aus)


def klartext_seite(pseudo, kennung: str) -> str:
    v = pseudo.vorgang
    ergebnis = v.ergebnis()
    typen = [(t, t) for t in ps.TYPEN]
    platzhalter = {klar: p for p, klar in ergebnis.zuordnung}
    zurueck = f"#/fall/{pseudo.ziel}/akten" if pseudo.ziel else "#/neu"

    def knopf(text: str, **angaben) -> str:
        fest = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(w)}">' for k, w in {"vorgang": kennung, **angaben}.items())
        return f'<form class="aktion klein-form" data-aktion="pseudo_entscheid" data-danach="neu-laden">{fest}<button type="submit">{esc(text)}</button><span class="ergebnis"></span></form>'

    fragen = "".join(
        f'<li><span class="mono">{esc(a.wert)}</span> <span class="klein">E-Mail-Adresse: Wessen Seite?</span> '
        + knopf("Täterseite: bleibt stehen", art="seite", angabe=a.schluessel, seite="taeter")
        + knopf("Geschädigte: wird ersetzt", art="seite", angabe=a.schluessel, seite="geschaedigte") + "</li>" for a in v.fragen())
    kandidaten = "".join(
        f'<li><button type="button" class="verweis" data-zeigen="fund-{esc(f.id)}">Zeile {v.erk.text.count(chr(10), 0, f.start) + 1}</button> '
        f'<span class="klein">{esc(v.erk.umgebung(f, 30)[0])}</span><mark class="fund s-offen">{esc(v.erk.umgebung(f, 30)[1])}</mark>'
        f'<span class="klein">{esc(v.erk.umgebung(f, 30)[2])}</span> <span class="marke">{esc(f.typ)}</span> <span class="klein">{esc(f.grund)}</span> '
        + knopf("annehmen", art="annehmen", fund=f.id) + knopf("verwerfen", art="verwerfen", fund=f.id) + "</li>" for f in v.kandidaten()[:200])
    je_angabe: dict[str, list] = {}
    for f in v.erk.funde:
        if f.angabe and ps.stand(f, v.ent) is not None:
            je_angabe.setdefault(v.erk.verweis.get(f.angabe, f.angabe), []).append(f)
    zeilen = []
    for schluessel, funde in sorted(je_angabe.items(), key=lambda x: x[1][0].start):
        a = v.erk.angabe(schluessel)
        if a is None:
            continue
        ersetzt = sum(1 for f in funde if ps.stand(f, v.ent))
        zeilen.append([f'<span class="mono">{esc(platzhalter.get(a.wert, "–"))}</span>', esc(a.wert), esc(v.ent.typ.get(schluessel, a.typ)),
                       f"{ersetzt} von {len(funde)}",
                       (knopf("nicht ersetzen", art="angabe", angabe=schluessel, ersetzen="") if ersetzt else knopf("doch ersetzen", art="angabe", angabe=schluessel, ersetzen="1"))
                       + f'<button type="button" class="verweis klein" data-zeigen="fund-{esc(funde[0].id)}">zeigen</button>'])
    ergaenzen = formular("pseudo_entscheid", feld("wert", "Angabe, die fehlt", pflicht=True, hilfe="So wie sie im Dokument steht, zum Beispiel ein Name.")
                         + wahl("typ", "Typ", typen, "PERSON"), "Ergänzen", verborgen={"vorgang": kennung, "art": "ergaenzen"}, danach="neu-laden")
    abschluss = formular(
        "pseudo_uebernehmen", "", "Übernehmen", verborgen={"vorgang": kennung}, danach="weiter", klasse="uebernehmen",
        frage=(f"{ergebnis.offen} Kandidaten sind noch offen und bleiben stehen. Trotzdem übernehmen?" if ergebnis.offen else ""))
    verwerfen = formular("pseudo_verwerfen", "", "Abbrechen: Die Datei bleibt, wie sie war", verborgen={"vorgang": kennung}, danach=zurueck, klasse="still")
    return (
        f'<h1>Pseudonymisieren · {esc(pseudo.name)}</h1>{KLARTEXT_BAND}'
        f'<p class="unter"><span data-warteschlange></span>{sum(ergebnis.ersetzt.values())} Fundstellen werden ersetzt, {len(ergebnis.zuordnung)} Platzhalter, {ergebnis.offen} Kandidaten offen. '
        "Technische Indikatoren bleiben stehen. Platzhalter, die schon im Dokument stehen, bleiben, wie sie sind: Neue zählen dahinter weiter.</p>"
        '<div class="klartext"><div class="klartext-text"><h2>Dokument</h2><p class="legende"><mark class="fund s-ersetzen">wird ersetzt</mark> '
        '<mark class="fund s-offen">Kandidat, noch offen</mark> <mark class="fund s-lassen">bleibt stehen</mark> <span class="technik">technischer Indikator</span></p>'
        f'<pre class="dokument">{text_markiert(v)}</pre></div>'
        '<div class="klartext-rand">'
        + (f"<h2>Rückfragen ({len(v.fragen())})</h2><ul class='entscheide'>{fragen}</ul>" if fragen else "")
        + f"<h2>Kandidaten ({len(v.kandidaten())})</h2>"
        + (f"<p class='klein'>Vorschläge, die nie von selbst ersetzt werden. Was nicht angenommen wird, bleibt stehen.</p><ul class='entscheide'>{kandidaten}</ul>"
           + knopf("Alle offenen stehen lassen", art="alle_verwerfen") if kandidaten else "<p class='klein'>Keine offenen Kandidaten.</p>")
        + "<h2>Ergänzen</h2><p class='klein'>Steht eine Angabe noch im Text, die niemand erkannt hat: hier eintragen. Sie wird im ganzen Dokument ersetzt.</p>" + ergaenzen
        + "<h2>Angaben und Platzhalter</h2>"
        + (tabelle(["Platzhalter", "Klartext", "Typ", "ersetzt", ""], zeilen, "Zuordnung", klasse="schlicht") if zeilen else "<p class='klein'>Noch keine Angabe erkannt.</p>")
        + "<h2>Übernehmen</h2><p class='klein'>Das Ergebnis geht in die PII-Prüfung. Besteht es, ersetzt es die Datei im Akten-Eingang, und der Klartext verlässt den Speicher. "
          "Die Zuordnungstabelle entsteht in der Ablage ausserhalb des Projekts, sobald die Akten in den Fall aufgenommen sind.</p>"
        + abschluss + verwerfen + "</div></div>")


# --------------------------------------------------------------------------- Ermittlung: Stand, Rückfrage, Chat

def ermittlung_feld(fall_id: str, stand: dict | None, verfuegbar: str = "") -> str:
    """Stand der gesteuerten Sitzung von Claude Code: läuft sie, mit welcher Sitzung und welchem Modell, dazu die Knöpfe.
    Den Verlauf zeigt der Chat, wer woran arbeitet die Tafel darunter."""
    stand = stand or {"status": "aus"}
    status = stand.get("status")
    h = [f'<div class="ermittlung" data-status="{esc(status)}"><p class="stand"><span class="marke z-{STATUS_FARBE.get(status, "leer")}">Ermittlung: {esc(STATUS_WORT.get(status, status))}</span>'
         + (f' <span class="klein">Sitzung <span class="mono">{esc(stand.get("sitzung") or "")}</span></span>' if stand.get("sitzung") else "")
         + (f' <span class="klein">Modell laut Claude Code: <span class="mono">{esc(stand.get("modell"))}</span></span>' if stand.get("modell") else "") + "</p>"]
    if verfuegbar:
        h.append(f'<p class="banner">{esc(verfuegbar)}</p>')
    if stand.get("meldung") and status == "fehler":
        h.append(f'<p class="banner">{esc(stand["meldung"])}</p>')
    knoepfe = []        # starten, senden, anhalten und fortsetzen stehen im Chat. Hier nur der Weg zu den Ergebnissen
    if status == "aus" and stand.get("frueher") and not verfuegbar:
        h.append(f'<p class="klein">Zu diesem Fall gibt es eine frühere Sitzung (<span class="mono">{esc(stand["frueher"])}</span>). Eine Nachricht im Chat setzt sie fort.</p>')
    if stand.get("unterlagen") == "bereit" or (status == "beendet" and not stand.get("unterlagen")):
        knoepfe.append(f'<a class="knopf" href="{pfad(fall_id, "ergebnisse")}">Ergebnisse ansehen</a>')
    h.append('<div class="knopfzeile">' + "".join(knoepfe) + "</div>")
    return "\n".join(h) + "</div>"


def wer_tafel(stand: dict | None) -> str:
    """Wer arbeitet woran: die Hauptsitzung und jeder Analyst, den sie beauftragt hat, mit dem letzten Schritt."""
    wer = (stand or {}).get("wer") or []
    if not wer:
        return ""
    return "<h2>Wer arbeitet woran</h2>" + tabelle(
        ["Analyst", "Stand", "Zuletzt", "Schritte"],
        [[esc(w.get("name") or ""), esc(w.get("stand") or ""), f'<span class="mono">{esc(w.get("zuletzt") or "")}</span>', str(w.get("schritte") or 0)] for w in wer],
        "Analysten", klasse="schlicht")


def rueckfrage_dialog(fragen: list[dict]) -> str:
    """Die Rückfrage, die als nächste zu beantworten ist, als Dialog. Er erscheint in jeder Ansicht, über allem anderen."""
    if not fragen:
        return ""
    frage = fragen[0]
    weitere = len(fragen) - 1 + int(frage.get("weitere") or 0)
    fall = str(frage.get("fall") or "")
    return ('<div class="rueckfrage" role="alertdialog" aria-modal="true" aria-labelledby="rueckfrage-titel"><h3 id="rueckfrage-titel">Claude Code fragt nach</h3>'
            f'<p>Fall <span class="mono">{esc(fall)}</span>: Claude Code möchte <span class="mono">{esc(frage.get("werkzeug") or "")}</span> ausführen und braucht dafür eine Zustimmung.</p>'
            f'<pre class="rohtext">{esc(frage.get("eingabe") or "")}</pre>'
            + (f'<p class="klein">{esc(frage["hinweis"])}</p>' if frage.get("hinweis") else "")
            + '<div class="knopfzeile">'
            + formular("ermittlung_antworten", "", "Erlauben", verborgen={"fall": fall, "frage": frage.get("id") or "", "erlauben": "1"}, danach="rueckfrage", klasse="klein-form")
            + formular("ermittlung_antworten", "", "Ablehnen", verborgen={"fall": fall, "frage": frage.get("id") or "", "erlauben": ""}, danach="rueckfrage", klasse="klein-form")
            + "</div><p class='klein'>Die Antwort steht im Sitzungsprotokoll, mit Zeit und dem Vermerk, dass sie über die Oberfläche kam."
            + (f" Danach {'folgt eine weitere Rückfrage' if weitere == 1 else f'folgen {weitere} weitere Rückfragen'}." if weitere > 0 else "") + "</p></div>")


def chat_feld(fall_id: str) -> str:
    """Der Platz des Chats in der Ansicht «Ermittlung». Das Skript der Oberfläche baut ihn auf: Verlauf, Eingabe, Knöpfe.
    Derselbe Chat steht in den anderen Ansichten des Falls klein am rechten Rand."""
    return f'<section class="chat gross" data-chat data-fall="{esc(fall_id)}" aria-label="Chat mit der Ermittlung"></section>'


def ermittlung_seite(fall: daten.Fall, bedienung, stand: dict | None, verfuegbar: str = "", abrechnung: str = "") -> str:
    kopf = "<h1>Ermittlung</h1><p class='unter'>Starten, zusehen, eingreifen. Jeder Schritt erscheint im Verlauf, jede Abfrage in der Arbeitsspur.</p>"
    if bedienung is None:
        return kopf + NUR_LESEN
    fid = fall.id
    return "\n".join([
        kopf, f'<div id="ermittlung" data-fall="{esc(fid)}">{ermittlung_feld(fid, stand, verfuegbar)}</div>', chat_feld(fid),
        f'<div id="ermittlung-wer" data-ohne-leiste>{wer_tafel(stand)}</div>',
        "<p class='klein'>Was du hier schreibst, liest das Sprachmodell: keine Namen, keine Telefonnummern, Platzhalter wie im Dokument. Die Oberfläche prüft jede Eingabe "
        "wie ein Dokument. Arbeitet die Ermittlung gerade, wartet eine Nachricht auf das Ende des laufenden Auftrags, oder sie unterbricht ihn.</p>"
        f"<p class='klein'>Die Oberfläche startet Claude Code im Projektordner mit <code>/ermittlung {esc(fid)}</code>. Berechtigungen, das Gateway und die Protokoll-Hooks "
        "gelten wie am Terminal. Die Modelle bleiben, wie das Projekt sie festlegt.</p>"
        + (f"<p class='klein' id='abrechnung'>{esc(abrechnung)}</p>" if abrechnung else "")])


# --------------------------------------------------------------------------- Bedienen eines Falls

def bedienen_seite(fall: daten.Fall, bedienung) -> str:
    kopf = "<h1>Bedienen</h1><p class='unter'>Freigaben, Abklärung von Hand, Dokumente, Zurückführen. Jeder Schritt steht im Sitzungsprotokoll, mit dem Vermerk «über die Oberfläche».</p>"
    if bedienung is None:
        return kopf + NUR_LESEN
    fid = fall.id
    h = [kopf, f'<p><a class="knopf" href="{pfad(fid, "akten")}">Akten</a> <a class="knopf" href="{pfad(fid, "ermittlung")}">Ermittlung</a> '
               f'<a class="knopf" href="{pfad(fid, "ergebnisse")}">Ergebnisse</a></p>']
    h.append("<h2>Freigaben</h2><p class='klein'>Drei Dinge sind aus, bis der Sachbearbeiter sie freigibt. Eine Freigabe braucht, wer sie verantwortet, und ihre Grundlage.</p>")
    for f in fall.freigaben():
        name = FREIGABE_NAME.get(f["name"], f["name"])
        if f["erteilt"]:
            h.append(f'<div class="karte"><h4>{esc(name)} <span class="marke z-gut">✓ erteilt</span></h4><p class="klein">durch {esc(f["durch"])} am {esc(f["am"])} · Grundlage: {esc(f["vermerk"])}</p>'
                     + formular("freigabe", "", "Freigabe entziehen", verborgen={"fall": fid, "art": f["name"], "entziehen": "1"}, danach="neu-laden", klasse="klein-form") + "</div>")
        else:
            h.append(f'<div class="karte"><h4>{esc(name)} <span class="marke z-leer">○ nicht erteilt</span></h4><p class="klein">{esc(daten.rapport.FREIGABE_TEXT[f["name"]])}</p>'
                     + formular("freigabe", '<div class="felder-raster">' + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True) + feld("vermerk", "Grundlage (Auftrag, Verfügung)", pflicht=True) + "</div>",
                                "Freigabe erteilen", verborgen={"fall": fid, "art": f["name"]}, danach="neu-laden",
                                frage=f"Freigabe «{name}» für Fall {fid} erteilen? {daten.rapport.FREIGABE_TEXT[f['name']]}") + "</div>")
    typen = [(k, v[0]) for k, v in INDIKATOR_TYPEN.items() if k in ("ip", "domain", "url", "hash", "wallet", "sonstiges")]
    h.append("<h2>Abklärung von Hand erfassen</h2><p class='klein'>Für Quellen ohne Schnittstelle: Was die Quelle zum Indikator sagt, wann und wer es abgeklärt hat. "
             "Der Eintrag geht über <code>tools/beleg.py</code> in die Kette und ist überall als «von Hand erfasst» gekennzeichnet. Keine Personendaten.</p>"
             + formular("beleg", '<div class="felder-raster">' + feld("indikator", "Indikator", pflicht=True, platzhalter="203.0.113.7") + wahl("typ", "Typ", typen, "ip")
                        + feld("quelle", "Quelle", pflicht=True, platzhalter="Spur, Weboberfläche") + feld("abgeklaert", "Abgeklärt am", pflicht=True, platzhalter="16.11.2026 14:30")
                        + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True) + feld("tatzeit", "Tatzeit", platzhalter="29.09.2026 07:31")
                        + wahl("anonymisierung", "Anonymisierungsdienst (nur IP)", [("", "keine Angabe"), ("ja", "ja"), ("kein-hinweis", "kein Hinweis")])
                        + feld("anon_art", "Art (bei «ja»)", platzhalter="VPN") + feld("dienst", "Dienst (bei «ja»)")
                        + '<div class="feld"><label><input type="checkbox" name="residential" value="1"> Residential Proxy</label></div>'
                        + feld("wortlaut", "Wortlaut der Auskunft", art="mehrzeilig", pflicht=True, breit=True) + "</div>",
                        "Beleg erfassen", verborgen={"fall": fid}, danach="neu-laden"))
    h.append("<h2>Dokumente erzeugen</h2><div class='knopfzeile'>"
             + "".join(formular("dokumente", "", titel, verborgen={"fall": fid, "was": name}, klasse="klein-form") for name, titel in
                       (("rapport", "Abschlussrapport"), ("protokoll", "Ermittlungsprotokoll"), ("anhang", "Datenblätter"), ("pdf", "alle als PDF"), ("kette", "Kette prüfen")))
             + f'</div><p class="klein">Ansehen und holen: <a href="{pfad(fid, "ergebnisse")}">Ergebnisse</a>.</p>')
    h.append("<h2>Zurückführen</h2><p class='klein'>Der fertige Rapport mit echten Angaben, lokal, mit der Zuordnungstabelle. "
             f'<a href="{pfad(fid, "zurueck")}">Zum Bildschirm «Zurückführen»</a>.</p>')
    from tools import fall as fallwerkzeug
    grund = fallwerkzeug.loeschbar(fid)
    h.append("<h2>Fall löschen</h2>" + (f"<p class='klein'>{esc(grund)}</p>" if grund else
             "<p class='klein'>In diesem Fall wurde noch nichts abgefragt. Er lässt sich löschen, zum Beispiel nach einer falschen Fall-ID.</p>"
             + formular("fall_loeschen", '<div class="felder-raster">' + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True) + "</div>", "Fall löschen",
                        verborgen={"fall": fid}, danach="#/", frage=f"Fall {fid} mit allen Dokumenten in seinem Eingang löschen?")))
    return "\n".join(h)


def zurueck_seite(fall: daten.Fall, bedienung) -> str:
    kopf = f"<h1>Zurückführen · {esc(fall.id)}</h1>"
    if bedienung is None:
        return kopf + NUR_LESEN
    tabelle_pfad = bedienung.zuordnung_pfad(fall.id)
    return (kopf + KLARTEXT_BAND
            + "<p>Ersetzt die Platzhalter im Abschlussrapport und in der Indikatorliste durch die echten Angaben aus der Zuordnungstabelle. Das Ergebnis liegt in der Ablage "
              "ausserhalb des Projektordners und erscheint nur auf diesem Bildschirm. Platzhalter, die nicht in dieser Tabelle stehen (zum Beispiel aus einer Pseudonymisierung "
              "vor dem Hochladen), bleiben stehen.</p>"
            + formular("zurueckfuehren", feld("zuordnung", "Zuordnungstabelle", wert=str(tabelle_pfad), breit=True,
                                              hilfe="Datei mit Platzhalter;Klartext, ausserhalb des Projektordners. " + ("Vorhanden." if tabelle_pfad.is_file() else "An diesem Ort liegt noch keine.")),
                       "Rapport zurückführen", verborgen={"fall": fall.id})
            + '<div id="klartext-ergebnis"></div>' + ablage_zeile(bedienung))


def quellen_bedienung(bedienung) -> str:
    """Testabfragen je Quelle, Kontingent, Stand der lokalen Listen. Von Schlüsseln nur die Namen der Variablen."""
    from gateway import krypto_listen as kl
    zeilen = []
    for q in daten.quellen():
        test = next((x.test for x in daten.QUELLEN if x.name == q["name"]), None)
        knopf = ""
        if bedienung is not None and q["eingerichtet"] and test:
            knopf = formular("quelle_testen", "", "Testabfrage", verborgen={"quelle": q["name"]}, klasse="klein-form")
            if q["name"] == "urlscan.io":
                knopf += formular("quelle_testen", "", "Kontingent", verborgen={"quelle": q["name"], "kontingent": "1"}, klasse="klein-form")
        zeilen.append([esc(q["name"]), f'<span class="marke z-{"gut" if q["eingerichtet"] else "leer"}">{esc(q["stand"])}</span>',
                       f'<span class="mono">{esc(q["schluessel"])}</span>' if q["schluessel"] else "–",
                       f'<span class="mono">{esc(test[0])}</span>' if test else '<span class="klein">keine Testabfrage</span>', knopf or '<span class="klein">–</span>'])
    try:
        liste = kl.laden()
        stand = (f"Stand {esc(liste.stand['stand'])} vom {esc(liste.stand['datum'])}, {daten.ds.zahl(liste.stand['eintraege'])} Einträge ({esc(liste.stand['umfang'])}), "
                 f"Prüfsumme <span class='mono'>{esc(liste.stand['sha256'])}</span>." + (f" {esc(liste.hinweis)}" if liste.hinweis else ""))
    except kl.Listenfehler as e:
        stand = f'<span class="marke z-kritisch">nicht verwendbar</span> {esc(e)}'
    return ("<h2>Bereitschaft und Testabfragen</h2><p class='klein'>Eine Testabfrage fragt die Quelle mit einem harmlosen, öffentlich bekannten Wert, über das Gateway und in der "
            "Fallakte SELBSTTEST. Schlüssel zeigt die Seite nie, nur den Namen der Variablen. Eintragen bleibt bei der Einrichtung (<code>./setup.sh</code>)."
            + ("" if bedienung is not None else " Testabfragen gibt es nur, wenn die Oberfläche bedienbar gestartet ist.") + "</p>"
            + tabelle(["Quelle", "Stand", "Variable des Schlüssels", "Testabfrage mit", ""], zeilen, "Bereitschaft der Quellen")
            + f"<h2>Lokale Listen</h2><p>Etikettenliste für Krypto-Adressen: {stand}</p>")
