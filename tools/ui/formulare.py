"""Die Bildschirme der Bedienung: Akten-Eingang, der lokale Bildschirm der Pseudonymisierung, Ermittlung mit Chat, Bedienen, Zurückführen.

Formulare sind schlichtes HTML. Das Skript der Oberfläche schickt sie ab: `data-aktion` nennt die Funktion in
tools/ui/bedienung.py oder tools/ui/sitzung.py, die Felder werden ihre Angaben. Ohne das Geheimnis des Starts nimmt der
Server nichts davon an.

Drei Bildschirme können echte Angaben zeigen: der Akten-Eingang (Dateinamen), die Pseudonymisierung und das Zurückführen.
Alle drei tragen das Band «lokal, Klartext». Ihren Inhalt gibt der Server nur an den Browser, der das Geheimnis hat.
"""
from __future__ import annotations

import json
import platform
from datetime import datetime

from gateway import pflichtquellen as pq, plattform, robin
from gateway.akte import FAELLE, eingang_stand
from tools import _pseudo as ps
from tools._html import TYPEN as INDIKATOR_TYPEN
from tools.pii_pruefung import pruefen as pii_pruefen
from tools.ui import daten, fehlerbuch
from tools.ui.seiten import esc, pfad, pflichtquellen_html, pflichtquellen_kurz, quellen_seite as quellen_ansicht, tabelle
from tools.ui.worte import AB_WANN

KLARTEXT_BAND = ('<div class="klartext-band" role="note"><b>lokal, Klartext</b> Dieser Bildschirm zeigt echte Angaben. Sie bleiben auf diesem Rechner: '
                 "im Speicher der Oberfläche und in der Ablage ausserhalb des Projektordners. Kein Sprachmodell sieht sie, und sie stehen in keinem Protokoll.</div>")
NUR_LESEN = ('<p class="banner">Die Oberfläche läuft im Modus «nur lesen». Bedienen lässt sie sich, wenn der Sachbearbeiter sie selbst an einem Terminal '
             "startet (<code>python3 tools/oberflaeche.py</code>) und das Browserfenster benutzt, das sich dabei öffnet.</p>")
OHNE_GEHEIMNIS = ('<p class="banner">Dieses Fenster kann nur lesen. Hochladen, ordnen und entfernen lässt sich aus dem Browserfenster, das die Oberfläche '
                  "beim Start geöffnet hat.</p>")
FREIGABE_NAME = {"aktiv": "Aktive Massnahmen", "darkweb": "Dark Web", "personenbezug": "Kontoabfragen"}
STAND_MARKE = {"sauber": ("gut", "✓ bereit"), "personendaten": ("kritisch", "✕ Personendaten"), "nicht_lesbar": ("leer", "– nicht lesbar"),
               "risiko": ("warnung", "! Risiko übernommen")}
RISIKO_FRAGE = ("Das Risiko übernehmen? Die gewählten Dateien gehen dann so in den Fall, wie sie sind. Die gesperrten Angaben stehen im Klartext in der "
                "Fallakte und gehen an das Sprachmodell. Kürzel und Begründung stehen im Register des Falls und im Sitzungsprotokoll.")
STATUS_WORT = {"aus": "nicht gestartet", "laeuft": "läuft", "wartet": "wartet auf eine Antwort", "angehalten": "angehalten", "beendet": "beendet", "fehler": "abgebrochen"}
STATUS_FARBE = {"laeuft": "gut", "wartet": "warnung", "fehler": "kritisch"}
PFLICHT_STAND_KOPF = "<h3>Stand laut Protokoll</h3>"
OHNE_VERTRAUEN = ('<details class="hinweis-vertrauen"><summary><b>Claude Code vertraut diesem Projektordner noch nicht.</b> Es fragt dann bei jedem Werkzeug '
                  "einzeln nach. So lässt es sich beheben.</summary>"
                  "<p>Claude Code wendet die Erlaubt-Liste eines Projekts erst an, wenn ihr dem Ordner vertraut habt. Vor dem Start:</p>"
                  "<ol><li>Im Terminal im Projektordner einmal <code>claude</code> starten und die Frage nach dem Ordner mit Ja bestätigen.</li>"
                  "<li>Claude Code mit <code>/exit</code> beenden.</li><li>Hier die Ermittlung starten.</li></ol>"
                  "<p class='klein'>Starten geht auch so: Die Oberfläche erklärt dann jede Frage und kann sie für Werkzeuge der Erlaubt-Liste abstellen.</p></details>")


def feld(name: str, text: str, *, art: str = "text", pflicht: bool = False, wert: str = "", hilfe: str = "", platzhalter: str = "", breit: bool = False) -> str:
    kennung = f"f-{name}"
    eingabe = (f'<textarea id="{kennung}" name="{esc(name)}" rows="4"{" required" if pflicht else ""} placeholder="{esc(platzhalter)}">{esc(wert)}</textarea>'
               if art == "mehrzeilig" else
               f'<input id="{kennung}" name="{esc(name)}" type="{esc(art)}" value="{esc(wert)}"{" required" if pflicht else ""} placeholder="{esc(platzhalter)}" autocomplete="off">')
    return (f'<div class="feld{" breit" if breit else ""}"><label for="{kennung}">{esc(text)}{"" if pflicht else " <span class=klein>(freiwillig)</span>"}</label>{eingabe}'
            + (f'<div class="klein">{esc(hilfe)}</div>' if hilfe else "") + "</div>")


def wahl(name: str, text: str, werte: list[tuple[str, str]], gewaehlt: str = "", pflicht: bool = False) -> str:
    """`pflicht`: Der Browser sendet das Formular nicht ab, solange der leere erste Eintrag gewählt ist."""
    return (f'<div class="feld"><label for="f-{esc(name)}">{esc(text)}</label><select id="f-{esc(name)}" name="{esc(name)}"{" required" if pflicht else ""}>'
            + "".join(f'<option value="{esc(w)}"{" selected" if w == gewaehlt else ""}>{esc(t)}</option>' for w, t in werte) + "</select></div>")


def formular(aktion: str, inhalt: str, knopf: str, *, verborgen: dict | None = None, danach: str = "", klasse: str = "", frage: str = "",
             gefahr: bool = False) -> str:
    """Ein Formular der Bedienung. `danach`: Adresse, die nach Erfolg geöffnet wird. `frage`: Rückfrage vor dem Absenden.
    `gefahr`: Die Rückfrage gilt einem Schritt, der etwas entfernt oder beendet. Ihr Knopf zum Bestätigen ist dann rot, und der Fokus
    steht auf «Abbrechen»."""
    fest = "".join(f'<input type="hidden" name="{esc(k)}" value="{esc(v)}">' for k, v in (verborgen or {}).items())
    return (f'<form class="aktion {esc(klasse)}" data-aktion="{esc(aktion)}"{f" data-danach={chr(34)}{esc(danach)}{chr(34)}" if danach else ""}'
            f'{f" data-frage={chr(34)}{esc(frage)}{chr(34)}" if frage else ""}{" data-gefahr" if gefahr and frage else ""}>{fest}{inhalt}'
            f'<div class="knoepfe"><button type="submit">{esc(knopf)}</button></div>'
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
            elif e.stand == "risiko":
                pruefung += (f' <span class="klein">{e.sperren} Fundstelle{"n" if e.sperren != 1 else ""} {"bleiben" if e.sperren != 1 else "bleibt"} im Klartext. '
                             f'Durch {esc(e.risiko["durch"])}: {esc(e.risiko["grund"])}</span>')
            elif e.stand == "nicht_lesbar":
                pruefung += f'<div class="klein">{esc(e.grund)}</div>'
            elif e.platzhalter:
                pruefung += f' <span class="klein">{e.platzhalter} Platzhalter</span>'
            else:
                pruefung += ' <span class="klein">keine Platzhalter gefunden</span>'
            if e.text is not None and e.hinweise:       # sperrt nicht, soll aber niemandem entgehen
                pruefung += (' <span class="marke z-warnung" title="Diese Angaben bleiben im Klartext stehen: Nach der Vorgabe sind es Angaben der Täterseite, '
                             'die die Ermittlung braucht. Bitte ansehen.">'
                             f'! {e.hinweise} Hinweis{"e" if e.hinweise != 1 else ""}</span>')
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
                    f'data-name="{esc(e.name)}">umbenennen</button>' + (f'<div class="klein">aus {esc(e.ordner)}</div>' if e.ordner else "")
                    + (f'<div class="klein">zum Nachbessern aus dem Fall geholt: ersetzt dort <span class="mono">{esc(e.statt["name"])}</span>, sobald aufgenommen</div>' if e.statt else ""))
            zeilen.append([haken(e.id, e.name, e.stand), name, esc(e.endung or "–"), f'<span data-roh="{e.groesse}">{groesse(e.groesse)}</span>', pruefung, pseudo, rolle])
        andere = ([("", "neuer Fall")] if ziel else []) + [(f, f) for f in andere_faelle(ziel)]
        verschieben = (' <span class="trenner"></span><button type="button" data-korb="verschieben" title="Legt die gewählten Dateien in den Akten-Eingang eines anderen Falls">'
                       'Verschieben</button> <label class="klein" for="korb-nach">nach</label> <select id="korb-nach" data-korb-nach>'
                       + "".join(f'<option value="{esc(w)}">{esc(t)}</option>' for w, t in andere) + "</select>") if andere else ""
        bereit = sum(1 for e in eintraege if e.stand == "sauber")
        pii = sum(1 for e in eintraege if e.stand == "personendaten")
        gewagt = sum(1 for e in eintraege if e.stand == "risiko")
        unlesbar = sum(1 for e in eintraege if e.stand == "nicht_lesbar")
        # Der Sachbearbeiter darf ein gesperrtes Dokument bewusst so aufnehmen, wie es ist: Er übernimmt das Risiko, mit Kürzel und Begründung
        risiko = ""
        if pii or gewagt:
            risiko = ("<details class='risiko'><summary>Trotzdem aufnehmen: Risiko übernehmen</summary>"
                      "<p class='klein'>Für ein gesperrtes Dokument, das ihr bewusst so aufnehmen wollt, wie es ist. Die gesperrten Angaben stehen dann im Klartext "
                      "in der Fallakte und gehen an das Sprachmodell. Das Register des Falls und das Sitzungsprotokoll halten fest, wer das entschieden hat und "
                      "warum. Der Bericht der Prüfung in der Zeile nennt die Stellen. Ersetzen geht weiterhin: «pseudonymisieren».</p>"
                      + formular("korb_risiko", '<div class="felder-raster">' + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True)
                                 + feld("grund", "Begründung", pflicht=True, platzhalter="Angaben werden für die Ermittlung gebraucht") + "</div>",
                                 "Risiko übernehmen für die gewählten Dateien", verborgen={"ziel": ziel}, danach="neu-laden", klasse="mit-auswahl", frage=RISIKO_FRAGE, gefahr=True)
                      + (formular("korb_risiko", "", "Für die gewählten Dateien zurücknehmen", verborgen={"ziel": ziel, "zurueck": "1"}, danach="neu-laden",
                                  klasse="mit-auswahl still") if gewagt else "") + "</details>")
        h.append(f'<h2>Im Akten-Eingang ({len(eintraege)})</h2><p class="klein">{bereit} bereit, {pii} mit Personendaten, '
                 + (f'{gewagt} trotz Fund zur Aufnahme vorgesehen, ' if gewagt else "") + f'{unlesbar} nicht lesbar.</p>'
                 f'<div class="auswahl" data-auswahl="korb" data-ziel="{esc(ziel)}">'
                 '<div class="auswahlleiste" role="group" aria-label="Mit der Auswahl"><span class="klein" data-gewaehlt>nichts gewählt</span> '
                 '<button type="button" data-korb="pseudo-auswahl">Nochmals pseudonymisieren</button> '
                 '<button type="button" data-korb="rolle-auswahl" data-rolle="rapport">Als Rapport</button> '
                 '<button type="button" data-korb="rolle-auswahl" data-rolle="beilage">Als Beilage</button> '
                 '<button type="button" data-korb="entfernen" data-frage="Die gewählten Dateien aus dem Akten-Eingang entfernen? Sie werden aus dem Speicher der Oberfläche gelöscht.">Entfernen</button>'
                 + verschieben + "</div>"
                 + tabelle([ALLE, "Datei", "Art", "Grösse", "PII-Prüfung", "Pseudonymisierung", "Rolle"], zeilen, "Akten-Eingang", klasse="daten auswahltabelle")
                 + '<div class="ergebnis" data-korb-ergebnis aria-live="polite"></div>' + risiko + '</div>')
        hinweise = []
        if pii:
            hinweise.append("<b>Personendaten:</b> Gesperrt ist, was nach der Vorgabe ersetzt sein muss: Angaben zur Dienststelle, zur Verfasserin oder zum Verfasser "
                            "und zu Geschädigten. «pseudonymisieren» öffnet das Dokument auf dem lokalen Bildschirm. Dort sind die Fundstellen markiert: annehmen, verwerfen, "
                            "ergänzen. Namen erkennt die Prüfung nicht von selbst, deshalb lohnt der Blick auch bei Dokumenten, die als bereit gelten.")
        if any(e.hinweise and e.text is not None for e in eintraege):
            hinweise.append("<b>Hinweise:</b> Angaben der Täterseite sperrt die Prüfung nicht: Rufnummern, Konten, E-Mail-Adressen. Die Ermittlung braucht sie, "
                            "sie bleiben stehen. Dasselbe gilt für Angaben, die in keinem Abschnitt zu einer Person stehen. Gehört eine davon zur geschädigten Seite: "
                            "«pseudonymisieren» öffnen und dort entscheiden. Der Bericht der Prüfung nennt die Stellen und den Abschnitt.")
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
             + "<details class='nachbessern'><summary>Gewählte nachbessern (nochmals pseudonymisieren)</summary><p class='klein'>Für ein Dokument, in dem noch eine "
               "geschützte Angabe im Klartext steht. Es kommt in den Akten-Eingang dieses Falls und lässt sich dort auf dem lokalen Bildschirm pseudonymisieren. "
               "Im Fall bleibt es liegen, bis die nachgebesserte Fassung aufgenommen ist. Dann ersetzt sie die alte, und das Register hält es fest.</p>"
             + formular("eingang_nachbessern", '<div class="felder-raster">' + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True) + "</div>", "Zum Nachbessern holen",
                        verborgen={"fall": fall_id, "namen": ""}, danach="neu-laden", klasse="mit-auswahl") + "</details>"
             + "<details><summary>Gewählte entfernen</summary><p class='klein'>Nimmt die Dokumente aus dem Eingang. Das Register der PII-Prüfung hält fest, was wann von wem und warum "
               "entfernt wurde. Was ein Agent schon gelesen hat, bleibt im Protokoll belegt.</p>"
             + formular("eingang_entfernen", '<div class="felder-raster">' + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True) + feld("grund", "Grund", pflicht=True, platzhalter="falsches Dokument")
                        + "</div>", "Entfernen", verborgen={"fall": fall_id, "namen": ""}, danach="neu-laden", klasse="mit-auswahl",
                        frage="Die gewählten Dokumente aus dem Eingang des Falls entfernen?", gefahr=True) + "</details>"
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
    belassen = len({v.erk.verweis.get(f.angabe, f.angabe) for f in v.erk.funde if f.frage == "taeter" and ps.stand(f, v.ent) is False})
    vorgabe = ("<p class='vorgabe'><b>Vorgabe.</b> Ersetzt wird, was zur Dienststelle, zur Verfasserin oder zum Verfasser und zu Geschädigten gehört. "
               "Angaben der Täterseite bleiben stehen: Die Ermittlung braucht sie."
               + (f" In diesem Dokument {'bleibt eine solche Angabe' if belassen == 1 else f'bleiben {belassen} solche Angaben'} stehen. "
                  f"Gehört {'sie' if belassen == 1 else 'eine davon'} doch zu einer geschädigten Person: unten «doch ersetzen»." if belassen else "")
               + (f" {v.feldreste} {'Rest einer Word-Feldfunktion wurde' if v.feldreste == 1 else 'Reste von Word-Feldfunktionen wurden'} entfernt: "
                  "Sie wiederholten Angaben im Klartext." if v.feldreste else "") + "</p>")
    return (
        f'<h1>Pseudonymisieren · {esc(pseudo.name)}</h1>{KLARTEXT_BAND}'
        f'<p class="unter"><span data-warteschlange></span>{sum(ergebnis.ersetzt.values())} Fundstellen werden ersetzt, {len(ergebnis.zuordnung)} Platzhalter, {ergebnis.offen} Kandidaten offen. '
        "Technische Indikatoren bleiben stehen. Platzhalter, die schon im Dokument stehen, bleiben, wie sie sind: Neue zählen dahinter weiter.</p>" + vorgabe +
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

def klartext_meldung(fall_id: str, stellen: list[dict]) -> str:
    """Was die Ermittlung gemeldet hat: Stellen, an denen eine geschützte Angabe noch im Klartext steht. Genannt sind Dokument, Zeile
    und die Art der Angabe, nie die Angabe selbst. Schreibt ein Agent sie doch in seine Beschreibung, zeigt die Seite die
    Beschreibung nicht: Sie geht durch dieselbe Prüfung wie eine Nachricht."""
    if not stellen:
        return ""
    punkte = []
    for s in stellen[:20]:
        was = s.get("was") or ""
        if was and any(f.stufe == "sperre" for f in pii_pruefen(was, "streng")[0]):
            was = "(Beschreibung nicht gezeigt: Sie nennt selbst eine Angabe)"
        punkte.append(f'<li><span class="mono">{esc(s.get("dokument") or "")}</span>' + (f', Zeile {int(s["zeile"])}' if s.get("zeile") else "") + (f": {esc(was)}" if was else "") + "</li>")
    n = len(stellen)
    return (f'<details class="klartext-meldung" open><summary><b>{n} {"Stelle" if n == 1 else "Stellen"} mit einer geschützten Angabe im Klartext</b> '
            '<span class="klein">gemeldet von der Ermittlung</span></summary>'
            "<p class='klein'>Die Ermittlung verwendet diese Angaben nicht und arbeitet weiter. Nachbessern: unter «Akten» das Dokument wählen und "
            "«Gewählte nachbessern». Es öffnet sich danach auf dem lokalen Bildschirm, und die nachgebesserte Fassung ersetzt die alte.</p>"
            f'<ul>{"".join(punkte)}</ul>' + (f"<p class='klein'>und {n - 20} weitere</p>" if n > 20 else "")
            + f'<p><a class="knopf" href="{pfad(fall_id, "akten")}">Zu den Akten</a></p></details>')


def ermittlung_feld(fall_id: str, stand: dict | None, verfuegbar: str = "", klartext: list[dict] | None = None) -> str:
    """Stand der gesteuerten Sitzung von Claude Code: läuft sie, mit welcher Sitzung und welchem Modell, dazu die Knöpfe.
    Den Verlauf zeigt der Chat, wer woran arbeitet die Tafel darunter. Dazu, was vor dem Start zu wissen ist (Claude Code
    vertraut dem Projektordner noch nicht) und was die Ermittlung zu den Dokumenten gemeldet hat."""
    stand = stand or {"status": "aus"}
    status = stand.get("status")
    h = [f'<div class="ermittlung" data-status="{esc(status)}"><p class="stand"><span class="marke z-{STATUS_FARBE.get(status, "leer")}">Ermittlung: {esc(STATUS_WORT.get(status, status))}</span>'
         + (f' <span class="klein">Sitzung <span class="mono">{esc(stand.get("sitzung") or "")}</span></span>' if stand.get("sitzung") else "")
         + (f' <span class="klein">Modell laut Claude Code: <span class="mono">{esc(stand.get("modell"))}</span></span>' if stand.get("modell") else "") + "</p>"]
    if verfuegbar:
        h.append(f'<p class="banner">{esc(verfuegbar)}</p>')
    elif stand.get("ordner") is False and status not in ("laeuft", "wartet"):
        h.append(OHNE_VERTRAUEN)
    if klartext:
        h.append(klartext_meldung(fall_id, klartext))
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


ZUSTIMMUNG_TITEL = {"aktiv": "Aktive Massnahme: Zustimmung nötig", "aussen": "Abruf am Gateway vorbei: Zustimmung nötig", "erlaubt": "Claude Code fragt nach",
                    "befehl": "Befehl: Zustimmung nötig", "datei": "Datei ändern: Zustimmung nötig", "sonst": "Zustimmung nötig"}


def _frage_felder(fragen: list[dict]) -> str:
    """Die Fragen der Ermittlung als Felder: je Frage die Auswahl und eine eigene Antwort. Die Namen der Felder zählen mit,
    die Antwort setzt der Server aus der gespeicherten Frage zusammen: Aus dem Browser kommt nur, was gewählt wurde."""
    h = []
    for i, f in enumerate(fragen):
        wahl = []
        for j, w in enumerate(f.get("wahl") or []):
            eingabe = (f'<input type="checkbox" name="wahl_{i}_{j}" value="1">' if f.get("mehrere") else f'<input type="radio" name="wahl_{i}" value="{j}">')
            wahl.append(f'<label class="wahl">{eingabe} <span><b>{esc(w.get("name") or "")}</b>'
                        + (f'<span class="klein">{esc(w["text"])}</span>' if w.get("text") else "") + "</span></label>")
        h.append(f'<div class="frage-feld" role="group" aria-labelledby="frage-{i}"><p class="frage-titel" id="frage-{i}">'
                 + (f'<span class="marke z-leer">{esc(f["kopf"])}</span> ' if f.get("kopf") else "") + f'{esc(f.get("frage") or "")}</p>'
                 + (f'<p class="klein">{"Mehrere Antworten sind möglich." if f.get("mehrere") else "Eine Antwort wählen, oder eine eigene schreiben."}</p>' if wahl else "")
                 + "".join(wahl)
                 + f'<label class="eigen" for="frei-{i}">Eigene Antwort{"" if not wahl else (" (zusätzlich)" if f.get("mehrere") else " (ersetzt die Auswahl)")}</label>'
                 f'<input type="text" id="frei-{i}" name="frei_{i}" autocomplete="off" maxlength="2000"></div>')
    return "".join(h)


def rueckfrage_dialog(fragen: list[dict]) -> str:
    """Die Rückfrage, die als nächste zu beantworten ist, als Dialog. Er erscheint in jeder Ansicht, über allem anderen.
    Zwei Arten: Die Ermittlung stellt dem Sachbearbeiter eine Frage, oder ein Schritt braucht seine Zustimmung. Was getan
    werden soll und warum gefragt wird, steht in Worten da (tools/ui/worte.py). Die Eingabe im Wortlaut steht unter «Einzelheiten»."""
    if not fragen:
        return ""
    from tools.ui import worte as wo
    frage = fragen[0]
    weitere = len(fragen) - 1 + int(frage.get("weitere") or 0)
    fall, kennung = str(frage.get("fall") or ""), str(frage.get("id") or "")
    danach = (f" Danach {'folgt eine weitere Rückfrage' if weitere == 1 else f'folgen {weitere} weitere Rückfragen'}." if weitere > 0 else "")
    wer = f' · {esc(wo.team(str(frage["wer"])))}' if frage.get("wer") else ""
    kopfzeile = f'<p class="klein">Fall <span class="mono">{esc(fall)}</span>{wer}</p>'
    einzelheiten = (f'<details class="einzelheiten"><summary>Einzelheiten: die Eingabe im Wortlaut</summary><p class="klein">Werkzeug <span class="mono">{esc(frage.get("werkzeug") or "")}</span></p>'
                    f'<pre class="rohtext">{esc(frage.get("eingabe") or "")}</pre></details>')
    if frage.get("art") == "frage":
        return ('<div class="rueckfrage art-frage" role="alertdialog" aria-modal="true" aria-labelledby="rueckfrage-titel"><h3 id="rueckfrage-titel">Die Ermittlung fragt dich</h3>'
                + kopfzeile
                + formular("ermittlung_antworten", _frage_felder(frage.get("fragen") or [])
                           + '<label class="klein trotzdem"><input type="checkbox" name="trotzdem" value="1"> Meine eigene Antwort nennt bewusst eine Angabe der '
                             "Täterseite (zum Beispiel eine Rufnummer). Trotz Prüfung senden.</label>",
                           "Antworten", verborgen={"fall": fall, "frage": kennung, "erlauben": "1"}, danach="rueckfrage", klasse="antwort haupt-form")
                + formular("ermittlung_antworten", "", "Nicht beantworten", verborgen={"fall": fall, "frage": kennung, "erlauben": ""}, danach="rueckfrage", klasse="klein-form still")
                + "<p class='klein'>Deine Antwort liest das Sprachmodell. Angaben zu Geschädigten, zur Verfasserin oder zum Verfasser und zur Dienststelle gehören nicht "
                  "hinein: Platzhalter wie im Dokument. Ohne Antwort trifft die Ermittlung selbst eine Annahme und nennt sie. Frage und Antwort stehen im "
                  "Sitzungsprotokoll." + danach + "</p>" + einzelheiten + "</div>")
    z = frage.get("worte") or {}
    art = str(z.get("art") or "sonst")
    angaben = "".join(f"<dt>{esc(name)}</dt><dd{klasse}>{esc(wert)}</dd>" for name, wert, klasse in (
        ("Ziel", z.get("ziel") or "", ' class="mono"'), ("Zweck laut Ermittlung", z.get("zweck") or "", "")) if wert)

    def knopf(text: str, klasse: str, **mehr) -> str:
        return formular("ermittlung_antworten", "", text, verborgen={"fall": fall, "frage": kennung, **mehr}, danach="rueckfrage", klasse="klein-form " + klasse)
    knoepfe = (knopf("Ablehnen", "haupt-form", erlauben="") + knopf("Trotzdem erlauben", "still", erlauben="1") if art == "aussen" else
               knopf("Erlauben", "haupt-form", erlauben="1")
               + (knopf("Erlauben und nicht mehr fragen", "", erlauben="1", merken="1") if z.get("merkbar") else "")
               + knopf("Ablehnen", "still", erlauben=""))
    return (f'<div class="rueckfrage art-{esc(art)}" role="alertdialog" aria-modal="true" aria-labelledby="rueckfrage-titel">'
            f'<h3 id="rueckfrage-titel">{esc(ZUSTIMMUNG_TITEL.get(art, ZUSTIMMUNG_TITEL["sonst"]))}</h3>' + kopfzeile
            + f'<p class="satz">{esc(z.get("satz") or frage.get("werkzeug") or "")}</p>'
            + (f'<dl class="angaben">{angaben}</dl>' if angaben else "")
            + (f'<p><b>Warum die Frage kommt:</b> {esc(z["grund"])}</p>' if z.get("grund") else "")
            + ('<details class="beheben"><summary>So entfällt die Frage künftig</summary><ol>' + "".join(f"<li>{esc(s)}</li>" for s in z["beheben"]) + "</ol></details>"
               if z.get("beheben") else "")
            + (f'<p class="banner">{esc(z["rat"])}</p>' if z.get("rat") else "")
            + f'<div class="knopfzeile">{knoepfe}</div>'
            + (f'<p class="klein">{esc(z["folge"])}</p>' if z.get("folge") else "")
            + "<p class='klein'>Die Antwort steht im Sitzungsprotokoll, mit Zeit und dem Vermerk, dass sie über die Oberfläche kam." + danach + "</p>"
            + einzelheiten + "</div>")


def pflicht_feld(fall: daten.Fall, arbeitet: bool = False) -> str:
    """Pflichtquellen vor dem Start: leer lassen, einzeln anwählen oder alle. Was angewählt ist, muss die Ermittlung abfragen.
    Anwählen lässt sich nur, was an diesem Arbeitsplatz bereit ist. Robin verlangt dazu die Freigabe «Dark Web» des Falls.
    Während die Ermittlung arbeitet, steht die Auswahl fest. Die Auswahl ist eingeklappt, damit der Chat seinen Platz behält:
    Ihre Kopfzeile sagt, wie viele Quellen vorgegeben sind und wie weit sie erfüllt sind. Der ausführliche Stand steht darin."""
    vorgegeben = pq.vorgabe(fall.daten)
    gruppen: dict[str, list[str]] = {}
    for w in pq.waehlbar(fall.daten):
        an = w["name"] in vorgegeben
        hindernis = (w["grund"] if not w["bereit"] else
                     f"braucht die Freigabe «{FREIGABE_NAME.get(w['freigabe'], w['freigabe'])}» des Falls" if w["freigabe_fehlt"] else "")
        gruppen.setdefault(w["gruppe"], []).append(
            f'<label class="pflicht-quelle{" gesperrt" if hindernis else ""}" title="{esc(w["zweck"])}">'
            f'<input type="checkbox" name="quelle" value="{esc(w["name"])}"{" checked" if an else ""}{" disabled" if hindernis and not an else ""}> '
            f'<b>{esc(w["name"])}</b> <span class="klein">{esc(hindernis or w["kurz"])}</span></label>')
    titel = {"mit Schlüssel": "Mit Schlüssel", "ohne Schlüssel": "Ohne Schlüssel", "Dark Web": "Dark Web"}

    def gruppe(name: str) -> str:
        return f'<div class="pflicht-gruppe"><h4>{esc(titel[name])}</h4>{"".join(gruppen[name])}</div>' if name in gruppen else ""
    # Zwei Spalten: links die Quellen mit Schlüssel, rechts die ohne und darunter das Dark Web
    spalten = (f'<div class="pflicht-spalte">{gruppe("mit Schlüssel")}</div>'
               f'<div class="pflicht-spalte">{gruppe("ohne Schlüssel")}{gruppe("Dark Web")}</div>')
    return (f'<details class="pflicht" id="pflicht" data-pflicht data-fall="{esc(fall.id)}" data-gespeichert="{esc(json.dumps(vorgegeben, ensure_ascii=False))}">'
            '<summary><b>Pflichtquellen</b> <span class="klein">(freiwillig)</span> <span class="marke" data-pflicht-marke></span> '
            f'<span class="klein" data-pflicht-kurz>{esc(pflichtquellen_kurz(fall))}</span></summary>'
            f'<fieldset class="pflicht-felder" data-pflicht-felder{" disabled" if arbeitet else ""}>'
            "<p class='klein'>Was du hier anwählst, muss die Ermittlung abfragen: jede Quelle für jeden Indikator aus den Akten, zu dem sie passt. "
            "Der Rapport lässt sich erst abschliessen, wenn das Protokoll es zeigt. Leer heisst: Das Team wählt die Quellen selbst. "
            "Weitere Quellen fragt es in jedem Fall nach eigenem Ermessen. Eine Pflichtquelle ersetzt keine Freigabe: Freigaben erteilst du unter "
            f'<a href="{pfad(fall.id, "bedienen")}">Bedienen</a>.</p>'
            '<div class="knopfzeile"><button type="button" class="klein-knopf" data-pflicht-alle>Alle auswählen</button> '
            '<button type="button" class="klein-knopf" data-pflicht-keine>Keine</button> <span class="klein" data-pflicht-zahl></span></div>'
            f'<div class="pflicht-gruppen">{spalten}</div>'
            '<div class="knopfzeile"><button type="button" data-pflicht-speichern>Pflichtquellen speichern</button> '
            '<span class="klein" data-pflicht-hinweis></span></div><div class="ergebnis" aria-live="polite"></div></fieldset>'
            f'<div id="pflicht-stand" data-ohne-leiste>{pflichtquellen_html(fall, PFLICHT_STAND_KOPF)}</div></details>')


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
        kopf, f'<div id="ermittlung" data-fall="{esc(fid)}">{ermittlung_feld(fid, stand, verfuegbar, fall.klartext_stellen())}</div>',
        pflicht_feld(fall, (stand or {}).get("status") in ("laeuft", "wartet")), chat_feld(fid),
        f'<div id="ermittlung-wer" data-ohne-leiste>{wer_tafel(stand)}</div>',
        "<p class='klein'>Was du hier schreibst, liest das Sprachmodell. Angaben zu Geschädigten, zur Verfasserin oder zum Verfasser und zur Dienststelle gehören nicht "
        "hierher: Platzhalter wie im Dokument. Die Oberfläche prüft jede Eingabe. Sperrt sie eine Angabe der Täterseite (eine Rufnummer, ein Konto), lässt sich die "
        "Nachricht bewusst doch senden. Arbeitet die Ermittlung gerade, wartet eine Nachricht auf das Ende des laufenden Auftrags, oder sie unterbricht ihn.</p>"
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
    # Dark Web: Robin sucht nur in einem Untersuchungsbereich, den ein Mensch gewählt hat. Der Sachbearbeiter wählt ihn hier.
    bereiche = [(k, f"{n}: {wofuer}" + (" (braucht zusätzlich die Freigabe «Kontoabfragen»)" if k == robin.BEREICH_MIT_PERSONENBEZUG else ""))
                for k, (n, wofuer) in robin.BEREICHE.items()]
    for f in fall.freigaben():
        name = FREIGABE_NAME.get(f["name"], f["name"])
        dunkel = f["name"] == "darkweb"
        if f["erteilt"]:
            zusatz = ""
            if dunkel:
                gewaehlt = f.get("bereich") or ""
                zusatz = ((f'<p class="klein">Untersuchungsbereich: <b>{esc(robin.BEREICHE[gewaehlt][0])}</b></p>' if gewaehlt else
                           '<p class="banner">Kein Untersuchungsbereich gewählt. So sucht Robin nicht: Es fragt danach, und die Ermittlung erreicht dich dafür nicht.</p>')
                          + formular("freigabe", wahl("bereich", "Untersuchungsbereich", bereiche, gewaehlt or "threat_intel"), "Bereich ändern" if gewaehlt else "Bereich wählen",
                                     verborgen={"fall": fid, "art": "darkweb", "bereich_aendern": "1"}, danach="neu-laden", klasse="klein-form"))
            h.append(f'<div class="karte"><h4>{esc(name)} <span class="marke z-gut">✓ erteilt</span></h4><p class="klein">durch {esc(f["durch"])} am {esc(daten.rapport.zeit_zeigen(f["am"]))} · Grundlage: {esc(f["vermerk"])}</p>'
                     + zusatz
                     + formular("freigabe", "", "Freigabe entziehen", verborgen={"fall": fid, "art": f["name"], "entziehen": "1"}, danach="neu-laden", klasse="klein-form") + "</div>")
        else:
            h.append(f'<div class="karte"><h4>{esc(name)} <span class="marke z-leer">○ nicht erteilt</span></h4><p class="klein">{esc(daten.rapport.FREIGABE_TEXT[f["name"]])}</p>'
                     + formular("freigabe", '<div class="felder-raster">' + feld("durch", "Durch (Kürzel oder Funktion)", pflicht=True) + feld("vermerk", "Grundlage (Auftrag, Verfügung)", pflicht=True)
                                + (wahl("bereich", "Untersuchungsbereich (worin Robin suchen darf)", [("", "bitte wählen")] + bereiche, pflicht=True) if dunkel else "") + "</div>",
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
                        verborgen={"fall": fid}, danach="#/", frage=f"Fall {fid} mit allen Dokumenten in seinem Eingang löschen?", gefahr=True)))
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


ABSCHALTEN_FRAGE = ("Alles abschalten? Laufende Ermittlungen werden angehalten, Robin und Web-Check gestoppt, und die Oberfläche beendet sich. "
                    "Gelöscht wird nichts.")


def arbeitsplatz_seite(bedienung) -> str:
    """Was zum Arbeitsplatz gehört und gerade läuft, und der Knopf «Alles abschalten». Im Modus «nur lesen» nur die Anzeige.
    Dasselbe am Terminal: python3 tools/dienste.py"""
    from tools import dienste
    farbe = {dienste.GUT: "gut", dienste.FEHLT: "kritisch"}
    stand = dienste.stand(False)
    zeilen = [[esc(was), f'<span class="marke z-{farbe.get(zeichen, "leer")}">{esc(wie)}</span>'] for zeichen, was, wie in dienste.stand_zeilen(stand)]
    laufend = sorted(fall for fall, sitzung in (bedienung.ermittlungen.items() if bedienung is not None else ()) if sitzung.laeuft())
    zeilen.insert(0, ["Oberfläche", '<span class="marke z-gut">läuft</span>' + ("" if bedienung is not None else " <span class='klein'>im Modus «nur lesen»</span>")])
    zeilen.insert(1, ["Ermittlung", f'<span class="marke z-gut">läuft</span> {esc(", ".join(laufend))}' if laufend else '<span class="marke z-leer">läuft keine</span>'])
    knopf = (formular("abschalten", "<p>Hält laufende Ermittlungen an, stoppt Robin und Web-Check und beendet die Oberfläche. Gelöscht wird nichts: Fallakten, Schlüssel "
                      "und Einstellungen bleiben. Eine angehaltene Ermittlung lässt sich später fortsetzen.</p>", "Alles abschalten",
                      danach="abgeschaltet", klasse="abschalten", frage=ABSCHALTEN_FRAGE, gefahr=True)
             if bedienung is not None else NUR_LESEN)
    return ("<h1>Arbeitsplatz</h1><p class='unter'>Was zu diesem Arbeitsplatz gehört und gerade läuft.</p>"
            + "<div data-ohne-leiste>" + tabelle(["Was", "Stand"], zeilen, "Was läuft") + "</div>"      # eine Handvoll Zeilen: ohne Filter und CSV
            + "<h2>Alles abschalten</h2>" + knopf
            + "<p class='klein'>Tor läuft dabei weiter, wenn der Arbeitsplatz es als Proxy nutzt: Es gehört zum System und braucht euer Passwort. "
              f"Am Terminal schaltet <code>{dienste.PY} tools/dienste.py aus</code> auch Tor ab, <code>{dienste.PY} tools/dienste.py ein</code> schaltet "
              f"Web-Check und Tor wieder ein. Die Oberfläche startet wieder mit <code>{dienste.PY} tools/oberflaeche.py</code>. Docker selbst bleibt an.</p>"
            + arbeitsplatz_loeschen(bedienung, stand))


LOESCHEN_FRAGE = ("Den Arbeitsplatz von diesem Rechner löschen? Fallakten und Sitzungsprotokolle werden zuerst gesichert. Danach verschwinden Schlüssel, "
                  "Fallakten, Einstellungen und der Projektordner. Das lässt sich nicht rückgängig machen.")


def arbeitsplatz_loeschen(bedienung, stand: dict | None = None) -> str:
    """Der Abschnitt «Arbeitsplatz löschen» der Seite «Arbeitsplatz»: eingeklappt, mit dem Plan (was gelöscht wird, wohin gesichert
    wird, was bleibt), einem Feld für die Bestätigung von Hand und dem Knopf. Im Modus «nur lesen» nur der Hinweis auf den Weg.
    `stand`: was läuft, wenn die Seite es schon erfragt hat."""
    from tools import loeschen
    kopf = "<h2>Arbeitsplatz löschen</h2>"
    if bedienung is None:
        return (kopf + "<p class='klein'>Den Arbeitsplatz von diesem Rechner entfernen kann nur der Sachbearbeiter: in der bedienbaren Oberfläche "
                f"oder am Terminal mit <code>{loeschen.PY} tools/loeschen.py alles</code>. Was dabei geschähe, zeigt <code>{loeschen.PY} tools/loeschen.py</code>, "
                "ohne etwas zu ändern.</p>")
    p = loeschen.plan(mit_oberflaeche=False, laeuft=stand, ablage=bedienung.ablage)      # die Seite nennt die Ablage dieser Oberfläche, nicht die Vorgabe
    plan = ("<div data-ohne-leiste>"
            + tabelle(["Was", "Was geschieht"], [[esc(was), ('<span class="marke z-kritisch">Achtung</span> ' if zeichen == loeschen.FEHLT else "") + esc(wie)]
                                                 for zeichen, was, wie in loeschen.plan_zeilen(p)], "Was gelöscht wird") + "</div>")
    bleibt = "<ul>" + "".join(f"<li><b>{esc(was)}:</b> {esc(wo)}</li>" for was, wo in p["bleibt"]) + "</ul>"
    if p["hindernis"]:
        knopf = f'<p class="banner">So lässt sich der Arbeitsplatz nicht löschen: {esc(p["hindernis"])}</p>'
    else:
        knopf = formular("arbeitsplatz_loeschen", '<div class="felder-raster">'
                         + feld("bestaetigung", f"Zur Bestätigung den Namen des Projektordners eintippen: {p['name']}", pflicht=True, platzhalter=p["name"], breit=True)
                         + "</div>",
                         "Alles löschen", danach="abgeschaltet", klasse="loeschen", frage=LOESCHEN_FRAGE, gefahr=True)
    return (kopf + '<details class="gefahrenbereich"><summary>Den Arbeitsplatz von diesem Rechner entfernen</summary>'
            "<p>Für den Fall, dass dieser Rechner den Arbeitsplatz nicht mehr führen soll. Zuerst werden Fallakten und Sitzungsprotokolle in ein Archiv "
            "ausserhalb des Projekts gesichert, mit der Prüfsumme jeder Datei, und das Archiv wird geprüft. Erst dann wird gelöscht. Scheitert die Sicherung, "
            "bleibt alles, wie es ist. Fallakten und Protokolle sind Beweismittel: Einen Weg, sie ohne Sicherung zu löschen, gibt es nicht.</p>"
            + plan + "<h3>Was bleibt</h3>" + bleibt + knopf
            + f"<p class='klein'>Dasselbe am Terminal: <code>{loeschen.PY} tools/loeschen.py alles</code>. Nur abschalten, ohne etwas zu löschen: «Alles abschalten» oben.</p>"
              "</details>")


# --------------------------------------------------------------------------- Fehlerprotokoll

FEHLER_UNTER = ("<h1>Fehlerprotokoll</h1><p class='unter'>Was an diesem Arbeitsplatz schiefging, an einem Ort: zum Nachsehen, Kopieren und Speichern, "
                "etwa für eine Fehlermeldung oder für die Frage an ein Sprachmodell.</p>")
FEHLER_STUFE = {"fehler": ("kritisch", "✕ Fehler"), "hinweis": ("neutral", "○ Hinweis")}
FEHLER_LEEREN_FRAGE = "Das Fehlerprotokoll leeren? Alle Einträge verschwinden, im Fenster und in der Datei in der Ablage. Fallakten und Protokolle der Fälle bleiben unberührt."
FEHLER_BEREICHE = (("Oberfläche", "der lokale Server: eine Ansicht liess sich nicht aufbauen, eine Anfrage wurde abgewiesen"),
                   ("Aktion", "Bedienung im Fenster: eine Aktion ist gescheitert oder wurde abgesagt"),
                   ("Ermittlung", "die Sitzung von Claude Code: ein Ende mit Fehler, Meldungen am Fehlerkanal, eine Abfrage mit Fehlschlag"),
                   ("Werkzeug", "Werkzeuge des Projekts, die die Oberfläche startet (Rapport, Protokoll, PDF, Testabfrage)"),
                   ("Browser", "ein Fehler im Skript dieses Fensters"))


def zeit_ch(zeit: str) -> str:
    """2026-11-19 14:03:12 wird 19.11.2026 14:03:12."""
    try:
        return datetime.strptime(zeit, "%Y-%m-%d %H:%M:%S").strftime("%d.%m.%Y %H:%M:%S")
    except ValueError:
        return zeit


def lauf_wort(lauf: str) -> str:
    """Wann ein Lauf der Oberfläche begann, aus seiner Kennung: oberflaeche-20261119-140312 wird 19.11.2026 14:03."""
    try:
        return datetime.strptime(lauf.replace("oberflaeche-", ""), "%Y%m%d-%H%M%S").strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return lauf or "unbekannt"


def fehler_kopf(bedienung, claude: str = "") -> str:
    """Der Kopf des Fehlerprotokolls als Text: was wissen muss, wer es liest, ohne den Arbeitsplatz zu kennen (auch ein Sprachmodell).
    `claude`: leer, wenn Claude Code bereit ist, sonst der Grund, warum nicht."""
    zahl = bedienung.fehlerbuch.zahl()
    return fehlerbuch.bereinigen("\n".join([
        "Fehlerprotokoll des OSINT-Arbeitsplatzes (Oberfläche im Browser, tools/oberflaeche.py)",
        f"Erstellt: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"System: {platform.system()} {platform.release()}" + (" (WSL)" if plattform.wsl() else "") + f", Python {platform.python_version()}",
        f"Lauf der Oberfläche: {bedienung.sitzung.replace('oberflaeche-', '')}. In diesem Lauf: {zahl['fehler']} Fehler, {zahl['hinweise']} Hinweise.",
        "Claude Code: " + (" ".join(claude.split()) if claude else "bereit"),
        "Bereiche: " + "; ".join(f"{name} = {was}" for name, was in FEHLER_BEREICHE) + ".",
        "Bereinigt: Schlüssel, das Geheimnis der Oberfläche, Benutzerordner und Rechnername sind ersetzt, ebenso Angaben, die die PII-Prüfung erkennt "
        "(zum Beispiel ‹Telefonnummer›, ‹IBAN›). Namen erkennt die Bereinigung nicht: vor dem Weitergeben durchsehen.",
        "Die Einträge stehen in der Reihenfolge, in der sie entstanden sind, der neueste zuletzt."]), ablage=bedienung.ablage)


def fehler_lesen(bedienbar: bool) -> str:
    """Das Fehlerprotokoll für ein Fenster ohne Geheimnis: nur, wo es zu sehen ist. Einträge zeigt der Server nur dem Fenster des Starts."""
    return FEHLER_UNTER + (
        '<p class="banner">Dieses Fenster kann nur lesen. Das Fehlerprotokoll zeigt die Oberfläche in dem Browserfenster, das sie beim Start geöffnet hat.</p>'
        if bedienbar else
        '<p class="banner">Die Oberfläche läuft im Modus «nur lesen» und führt kein Fehlerprotokoll. Was schiefgeht, steht im Terminal, in dem sie läuft.</p>')


def _fehler_eintrag(e: dict, dieser: bool) -> str:
    farbe, wort = FEHLER_STUFE[e["stufe"]]
    zeilen = e["einzelheiten"].count("\n") + 1 if e["einzelheiten"] else 0
    mal = (f'<span class="klein">{int(e["mal"])} mal, zuletzt {esc(zeit_ch(str(e.get("zuletzt") or ""))[-8:])}</span>' if e.get("mal") else "")
    fall = (f'<a class="eintrag-fall" href="{pfad(e["fall"])}">Fall {esc(e["fall"])}</a>' if e["fall"] and (FAELLE / e["fall"] / "fall.json").is_file()
            else f'<span class="eintrag-fall">Fall {esc(e["fall"])}</span>' if e["fall"] else "")
    return (f'<li class="eintrag s-{esc(e["stufe"])}" data-stufe="{esc(e["stufe"])}" data-lauf="{"dieser" if dieser else "frueher"}" data-kopf="{esc(fehlerbuch.kopfzeile(e))}">'
            f'<div class="eintrag-kopf"><span class="marke z-{farbe}">{wort}</span><time>{esc(zeit_ch(e["zeit"]))}</time>'
            f'<span class="eintrag-bereich">{esc(e["bereich"])}</span>{fall}{mal}'
            '<button type="button" class="klein-knopf" data-fehler-eintrag title="Diesen Eintrag in die Zwischenablage kopieren">kopieren</button></div>'
            f'<p class="eintrag-meldung">{esc(e["meldung"])}</p>'
            + (f'<details class="eintrag-mehr"><summary>Einzelheiten ({zeilen} {"Zeile" if zeilen == 1 else "Zeilen"})</summary><pre class="rohtext">{esc(e["einzelheiten"])}</pre></details>'
               if e["einzelheiten"] else "") + "</li>")


def fehler_seite(bedienung) -> str:
    """Das Fehlerprotokoll: Zahlen, Knöpfe zum Kopieren, Speichern und Leeren, die Einträge (neueste zuerst), und was hier steht und was nicht.
    Den Text zum Kopieren und Speichern gibt der Server daneben mit: Er ist derselbe wie auf der Seite, nur in der Reihenfolge des Entstehens."""
    buch = bedienung.fehlerbuch
    eintraege, zahl = buch.liste(), buch.zahl()
    frueher = sum(1 for e in eintraege if e["lauf"] != buch.lauf)
    h = [FEHLER_UNTER, '<div data-fehlerprotokoll>',
         '<div class="kacheln fehler-zahlen">' + "".join(
             f'<div class="kachel{" " + klasse if n and klasse else ""}"><div class="wert">{daten.ds.zahl(n)}</div><div class="name">{esc(name)}</div></div>'
             for n, name, klasse in ((zahl["fehler"], "Fehler in diesem Lauf", "k-kritisch"), (zahl["hinweise"], "Hinweise in diesem Lauf", ""),
                                     (frueher, "Einträge aus früheren Läufen", ""))) + "</div>"]
    if not eintraege:
        h.append('<p class="fehler-leer"><b>Keine Einträge.</b> Seit dem Start der Oberfläche ist nichts schiefgegangen, und aus früheren Läufen liegt nichts vor.</p>')
    else:
        h.append('<div class="knopfzeile fehler-knoepfe"><button type="button" class="haupt" data-fehler-kopieren>Alles kopieren</button>'
                 '<button type="button" data-fehler-speichern>Als Datei speichern</button>'
                 + formular("fehler_leeren", "", "Leeren", danach="neu-laden", klasse="klein-form", frage=FEHLER_LEEREN_FRAGE, gefahr=True)
                 + '<span class="klein" data-fehler-meldung role="status" aria-live="polite"></span></div>'
                 '<p class="fehler-durchsehen"><b>Vor dem Weitergeben durchsehen.</b> Schlüssel, Pfade und erkannte Angaben (Rufnummer, IBAN …) sind ersetzt. '
                 "Namen erkennt die Bereinigung nicht, und technische Angaben aus einem Fall (IP-Adresse, Domain) bleiben stehen.</p>"
                 '<div class="fehler-filter" role="group" aria-label="Fehlerprotokoll filtern">'
                 '<input type="search" data-fehler-suche placeholder="Einträge durchsuchen" aria-label="Einträge durchsuchen">'
                 '<button type="button" aria-pressed="false" data-fehler-filter="fehler">nur Fehler</button>'
                 '<button type="button" aria-pressed="false" data-fehler-filter="dieser">nur dieser Lauf</button>'
                 '<span class="klein" data-fehler-zahl></span></div>')
        zeilen, lauf = [], None
        for e in reversed(eintraege):       # neueste zuerst, je Lauf der Oberfläche eine Zwischenzeile
            if e["lauf"] != lauf:
                lauf = e["lauf"]
                dieser = lauf == buch.lauf
                zeilen.append(f'<li class="lauf-kopf" data-lauf="{"dieser" if dieser else "frueher"}">'
                              + (f"Dieser Lauf der Oberfläche, gestartet {esc(lauf_wort(lauf))}" if dieser else f"Früherer Lauf, gestartet {esc(lauf_wort(lauf))}") + "</li>")
            zeilen.append(_fehler_eintrag(e, e["lauf"] == buch.lauf))
        h.append('<ol class="fehlerliste" aria-label="Einträge, neueste zuerst">' + "".join(zeilen) + "</ol>"
                 '<p class="fehler-leer" data-fehler-nichts hidden>Kein Eintrag passt zu diesem Filter.</p>')
    ort = (f'Die Einträge liegen auch als Datei in der Ablage ausserhalb des Projektordners: <span class="mono">{esc(buch.datei)}</span> '
           f"(eine Zeile je Eintrag, nur für den eigenen Benutzer lesbar; wird sie grösser als {fehlerbuch.DATEI_GROESSE // (1024 * 1024)} MB, fallen die ältesten "
           "Einträge weg). So überstehen sie das Ende der Oberfläche."
           + (f' <b class="z-kritisch">Die Datei liess sich zuletzt nicht schreiben ({esc(buch.schreibfehler)}): Die Einträge stehen nur im Speicher.</b>' if buch.schreibfehler else ""))
    h.append('<details class="fehler-erklaerung"><summary>Was hier steht und was nicht</summary>'
             "<p>Die Oberfläche hält fest, was bei ihr schiefgeht:</p><ul>"
             + "".join(f"<li><b>{esc(name)}</b>: {esc(was)}</li>" for name, was in FEHLER_BEREICHE) + "</ul>"
             "<p>Jeder Eintrag wird bereinigt, bevor er irgendwo steht: Der Wert eines Schlüssels ist durch den Namen seiner Variablen ersetzt, "
             "Benutzerordner, Projektordner und Rechnername sind gekürzt, und was die PII-Prüfung erkennt, ist durch seine Art ersetzt. "
             "Eine Absage aus dem Akten-Eingang, vom lokalen Bildschirm für Klartext oder nach einem Fund der PII-Prüfung steht ohne ihren Wortlaut da: "
             "Er könnte einen Dateinamen oder eine Eingabe nennen.</p>"
             "<p>Nicht hier steht, was zu einem Fall gehört: Abfragen und Antworten der Quellen stehen in der Protokollkette des Falls, "
             "die Schritte einer Ermittlung im Sitzungsprotokoll. Das Fehlerprotokoll ist kein Beleg.</p>"
             f"<p>{ort}</p></details></div>")
    return "\n".join(h)


QUELLEN_VERWALTEN = ("<details class='hinweis-vertrauen quellen-hinweis'><summary><b>Schlüssel und Schalter.</b> Was hier eingetragen oder umgestellt wird, "
                     "steht in der Schlüsseldatei des Projekts.</summary>"
                     "<ul><li>Einen Schlüssel einfügen und speichern: Er geht von diesem Fenster an den lokalen Server und in die Schlüsseldatei, sonst nirgends hin. "
                     "Die Oberfläche zeigt ihn danach nie wieder an.</li>"
                     "<li>Ob ein Schlüssel gilt, zeigt die <b>Testabfrage</b>: eine harmlose Abfrage mit einem öffentlich bekannten Wert, über das Gateway und in der "
                     "Fallakte SELBSTTEST.</li>"
                     "<li><b>Ausschalten</b> nimmt eine Quelle aus dem Spiel, ohne ihren Schlüssel zu entfernen: Das Gateway fragt sie dann nicht, "
                     "und die Ermittlung erfährt, dass sie ausgeschaltet ist.</li>"
                     f"<li>{AB_WANN}</li></ul></details>")


def quellen_knoepfe(q: dict) -> str:
    """Was sich mit einer Quelle gleich tun lässt: testen, aus- oder einschalten."""
    test = next((x.test for x in daten.QUELLEN if x.name == q["name"]), None)
    knoepfe = ""
    if q["eingerichtet"] and test:
        knoepfe += formular("quelle_testen", "", "Testabfrage", verborgen={"quelle": q["name"]}, klasse="klein-form")
        if q["name"] == "urlscan.io":
            knoepfe += formular("quelle_testen", "", "Kontingent", verborgen={"quelle": q["name"], "kontingent": "1"}, klasse="klein-form")
    if q["schluessel"] and not q["gesetzt"] and not q["aus_umgebung"]:        # der Weg zum Feld für den Schlüssel, ohne erst aufklappen zu müssen
        knoepfe += '<button type="button" data-schluessel-oeffnen>Schlüssel eintragen</button>'
    if q["schaltbar"] and (q["aus"] or q["eingerichtet"]):      # ausschalten lässt sich, was bereit ist. Was ausgeschaltet ist, lässt sich einschalten
        knoepfe += (formular("quelle_schalten", "", "Einschalten", verborgen={"quelle": q["name"]}, danach="neu-laden", klasse="klein-form") if q["aus"] else
                    formular("quelle_schalten", "", "Ausschalten", verborgen={"quelle": q["name"], "aus": "1"}, danach="neu-laden", klasse="klein-form still"))
    return knoepfe


def quellen_verwalten(q: dict) -> str:
    """Der Schlüssel einer Quelle: eintragen, ersetzen, entfernen. Das Feld zeigt nie einen eingetragenen Wert."""
    if not q["schluessel"]:
        return ""
    if q["aus_umgebung"]:
        return (f'<p class="klein">Der Schlüssel <span class="mono">{esc(q["schluessel"])}</span> ist in der Umgebung des Terminals gesetzt, in dem die Oberfläche '
                "läuft. Er gilt vor der Schlüsseldatei und lässt sich hier nicht ändern.</p>")
    kennung = "schluessel-" + "".join(z if z.isalnum() else "-" for z in q["name"].lower())
    eingabe = (f'<div class="feld"><label for="{kennung}">{"Neuer Schlüssel" if q["gesetzt"] else "Schlüssel"} für {esc(q["name"])} '
               f'<span class="klein">(<span class="mono">{esc(q["schluessel"])}</span>)</span></label>'
               f'<input id="{kennung}" name="wert" type="password" required autocomplete="off" spellcheck="false" autocapitalize="off" data-1p-ignore data-lpignore="true" '
               'placeholder="hier einfügen"></div>')
    return ('<div class="quelle-verwalten">'
            + formular("quelle_schluessel", eingabe, "Schlüssel ersetzen" if q["gesetzt"] else "Schlüssel eintragen", verborgen={"quelle": q["name"]}, danach="neu-laden", klasse="schluessel-form")
            + (formular("quelle_schluessel", "", "Schlüssel entfernen", verborgen={"quelle": q["name"], "entfernen": "1"}, danach="neu-laden", klasse="klein-form still",
                        frage=f"Den Schlüssel für {q['name']} aus der Schlüsseldatei entfernen? " + (
                            "Die Quelle läuft danach ohne Schlüssel weiter, gedrosselt." if q["auch_ohne"] else "Die Quelle ist danach nicht mehr eingerichtet."), gefahr=True)
               if q["gesetzt"] else "")
            + '<p class="klein quelle-schluessel-hilfe">Nur den Schlüssel selbst einfügen, ohne Namen und Gleichheitszeichen. Die Oberfläche zeigt ihn nicht an, '
              "auch später nicht.</p></div>")


def quellen_seite(bedienung) -> str:
    """Die Seite «Quellen». Bedienbar lässt sich jede Quelle testen, aus- und einschalten, und ihr Schlüssel eintragen, ersetzen oder
    entfernen. Im Modus «nur lesen» zeigt die Seite den Stand. Von Schlüsseln nie den Wert, nur den Namen der Variablen."""
    from gateway import krypto_listen as kl
    try:
        liste = kl.laden()
        stand = (f"Stand {esc(liste.stand['stand'])} vom {esc(liste.stand['datum'])}, {daten.ds.zahl(liste.stand['eintraege'])} Einträge ({esc(liste.stand['umfang'])}), "
                 f"Prüfsumme <span class='mono'>{esc(liste.stand['sha256'])}</span>." + (f" {esc(liste.hinweis)}" if liste.hinweis else ""))
    except kl.Listenfehler as e:
        stand = f'<span class="marke z-kritisch">nicht verwendbar</span> {esc(e)}'
    if bedienung is None:
        seite = quellen_ansicht(hinweis="<p class='klein'>Schlüssel eintragen, Quellen ein- und ausschalten und Testabfragen gibt es, wenn die Oberfläche bedienbar "
                                        "gestartet ist. Am Terminal: <code>./setup.sh</code> und «Einstellungen ändern».</p>")
    else:
        seite = quellen_ansicht(quellen_knoepfe, quellen_verwalten, QUELLEN_VERWALTEN)
    return seite + f"<h2>Lokale Listen</h2><p>Etikettenliste für Krypto-Adressen: {stand}</p>"
