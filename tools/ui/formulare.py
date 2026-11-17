"""Die Bildschirme der Bedienung: Formulare, der lokale Bildschirm der Pseudonymisierung, Zurückführen, Stand der Ermittlung.

Formulare sind schlichtes HTML. Das Skript der Oberfläche schickt sie ab: `data-aktion` nennt die Funktion in
tools/ui/bedienung.py, die Felder werden ihre Angaben. Ohne das Geheimnis des Starts nimmt der Server nichts davon an.

Zwei Bildschirme zeigen echte Angaben: die Pseudonymisierung und das Zurückführen. Beide tragen das Band
«lokal, Klartext». Ihren Inhalt gibt der Server nur an den Browser, der das Geheimnis hat.
"""
from __future__ import annotations

from tools import _pseudo as ps
from tools._html import TYPEN as INDIKATOR_TYPEN
from tools.ui import daten
from tools.ui.seiten import esc, pfad, tabelle

KLARTEXT_BAND = ('<div class="klartext-band" role="note"><b>lokal, Klartext</b> Dieser Bildschirm zeigt echte Angaben. Sie bleiben auf diesem Rechner: '
                 "im Speicher der Oberfläche und in der Ablage ausserhalb des Projektordners. Kein Sprachmodell sieht sie, und sie stehen in keinem Protokoll.</div>")
NUR_LESEN = ('<p class="banner">Die Oberfläche läuft im Modus «nur lesen». Bedienen lässt sie sich, wenn der Sachbearbeiter sie selbst an einem Terminal '
             "startet (<code>python3 tools/oberflaeche.py</code>) und das Browserfenster benutzt, das sich dabei öffnet.</p>")
FREIGABE_NAME = {"aktiv": "Aktive Massnahmen", "darkweb": "Dark Web", "personenbezug": "Kontoabfragen"}


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


# --------------------------------------------------------------------------- Neuer Fall

def neu_seite(bedienung) -> str:
    kopf = "<h1>Neuer Fall</h1><p class='unter'>Dokument hineinziehen, Fall-ID und Titel eingeben, dann wählen, ob es schon geschwärzt ist.</p>"
    if bedienung is None:
        return kopf + NUR_LESEN
    stamm = (feld("fall", "Fall-ID", pflicht=True, platzhalter="2026-0412", hilfe="Buchstaben, Ziffern, Punkt, Strich, Unterstrich. Keine Namen.")
             + feld("titel", "Titel", pflicht=True, platzhalter="Phishing Kundenportal", hilfe="Ohne Personendaten: Der Titel steht in jedem Dokument der Akte.")
             + feld("kuerzel", "Kürzel des Sachbearbeiters") + feld("auftrag", "Auftrag in ein bis zwei Sätzen", art="mehrzeilig", breit=True, hilfe="Ohne Personendaten."))
    datei = ('<div class="ablegen" data-ablegen><label for="f-datei"><b>Dokument hierher ziehen</b> oder auswählen</label>'
             '<input id="f-datei" name="datei" type="file" accept=".txt,.md,.docx,.pdf" required><div class="klein" data-dateiname>noch kein Dokument gewählt</div></div>')
    weg = ('<fieldset class="weg"><legend>Was für ein Dokument ist es?</legend>'
           '<label><input type="radio" name="weg" value="geschwaerzt" checked> <b>Das Dokument ist schon geschwärzt.</b> Es geht direkt in die PII-Prüfung und in den Fall.</label>'
           '<label><input type="radio" name="weg" value="klartext"> <b>Das Dokument ist Klartext.</b> Zuerst folgt der lokale Bildschirm der Pseudonymisierung: '
           "Die Fundstellen sind im Text markiert, annehmen, verwerfen, ergänzen. Erst das Ergebnis geht in die PII-Prüfung und in den Fall.</label></fieldset>")
    return (kopf + formular("neu", f'{datei}<div class="felder-raster">{stamm}</div>{weg}', "Weiter", klasse="neu")
            + ablage_zeile(bedienung)
            + "<p class='klein'>Lehnt die PII-Prüfung ein Dokument ab, zeigt die Seite die Fundstellen maskiert und nimmt nichts auf.</p>")


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


def klartext_seite(pseudo, kennung: str, faelle: list[str]) -> str:
    v = pseudo.vorgang
    ergebnis = v.ergebnis()
    typen = [(t, t) for t in ps.TYPEN]
    platzhalter = {klar: p for p, klar in ergebnis.zuordnung}

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
        "pseudo_abschliessen",
        '<div class="felder-raster">' + feld("fall", "Fall-ID", pflicht=True, wert=faelle[0] if len(faelle) == 1 else "", hilfe="Neu oder ein bestehender Fall: Dann wird das Dokument nachgezogen.")
        + feld("titel", "Titel (nur bei einem neuen Fall)") + feld("kuerzel", "Kürzel des Sachbearbeiters") + feld("auftrag", "Auftrag", art="mehrzeilig", breit=True) + "</div>",
        "Ergebnis prüfen und in den Fall aufnehmen", verborgen={"vorgang": kennung}, danach="fall",
        frage=(f"{ergebnis.offen} Kandidaten sind noch offen und bleiben stehen. Trotzdem aufnehmen?" if ergebnis.offen else ""))
    verwerfen = formular("pseudo_verwerfen", "", "Abbrechen und Dokument aus dem Speicher entfernen", verborgen={"vorgang": kennung}, danach="#/neu", klasse="still")
    return (
        f"<h1>Pseudonymisieren · {esc(pseudo.name)}</h1>{KLARTEXT_BAND}"
        f'<p class="unter">{sum(ergebnis.ersetzt.values())} Fundstellen werden ersetzt, {len(ergebnis.zuordnung)} Platzhalter, {ergebnis.offen} Kandidaten offen. '
        "Technische Indikatoren bleiben stehen.</p>"
        '<div class="klartext"><div class="klartext-text"><h2>Dokument</h2><p class="legende"><mark class="fund s-ersetzen">wird ersetzt</mark> '
        '<mark class="fund s-offen">Kandidat, noch offen</mark> <mark class="fund s-lassen">bleibt stehen</mark> <span class="technik">technischer Indikator</span></p>'
        f'<pre class="dokument">{text_markiert(v)}</pre></div>'
        '<div class="klartext-rand">'
        + (f"<h2>Rückfragen ({len(v.fragen())})</h2><ul class='entscheide'>{fragen}</ul>" if fragen else "")
        + f"<h2>Kandidaten ({len(v.kandidaten())})</h2>"
        + (f"<p class='klein'>Vorschläge, die nie von selbst ersetzt werden. Was nicht angenommen wird, bleibt stehen.</p><ul class='entscheide'>{kandidaten}</ul>" if kandidaten
           else "<p class='klein'>Keine offenen Kandidaten.</p>")
        + "<h2>Ergänzen</h2><p class='klein'>Steht eine Angabe noch im Text, die niemand erkannt hat: hier eintragen. Sie wird im ganzen Dokument ersetzt.</p>" + ergaenzen
        + "<h2>Angaben und Platzhalter</h2>"
        + (tabelle(["Platzhalter", "Klartext", "Typ", "ersetzt", ""], zeilen, "Zuordnung", klasse="schlicht") if zeilen else "<p class='klein'>Noch keine Angabe erkannt.</p>")
        + "<h2>Abschliessen</h2><p class='klein'>Das Ergebnis geht in die PII-Prüfung. Besteht es, kommt es in den Fall, und die Zuordnungstabelle in die Ablage ausserhalb des Projekts.</p>"
        + abschluss + verwerfen + "</div></div>")


# --------------------------------------------------------------------------- Bedienen eines Falls

def ermittlung_feld(fall_id: str, stand: dict | None, verfuegbar: str = "") -> str:
    """Stand der gesteuerten Sitzung von Claude Code: wer woran arbeitet, Knöpfe, offene Rückfrage."""
    stand = stand or {"status": "aus"}
    status = stand.get("status")
    wort = {"aus": "nicht gestartet", "laeuft": "läuft", "wartet": "wartet auf eine Antwort", "angehalten": "angehalten", "beendet": "beendet", "fehler": "abgebrochen"}.get(status, status)
    farbe = {"laeuft": "gut", "wartet": "warnung", "fehler": "kritisch"}.get(status, "leer")
    h = [f'<div class="ermittlung" data-status="{esc(status)}"><p><span class="marke z-{farbe}">Ermittlung: {esc(wort)}</span>'
         + (f' <span class="klein">Sitzung <span class="mono">{esc(stand.get("sitzung") or "")}</span></span>' if stand.get("sitzung") else "")
         + (f' <span class="klein">Modell laut Claude Code: <span class="mono">{esc(stand.get("modell"))}</span></span>' if stand.get("modell") else "") + "</p>"]
    if verfuegbar:
        h.append(f'<p class="banner">{esc(verfuegbar)}</p>')
    if stand.get("meldung"):
        h.append(f'<p class="klein">{esc(stand["meldung"])}</p>')
    knoepfe = []
    if status in ("aus", "beendet", "fehler") and not verfuegbar:
        knoepfe.append(formular("ermittlung_starten", "", "Ermittlung starten" if status == "aus" else "Ermittlung neu starten", verborgen={"fall": fall_id}, danach="neu-laden",
                                klasse="klein-form", frage=f"Claude Code startet jetzt mit /ermittlung {fall_id}. Das verbraucht Kontingent des angemeldeten Kontos. Starten?"))
    if status in ("laeuft", "wartet"):
        knoepfe.append(formular("ermittlung_anhalten", "", "Anhalten", verborgen={"fall": fall_id}, danach="neu-laden", klasse="klein-form"))
    if status in ("angehalten", "beendet", "fehler") and stand.get("sitzung") and not verfuegbar:
        knoepfe.append(formular("ermittlung_fortsetzen", "", "Fortsetzen", verborgen={"fall": fall_id}, danach="neu-laden", klasse="klein-form"))
    h.append('<div class="knopfzeile">' + "".join(knoepfe) + "</div>")
    frage = stand.get("frage")
    if frage:
        h.append(
            '<div class="rueckfrage" role="alertdialog" aria-labelledby="rueckfrage-titel"><h3 id="rueckfrage-titel">Claude Code fragt nach</h3>'
            f'<p>Claude Code möchte <span class="mono">{esc(frage.get("werkzeug") or "")}</span> ausführen und braucht dafür eine Zustimmung.</p>'
            f'<pre class="rohtext">{esc(frage.get("eingabe") or "")}</pre>'
            + (f'<p class="klein">{esc(frage["hinweis"])}</p>' if frage.get("hinweis") else "")
            + '<div class="knopfzeile">'
            + formular("ermittlung_antworten", "", "Erlauben", verborgen={"fall": fall_id, "frage": frage.get("id") or "", "erlauben": "1"}, danach="neu-laden", klasse="klein-form")
            + formular("ermittlung_antworten", "", "Ablehnen", verborgen={"fall": fall_id, "frage": frage.get("id") or "", "erlauben": ""}, danach="neu-laden", klasse="klein-form")
            + "</div><p class='klein'>Die Antwort steht im Sitzungsprotokoll, mit Zeit und dem Vermerk, dass sie über die Oberfläche kam.</p></div>")
    wer = stand.get("wer") or []
    if wer:
        h.append("<h3>Wer arbeitet woran</h3>" + tabelle(["Analyst", "Stand", "Zuletzt", "Schritte"],
                 [[esc(w.get("name") or ""), esc(w.get("stand") or ""), f'<span class="mono">{esc(w.get("zuletzt") or "")}</span>', str(w.get("schritte") or 0)] for w in wer],
                 "Analysten", klasse="schlicht"))
    verlauf = stand.get("verlauf") or []
    if verlauf:
        h.append('<details class="technik"><summary>Verlauf der Sitzung</summary><ol class="verlauf">'
                 + "".join(f'<li><span class="klein">{esc(z.get("zeit") or "")}</span> <b>{esc(z.get("wer") or "")}</b> {esc(z.get("text") or "")}</li>' for z in verlauf[-60:]) + "</ol></details>")
    return "\n".join(h) + "</div>"


def bedienen_seite(fall: daten.Fall, bedienung, stand: dict | None, verfuegbar: str = "", abrechnung: str = "") -> str:
    kopf = "<h1>Bedienen</h1><p class='unter'>Ermittlung steuern, freigeben, Dokumente nachziehen und erzeugen. Jeder Schritt steht im Sitzungsprotokoll, mit dem Vermerk «über die Oberfläche».</p>"
    if bedienung is None:
        return kopf + NUR_LESEN
    fid = fall.id
    h = [kopf, "<h2>Ermittlung</h2>", f'<div id="ermittlung" data-fall="{esc(fid)}">{ermittlung_feld(fid, stand, verfuegbar)}</div>',
         "<p class='klein'>Die Oberfläche startet Claude Code im Projektordner mit <code>/ermittlung "
         f"{esc(fid)}</code>. Berechtigungen, das Gateway und die Protokoll-Hooks gelten wie am Terminal. Die Modelle bleiben, wie das Projekt sie festlegt.</p>"
         + (f"<p class='klein' id='abrechnung'>{esc(abrechnung)}</p>" if abrechnung else "")]
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
    datei = ('<div class="ablegen" data-ablegen><label for="f-datei"><b>Weiteres Dokument hierher ziehen</b> oder auswählen</label>'
             '<input id="f-datei" name="datei" type="file" accept=".txt,.md,.docx,.pdf" required><div class="klein" data-dateiname>noch kein Dokument gewählt</div></div>'
             '<fieldset class="weg"><legend>Was für ein Dokument ist es?</legend><label><input type="radio" name="weg" value="geschwaerzt" checked> schon geschwärzt</label>'
             '<label><input type="radio" name="weg" value="klartext"> Klartext: zuerst lokal pseudonymisieren</label></fieldset>')
    h.append("<h2>Weiteres Dokument</h2>" + formular("neu", datei, "Weiter", verborgen={"fall": fid, "bestehend": "1"}, klasse="neu"))
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
             + f'</div><p class="klein">Ansehen und holen: <a href="{pfad(fid, "dokumente")}">Dokumente</a>.</p>')
    h.append("<h2>Zurückführen</h2><p class='klein'>Der fertige Rapport mit echten Angaben, lokal, mit der Zuordnungstabelle. "
             f'<a href="{pfad(fid, "zurueck")}">Zum Bildschirm «Zurückführen»</a>.</p>')
    return "\n".join(h)


def zurueck_seite(fall: daten.Fall, bedienung) -> str:
    kopf = f"<h1>Zurückführen · {esc(fall.id)}</h1>"
    if bedienung is None:
        return kopf + NUR_LESEN
    tabelle_pfad = bedienung.zuordnung_pfad(fall.id)
    return (kopf + KLARTEXT_BAND
            + "<p>Ersetzt die Platzhalter im Abschlussrapport und in der Indikatorliste durch die echten Angaben aus der Zuordnungstabelle. Das Ergebnis liegt in der Ablage "
              "ausserhalb des Projektordners und erscheint nur auf diesem Bildschirm.</p>"
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
