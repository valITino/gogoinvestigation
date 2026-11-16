"""Die Ansichten der Oberfläche als HTML. Erzeugt auf dem Server, damit Oberfläche und Anhang für die Akte
(tools/anhang.py) dasselbe zeigen. Nur Standardbibliothek.

Zwei Regeln gelten für jede Zeile, die hier entsteht:
  - Alles, was aus einer Quelle stammt, geht durch esc() und steht als Text da. Nichts davon wird als HTML ausgeführt.
  - Adressen aus dem Fall (URLs, Domains, Onion-Adressen) werden nie zu einem Verweis. Verweise gibt es nur auf
    Ansichten der Oberfläche selbst (sie beginnen mit #/ oder /fall/).

Jeder gezeigte Wert trägt die Stelle, an der er in der Rohdatei steht (data-stelle). Die Selbsttests lesen das
Ergebnis und prüfen jeden Wert an dieser Stelle nach.
"""
from __future__ import annotations

import base64
import html
import json
import re
from urllib.parse import quote

from tools import rapport
from tools._html import STATUS, TYPEN
from tools.ui import blaetter, daten, darsteller as ds

EINBETTEN = False        # der Anhang für die Akte bettet Bilder ein, statt auf den Server zu verweisen
LANG = 220              # ab so vielen Zeichen steht ein Wert eingeklappt da
SEHR_LANG = 4000        # ab so vielen Zeichen zeigt die Oberfläche den Anfang und verweist auf die Rohdatei
BAUM_GRENZE = 6000      # so viele Angaben zeigt ein Baum höchstens, der Rest steht in der Rohdatei
ERGEBNIS = {"ok": ("●", "Treffer", "gut"), "kein_treffer": ("○", "kein Treffer", "neutral"), "fehler": ("✕", "Fehlschlag", "kritisch"),
            "abgelehnt": ("⊘", "abgelehnt", "warnung")}
ZELLE = {"Treffer": ("●", "gut"), "kein Treffer": ("○", "neutral"), "Fehlschlag": ("✕", "kritisch"), "abgelehnt": ("⊘", "warnung"),
         "nicht abgefragt": ("·", "leer"), "Quelle nicht eingerichtet": ("–", "leer"), "passt nicht": ("", "passt-nicht")}
ART = {"feststellung": "Feststellung", "bewertung": "Bewertung", "hypothese": "Hypothese"}
ART_ERKLAERT = {"feststellung": "Was eine Quelle unmittelbar zeigt.", "bewertung": "Was das Team aus Feststellungen schliesst.",
                "hypothese": "Eine mögliche Erklärung, die noch nicht belegt ist."}


def esc(wert: object) -> str:
    return html.escape(str(wert), quote=True)


def pfad(fall_id: str, *teile: str) -> str:
    return "#/fall/" + "/".join(quote(str(t), safe="") for t in (fall_id, *teile))


def zeit(utc: object) -> str:
    """Zeit in der Zeitzone des Arbeitsplatzes, der Originalwert steht als Hinweis dabei."""
    if not utc:
        return ""
    lokal, original = ds.zeit(utc)
    return f'<time title="Original: {esc(original)}">{esc(lokal)}</time>' if original else esc(lokal)


def hilfe(text: str) -> str:
    return f' <span class="hilfe" tabindex="0" title="{esc(text)}" aria-label="{esc(text)}">?</span>' if text else ""


def ergebnis_marke(e: dict) -> str:
    zeichen, wort, farbe = ERGEBNIS.get(e.get("ergebnis"), ("?", str(e.get("ergebnis") or "unbekannt"), "neutral"))
    cache = (e.get("antwort") or {}).get("aus_cache") or e.get("aus_cache")
    return (f'<span class="marke z-{farbe}">{zeichen} {esc(wort)}</span>'
            + (f' <span class="marke" title="Diese Antwort kam aus der Fallakte, nicht erneut von der Quelle.">aus dem Fall-Cache ({esc(cache)})</span>' if cache else ""))


# --------------------------------------------------------------------------- Werte

def bild_html(angabe: str, fall_id: str) -> str:
    """Ein Bild aus den Rohdaten dieses Falls, genannt als «faelle/<Fall>/rohdaten/<Datei>». Nur Rohdateien des gezeigten Falls,
    nie eine fremde Adresse und nie die Akte eines anderen Falls."""
    m = re.fullmatch(r"faelle/([A-Za-z0-9][A-Za-z0-9._-]{2,63})/(rohdaten/[A-Za-z0-9._/-]+\.(?:png|jpe?g|gif|webp))", angabe)
    if not m or ".." in angabe or m.group(1) != fall_id:
        return ""
    if EINBETTEN:
        try:
            roh = daten.Fall(m.group(1)).rohdatei(m.group(2))
            if roh.form != "bild":
                return ""
            quelle = f"data:{daten.BILD[roh.pfad.suffix.lower()]};base64,{base64.b64encode(roh.pfad.read_bytes()).decode()}"
        except daten.NichtGefunden:
            return ""
    else:
        quelle = f"/fall/{quote(m.group(1))}/datei/{quote(m.group(2))}"
    return (f'<figure><img class="rohbild" src="{esc(quelle)}" alt="Bildschirmfoto aus den Rohdaten" loading="lazy">'
            "<figcaption>Bild aus den Rohdaten des Falls. Die Seite selbst wurde dafür nicht aufgerufen.</figcaption></figure>")


def wert_html(a: ds.Angabe, fall_id: str = "") -> str:
    """Ein Wert mit seiner Stelle in der Rohdatei. Lange Werte stehen eingeklappt da, der volle Wert ist einen Klick entfernt."""
    if a.art == "schluessel":       # der Name einer Zeile (zum Beispiel das Sicherheitsprodukt): ein Schlüssel der Rohantwort, kein Wert
        return f'<span class="k">{esc(a.anzeige)}</span>'
    stelle = f' data-stelle="{esc(a.stelle)}"' if a.stelle or a.stelle == "" else ""
    # Nennt die Antwort die Einheit selbst (BTC, USDC), steht sie als eigener Wert mit eigener Stelle daneben
    aus_antwort = f' <span class="w einheit" data-stelle="{esc(a.einheit_stelle)}">{esc(a.einheit)}</span>' if a.einheit_stelle else ""
    if a.schluessel == "seite.bildschirmfoto" and isinstance(a.wert, str):
        return f'<span class="w"{stelle}>{esc(a.wert)}</span>' + bild_html(a.wert, fall_id)
    if not isinstance(a.wert, str):
        roh = f" data-roh='{esc(json.dumps(a.wert, ensure_ascii=False))}'"
        original = f' <span class="orig">(Original: {esc(a.original)})</span>' if a.original else ""
        klasse = "w leer" if a.wert is None or a.wert == [] or a.wert == {} else "w"
        return f'<span class="{klasse}"{stelle}{roh}>{esc(a.anzeige)}</span>{original}{aus_antwort}'
    text = a.wert
    if a.original:      # eine Zeit als Text: lokale Zeit zeigen, Original daneben
        return f"<span class=\"w\"{stelle} data-roh='{esc(json.dumps(text, ensure_ascii=False))}'>{esc(a.anzeige)}</span> <span class=\"orig\">(Original: {esc(a.original)})</span>"
    einheit = aus_antwort or (f' <span class="einheit">{esc(a.einheit)}</span>' if a.einheit and text else "")
    if len(text) > SEHR_LANG:
        return (f'<details class="lang"><summary>{esc(text[:LANG])}… <span class="klein">({ds.zahl(len(text))} Zeichen)</span></summary>'
                f'<span class="w"{stelle} data-gekuerzt="{len(text)}">{esc(text[:SEHR_LANG])}</span>'
                f'<span class="klein"> … der Rest steht in der Rohdatei.</span></details>')
    if len(text) > LANG:
        return f'<details class="lang"><summary>{esc(text[:LANG])}…</summary><span class="w"{stelle}>{esc(text)}</span></details>'
    return f'<span class="w{" leer" if text == "" else ""}"{stelle}>{esc(text) if text else "leer"}</span>{einheit}'


def tabelle(kopf: list[str], zeilen: list[list[str]], name: str = "", klasse: str = "daten") -> str:
    """Eine Tabelle. Die Oberfläche macht jede Tabelle der Klasse «daten» sortierbar, filterbar und als CSV ausgebbar."""
    if not zeilen:
        return '<p class="klein">keine Einträge</p>'
    return (f'<div class="tabelle-breit"><table class="{klasse}" data-name="{esc(name)}"><thead><tr>' + "".join(f"<th>{k}</th>" for k in kopf)
            + "</tr></thead><tbody>" + "".join("<tr>" + "".join(f"<td>{z}</td>" for z in zeile) + "</tr>" for zeile in zeilen) + "</tbody></table></div>")


def liste_html(liste: ds.Liste, name: str = "", fall_id: str = "") -> str:
    zeilen = [[wert_html(z, fall_id) if z is not None else '<span class="klein">–</span>' for z in zeile] for zeile in liste.zeilen]
    return tabelle([esc(s) for s in liste.spalten], zeilen, name or liste.name)


def baum_html(knoten: object, zaehler: list[int], tiefe: int = 0) -> str:
    """Ein Baum zum Aufklappen. Blätter sind Werte mit ihrer Stelle."""
    if knoten is ds.BAUM_LEER:
        return ""
    if isinstance(knoten, tuple):
        stelle, wert = knoten
        zaehler[0] += 1
        if zaehler[0] > BAUM_GRENZE:
            return ""
        return wert_html(ds.Angabe("", wert, ds.anzeigen(wert, "text")[0] if not isinstance(wert, (dict, list)) or wert else "keine Einträge", stelle))
    paare = list(knoten.items()) if isinstance(knoten, dict) else list(knoten)
    teile = []
    for schluessel, kind in paare:
        if zaehler[0] > BAUM_GRENZE:
            break
        name = f'<span class="k">{esc(schluessel)}</span>'
        if isinstance(kind, tuple):
            teile.append(f"<li>{name}: {baum_html(kind, zaehler, tiefe + 1)}</li>")
        else:
            n = len(kind)
            teile.append(f'<li><details{" open" if tiefe < 1 and n <= 12 else ""}><summary>{name} <span class="klein">({n})</span></summary>{baum_html(kind, zaehler, tiefe + 1)}</details></li>')
    return f'<ul class="baum">{"".join(teile)}</ul>'


def blatt_html(blatt: ds.Blatt, roh: daten.Rohdatei | None, fall_id: str, beleg: str) -> str:
    """Was die Quelle sagt, in den Abschnitten des Darstellers, danach alles Übrige als Baum."""
    h: list[str] = []
    if roh is None:
        return '<p class="klein">Zu diesem Eintrag gibt es keine Rohdatei.</p>'
    if roh.form == "fehlt":
        return '<p class="banner">Die Rohdatei fehlt in der Fallakte.</p>'
    roh_ansicht = f'<a href="{pfad(fall_id, "roh", beleg)}">Rohdatei ansehen</a>'
    if roh.zu_gross:
        return (f'<p>Die Rohdatei ist {esc(ds.groesse(roh.bytes))} gross. Die Oberfläche ordnet Dateien bis {esc(ds.groesse(daten.GROSS))} zu. '
                f'Der Inhalt steht vollständig in der Rohdatei: {roh_ansicht}.</p>')
    if blatt.form != "json":
        was = {"text": "Text", "csv": "eine Tabelle (CSV)", "bild": "ein Bild"}.get(roh.form, "kein JSON")
        return f"<p>Die Antwort ist {was}. Sie steht unverändert in der Rohdatei: {roh_ansicht}.</p>" + rohdatei_inhalt(roh, fall_id, kurz=True)
    for titel, teile in blatt.abschnitte:
        h.append(f"<h3>{esc(titel)}</h3>")
        felder = [t for t in teile if isinstance(t, ds.Angabe)]
        if felder:
            h.append('<dl class="felder">' + "".join(f"<dt>{esc(a.name)}{hilfe(a.hilfe)}</dt><dd>{wert_html(a, fall_id)}</dd>" for a in felder) + "</dl>")
        for t in teile:
            if isinstance(t, ds.Liste):
                h.append(f"<h4>{esc(t.name)}{hilfe(t.hilfe)} <span class='klein'>({len(t.zeilen)})</span></h4>" + liste_html(t, f"{beleg} {t.name}", fall_id))
    if not blatt.abschnitte and blatt.eigen:
        h.append('<p class="klein">Die Antwort enthält keines der Felder, die der Darsteller kennt. Alles steht unter «Weitere Angaben der Quelle».</p>')
    zaehler = [0]
    rest = baum_html(ds.baum(roh.inhalt, {z for z, _ in blatt.weitere}), zaehler) if blatt.weitere else ""
    h.append(f'<h3>Weitere Angaben der Quelle</h3><p class="klein" data-gesamt="{blatt.gesamt}" data-zugeordnet="{blatt.zugeordnet}">'
             f"Die Rohantwort enthält {ds.zahl(blatt.gesamt)} Angaben. {ds.zahl(blatt.zugeordnet)} sind oben zugeordnet, "
             f"{ds.zahl(len(blatt.weitere))} stehen hier." + ("" if blatt.eigen else " Für dieses Werkzeug gibt es keinen eigenen Darsteller: Die ganze Antwort steht hier.") + "</p>")
    if rest:
        h.append(rest)
        if zaehler[0] > BAUM_GRENZE:
            h.append(f'<p class="klein">Gezeigt sind die ersten {ds.zahl(BAUM_GRENZE)} Angaben. Alle stehen in der Rohdatei: {roh_ansicht}.</p>')
    else:
        h.append('<p class="klein">Keine: Jede Angabe der Rohantwort ist oben zugeordnet.</p>')
    return "\n".join(h)


def rohdatei_inhalt(roh: daten.Rohdatei, fall_id: str, kurz: bool = False) -> str:
    """Die Rohdatei selbst: JSON als Baum, HTML und DOM als Text, Bilder als Bild, CSV als Tabelle."""
    adresse = f"/fall/{quote(fall_id)}/datei/{quote(roh.name)}"
    if roh.form == "bild":
        return f'<figure><img class="rohbild" src="{esc(adresse)}" alt="Bild aus den Rohdaten: {esc(roh.name)}"><figcaption>{esc(roh.name)}</figcaption></figure>'
    if roh.form == "json" and not kurz:
        zaehler = [0]
        aus = baum_html(ds.baum(roh.inhalt), zaehler)
        return aus + (f'<p class="klein">Gezeigt sind die ersten {ds.zahl(BAUM_GRENZE)} Angaben. Die ganze Datei als Text: '
                      f'<a href="{esc(adresse)}" target="_blank" rel="noopener">öffnen</a>.</p>' if zaehler[0] > BAUM_GRENZE else "")
    if roh.form == "csv":
        zeilen = daten.csv_lesen(str(roh.inhalt), 60 if kurz else 2000)
        if zeilen:
            breite = max(len(z) for z in zeilen)
            kopf = [esc(k) for k in zeilen[0]] + [""] * (breite - len(zeilen[0]))
            return tabelle(kopf, [[esc(z) for z in zeile] + [""] * (breite - len(zeile)) for zeile in zeilen[1:]], roh.name)
    text = str(roh.inhalt or "")
    grenze = 3000 if kurz else 400_000
    hinweis = (f'<p class="klein">Gezeigt ist der Anfang. Die ganze Datei als Text: <a href="{esc(adresse)}" target="_blank" rel="noopener">öffnen</a>.</p>'
               if len(text) > grenze or roh.zu_gross else "")
    return f'<pre class="rohtext">{esc(text[:grenze])}</pre>{hinweis}'


# --------------------------------------------------------------------------- Kopf des Falls

def kopf(fall: daten.Fall) -> str:
    d = fall.daten
    freigaben = "".join(
        f'<span class="marke z-{"gut" if f["erteilt"] else "leer"}" title="{esc(daten.rapport.FREIGABE_TEXT[f["name"]])}">'
        f'{"✓" if f["erteilt"] else "○"} {esc(f["name"])}{": erteilt durch " + esc(f["durch"]) if f["erteilt"] else ": nicht erteilt"}</span>' for f in fall.freigaben())
    schritte = "".join(
        f'<li class="{"erledigt" if s["erledigt"] else "uebersprungen" if s["uebersprungen"] else "offen"}{" aktuell" if s["aktuell"] else ""}" '
        f'title="{esc(s["woran"])}"{" aria-current=step" if s["aktuell"] else ""}><span class="nr">{i + 1}</span> {esc(s["name"])}'
        f'<span class="klein">{"erledigt" if s["erledigt"] else "nicht abgelegt" if s["uebersprungen"] else "offen"}</span></li>'
        for i, s in enumerate(fall.schritte()))
    muster = '<span class="marke z-warnung">MUSTER: erfundener Fall</span> ' if d.get("muster") else ""
    return (f'<div class="fallkopf"><div><span class="fallid">{esc(fall.id)}</span> {muster}<span class="falltitel">{esc(d.get("titel") or "")}</span></div>'
            f'<div class="freigaben" aria-label="Freigaben">{freigaben}</div></div><ol class="schritte" aria-label="Stand der Ermittlung">{schritte}</ol>')


# --------------------------------------------------------------------------- Ansichten

def faelle_seite() -> str:
    zeilen = [[f'<a href="{pfad(f["id"])}">{esc(f["id"])}</a>' + (' <span class="marke z-warnung">Muster</span>' if f["muster"] else ""), esc(f["titel"]),
               zeit(f["eroeffnet"]), esc(f["sachbearbeiter"]), esc(f["klassifizierung"])] for f in daten.faelle()]
    return ("<h1>Fälle</h1><p class='unter'>Alle Fallakten in diesem Arbeitsplatz. Die Oberfläche liest sie nur.</p>"
            + (tabelle(["Fall", "Titel", "Eröffnet", "Sachbearbeitung", "Klassifizierung"], zeilen, "Fälle") if zeilen else
               "<p>Noch kein Fall angelegt. Ein Fall entsteht mit <code>python3 tools/fall.py neu &lt;Fall-ID&gt; --titel \"…\" --rapport &lt;Dokument&gt;</code>.</p>"))


def quellen_seite() -> str:
    zeilen = []
    for q in daten.quellen():
        farbe = "gut" if q["stand"] in ("eingerichtet", "kein Schlüssel nötig") else "warnung" if "gedrosselt" in q["stand"] else "leer"
        zeilen.append([esc(q["name"]), esc(q["zweck"]), f'<span class="marke z-{farbe}">{esc(q["stand"])}</span>',
                       esc(", ".join(q["werkzeuge"])) or '<span class="klein">über ein gebündeltes Werkzeug</span>',
                       esc(", ".join(f"{w}: Freigabe {f}" for w, f in q["freigabe"].items())), esc(q["hinweis"])])
    return ("<h1>Quellen</h1><p class='unter'>Was das Gateway befragen kann und ob die Quelle an diesem Arbeitsplatz eingerichtet ist. "
            "Von Schlüsseln zeigt die Oberfläche nur, ob einer gesetzt ist.</p>"
            + tabelle(["Quelle", "Wozu", "Stand", "Werkzeuge", "Freigabe nötig", "Hinweis"], zeilen, "Quellen"))


def uebersicht(fall: daten.Fall) -> str:
    k = fall.kennzahlen()
    r, p = k["rapport"], k["protokoll"]
    h = [f"<h1>Fallübersicht</h1><p class='unter'>{esc(fall.daten.get('auftrag') or 'Kein Auftrag in der Fallakte vermerkt.')}</p>"]
    kacheln = [(r["indikatoren"], "Indikatoren", f"{r['bewertung']['boesartig']} bösartig, {r['bewertung']['verdaechtig']} verdächtig"),
               (len(r["abfragen"]), "Abfragen", f"{r['ohne_treffer']} ohne Treffer, {r['fehlgeschlagen']} fehlgeschlagen" + (f", {r['abgelehnt']} abgelehnt" if r["abgelehnt"] else "")),
               (len(r["quellen"]), "Quellen genutzt", f"{len(r['auswertungen'])} Auswertungen daraus" if r["auswertungen"] else ""),
               (r["befunde"], "Befunde", f"{r['gegengeprueft']} gegengeprüft"),
               (p["cache"], "aus dem Fall-Cache", "Antwort kam aus der Fallakte"), (p["aktiv"], "aktive Massnahmen", "Ziel wurde kontaktiert")]
    h.append('<div class="kacheln">' + "".join(f'<div class="kachel"><div class="wert">{esc(w)}</div><div class="name">{esc(n)}</div><div class="zusatz">{esc(z)}</div></div>'
                                              for w, n, z in kacheln) + "</div>")
    h.append('<p class="klein">Dieselben Zahlen wie im Abschlussrapport (Abschnitt 3) und im Ermittlungsprotokoll: Sie kommen aus denselben Funktionen.</p>')
    h.append("<h2>Stand der Schritte</h2>" + tabelle(["Schritt", "Stand", "Woran die Oberfläche das erkennt"],
                                                     [[esc(s["name"]), "erledigt" if s["erledigt"] else "nicht abgelegt" if s["uebersprungen"] else "offen", esc(s["woran"])] for s in fall.schritte()],
                                                     "Schritte", klasse="schlicht"))
    offen = offene_punkte(fall)
    h.append("<h2>Offene Punkte</h2>" + ("<ul>" + "".join(f"<li>{o}</li>" for o in offen) + "</ul>" if offen else '<p class="klein">Keine.</p>'))
    a = fall.abdeckung()
    h.append("<h2>Abdeckung: Indikator × Quelle</h2>")
    if a["zeilen"]:
        kopf_ = ["Indikator", "Typ"] + [f'<span class="hoch">{esc(s)}</span>' for s in a["spalten"]]
        zeilen = []
        for z in a["zeilen"]:
            i = z["indikator"]
            zeile = [f'<a href="{pfad(fall.id, "indikator", i.get("id", ""))}">{esc(i.get("id", ""))}</a> <span class="mono">{esc(rapport.kuerzen(i.get("wert", ""), 34))}</span>',
                     esc(TYPEN.get(i.get("typ"), ("?",))[0])]
            for spalte, c in zip(a["spalten"], z["zellen"]):
                zeichen, farbe = ZELLE.get(c["zustand"], ("?", "neutral"))
                titel = f"{spalte}: {c['zustand']}" + (f", {c['anzahl']} Abfrage(n)" if c.get("anzahl") else "")
                inhalt = f'<span class="zelle z-{farbe}" title="{esc(titel)}" aria-label="{esc(titel)}">{zeichen}<span class="nur-text">{esc(c["zustand"])}</span></span>'
                zeile.append(f'<a href="{pfad(fall.id, "beleg", c["beleg"])}">{inhalt}</a>' if c.get("beleg") else inhalt)
            zeilen.append(zeile)
        h.append(tabelle(kopf_, zeilen, "Abdeckung", klasse="daten abdeckung"))
        h.append('<p class="legende">' + "".join(f'<span><span class="zelle z-{f}">{z or "&nbsp;"}</span> {esc(n)}</span>' for n, (z, f) in ZELLE.items())
                 + "</p><p class='klein'>Ein Klick auf eine Zelle führt zum Beleg. «Passt nicht» heisst: Die Quelle sagt zu diesem Typ von Indikator nichts.</p>")
    else:
        h.append('<p class="klein">Noch keine Indikatoren.</p>')
    return "\n".join(h)


def offene_punkte(fall: daten.Fall) -> list[str]:
    punkte: list[str] = []
    kette = fall.kette()
    if not kette["ok"]:
        punkte.append(f'<b>Die Protokollkette ist nicht unversehrt.</b> {esc(kette["fehler"][0])}')
    b = fall.befunde()
    if b is None:
        punkte.append("befunde.json fehlt noch. Die Befunde schreibt der Rapportführer.")
    elif b.get("_fehler"):
        punkte.append(esc(b["_fehler"]))
    else:
        maengel, hinweise = rapport.pruefen(b, {e["id"]: e for e in fall.eintraege()}, True, fall.pfad)
        punkte += [f"Mangel in befunde.json: {esc(m)}" for m in maengel] + [f"Hinweis zu befunde.json: {esc(x)}" for x in hinweise]
        ohne = [f.get("id", "?") for f in b.get("befunde") or [] if not f.get("gegenpruefung")]
        if ohne:
            punkte.append(f"{len(ohne)} Befund(e) ohne Gegenprüfung: {esc(', '.join(ohne))}")
    for e in fall.eintraege():
        if e.get("ergebnis") in ("fehler", "abgelehnt"):
            punkte.append(f'<a href="{pfad(fall.id, "beleg", e["id"])}">{esc(e["id"])}</a> {esc(e.get("quelle") or "")}: '
                          f'{"abgelehnt" if e.get("ergebnis") == "abgelehnt" else "fehlgeschlagen"} ({esc(e.get("fehler") or "ohne Meldung")})')
    for d in fall.dokumente():
        if d["html"] and d["aktuell"] is False:
            punkte.append(f'{esc(d["titel"])}: {esc(d["vermerk"])}')
    return punkte


def indikatoren_seite(fall: daten.Fall) -> str:
    zeilen = []
    for i in fall.indikatoren():
        name, _, zeichen, _ = STATUS.get(i.get("bewertung"), STATUS["unbekannt"])
        zeilen.append([f'<a href="{pfad(fall.id, "indikator", i.get("id", ""))}">{esc(i.get("id", ""))}</a>', esc(TYPEN.get(i.get("typ"), ("?",))[0]),
                       f'<span class="mono">{esc(i.get("wert", ""))}</span>', esc(i.get("rolle") or ""), esc(i.get("herkunft") or ""),
                       f'<span class="marke z-{i.get("bewertung") or "unbekannt"}">{esc(zeichen)} {esc(name)}</span>', str(len(fall.zu_indikator(i)))])
    return ("<h1>Indikatoren</h1><p class='unter'>Jede Zeile führt zum Datenblatt: alles, was irgendeine Quelle zu diesem Indikator geliefert hat. "
            "Die Werte stehen als Text da und sind nie anklickbar.</p>"
            + (tabelle(["Nr.", "Typ", "Wert", "Rolle", "Herkunft", "Bewertung des Teams", "Protokolleinträge"], zeilen, "Indikatoren") if zeilen else '<p class="klein">Noch keine Indikatoren.</p>'))


def befund_karte(f: dict, fall_id: str) -> str:
    art = f.get("art") or "?"
    belege = " ".join(f'<a class="beleg" href="{pfad(fall_id, "beleg", b)}">{esc(b)}</a>' for b in f.get("belege") or []) or "–"
    return (f'<div class="karte art-{esc(art)}"><h4>{esc(f.get("id", ""))} · {esc(f.get("titel", ""))}</h4>'
            f'<div class="zeile"><span class="marke art" title="{esc(ART_ERKLAERT.get(art, ""))}">{esc(ART.get(art, art))}</span>'
            f'<span class="marke">Sicherheit {esc(rapport.SICHERHEIT.get(f.get("sicherheit"), "?"))}</span></div>'
            f'<p>{esc(f.get("text") or "")}</p><p class="klein">Belege: {belege} · <a href="{pfad(fall_id, "rapport", f.get("id", ""))}">im Rapport</a></p></div>')


def datenblatt(fall: daten.Fall, kennung: str, fuer_akte: bool = False) -> str:
    """Das Datenblatt eines Indikators. `fuer_akte`: ohne Verweise in die Oberfläche, für den Anhang."""
    d = fall.datenblatt(kennung)
    i = d["indikator"]
    name, _, zeichen, _ = STATUS.get(i.get("bewertung"), STATUS["unbekannt"])

    def beleg_verweis(b: str) -> str:
        return f'<span class="beleg">{esc(b)}</span>' if fuer_akte else f'<a class="beleg" href="{pfad(fall.id, "beleg", b)}">{esc(b)}</a>'

    h = [f'<h1 id="{esc(kennung)}">{esc(kennung)} · <span class="mono">{esc(i.get("wert", ""))}</span></h1>',
         f'<p class="unter">{esc(TYPEN.get(i.get("typ"), ("Sonstiges",))[0])} · {esc(i.get("rolle") or "ohne Rolle")} · Herkunft: {esc(i.get("herkunft") or "–")}</p>',
         f'<p><span class="marke art" title="{esc(ART_ERKLAERT["bewertung"])}">Bewertung des Teams</span> <span class="marke z-{esc(i.get("bewertung") or "unbekannt")}">{esc(zeichen)} {esc(name)}</span> '
         '<span class="klein">Alles darunter sind Angaben der Quellen. Die Oberfläche deutet sie nicht.</span></p>']
    gefragt = ", ".join(f"{esc(b['quelle'])} ({esc(daten.ZUSTAND.get(b['ergebnis'], b['ergebnis']))}, {esc(b['beleg'])})" for b in d["befragt"] if b["art"] != "auswertung")
    for titel, felder in d["abschnitte"]:
        h.append(f"<h2>{esc(titel)}</h2>")
        einzel = [f for f in felder if any(isinstance(w.angabe, ds.Angabe) for w in f.werte)]
        listen = [(f, w) for f in felder for w in f.werte if isinstance(w.angabe, ds.Liste)]
        if not einzel and not listen:
            h.append(f'<p class="keine">keine Angabe. <span class="klein">Gefragt wurden: {gefragt or "keine Quelle"}.</span></p>')
            continue
        if einzel:
            zeilen = []
            for f in einzel:
                werte = [w for w in f.werte if isinstance(w.angabe, ds.Angabe)]
                for nr, w in enumerate(werte):
                    marke = ' <span class="marke z-warnung" title="Die Quellen nennen für dieses Feld Verschiedenes.">Widerspruch</span>' if f.widerspruch and nr == 0 else ""
                    zeilen.append([(esc(f.name) + hilfe(w.angabe.hilfe) + marke) if nr == 0 else '<span class="klein">〃</span>',
                                   f'<span data-beleg="{esc(w.beleg)}">{wert_html(w.angabe, fall.id)}</span>', esc(w.quelle),
                                   beleg_verweis(w.beleg), zeit(w.zeit), f'<span class="mono klein">{esc(w.angabe.stelle)}</span>'])
            h.append(tabelle(["Feld", "Wert", "Quelle", "Beleg", "Abfragezeit", "Stelle in der Rohdatei"], zeilen, f"{kennung} {titel}", klasse="daten felder-tab"))
        for f, w in listen:
            h.append(f"<h3>{esc(f.name)}{hilfe(w.angabe.hilfe)} <span class='klein'>{esc(w.quelle)} · {beleg_verweis(w.beleg)} · {zeit(w.zeit)} · {len(w.angabe.zeilen)} Zeilen</span></h3>"
                     + f'<div data-beleg="{esc(w.beleg)}">' + liste_html(w.angabe, f"{kennung} {f.name} {w.quelle}", fall.id) + "</div>")
    h.append("<h2>Befragte Quellen</h2>")
    zeiten = {e["id"]: e.get("zeit_utc") for e in fall.eintraege()}

    def aus_cache(b: dict) -> str:
        if not b["aus_cache"]:
            return ""
        return f' <span class="marke z-neutral" title="Die Quelle wurde nicht erneut gefragt.">aus dem Fall-Cache</span> <span class="klein">ursprünglich {beleg_verweis(b["aus_cache"])} vom {zeit(zeiten.get(b["aus_cache"]))}</span>'
    h.append(tabelle(["Beleg", "Quelle", "Werkzeug", "Ziel", "Ergebnis", "Abfragezeit"],
                     [[beleg_verweis(b["beleg"]), esc(b["quelle"] or ""), f'<span class="mono">{esc(b["werkzeug"] or "")}</span>', f'<span class="mono">{esc(b["ziel"] or "")}</span>',
                       ergebnis_marke(b) + aus_cache(b) + (f' <span class="klein">{esc(b["fehler"])}</span>' if b["fehler"] else ""), zeit(b["zeit"])] for b in d["befragt"]],
                     f"{kennung} Befragte Quellen") if d["befragt"] else '<p class="keine">Zu diesem Indikator wurde keine Quelle befragt.</p>')
    h.append("<h2>Befunde, die den Indikator nennen</h2>")
    h.append("".join(befund_karte(f, fall.id) if not fuer_akte else
                     f'<div class="karte art-{esc(f.get("art") or "")}"><h4>{esc(f.get("id", ""))} · {esc(f.get("titel", ""))}</h4><div class="zeile"><span class="marke art">{esc(ART.get(f.get("art"), "?"))}</span>'
                     f'<span class="marke">Sicherheit {esc(rapport.SICHERHEIT.get(f.get("sicherheit"), "?"))}</span></div><p>{esc(f.get("text") or "")}</p>'
                     f'<p class="klein">Belege: {esc(" ".join(f.get("belege") or []) or "–")}</p></div>' for f in d["befunde"])
             or '<p class="keine">Kein Befund nennt diesen Indikator.</p>')
    if d["beziehungen"]:
        werte = {x.get("id"): x.get("wert") for x in fall.indikatoren()}
        h.append("<h2>Beziehungen laut Team</h2>" + tabelle(
            ["Von", "Beziehung", "Nach", "Sicherheit", "Belege"],
            [[f'{esc(r["von"])} <span class="mono">{esc(rapport.kuerzen(werte.get(r["von"], ""), 40))}</span>', esc(r.get("art", "")),
              f'{esc(r["nach"])} <span class="mono">{esc(rapport.kuerzen(werte.get(r["nach"], ""), 40))}</span>', esc(rapport.SICHERHEIT.get(r.get("sicherheit"), "?")),
              " ".join(beleg_verweis(b) for b in r.get("belege") or []) or "ohne Beleg (Hypothese)"] for r in d["beziehungen"]], f"{kennung} Beziehungen"))
    return "\n".join(h)


def eintrag_kopf(fall: daten.Fall, e: dict, wer: str = "") -> str:
    antwort, anfrage = e.get("antwort") or {}, e.get("anfrage") or {}
    art = {"aktiv": "aktiv: Das Ziel wurde aufgerufen", "auswertung": "Auswertung: vom Gateway aus mehreren Abfragen errechnet", "lokal": "lokale Liste: keine Anfrage nach aussen",
           "tor": "über Tor (Robin)", "von_hand": "von Hand erfasst", "extern": "weiteres Werkzeug"}.get(e.get("art"), "passiv: Das Ziel wurde nicht kontaktiert")
    felder = [("Quelle", esc(e.get("quelle") or "")), ("Werkzeug", f'<span class="mono">{esc(e.get("werkzeug") or "")}</span>'),
              ("Ziel", f'<span class="mono">{esc(e.get("ziel") or "")}</span>'), ("Abfragezeit", zeit(e.get("zeit_utc"))), ("Ergebnis", ergebnis_marke(e)), ("Art", esc(art)),
              ("Durch", esc(wer or e.get("agent") or "–"))]
    h = ['<div class="kopf">' + "".join(f"<div><b>{n}</b>{w}</div>" for n, w in felder) + "</div>", f"<p><b>Zweck:</b> {esc(e.get('zweck') or '–')}</p>"]
    if antwort.get("aus_cache"):
        ursprung = next((x for x in fall.eintraege() if x.get("id") == antwort["aus_cache"]), {})
        h.append(f'<p class="banner">Diese Antwort kam aus dem Fall-Cache. Ursprüngliche Abfrage: <a href="{pfad(fall.id, "beleg", antwort["aus_cache"])}">{esc(antwort["aus_cache"])}</a> '
                 f"vom {zeit(ursprung.get('zeit_utc'))}. Die Quelle wurde beim zweiten Mal nicht erneut gefragt.</p>")
    if e.get("fehler"):
        h.append(f'<p class="banner">Meldung: {esc(e["fehler"])}</p>')
    if e.get("grundlage"):
        h.append("<p><b>Beruht auf:</b> " + " ".join(f'<a class="beleg" href="{pfad(fall.id, "beleg", p)}">{esc(p)}</a>' for p in e["grundlage"][:200])
                 + (f" und {len(e['grundlage']) - 200} weiteren" if len(e["grundlage"]) > 200 else "") + (f" <span class='klein'>Tatsachen aus: {esc(', '.join(e.get('quellen') or []))}</span>" if e.get("quellen") else "") + "</p>")
    teil = next((x["id"] for x in fall.eintraege() if e.get("id") in (x.get("grundlage") or [])), None)
    if teil:
        h.append(f'<p class="klein">Teil der Auswertung <a class="beleg" href="{pfad(fall.id, "beleg", teil)}">{esc(teil)}</a>.</p>')
    technik = [("Anfrage", f'<span class="mono">{esc(anfrage.get("methode") or "")} {esc(anfrage.get("url") or "")}</span>' if anfrage else "keine Anfrage nach aussen"),
               ("HTTP-Status", esc(antwort.get("status") if antwort.get("status") is not None else "–")), ("Grösse", esc(ds.groesse(antwort.get("bytes"))) if antwort.get("bytes") is not None else "–"),
               ("Dauer", f'{esc(antwort.get("dauer_ms"))} ms' if antwort.get("dauer_ms") is not None else "–"), ("Über Proxy", "ja" if anfrage.get("proxy") else "nein"),
               ("Freigabe", esc(e.get("freigabe") or "keine nötig")), ("Zeit laut Protokoll (UTC)", f'<span class="mono">{esc(e.get("zeit_utc") or "")}</span>'),
               ("Kettenwert", f'<span class="mono">{esc(e.get("kette") or "")}</span>'), ("Kettenwert des Vorgängers", f'<span class="mono">{esc(e.get("vorher") or "")}</span>')]
    h.append('<details class="technik"><summary>Protokolleintrag</summary><dl class="felder">' + "".join(f"<dt>{n}</dt><dd>{w}</dd>" for n, w in technik) + "</dl></details>")
    return "\n".join(h)


def roh_vermerk(fall: daten.Fall, e: dict, roh: daten.Rohdatei | None) -> str:
    antwort = e.get("antwort") or {}
    if roh is None:
        return ""
    passt, text = fall.passt_zur_kette(e)
    marke = f'<span class="marke z-{"gut" if passt else "kritisch"}">{"✓ passt zur Kette" if passt else "✕ passt nicht zur Kette"}</span>'
    return (f'<dl class="felder"><dt>Rohdatei</dt><dd><span class="mono">{esc(roh.name)}</span></dd><dt>Grösse</dt><dd>{esc(ds.groesse(roh.bytes))}</dd>'
            f'<dt>SHA-256 laut Protokoll</dt><dd><span class="mono">{esc(antwort.get("sha256") or "")}</span></dd><dt>Prüfung</dt><dd>{marke} {esc(text)}</dd></dl>')


def beleg_seite(fall: daten.Fall, beleg: str) -> str:
    e, roh, blatt = fall.blatt(beleg)
    wer = fall.akteure().get(beleg, "")
    nachbarn = [x["id"] for x in fall.eintraege()]
    nr = nachbarn.index(beleg)
    blaettern = " ".join(f'<a href="{pfad(fall.id, "beleg", nachbarn[i])}">{t}</a>' for i, t in ((nr - 1, "← " + nachbarn[nr - 1] if nr else ""), (nr + 1, (nachbarn[nr + 1] + " →") if nr + 1 < len(nachbarn) else "")) if t and 0 <= i < len(nachbarn))
    return (f'<h1>{esc(beleg)} · {esc(blatt.titel)}</h1><p class="unter nicht-drucken">{blaettern}</p>{eintrag_kopf(fall, e, wer)}'
            f"<h2>Was die Quelle sagt</h2><p class='klein'>Feststellungen der Quelle, geordnet vom Darsteller. Jeder Wert stammt aus der Rohdatei. "
            f"Wer mit der Maus auf einem Wert bleibt, sieht die Stelle.</p>{blatt_html(blatt, roh, fall.id, beleg)}"
            f"<h2>Rohdatei</h2>{roh_vermerk(fall, e, roh) or '<p class=klein>keine</p>'}"
            + (f'<p><a href="{pfad(fall.id, "roh", beleg)}">Rohdatei ansehen</a></p>' if roh is not None and roh.form != "fehlt" else ""))


def roh_seite(fall: daten.Fall, beleg: str) -> str:
    e = fall.eintrag(beleg)
    roh = fall.roh_zu(e)
    if roh is None:
        return f'<h1>{esc(beleg)}</h1><p>Zu diesem Eintrag gibt es keine Rohdatei.</p>'
    form = {"json": "JSON, als Baum", "text": "Text", "csv": "CSV, als Tabelle", "bild": "Bild", "fehlt": "fehlt"}[roh.form]
    return (f'<h1>Rohdatei zu {esc(beleg)}</h1><p class="unter">{esc(e.get("quelle") or "")} · <span class="mono">{esc(e.get("ziel") or "")}</span> · {form} · '
            f'<a href="{pfad(fall.id, "beleg", beleg)}">zum Beleg</a></p>{roh_vermerk(fall, e, roh)}{eintrag_kopf(fall, e)}<h2>Inhalt</h2>'
            + ('<p class="banner">Die Rohdatei fehlt in der Fallakte.</p>' if roh.form == "fehlt" else rohdatei_inhalt(roh, fall.id)))


def rohdaten_seite(fall: daten.Fall) -> str:
    zeilen = []
    for e in fall.eintraege():
        antwort = e.get("antwort") or {}
        if not antwort.get("rohdaten") or antwort.get("aus_cache"):
            continue
        zeilen.append([f'<a href="{pfad(fall.id, "roh", e["id"])}">{esc(e["id"])}</a>', esc(e.get("quelle") or ""), f'<span class="mono">{esc(e.get("werkzeug") or "")}</span>',
                       f'<span class="mono">{esc(rapport.kuerzen(e.get("ziel") or "", 60))}</span>', f'<span class="mono">{esc(antwort["rohdaten"].split("/")[-1])}</span>',
                       f'<span data-roh="{esc(antwort.get("bytes") or 0)}">{esc(ds.groesse(antwort.get("bytes") or 0))}</span>', zeit(e.get("zeit_utc"))])
    kette = fall.kette()
    return (f"<h1>Rohdaten</h1><p class='unter'>Die unveränderten Antworten der Quellen, je Abfrage eine Datei. "
            f"{'✓ Alle Prüfsummen stimmen mit dem Protokoll überein.' if kette['ok'] else '✕ Die Prüfung hat Abweichungen ergeben, siehe Arbeitsspur.'}</p>"
            + (tabelle(["Beleg", "Quelle", "Werkzeug", "Ziel", "Datei", "Grösse", "Abfragezeit"], zeilen, "Rohdaten") if zeilen else '<p class="klein">Noch keine Rohdaten.</p>'))


def suche_seite(fall: daten.Fall, frage: str) -> str:
    kopf_ = (f'<h1>Suche</h1><form class="suchform" role="search"><label for="suchfeld">Suche im ganzen Fall: Indikatoren, Befunde, Protokoll und Rohdaten</label>'
             f'<input id="suchfeld" name="q" type="search" value="{esc(frage)}" autocomplete="off"> <button type="submit">Suchen</button></form>')
    if len(frage.strip()) < 2:
        return kopf_ + '<p class="klein">Mindestens zwei Zeichen eingeben.</p>'
    treffer = fall.suche(frage)
    zeilen = [[esc(t["wo"]), f'<a href="{pfad(fall.id, *t["ziel"].split("/"))}">{esc(t["titel"])}</a>', esc(t["auszug"])] for t in treffer]
    return kopf_ + f"<p>{len(treffer)} Treffer für «{esc(frage)}».</p>" + (tabelle(["Wo", "Treffer", "Auszug"], zeilen, "Suche") if zeilen else "")


def dokumente_seite(fall: daten.Fall) -> str:
    h = ["<h1>Dokumente</h1><p class='unter'>Der erzeugte Abschlussrapport und das Ermittlungsprotokoll bleiben die Dokumente für die Akte. "
         "Die Oberfläche zeigt sie und sagt, ob sie dem Stand der Daten entsprechen.</p>"]
    zeilen = []
    for d in fall.dokumente():
        stand = '<span class="marke z-leer">noch nicht erzeugt</span>' if not d["html"] else \
            f'<span class="marke z-{"gut" if d["aktuell"] else "warnung"}">{"✓" if d["aktuell"] else "?" if d["aktuell"] is None else "!"} {esc(d["vermerk"])}</span>'
        ansehen = f'<a href="{pfad(fall.id, "dokument", d["name"])}">ansehen</a>' if d["html"] else "–"
        pdf = (f'<a href="/fall/{quote(fall.id)}/dokument/{d["name"]}.pdf" download>PDF holen</a>' if d["pdf"] else
               f'<span class="klein">noch kein PDF. Erzeugen: <code>python3 tools/{"anhang" if d["name"] == "Datenblaetter" else "pdf"}.py {esc(fall.id)}</code></span>')
        zeilen.append([esc(d["titel"]), stand, ansehen, pdf])
    h.append(tabelle(["Dokument", "Stand", "HTML", "PDF"], zeilen, "Dokumente", klasse="schlicht"))
    csvs = [n for n in ("indikatoren.csv", "Ermittlungsprotokoll.csv") if (fall.pfad / "rapport" / n).is_file()]
    if csvs:
        h.append("<p>Maschinenlesbar: " + ", ".join(f'<a href="/fall/{quote(fall.id)}/dokument/{n}" download>{n}</a>' for n in csvs) + "</p>")
    return "\n".join(h)


def dokument_seite(fall: daten.Fall, name: str) -> str:
    fall.dokument(f"{name}.html")
    return (f'<h1>{esc(name)}</h1><p class="unter nicht-drucken">Das gespeicherte Dokument der Akte, unverändert. '
            f'<a href="{pfad(fall.id, "dokumente")}">zurück zu den Dokumenten</a></p>'
            f'<iframe class="dokument" title="{esc(name)}" src="/fall/{quote(fall.id)}/dokument/{esc(name)}.html" sandbox="allow-same-origin"></iframe>')


def rapport_seite(fall: daten.Fall) -> str:
    """Der interaktive Rapport: derselbe Inhalt, dieselbe Reihenfolge und derselbe Wortlaut wie der Abschlussrapport,
    weil er aus demselben Generator kommt. Die Oberfläche ergänzt Filter, Aufklappen und Verweise in die Belege."""
    r = fall.rapport_html()
    if r.get("fehlt"):
        return f"<h1>Rapport</h1><p>{esc(r['fehlt'])}</p>"
    b = fall.befunde() or {}
    wer = fall.akteure()
    text = r["html"]
    text = re.sub(r'href="Ermittlungsprotokoll\.html#([PX]-\d+)"', lambda m: f'href="{pfad(fall.id, "beleg", m.group(1))}"', text)
    text = text.replace("href='Ermittlungsprotokoll.html'", f'href="{pfad(fall.id, "dokument", "Ermittlungsprotokoll")}"')
    text = re.sub(r"""href=(['"])#(B-\d+)\1""", lambda m: f'href="{pfad(fall.id, "rapport", m.group(2))}"', text)
    text = re.sub(r"""href=(['"])#(I-\d+)\1""", lambda m: f'href="{pfad(fall.id, "indikator", m.group(2))}"', text)
    for f in b.get("befunde") or []:
        analysten = sorted({wer[p] for p in f.get("belege") or [] if p in wer})
        merkmale = (f' data-sicherheit="{esc(f.get("sicherheit") or "")}" data-art="{esc(f.get("art") or "")}" data-indikatoren="{esc(" ".join(f.get("indikatoren") or []))}"'
                    f' data-analysten="{esc(" ".join(analysten))}" data-belege="{esc(" ".join(f.get("belege") or []))}"')
        text = text.replace(f" id='{esc(f.get('id', ''))}'>", f" id='{esc(f.get('id', ''))}'{merkmale}>", 1)
    stand = next((d for d in fall.dokumente() if d["name"] == "Abschlussrapport"), {})
    vermerk = ('<span class="marke z-leer">Der Abschlussrapport für die Akte ist noch nicht erzeugt.</span>' if not stand.get("html") else
               f'<span class="marke z-{"gut" if stand["aktuell"] else "warnung"}">Abschlussrapport der Akte: {esc(stand["vermerk"])}</span>')
    fluss = json.dumps([g.get("beleg") for g in b.get("geldfluesse") or []])
    zeitachse = json.dumps([{"zeit": z.get("zeit"), "text": z.get("ereignis"), "belege": z.get("belege") or []} for z in b.get("zeitachse") or []], ensure_ascii=False)
    return (f'<div class="rapport-leiste nicht-drucken">{vermerk} <a href="{pfad(fall.id, "dokument", "Abschlussrapport")}">gespeichertes Dokument ansehen</a></div>'
            f'<div class="rapport" data-fall="{esc(fall.id)}" data-fluesse="{esc(fluss)}" data-zeitachse="{esc(zeitachse)}">{text}</div>')


def spur_daten(fall: daten.Fall, ab: int) -> dict:
    return fall.spur(ab)


def begriffe() -> str:
    return tabelle(["Begriff", "In einfachen Worten"], [[esc(k), esc(v)] for k, v in sorted(blaetter.BEGRIFFE.items())], "Begriffe", klasse="schlicht")
