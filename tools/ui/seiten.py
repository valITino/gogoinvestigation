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

from gateway import plattform, robin
from gateway.akte import eingang_stand
from tools import protokoll as protokollwerkzeug, rapport
from tools._html import STATUS, TYPEN
from tools.ui import blaetter, daten, darsteller as ds

EINBETTEN = False        # der Anhang für die Akte bettet Bilder ein, statt auf den Server zu verweisen
LANG = 220              # ab so vielen Zeichen steht ein Wert eingeklappt da
SEHR_LANG = 4000        # ab so vielen Zeichen zeigt die Oberfläche den Anfang und verweist auf die Rohdatei
BAUM_GRENZE = 6000      # so viele Angaben zeigt ein Baum höchstens, der Rest steht in der Rohdatei
ERGEBNIS = {"ok": ("●", "Treffer", "gut"), "kein_treffer": ("○", "kein Treffer", "neutral"), "fehler": ("✕", "Fehlschlag", "kritisch"),
            "abgelehnt": ("⊘", "abgelehnt", "warnung"), "nicht_ausgefuehrt": ("⊘", "nicht ausgeführt", "warnung")}
ZELLE = {"Treffer": ("●", "gut"), "kein Treffer": ("○", "neutral"), "Fehlschlag": ("✕", "kritisch"), "abgelehnt": ("⊘", "warnung"), "nicht ausgeführt": ("⊘", "warnung"),
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


def ergebnis_marke(e: dict, pfad_akte: object = None) -> str:
    """Das Ergebnis eines Eintrags als Marke. Mit dem Ordner der Fallakte sagt sie bei Robin und bei der Prüfung gegen die Sperrliste,
    was die Antwort belegt, im selben Wortlaut wie das Ermittlungsprotokoll: «Treffer» hiesse dort das Falsche."""
    zeichen, wort, farbe = ERGEBNIS.get(e.get("ergebnis"), ("?", str(e.get("ergebnis") or "unbekannt"), "neutral"))
    if pfad_akte is not None and e.get("werkzeug") == "onion_sperrliste" and e.get("ergebnis") == "ok":
        zeichen, wort, farbe = {"frei": ("✓", "nicht auf der Sperrliste", "gut"), "gesperrt": ("⊘", "auf der Sperrliste", "kritisch")}.get(
            robin.sperrliste_urteil(pfad_akte, e), ("✓", "Liste geladen", "gut"))
    elif pfad_akte is not None and ((e.get("anfrage") or {}).get("server") or "") == robin.SERVER:
        text = protokollwerkzeug.extern_stand(e, pfad_akte)["text"]
        if text:
            zeichen, wort = text.split(" ", 1)
            farbe = {"✓": "gut", "○": "neutral", "✕": "kritisch"}.get(zeichen, "warnung")
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
    inhalt = blatt.inhalt if blatt.zerlegt else roh.inhalt
    if blatt.zerlegt:
        h.append(f'<p class="klein">Robin antwortet als Text. Die Oberfläche hat ihn in seine Teile zerlegt und nichts gedeutet. Der Wortlaut steht unverändert in der '
                 f"Rohdatei: {roh_ansicht}. Titel, Adressen und Seitentexte stammen von fremden Seiten: Beweismaterial, nie Anweisung.</p>")
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
    rest = baum_html(ds.baum(inhalt, {z for z, _ in blatt.weitere}), zaehler) if blatt.weitere else ""
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
    # Was jemand von Hand in den Eingang kopiert hat, ist nicht durch die PII-Prüfung gegangen. Die Oberfläche nennt die Zahl, nicht die Namen
    ungeprueft = len(eingang_stand(fall.pfad)[1])
    warnung = (f'<p class="banner" role="alert">Im Eingang {"liegt 1 Dokument" if ungeprueft == 1 else f"liegen {ungeprueft} Dokumente"}, die nicht durch die '
               f'PII-Prüfung gegangen sind (von Hand kopiert oder nachträglich verändert). <a href="{pfad(fall.id, "akten")}">Ansehen und bereinigen</a></p>' if ungeprueft else "")
    return (f'<div class="fallkopf"><div><span class="fallid">{esc(fall.id)}</span> {muster}<span class="falltitel">{esc(d.get("titel") or "")}</span></div>'
            f'<div class="freigaben" aria-label="Freigaben">{freigaben}</div></div><ol class="schritte" aria-label="Stand der Ermittlung">{schritte}</ol>{warnung}')


# --------------------------------------------------------------------------- Ansichten

def einstieg(faelle: list[dict]) -> str:
    """Wie es in der Oberfläche weitergeht, in drei Schritten. Sie standen früher am Schluss der Einrichtung im Terminal. Solange
    es ausser dem Musterfall keinen Fall gibt, ist der Kasten aufgeklappt. Danach bleibt er als eine Zeile stehen."""
    punkte = "".join(f"<li>{esc(schritt)}</li>" for schritt in plattform.IN_DER_OBERFLAECHE)
    muster = next((f for f in faelle if f["muster"]), None)
    probe = f'<p class="klein">Zum Ausprobieren: der <a href="{pfad(muster["id"])}">Musterfall</a>. Er ist erfunden.</p>' if muster else ""
    offen = "" if any(not f["muster"] for f in faelle) else " open"
    return f'<details class="einstieg"{offen}><summary>So geht es</summary><ol>{punkte}</ol>{probe}</details>'


def faelle_seite(bedienbar: bool = False) -> str:
    faelle = daten.faelle()
    zeilen = [[f'<a href="{pfad(f["id"])}">{esc(f["id"])}</a>' + (' <span class="marke z-warnung">Muster</span>' if f["muster"] else ""), esc(f["titel"]),
               zeit(f["eroeffnet"]), esc(f["sachbearbeiter"]), esc(f["klassifizierung"])] for f in faelle]
    neu = ('<p><a class="knopf haupt" href="#/neu">Neuer Fall</a> <span class="klein">Akten hineinziehen, prüfen, wo nötig nochmals pseudonymisieren, Fall anlegen.</span></p>'
           + einstieg(faelle) if bedienbar else "")
    return ("<h1>Fälle</h1><p class='unter'>Alle Fallakten in diesem Arbeitsplatz." + ("" if bedienbar else " Die Oberfläche liest sie nur.") + "</p>" + neu
            + (tabelle(["Fall", "Titel", "Eröffnet", "Sachbearbeitung", "Klassifizierung"], zeilen, "Fälle") if zeilen else
               "<p>Noch kein Fall angelegt." + ("" if bedienbar else " Ein Fall entsteht in der bedienbaren Oberfläche unter «Neuer Fall» oder mit "
                                                "<code>python3 tools/fall.py neu &lt;Fall-ID&gt; --titel \"…\" --rapport &lt;Dokument&gt;</code>.") + "</p>"))


QUELLE_STAND = {      # Stand einer Quelle -> (Merkmal für den Filter, Farbe, Marke)
    "ausgeschaltet": ("aus", "leer", "⏻ ausgeschaltet"), "eingerichtet": ("bereit", "gut", "✓ bereit"), "kein Schlüssel nötig": ("bereit", "gut", "✓ bereit"),
    "läuft ohne Schlüssel, gedrosselt": ("bereit", "warnung", "✓ bereit, gedrosselt"), "nicht eingerichtet": ("fehlt", "leer", "○ Schlüssel fehlt")}


def quellen_seite(knoepfe=None, verwalten=None, hinweis: str = "") -> str:
    """Die Quellen dieses Arbeitsplatzes: je Quelle eine Zeile mit Stand, Zweck und Einzelheiten, darüber Zahlen und ein Filter.
    Von Schlüsseln steht hier nur der Name der Variablen und ob einer eingetragen ist, nie ein Wert.
    `knoepfe`, `verwalten`: was die bedienbare Oberfläche je Quelle dazusetzt (tools/ui/formulare.py). Ohne sie liest die Seite nur."""
    quellen = daten.quellen()
    merkmal = {q["name"]: QUELLE_STAND[q["stand"]][0] for q in quellen}
    zahl = {m: sum(1 for v in merkmal.values() if v == m) for m in ("bereit", "fehlt", "aus")}
    kacheln = "".join(f'<div class="kachel"><div class="wert">{wert}</div><div class="name">{esc(name)}</div><div class="zusatz">{esc(zusatz)}</div></div>' for wert, name, zusatz in (
        (f"{zahl['bereit']} <span class='klein'>von {len(quellen)}</span>", "Quellen bereit", f"{sum(1 for q in quellen if not q['schluessel'])} brauchen keinen Schlüssel"),
        (str(zahl["fehlt"]), "nicht eingerichtet", "der Schlüssel fehlt, jede Quelle ist für sich freiwillig"), (str(zahl["aus"]), "ausgeschaltet", "das Gateway fragt sie nicht")))
    eintraege = []
    for q in quellen:
        _m, farbe, marke = QUELLE_STAND[q["stand"]]
        schluessel = (f'<span class="quelle-schluessel"><span class="mono">{esc(q["schluessel"])}</span> '
                      + ("aus der Umgebung des Terminals" if q["aus_umgebung"] else "eingetragen" if q["gesetzt"] else "nicht eingetragen") + "</span>"
                      if q["schluessel"] else '<span class="quelle-schluessel">kein Schlüssel nötig</span>')
        angaben = [("Werkzeuge", f'<span class="mono">{esc(", ".join(q["werkzeuge"]))}</span>' if q["werkzeuge"] else "über ein gebündeltes Werkzeug (ip_einordnung oder die Blockchain-Werkzeuge)")]
        if q["freigabe"]:
            angaben.append(("Freigabe nötig", esc(", ".join(f"{w}: Freigabe {f}" for w, f in q["freigabe"].items()))))
        if q["hinweis"]:
            angaben.append(("Hinweis", esc(q["hinweis"])))
        if q["woher"]:
            angaben.append(("Schlüssel bekommen", f'<span class="mono">{esc(q["woher"])}</span>'))
        if q["ohne_schalter"]:
            angaben.append(("Kein Schalter", esc("Diese Quelle lässt sich nicht ausschalten. " + q["ohne_schalter"])))
        eintraege.append(
            f'<li class="quelle s-{merkmal[q["name"]]}" data-stand="{merkmal[q["name"]]}" data-name="{esc(q["name"])}" '
            f'data-suche="{esc(" ".join([q["name"], q["schluessel"], *q["werkzeuge"]]).lower())}">'
            f'<div class="quelle-kopf"><h3>{esc(q["name"])}</h3><span class="marke z-{farbe}">{marke}</span>{schluessel}'
            + (f'<div class="quelle-knoepfe">{knoepfe(q)}</div>' if knoepfe else "") + "</div>"
            f'<p class="quelle-zweck">{esc(q["zweck"])}</p>'
            f'<details class="quelle-mehr"><summary>{"Einzelheiten und Schlüssel" if verwalten and q["schluessel"] else "Einzelheiten"}</summary>'
            '<dl class="felder">' + "".join(f"<dt>{esc(name)}</dt><dd>{wert}</dd>" for name, wert in angaben) + "</dl>"
            + (verwalten(q) if verwalten else "") + "</details></li>")
    return ("<h1>Quellen</h1><p class='unter'>Was das Gateway befragen kann und ob die Quelle an diesem Arbeitsplatz eingerichtet ist. "
            "Von Schlüsseln zeigt die Oberfläche nur, ob einer gesetzt ist, nie den Wert.</p>" + hinweis
            + f'<div data-quellen><div class="kacheln quellen-zahlen">{kacheln}</div>'
            '<div class="listenfilter" role="group" aria-label="Quellen filtern">'
            '<input type="search" data-quellen-suche placeholder="Quelle oder Werkzeug suchen" aria-label="Quelle oder Werkzeug suchen">'
            + "".join(f'<button type="button" aria-pressed="{"true" if not wert else "false"}" data-quellen-filter="{wert}">{esc(text)}</button>'
                      for wert, text in (("", "alle"), ("bereit", "bereit"), ("fehlt", "Schlüssel fehlt"), ("aus", "ausgeschaltet")))
            + '<span class="klein" data-quellen-zahl></span></div>'
            f'<ul class="quellenliste" aria-label="Quellen">{"".join(eintraege)}</ul>'
            '<p class="liste-leer" data-quellen-nichts hidden>Keine Quelle passt zu diesem Filter.</p></div>')


PFLICHT_MARKE = {"erfuellt": ("✓ erfüllt", "gut"), "offen": ("○ offen", "kritisch"), "fehlgeschlagen": ("✕ Fehlschlag", "warnung"),
                 "entfaellt": ("– entfällt", "leer"), "wartet": ("… noch nicht fällig", "leer"), "unbekannt": ("? unbekannt", "kritisch")}


def pflichtquellen_kurz(fall: daten.Fall) -> str:
    """Der Stand der Pflichtquellen in einer Zeile. Leer ohne Vorgabe."""
    s = fall.pflichtquellen()
    if not s:
        return ""
    z = s["zahlen"]
    if not z["faellig"]:
        return "noch nichts fällig"
    return (f"{z['erfuellt']} von {z['faellig']} erfüllt" + (f", {z['fehlgeschlagen']} fehlgeschlagen" if z["fehlgeschlagen"] else "")
            + (f", {z['offen']} offen" if z["offen"] else ""))


def pflichtquellen_html(fall: daten.Fall, kopf: str = "<h2>Pflichtquellen</h2>") -> str:
    """Die Pflichtquellen eines Falls und was das Protokoll dazu zeigt: je Quelle, ob sie für jeden passenden Indikator gefragt
    wurde. Leer ohne Vorgabe. Steht in der Fallübersicht und in der Ansicht «Ermittlung» (dort unter der Auswahl, mit eigenem Kopf)."""
    s = fall.pflichtquellen()
    if not s:
        return ""
    z = s["zahlen"]
    wer = ((f" am {esc(rapport.zeit_zeigen(s['am']))}" if s["am"] else "") + (f" durch {esc(s['durch'])}" if s["durch"] else "")
           + (f", über die {esc(s['weg'])}" if s["weg"] else ""))
    zeilen = []
    for r in s["zeilen"]:
        wort, farbe = PFLICHT_MARKE.get(r["stand"], (r["stand"], "neutral"))
        if r["einmal"]:
            faellig = "einmal im Fall" if r["faellig"] else "–"
        else:
            faellig = f"{len(r['erfuellt'])} von {len(r['faellig'])} Indikator{'en' if len(r['faellig']) != 1 else ''}" if r["faellig"] else "–"
        einzel = []
        for wort_, ids in (("offen", r["offen"]), ("Fehlschlag", r["fehlgeschlagen"])):
            if ids and not r["einmal"]:
                einzel.append(f"{wort_}: " + " ".join(f'<a href="{pfad(fall.id, "indikator", i)}">{esc(i)}</a>' for i in ids))
        if r["grund"]:
            einzel.append(esc(r["grund"]))
        belege = list(dict.fromkeys(b for i in r["faellig"] for b in r["belege"].get(i, [])[:1]))
        zeilen.append([esc(r["quelle"]), f'<span class="marke z-{farbe}">{esc(wort)}</span>', esc(faellig), " · ".join(einzel) or "–",
                       (" ".join(f'<a href="{pfad(fall.id, "beleg", b)}">{esc(b)}</a>' for b in belege[:8])
                        + (f" und {len(belege) - 8} weitere" if len(belege) > 8 else "")) if belege else "–"])
    stand = (f"{z['erfuellt']} von {z['faellig']} fälligen Abfragen erfüllt" + (f", {z['fehlgeschlagen']} fehlgeschlagen" if z["fehlgeschlagen"] else "")
             + (f", {z['offen']} offen" if z["offen"] else "")) if z["faellig"] else "noch nichts fällig"
    return (f"{kopf}<p class='klein'>Vorgegeben{wer}. Jede dieser Quellen muss für jeden Indikator aus den Akten gefragt werden, zu dem sie passt. "
            f"Suchquellen und Quellen für Gruppen und Konten mindestens einmal. Stand laut Protokoll: <b>{esc(stand)}</b>."
            + ("" if s["bekannt"] else " Die Indikatoren des Falls stehen noch nicht fest.") + "</p>"
            + tabelle(["Quelle", "Stand", "Fällig", "Einzelheiten", "Belege"], zeilen, "Pflichtquellen", klasse="schlicht"))


def uebersicht(fall: daten.Fall) -> str:
    k = fall.kennzahlen()
    r, p = k["rapport"], k["protokoll"]
    h = [f"<h1>Fallübersicht</h1><p class='unter'>{esc(fall.daten.get('auftrag') or 'Kein Auftrag in der Fallakte vermerkt.')}</p>"]
    kacheln = [(r["indikatoren"], "Indikatoren", f"{r['bewertung']['boesartig']} bösartig, {r['bewertung']['verdaechtig']} verdächtig"),
               (len(r["abfragen"]), "Abfragen", rapport.abfragen_zusatz(r)),
               (len(r["quellen"]), "Quellen genutzt", f"{len(r['auswertungen'])} Auswertungen daraus" if r["auswertungen"] else ""),
               (r["befunde"], "Befunde", f"{r['gegengeprueft']} gegengeprüft"),
               (p["cache"], "aus dem Fall-Cache", "Antwort kam aus der Fallakte"), (p["aktiv"], "aktive Massnahmen", "Ziel wurde kontaktiert")]
    h.append('<div class="kacheln">' + "".join(f'<div class="kachel"><div class="wert">{esc(w)}</div><div class="name">{esc(n)}</div><div class="zusatz">{esc(z)}</div></div>'
                                              for w, n, z in kacheln) + "</div>")
    h.append('<p class="klein">Dieselben Zahlen wie im Abschlussrapport (Abschnitt 3) und im Ermittlungsprotokoll: Sie kommen aus denselben Funktionen.</p>')
    if r["nicht_ausgefuehrt"]:
        h.append(f'<p class="klein">{esc(rapport.ohne_ausfuehrung_satz(r))}</p>')
    h.append("<h2>Stand der Schritte</h2>" + tabelle(["Schritt", "Stand", "Woran die Oberfläche das erkennt"],
                                                     [[esc(s["name"]), "erledigt" if s["erledigt"] else "nicht abgelegt" if s["uebersprungen"] else "offen", esc(s["woran"])] for s in fall.schritte()],
                                                     "Schritte", klasse="schlicht"))
    offen = offene_punkte(fall)
    h.append("<h2>Offene Punkte</h2>" + ("<ul>" + "".join(f"<li>{o}</li>" for o in offen) + "</ul>" if offen else '<p class="klein">Keine.</p>'))
    pflicht = pflichtquellen_html(fall)
    if pflicht:
        h.append(pflicht)
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
        if e.get("ergebnis") in ("fehler", "abgelehnt", "nicht_ausgefuehrt"):
            punkte.append(f'<a href="{pfad(fall.id, "beleg", e["id"])}">{esc(e["id"])}</a> {esc(e.get("quelle") or "")}: '
                          f'{ {"abgelehnt": "abgelehnt", "nicht_ausgefuehrt": "nicht ausgeführt"}.get(e.get("ergebnis"), "fehlgeschlagen")} ({esc(e.get("fehler") or "ohne Meldung")})')
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
           "tor": "über Tor (Robin)", "robin_lokal": "Robin, im Container: keine Abfrage nach aussen", "von_hand": "von Hand erfasst",
           "extern": "weiteres Werkzeug"}.get(e.get("art"), "passiv: Das Ziel wurde nicht kontaktiert")
    felder = [("Quelle", esc(e.get("quelle") or "")), ("Werkzeug", f'<span class="mono">{esc(e.get("werkzeug") or "")}</span>'),
              ("Ziel", f'<span class="mono">{esc(e.get("ziel") or "")}</span>'), ("Abfragezeit", zeit(e.get("zeit_utc"))), ("Ergebnis", ergebnis_marke(e, fall.pfad)), ("Art", esc(art)),
              ("Durch", esc(wer or e.get("agent") or "–"))]
    h = ['<div class="kopf">' + "".join(f"<div><b>{n}</b>{w}</div>" for n, w in felder) + "</div>", f"<p><b>Zweck:</b> {esc(e.get('zweck') or '–')}</p>"]
    if antwort.get("aus_cache"):
        ursprung = next((x for x in fall.eintraege() if x.get("id") == antwort["aus_cache"]), {})
        h.append(f'<p class="banner">Diese Antwort kam aus dem Fall-Cache. Ursprüngliche Abfrage: <a href="{pfad(fall.id, "beleg", antwort["aus_cache"])}">{esc(antwort["aus_cache"])}</a> '
                 f"vom {zeit(ursprung.get('zeit_utc'))}. Die Quelle wurde beim zweiten Mal nicht erneut gefragt.</p>")
    if e.get("fehler"):
        h.append(f'<p class="banner">Meldung: {esc(e["fehler"])}</p>')
    if ((anfrage.get("server") or "") == robin.SERVER) and e.get("art") != "von_hand":
        # Robin: was die Antwort belegt, und zu jeder Seite, ob ihre Adresse vorher gegen die Sperrliste geprüft war
        stand = protokollwerkzeug.extern_stand(e, fall.pfad)
        if stand["meldung"] and stand["meldung"] != e.get("fehler"):
            h.append(f'<p class="klein">{"Meldung" if stand["ergebnis"] in ("fehler", "nicht_ausgefuehrt") else "Hinweis"}: {esc(stand["meldung"])}</p>')
        if stand["angaben"]:
            h.append(f'<p class="klein">{esc(" · ".join(stand["angaben"]))}</p>')
        if e.get("regel"):      # am Terminal zugelassen, obwohl der Aufruf die Regeln des Falls nicht einhielt
            h.append(f'<p class="banner">Nicht nach den Regeln für Robin: {esc(e["regel"])}</p>')
        if e.get("seiten"):
            wort = {"ok": "gelesen", "blocked": "von der Seite abgewiesen", "error": "nicht lesbar", "refused_not_onion": "abgelehnt, keine Onion-Adresse"}
            h.append(tabelle(["Seite", "Stand", "Sperrliste"],
                             [[f'<span class="mono">{esc(s.get("adresse") or "")}</span>', esc(wort.get(s.get("stand"), str(s.get("stand") or "?")) + (f" (HTTP {s['http']})" if s.get("http") else "")),
                               esc(s.get("sperrliste") or "?") + (f' (<a class="beleg" href="{pfad(fall.id, "beleg", s["sperrliste_beleg"])}">{esc(s["sperrliste_beleg"])}</a>)' if s.get("sperrliste_beleg") else "")]
                              for s in e["seiten"]], f"{e.get('id')} Seiten", klasse="schlicht"))
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
    fid = quote(fall.id)
    pdf = f' · <a href="/fall/{fid}/dokument/{esc(name)}.pdf" download>PDF holen</a>' if (fall.pfad / "rapport" / f"{name}.pdf").is_file() else ""
    return (f'<h1>{esc(name)}</h1><p class="unter nicht-drucken">Das gespeicherte Dokument der Akte, unverändert. '
            f'<a href="{pfad(fall.id, "ergebnisse")}">zurück zu den Ergebnissen</a> · <a href="/fall/{fid}/dokument/{esc(name)}.html?holen=1" download>HTML holen</a>{pdf}</p>'
            f'<iframe class="dokument" title="{esc(name)}" src="/fall/{fid}/dokument/{esc(name)}.html" sandbox="allow-same-origin"></iframe>')


ARCHIVE = (("unterlagen,sitzung", "Unterlagen und Sitzungsprotokoll", "Rapport, Ermittlungsprotokoll und Datenblätter (HTML und PDF), Indikatorliste, Befunde. "
            "Dazu das Sitzungsprotokoll: jeder Auftrag, jeder Werkzeugaufruf, jede Rückfrage mit Antwort, und der Verlauf aus dem Chat."),
           ("unterlagen", "Nur die Unterlagen", "Rapport, Ermittlungsprotokoll und Datenblätter (HTML und PDF), Indikatorliste, Befunde."),
           ("unterlagen,sitzung,akte", "Die ganze Fallakte", "Alles oben, dazu fall.json, die Dokumente des Eingangs, die Protokollkette, der Arbeitsstand und "
            "alle Rohdaten: die unveränderten Antworten der Quellen."))
WEGE = (("rapport", "Rapport", "Befunde filtern und aufklappen bis zum Beleg, Beziehungsgraf, Geldfluss, Zeitachse."),
        ("indikatoren", "Indikatoren", "Je Indikator ein Datenblatt: jeder Wert mit Quelle, Abfragezeit und Beleg."),
        ("rohdaten", "Rohdaten", "Die Antworten der Quellen, unverändert, mit Prüfsumme."),
        ("uebersicht", "Fallübersicht", "Kennzahlen, offene Punkte und die Abdeckung Indikator × Quelle."),
        ("suche", "Suche", "Im ganzen Fall: Indikatoren, Befunde, Protokoll und Rohdaten."))


def ergebnisse_seite(fall: daten.Fall, bedienbar: bool = False) -> str:
    """Alles, was die Ermittlung hinterlassen hat, an einem Ort: ansehen, einzeln holen, als ein Archiv mitnehmen."""
    from tools.ui import formulare
    fid = quote(fall.id)
    dokumente = fall.dokumente()
    h = ["<h1>Ergebnisse</h1><p class='unter'>Was die Ermittlung hinterlassen hat: ansehen, einzeln holen oder alles zusammen mitnehmen.</p>"]
    if not any(d["html"] for d in dokumente):
        h.append('<p class="banner">Zu diesem Fall sind noch keine Unterlagen erzeugt. Sie entstehen am Ende der Ermittlung'
                 + (", oder hier mit «Alle Unterlagen neu erzeugen»." if bedienbar else ".") + "</p>")
    veraltet = [d["titel"] for d in dokumente if d["html"] and d["aktuell"] is False]
    if veraltet:
        h.append(f'<p class="banner">Älter als die Daten: {esc(", ".join(veraltet))}. ' + ("Mit «Alle Unterlagen neu erzeugen» entsteht der aktuelle Stand." if bedienbar else "") + "</p>")
    h.append('<h2>Ansehen</h2><div class="wege">' + "".join(
        f'<a class="weg" href="{pfad(fall.id, ziel)}"><b>{esc(titel)}</b><span>{esc(text)}</span></a>' for ziel, titel, text in WEGE) + "</div>")
    zeilen = []
    for d in dokumente:
        stand = '<span class="marke z-leer">noch nicht erzeugt</span>' if not d["html"] else \
            f'<span class="marke z-{"gut" if d["aktuell"] else "warnung"}">{"✓" if d["aktuell"] else "?" if d["aktuell"] is None else "!"} {esc(d["vermerk"])}</span>'
        ansehen = f'<a href="{pfad(fall.id, "dokument", d["name"])}">ansehen</a>' if d["html"] else "–"
        holen = " · ".join(([f'<a href="/fall/{fid}/dokument/{d["name"]}.html?holen=1" download>HTML</a>'] if d["html"] else [])
                           + ([f'<a href="/fall/{fid}/dokument/{d["name"]}.pdf" download>PDF</a>'] if d["pdf"] else [])) or "–"
        zeilen.append([esc(d["titel"]), stand, ansehen, holen + ('' if d["pdf"] or not d["html"] else ' <span class="klein">(noch kein PDF)</span>')])
    for name, titel in (("indikatoren.csv", "Indikatorliste"), ("Ermittlungsprotokoll.csv", "Ermittlungsprotokoll als Tabelle")):
        da = (fall.pfad / "rapport" / name).is_file()
        zeilen.append([esc(titel), '<span class="marke z-gut">✓ vorhanden</span>' if da else '<span class="marke z-leer">noch nicht erzeugt</span>', "–",
                       f'<a href="/fall/{fid}/dokument/{name}" download>CSV</a>' if da else "–"])
    befunde = (fall.pfad / "befunde.json").is_file()
    zeilen.append(["Befunde, strukturiert", '<span class="marke z-gut">✓ vorhanden</span>' if befunde else '<span class="marke z-leer">noch nicht geschrieben</span>',
                   f'<a href="{pfad(fall.id, "rapport")}">im Rapport</a>' if befunde else "–", f'<a href="/fall/{fid}/befunde.json" download>JSON</a>' if befunde else "–"])
    h.append("<h2>Unterlagen</h2>" + tabelle(["Dokument", "Stand", "Ansehen", "Herunterladen"], zeilen, "Unterlagen", klasse="schlicht"))
    if bedienbar:
        h.append('<div class="knopfzeile">' + formulare.formular("dokumente", "", "Alle Unterlagen neu erzeugen", verborgen={"fall": fall.id, "was": "alles"}, danach="neu-laden", klasse="klein-form")
                 + "</div><p class='klein'>Erzeugt Abschlussrapport, Ermittlungsprotokoll, PDF und Datenblätter aus dem Stand der Daten. Einzeln: unter «Bedienen».</p>")
    h.append("<h2>Alles mitnehmen</h2><ul class='archive'>" + "".join(
        f'<li><a class="knopf{" haupt" if i == 0 else ""}" href="/fall/{fid}/paket.zip?teile={teile}" download>{esc(titel)} (ZIP)</a><span class="klein">{esc(text)}</span></li>'
        for i, (teile, titel, text) in enumerate(ARCHIVE)) + "</ul>"
        "<p class='klein'>Jedes Archiv enthält die Datei INHALT.txt: jede Datei mit Grösse und Prüfsumme, dazu der Stand der Protokollkette. "
        "Die Unterlagen sind pseudonymisiert. Den Rapport mit echten Angaben gibt es unter «Bedienen», «Zurückführen»: Er bleibt ausserhalb des Projektordners.</p>")
    zeilen_s, meldungen = protokollwerkzeug.sitzungen_laden(fall.id)
    eigene = [z for z in zeilen_s if z.get("fall") == fall.id]
    sitzungen = sorted({str(z.get("sitzung") or "") for z in eigene})
    kette = fall.kette()
    verlaeufe = len(list((fall.pfad / "arbeitsstand").glob("verlauf-oberflaeche-*.txt"))) if (fall.pfad / "arbeitsstand").is_dir() else 0
    versuche = len(protokollwerkzeug.nicht_ausgefuehrt(eigene))
    mit_beleg = len(fall.kennzahlen()["protokoll"]["ohne_ausfuehrung"])
    nie = versuche + mit_beleg                                              # dieselbe Zahl wie die Kachel «nicht ausgeführt» im Ermittlungsprotokoll
    h.append("<h2>Protokoll der Sitzung</h2><ul>"
             f"<li>Sitzungsprotokoll: {len(eigene)} Einträge aus {len(sitzungen)} Sitzung{'en' if len(sitzungen) != 1 else ''}. "
             "Der Protokoll-Hook schreibt es mit: Aufträge, Werkzeugaufrufe (auch was verlangt, aber nicht ausgeführt wurde), Analysten, "
             "Schritte über die Oberfläche, Rückfragen mit Antwort.</li>"
             f"<li>Verlangt, aber nicht ausgeführt: {nie} {'Aufruf' if nie == 1 else 'Aufrufe'}. Davon {mit_beleg} mit Beleg (Robin hat geantwortet, aber nichts "
             f"gesucht und nichts gelesen: Ermittlungsprotokoll, Abschnitt 3) und {versuche} ohne Nummer (vom Gateway zurückgewiesen, von einer Berechtigung "
             "verboten oder in der Rückfrage abgelehnt: Abschnitt 4). Sie zählen nicht als Abfrage.</li>"
             f"<li>Verlauf aus dem Chat: {verlaeufe} Datei{'en' if verlaeufe != 1 else ''} im Arbeitsstand des Falls. Eine Lesehilfe, kein Beleg.</li>"
             f"<li>Protokollkette der Abfragen: <span class='z-{'gut' if kette['ok'] else 'kritisch'}'>{'✓ unversehrt' if kette['ok'] else '✕ gebrochen'}</span>, "
             f"{len(fall.eintraege())} Einträge. Lesbar aufbereitet im Ermittlungsprotokoll.</li>"
             + "".join(f"<li class='z-kritisch'>{esc(m)}</li>" for m in meldungen) + "</ul>")
    return "\n".join(h)


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
