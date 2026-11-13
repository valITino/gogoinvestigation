"""Gemeinsame Bausteine für Abschlussrapport und Ermittlungsprotokoll: Seitengerüst, Stil und
Diagramme als eingebettetes SVG. Nur Standardbibliothek, keine Schriften oder Skripte von aussen.
Die erzeugten Dateien sind in sich geschlossen und lassen sich aus dem Browser als PDF drucken.
"""
from __future__ import annotations

import html
import math
import random

esc = html.escape

# Farbrollen. Hell und dunkel sind je eigens gewählt, im Druck gilt immer hell.
_HELL = """--flaeche:#fcfcfb;--seite:#f9f9f7;--tinte:#0b0b0b;--tinte-2:#52514e;--gedaempft:#898781;
--raster:#e1e0d9;--achse:#c3c2b7;--rand:rgba(11,11,11,.10);--serie:#2a78d6;--serie-hell:#cde2fb;
--gut:#0ca30c;--warnung:#fab219;--kritisch:#d03b3b;--neutral:#898781;--marke:#fff4cc;"""
_DUNKEL = """--flaeche:#1a1a19;--seite:#0d0d0d;--tinte:#f0efec;--tinte-2:#c3c2b7;--gedaempft:#898781;
--raster:#2c2c2a;--achse:#383835;--rand:rgba(255,255,255,.10);--serie:#3987e5;--serie-hell:#0d366b;
--gut:#0ca30c;--warnung:#fab219;--kritisch:#d03b3b;--neutral:#898781;--marke:#3a3214;"""

STIL = f"""
:root{{color-scheme:light dark;{_HELL}}}
@media (prefers-color-scheme:dark){{:root{{{_DUNKEL}}}}}
@media print{{:root{{{_HELL}}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--seite);color:var(--tinte);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:980px;margin:0 auto;padding:32px 28px 64px;background:var(--flaeche);
  border-left:1px solid var(--rand);border-right:1px solid var(--rand);min-height:100vh}}
h1{{font-size:28px;line-height:1.2;margin:0 0 4px;font-weight:650}}
h2{{font-size:20px;margin:44px 0 12px;padding-top:14px;border-top:1px solid var(--raster);font-weight:650}}
h3{{font-size:16px;margin:24px 0 8px;font-weight:650}}
p{{margin:8px 0}} ul,ol{{margin:8px 0;padding-left:22px}} li{{margin:4px 0}}
a{{color:inherit;text-decoration:underline;text-decoration-color:var(--achse);text-underline-offset:2px}}
a:hover{{text-decoration-color:var(--tinte)}}
code,.mono{{font:12.5px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}}
.unter{{color:var(--tinte-2);margin:0 0 18px}}
.klein{{font-size:13px;color:var(--tinte-2)}}
.banner{{background:var(--marke);border:1px solid var(--rand);border-radius:6px;padding:10px 14px;margin:0 0 20px;font-weight:600}}
.kopf{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:2px 24px;margin:16px 0 8px;
  padding:14px 16px;border:1px solid var(--rand);border-radius:8px}}
.kopf div{{padding:3px 0}} .kopf b{{display:block;font-size:12px;font-weight:600;color:var(--tinte-2)}}
.kacheln{{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px;margin:14px 0}}
.kachel{{border:1px solid var(--rand);border-radius:8px;padding:12px 14px}}
.kachel .wert{{font-size:28px;font-weight:650;line-height:1.15}}
.kachel .name{{font-size:13px;color:var(--tinte-2)}}
.kachel .zusatz{{font-size:12px;color:var(--gedaempft)}}
table{{border-collapse:collapse;width:100%;margin:10px 0;font-size:13.5px}}
th{{text-align:left;font-weight:600;color:var(--tinte-2);font-size:12px;border-bottom:1px solid var(--achse);padding:6px 10px 6px 0;vertical-align:bottom}}
td{{border-bottom:1px solid var(--raster);padding:7px 10px 7px 0;vertical-align:top}}
td.zahl,th.zahl{{text-align:right;font-variant-numeric:tabular-nums}}
.tabelle-breit{{overflow-x:auto}} .nw{{white-space:nowrap}} td.wert{{min-width:230px}}
table.eintraege{{table-layout:fixed}} .eintrag{{break-inside:avoid}}
.eintrag .haupt td{{border-bottom:0;padding-bottom:3px}} .eintrag .technik td{{padding-top:0;overflow-wrap:anywhere}}
.marke{{display:inline-block;border:1px solid var(--achse);border-radius:999px;padding:0 8px;font-size:12px;
  line-height:20px;white-space:nowrap;color:var(--tinte-2)}}
.punkt{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:5px;vertical-align:-1px}}
.beleg{{font:12px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:nowrap}}
.karte{{border:1px solid var(--rand);border-radius:8px;padding:14px 16px;margin:12px 0;break-inside:avoid}}
.karte h3{{margin:0 0 6px}} .karte .zeile{{display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center;margin:8px 0 0}}
.einfach{{border-left:3px solid var(--serie);padding:2px 0 2px 12px;margin:10px 0;color:var(--tinte-2)}}
.einfach b{{color:var(--tinte)}}
.hypothese{{border-style:dashed}}
figure{{margin:16px 0;break-inside:avoid}} figcaption{{font-size:13px;color:var(--tinte-2);margin-top:6px}}
svg{{display:block;max-width:100%;height:auto}}
svg text{{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;fill:var(--tinte)}}
svg .zweit{{fill:var(--tinte-2)}} svg .leise{{fill:var(--gedaempft)}}
.legende{{display:flex;flex-wrap:wrap;gap:6px 18px;font-size:13px;color:var(--tinte-2);margin:8px 0}}
.legende span{{white-space:nowrap}}
.zeitachse{{list-style:none;padding:0;margin:14px 0}}
.zeitachse li{{display:grid;grid-template-columns:170px 18px 1fr;gap:0 10px;margin:0;position:relative}}
.zeitachse time{{font-variant-numeric:tabular-nums;color:var(--tinte-2);font-size:13px;padding-top:1px;text-align:right}}
.zeitachse .spur{{position:relative}}
.zeitachse .spur::before{{content:"";position:absolute;left:8px;top:0;bottom:0;width:1px;background:var(--achse)}}
.zeitachse li:first-child .spur::before{{top:8px}} .zeitachse li:last-child .spur::before{{bottom:calc(100% - 8px)}}
.zeitachse .spur::after{{content:"";position:absolute;left:3px;top:5px;width:10px;height:10px;border-radius:50%;
  background:var(--serie);box-shadow:0 0 0 2px var(--flaeche)}}
.zeitachse .text{{padding-bottom:16px}}
.fuss{{margin-top:48px;padding-top:14px;border-top:1px solid var(--raster);font-size:12.5px;color:var(--tinte-2)}}
@media print{{
  :root{{--flaeche:#fff;--seite:#fff}}
  *{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  body{{background:#fff;font-size:13.5px}} main{{border:0;max-width:none;padding:0;min-height:0;background:#fff}}
  h2{{break-after:avoid;margin-top:28px}} h3{{break-after:avoid}} tr{{break-inside:avoid}}
  tr:first-child{{break-after:avoid}} thead{{display:table-header-group}}
  a{{text-decoration:none}} .nicht-drucken{{display:none}}}}
@page{{size:A4;margin:16mm 14mm}}
"""


def seite(titel: str, inhalt: str) -> str:
    return (f'<!DOCTYPE html>\n<html lang="de-CH"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{esc(titel)}</title><style>{STIL}</style></head>\n<body><main>\n{inhalt}\n</main></body></html>\n')


def kuerzen(text: str, n: int) -> str:
    t = str(text)
    return t if len(t) <= n else t[: n - 1].rstrip() + "…"


def kachel(wert: object, name: str, zusatz: str = "") -> str:
    z = f'<div class="zusatz">{esc(zusatz)}</div>' if zusatz else ""
    return f'<div class="kachel"><div class="wert">{esc(str(wert))}</div><div class="name">{esc(name)}</div>{z}</div>'


# --------------------------------------------------------------------------- Balkendiagramm

def balken(zeilen: list[dict], *, maximum: float | None = None, beschriftung: str = "",
           breite: int = 760, namensspalte: int = 230) -> str:
    """Waagrechte Balken, ein Wert je Zeile, Wert an der Balkenspitze.

    zeilen: [{"name": str, "wert": float, "anzeige": str, "farbe": css (optional), "hinweis": str (optional)}]
    """
    if not zeilen:
        return ""
    hoehe_zeile, dicke, oben = 30, 14, 6
    wertspalte = 96
    lauf = breite - namensspalte - wertspalte
    hoechst = maximum or max(z["wert"] for z in zeilen) or 1
    hoehe = oben + hoehe_zeile * len(zeilen) + 6
    teile = [f'<svg viewBox="0 0 {breite} {hoehe}" role="img" aria-label="{esc(beschriftung)}">',
             f'<line x1="{namensspalte}" y1="{oben}" x2="{namensspalte}" y2="{hoehe - 6}" stroke="var(--achse)" stroke-width="1"/>']
    for i, z in enumerate(zeilen):
        y = oben + i * hoehe_zeile + (hoehe_zeile - dicke) / 2
        mitte = y + dicke / 2 + 4.5
        w = max(0.0, min(1.0, z["wert"] / hoechst)) * lauf
        farbe = z.get("farbe", "var(--serie)")
        titel = esc(f'{z["name"]}: {z["anzeige"]}' + (f' ({z["hinweis"]})' if z.get("hinweis") else ""))
        teile.append(f'<g><title>{titel}</title>')
        teile.append(f'<text x="{namensspalte - 10}" y="{mitte:.1f}" text-anchor="end" font-size="13">{esc(kuerzen(z["name"], 30))}</text>')
        if w >= 1:
            r = min(4, w)
            x0, x1 = namensspalte, namensspalte + w
            teile.append(f'<path d="M{x0},{y:.1f} H{x1 - r:.1f} Q{x1:.1f},{y:.1f} {x1:.1f},{y + r:.1f} V{y + dicke - r:.1f} '
                         f'Q{x1:.1f},{y + dicke:.1f} {x1 - r:.1f},{y + dicke:.1f} H{x0} Z" fill="{farbe}"/>')
        teile.append(f'<text x="{namensspalte + w + 8:.1f}" y="{mitte:.1f}" font-size="13" class="zweit">{esc(z["anzeige"])}</text>')
        teile.append("</g>")
    teile.append("</svg>")
    return "".join(teile)


# --------------------------------------------------------------------------- Beziehungsgraf

STATUS = {  # Bewertung -> (Bezeichnung, Farbe, Zeichen im Knoten, Zeichenfarbe)
    "boesartig": ("Bösartig", "var(--kritisch)", "!", "#ffffff"),
    "verdaechtig": ("Verdächtig", "var(--warnung)", "~", "#0b0b0b"),
    "unauffaellig": ("Unauffällig", "var(--gut)", "✓", "#ffffff"),
    "unbekannt": ("Unbekannt", "var(--neutral)", "?", "#ffffff"),
}
TYPEN = {  # Indikatortyp -> (Kurzbezeichnung, Form)
    "ip": ("IP", "kreis"), "domain": ("Domain", "quadrat"), "url": ("URL", "raute"),
    "hash": ("Datei", "sechseck"), "gruppe": ("Gruppe", "dreieck"), "onion": ("Onion", "fuenfeck"),
    "konto": ("Konto", "fuenfeck"), "email": ("E-Mail", "fuenfeck"), "wallet": ("Wallet", "fuenfeck"),
    "sonstiges": ("Sonstiges", "fuenfeck"),
}


def _form(form: str, x: float, y: float, r: float, attribute: str) -> str:
    def vieleck(n: int, drehung: float, faktor: float = 1.0) -> str:
        punkte = " ".join(f"{x + r * faktor * math.cos(drehung + 2 * math.pi * i / n):.1f},"
                          f"{y + r * faktor * math.sin(drehung + 2 * math.pi * i / n):.1f}" for i in range(n))
        return f'<polygon points="{punkte}" {attribute}/>'
    if form == "kreis":
        return f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" {attribute}/>'
    if form == "quadrat":
        s = r * 0.9
        return f'<rect x="{x - s:.1f}" y="{y - s:.1f}" width="{2 * s:.1f}" height="{2 * s:.1f}" rx="3" {attribute}/>'
    if form == "raute":
        return vieleck(4, 0, 1.15)
    if form == "sechseck":
        return vieleck(6, 0, 1.08)
    if form == "dreieck":
        return vieleck(3, -math.pi / 2, 1.25)
    return vieleck(5, -math.pi / 2, 1.1)


def _anordnen(knoten: list[str], kanten: list[tuple[str, str]], breite: float, hoehe: float) -> dict:
    """Kräftebasierte Anordnung (Fruchterman-Reingold) mit festem Startwert: gleiche Daten, gleiches Bild."""
    zufall = random.Random(20261113)
    n = len(knoten)
    if n == 1:
        return {knoten[0]: (breite / 2, hoehe / 2)}
    pos = {k: [zufall.uniform(0.25, 0.75) * breite, zufall.uniform(0.25, 0.75) * hoehe] for k in knoten}
    ideal = 0.85 * math.sqrt(breite * hoehe / n)
    temperatur = breite / 6
    for _ in range(400):
        schub = {k: [0.0, 0.0] for k in knoten}
        for i, a in enumerate(knoten):
            for b in knoten[i + 1:]:
                dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
                d = max(math.hypot(dx, dy), 0.5)
                kraft = ideal * ideal / d
                schub[a][0] += dx / d * kraft; schub[a][1] += dy / d * kraft
                schub[b][0] -= dx / d * kraft; schub[b][1] -= dy / d * kraft
        for a, b in kanten:
            dx, dy = pos[a][0] - pos[b][0], pos[a][1] - pos[b][1]
            d = max(math.hypot(dx, dy), 0.5)
            kraft = d * d / ideal
            schub[a][0] -= dx / d * kraft; schub[a][1] -= dy / d * kraft
            schub[b][0] += dx / d * kraft; schub[b][1] += dy / d * kraft
        for k in knoten:   # leichter Zug zur Mitte hält unverbundene Knoten im Bild
            schub[k][0] += (breite / 2 - pos[k][0]) * 0.06
            schub[k][1] += (hoehe / 2 - pos[k][1]) * 0.10
            laenge = max(math.hypot(*schub[k]), 0.01)
            pos[k][0] += schub[k][0] / laenge * min(laenge, temperatur)
            pos[k][1] += schub[k][1] / laenge * min(laenge, temperatur)
        temperatur = max(temperatur * 0.985, 1.0)
    xs, ys = [p[0] for p in pos.values()], [p[1] for p in pos.values()]
    spanne_x, spanne_y = (max(xs) - min(xs)) or 1, (max(ys) - min(ys)) or 1
    return {k: ((p[0] - min(xs)) / spanne_x * breite, (p[1] - min(ys)) / spanne_y * hoehe) for k, p in pos.items()}


def _ueberlappung(a: tuple, b: tuple) -> tuple[float, float]:
    """Überlappung zweier Rechtecke (x0, y0, x1, y1) je Achse. Werte <= 0 heissen: keine."""
    return min(a[2], b[2]) - max(a[0], b[0]), min(a[3], b[3]) - max(a[1], b[1])


def _entzerren(pos: dict, masse: dict, breite: float, hoehe: float, abstand: float = 26) -> dict:
    """Schiebt Knoten samt Beschriftung auseinander, bis sich keine zwei Kästen mehr überlagern."""
    pos = {k: list(v) for k, v in pos.items()}
    namen = list(pos)

    def kasten(k: str) -> tuple:
        b, oben, unten = masse[k]
        return (pos[k][0] - b / 2 - abstand / 2, pos[k][1] - oben - abstand / 2,
                pos[k][0] + b / 2 + abstand / 2, pos[k][1] + unten + abstand / 2)

    for _ in range(400):
        bewegt = False
        for i, a in enumerate(namen):
            for b in namen[i + 1:]:
                dx, dy = _ueberlappung(kasten(a), kasten(b))
                if dx <= 0 or dy <= 0:
                    continue
                bewegt = True
                if dx < dy:      # entlang der Achse mit der kleineren Überlappung trennen
                    richtung = 1 if pos[a][0] >= pos[b][0] else -1
                    pos[a][0] += richtung * dx / 2; pos[b][0] -= richtung * dx / 2
                else:
                    richtung = 1 if pos[a][1] >= pos[b][1] else -1
                    pos[a][1] += richtung * dy / 2; pos[b][1] -= richtung * dy / 2
        for k in namen:          # im Bild halten
            b, oben, unten = masse[k]
            pos[k][0] = min(max(pos[k][0], b / 2 + 4), breite - b / 2 - 4)
            pos[k][1] = min(max(pos[k][1], oben + 4), hoehe - unten - 4)
        if not bewegt:
            break
    return {k: (v[0], v[1]) for k, v in pos.items()}


def graf(knoten: list[dict], kanten: list[dict]) -> str:
    """Beziehungsgraf. knoten: [{"id","typ","wert","bewertung"}], kanten: [{"von","nach","art","sicherheit"}]."""
    if not knoten:
        return ""
    breite = 900
    hoehe = 460 if len(knoten) <= 6 else 600 if len(knoten) <= 12 else 780
    r = 15
    ids = [k["id"] for k in knoten]
    paare = [(k["von"], k["nach"]) for k in kanten if k["von"] in ids and k["nach"] in ids and k["von"] != k["nach"]]
    texte, masse = {}, {}
    for k in knoten:
        kurz, _ = TYPEN.get(k.get("typ") or "sonstiges", TYPEN["sonstiges"])
        zeile1, zeile2 = f'{k["id"]} · {kurz}', kuerzen(k["wert"], 28)
        texte[k["id"]] = (zeile1, zeile2)
        masse[k["id"]] = (max(len(zeile1) * 7.4, len(zeile2) * 6.6, 2 * r) + 8, r + 4, r + 38)   # Breite, über und unter der Mitte
    pos = _anordnen(ids, paare, breite - 240, hoehe - 130)
    pos = _entzerren({k: (x + 120, y + 40) for k, (x, y) in pos.items()}, masse, breite, hoehe)

    def kasten(k: str) -> tuple:
        b, oben, unten = masse[k]
        return pos[k][0] - b / 2, pos[k][1] - oben, pos[k][0] + b / 2, pos[k][1] + unten

    teile = [f'<svg viewBox="0 0 {breite} {hoehe}" role="img" aria-label="Beziehungsgraf der Indikatoren">']
    for k in kanten:
        if (k["von"], k["nach"]) not in paare:
            continue
        (x1, y1), (x2, y2) = pos[k["von"]], pos[k["nach"]]
        strich = ' stroke-dasharray="5 4"' if k.get("sicherheit") == "tief" else ""
        teile.append(f'<g><title>{esc(k["von"])} {esc(k.get("art", ""))} {esc(k["nach"])}</title>'
                     f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="var(--gedaempft)" stroke-width="1.5"{strich}/></g>')
    belegt: list[tuple] = []
    for k in kanten:   # Beschriftungen über allen Linien, an der freiesten Stelle der Kante
        if (k["von"], k["nach"]) not in paare or not k.get("art"):
            continue
        (x1, y1), (x2, y2) = pos[k["von"]], pos[k["nach"]]
        text = kuerzen(k["art"], 26)
        halb = len(text) * 6.4 / 2 + 4
        beste, wenigste = None, None
        for t in (0.5, 0.42, 0.58, 0.34, 0.66, 0.27, 0.73):
            x, y = x1 + (x2 - x1) * t, y1 + (y2 - y1) * t
            feld = (x - halb, y - 16, x + halb, y + 2)
            stoerung = sum(max(0.0, dx) * max(0.0, dy) for dx, dy in
                           [_ueberlappung(feld, kasten(n)) for n in ids] + [_ueberlappung(feld, f) for f in belegt])
            if wenigste is None or stoerung < wenigste:
                beste, wenigste = (x, y, feld), stoerung
            if stoerung == 0:
                break
        x, y, feld = beste
        belegt.append(feld)
        teile.append(f'<text x="{x:.1f}" y="{y - 4:.1f}" text-anchor="middle" font-size="11.5" class="zweit" '
                     f'stroke="var(--flaeche)" stroke-width="4" paint-order="stroke" stroke-linejoin="round">{esc(text)}</text>')
    halo = 'stroke="var(--flaeche)" stroke-width="4" paint-order="stroke" stroke-linejoin="round"'
    for k in knoten:
        x, y = pos[k["id"]]
        name, farbe, zeichen, zeichenfarbe = STATUS.get(k.get("bewertung") or "unbekannt", STATUS["unbekannt"])
        kurz, form = TYPEN.get(k.get("typ") or "sonstiges", TYPEN["sonstiges"])
        zeile1, zeile2 = texte[k["id"]]
        teile.append(f'<g><title>{esc(k["id"])} · {esc(kurz)} · {esc(k["wert"])} · {esc(name)}</title>')
        teile.append(_form(form, x, y, r, f'fill="{farbe}" stroke="var(--flaeche)" stroke-width="2"'))
        teile.append(f'<text x="{x:.1f}" y="{y + 4.5:.1f}" text-anchor="middle" font-size="13" font-weight="700" style="fill:{zeichenfarbe}">{zeichen}</text>')
        teile.append(f'<text x="{x:.1f}" y="{y + r + 16:.1f}" text-anchor="middle" font-size="12" font-weight="600" {halo}>{esc(zeile1)}</text>')
        teile.append(f'<text x="{x:.1f}" y="{y + r + 31:.1f}" text-anchor="middle" font-size="11.5" class="zweit" {halo}>{esc(zeile2)}</text>')
        teile.append("</g>")
    teile.append("</svg>")
    return "".join(teile)


def graf_legende(knoten: list[dict], kanten: list[dict]) -> str:
    teile = ['<div class="legende">']
    for schluessel in ("boesartig", "verdaechtig", "unauffaellig", "unbekannt"):
        if any((k.get("bewertung") or "unbekannt") == schluessel for k in knoten):
            name, farbe, zeichen, _ = STATUS[schluessel]
            teile.append(f'<span><span class="punkt" style="background:{farbe}"></span>{esc(zeichen)} {esc(name)}</span>')
    formen = {}
    for k in knoten:
        kurz, form = TYPEN.get(k.get("typ") or "sonstiges", TYPEN["sonstiges"])
        formen.setdefault(form, []).append(kurz)
    for form, namen in formen.items():
        symbol = _form(form, 8, 8, 6, 'fill="none" stroke="var(--tinte-2)" stroke-width="1.5"')
        teile.append(f'<span><svg viewBox="0 0 16 16" width="16" height="16" style="display:inline-block;vertical-align:-3px">{symbol}</svg> '
                     f'{esc(" / ".join(sorted(set(namen))))}</span>')
    if any(k.get("sicherheit") == "tief" for k in kanten):
        teile.append('<span>- - -  unsichere Verbindung (Sicherheit tief)</span>')
    teile.append("</div>")
    return "".join(teile)
