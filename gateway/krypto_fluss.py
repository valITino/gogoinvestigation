"""Geldfluss verfolgen: Wohin ist ein Betrag gegangen, und wo lässt sich ansetzen?

Ausgangspunkt ist eine Zahlung (oder alles, was eine Adresse verlassen hat). Von dort folgt das Modul dem
Geld Station um Station, bis es an einer Stelle ankommt, an der die Verfolgung endet:

    liegt     Das Geld liegt unbewegt auf einer Adresse.
    dienst    Es ist bei einem benannten Dienst angekommen (Börse, Zahlungsdienst). Dort ist ein
              Editionsbegehren möglich: Der Dienst weiss, wem die Einzahlung gutgeschrieben wurde.
    sammel    Es ist in einer Sammelbewegung aufgegangen, wie sie Dienste machen. Name unbekannt.
    mischer   Es ging an einen Mischdienst (laut Etikett) oder durch eine Transaktion mit dessen Muster.
    vertrag   Es ging an ein Programm auf der Kette (Tauschbörse, Brücke). Was dieses damit tat, ist
              mit den hier genutzten Quellen nicht sichtbar.
    grenze    Die Verfolgung wurde abgebrochen: Tiefe, Kleinbetrag, Abfragebudget, oder die Quelle hat nicht
              geantwortet. Das Ergebnis nennt, wo sich fortsetzen lässt.
    gebuehr   Anteil, der als Transaktionsgebühr an die Miner ging (Bitcoin).
    unklar    Kein passender Abgang gefunden, oder eine Form, der sich nicht folgen lässt.

Die Summe aller Enden ist der Startbetrag. Was nicht aufgeht, wird als «unklar» ausgewiesen, nie verschwiegen.

Zwei Verfahren, weil die Ketten verschieden buchen:

Bitcoin kennt keine Kontostände, sondern einzelne Zahlungsausgänge, die jeweils genau einmal ausgegeben
werden. Welcher Ausgang wohin ging, ist eine Tatsache der Kette. Legt eine Transaktion mehrere Eingänge
zusammen und verteilt sie auf mehrere Ausgänge, ist nicht bestimmbar, welcher Franken wohin ging. Der verfolgte
Betrag wird dann im Verhältnis der Ausgänge aufgeteilt (anteilige Zuordnung).

Ethereum, TRON und Verwandte führen Kontostände. Geht ein Betrag auf einer Adresse ein, wird er den nächsten
Abgängen derselben Währung zugeordnet, in ihrer zeitlichen Reihenfolge, bis er aufgebraucht ist («zuerst
herein, zuerst hinaus»). Lag dort schon Guthaben, ist das eine Annahme. Sie ist üblich, aber nicht zwingend.

Jede einzelne Zahlung im Ergebnis ist eine Feststellung aus der Kette. Die Zuordnung über mehrere Stationen ist
eine Bewertung nach dem genannten Verfahren.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .kern import Abbruch, Vorgang
from .krypto_ketten import (SEITE, Kette, Quellfehler, Wert, btc_tx, btc_txs, btc_verbleib, dezimal, evm_adresse,
                            evm_token_stand, gleich, konto_zahlungen, nach, tron_konto, zeit_iso)
from .krypto_zuordnung import Zuordner, dienst, kurz, mischer

ENDEN = {  # Art -> (Bezeichnung, Erklärung für Leser ohne Vorwissen)
    "dienst": ("Bei einem Dienst angekommen", "Börse oder Zahlungsdienst. Der Dienst weiss, welchem Kunden die Einzahlung gutgeschrieben wurde."),
    "sammel": ("In Sammelbewegung aufgegangen", "Muster eines Dienstes, der Kundengelder zusammenlegt. Der Name ist nicht bekannt."),
    "liegt": ("Liegt unbewegt", "Der Betrag wurde seit dem Eingang nicht weitergeleitet."),
    "mischer": ("Durch Mischdienst", "Mischdienst laut Etikett, oder Transaktion mit dessen Muster: Viele Beteiligte legen gleiche Beträge zusammen, damit die Zuordnung verloren geht."),
    "vertrag": ("An Programm auf der Kette", "Tauschbörse, Brücke oder anderes Programm. Was dort geschah, zeigen die genutzten Quellen nicht."),
    "grenze": ("Nicht weiterverfolgt", "Verfolgung an dieser Stelle beendet: Tiefe, Kleinbetrag, Abfragebudget, oder die Quelle hat nicht geantwortet."),
    "gebuehr": ("Transaktionsgebühren", "Anteil, der als Gebühr an die Betreiber des Netzes ging."),
    "unklar": ("Verbleib unklar", "Kein passender Abgang gefunden, oder eine Form, der sich nicht folgen lässt."),
}
SAMMEL_EINGAENGE = 8      # Bitcoin: ab so vielen verschiedenen Absenderadressen gilt eine Transaktion als Sammelbewegung
SAMMEL_AUSGAENGE = 20     # Bitcoin: ab so vielen Empfängern gilt sie als Sammelauszahlung
MISCH_GLEICHE = 5         # Bitcoin: ab so vielen gleich hohen Ausgängen (und Eingängen) Muster eines Mischdienstes
START_SEITEN = 6          # Bitcoin: so viele Seiten zu 50 Transaktionen werden für eine Startadresse geladen
KLEIN_JE_STATION = 12     # Konto-Ketten: so viele Empfänger von Kleinbeträgen zeigt eine Station einzeln, die grössten zuerst


@dataclass
class Grenzen:
    tiefe: int = 4               # wie viele Stationen ab dem Start
    min_anteil: float = 0.02     # Teilbeträge unter diesem Anteil des Startbetrags werden nicht weiterverfolgt
    stationen: int = 60          # Höchstzahl Stationen im Ergebnis


@dataclass
class Graf:
    kette: Kette
    wert: Wert
    start: int = 0                                           # Startbetrag in kleinster Einheit
    knoten: dict[str, dict] = field(default_factory=dict)    # Schlüssel -> Station
    kanten: dict[tuple[str, str], dict] = field(default_factory=dict)
    enden: list[dict] = field(default_factory=list)
    hinweise: list[str] = field(default_factory=list)

    def station(self, schluessel: str, adresse: str | None, tiefe: int) -> dict:
        k = self.knoten.get(schluessel)
        if k is None:
            k = self.knoten[schluessel] = {"nr": len(self.knoten) + 1, "schluessel": schluessel, "adresse": adresse, "tiefe": tiefe,
                                           "betrag": 0, "hinweise": [], "rolle": "start" if tiefe == 0 else "station"}
        return k

    def fluss(self, von: str, an: str, betrag: int, tx: str | None, zeit: int | None, passgenau: bool = False) -> None:
        k = self.kanten.setdefault((von, an), {"betrag": 0, "tx": [], "zeit_von": zeit, "zeit_bis": zeit, "anzahl": 0, "passgenau": True})
        k["betrag"] += betrag
        k["anzahl"] += 1
        k["passgenau"] = k["passgenau"] and passgenau
        if tx and tx not in k["tx"] and len(k["tx"]) < 6:
            k["tx"].append(tx)
        if zeit:
            k["zeit_von"] = min(k["zeit_von"] or zeit, zeit)
            k["zeit_bis"] = max(k["zeit_bis"] or zeit, zeit)
        self.knoten[an]["betrag"] += betrag

    def ende(self, schluessel: str | None, art: str, betrag: int, text: str = "", **mehr: Any) -> None:
        if betrag <= 0:
            return
        for e in self.enden:
            if e["knoten"] == schluessel and e["art"] == art and e.get("text") == text and e.get("name") == mehr.get("name"):
                e["betrag"] += betrag
                return
        self.enden.append({"knoten": schluessel, "art": art, "betrag": betrag, "text": text, **mehr})

    def hinweis(self, text: str) -> None:
        if text not in self.hinweise:
            self.hinweise.append(text)

    @property
    def verteilt(self) -> int:
        return sum(e["betrag"] for e in self.enden)


def _notiz(k: dict, text: str) -> None:
    if text not in k["hinweise"]:
        k["hinweise"].append(text)


# --------------------------------------------------------------------------- Bitcoin

def muster(tx: dict) -> tuple[str | None, str]:
    """Erkennt an der Form einer Bitcoin-Transaktion, ob hier ein Dienst oder ein Mischdienst am Werk ist.
    Rückgabe: (None | 'mischer' | 'sammel', Begründung)."""
    ein = {e["adresse"] for e in tx["eingaenge"] if e.get("adresse")}
    aus = [a for a in tx["ausgaenge"] if a["betrag"] > 0]
    haeufig = Counter(a["betrag"] for a in aus).most_common(1)
    if haeufig and haeufig[0][1] >= MISCH_GLEICHE and len(tx["eingaenge"]) >= MISCH_GLEICHE:
        return "mischer", (f"{haeufig[0][1]} Ausgänge über denselben Betrag bei {len(tx['eingaenge'])} Eingängen: "
                           "Muster eines Mischdienstes (CoinJoin)")
    if len(ein) >= SAMMEL_EINGAENGE:
        return "sammel", f"legt Guthaben von {len(ein)} Adressen zusammen: Muster eines Dienstes, der Einzahlungen einsammelt"
    if len(aus) >= SAMMEL_AUSGAENGE:
        return "sammel", f"zahlt in einer Transaktion an {len(aus)} Empfänger aus: Muster eines Dienstes"
    return None, ""


async def btc_start(v: Vorgang, g: Graf, *, tx: dict | None, adresse: str | None) -> tuple[list[tuple], dict]:
    """Bestimmt die Ausgänge, von denen die Verfolgung ausgeht. Rückgabe: (Arbeitsposten, Vorwissen).
    Vorwissen erspart Abfragen: Wer die Transaktionen einer Adresse schon kennt, weiss auch, welche davon
    welchen Eingang wieder ausgegeben hat."""
    posten: list[tuple] = []
    wissen: dict = {"ausgegeben_in": {}, "vollstaendig": set()}
    if tx is not None:
        treffer = [a for a in tx["ausgaenge"] if a["betrag"] > 0 and (adresse is None or gleich(g.kette, a.get("adresse"), adresse))]
        if adresse is None and len([a for a in tx["ausgaenge"] if a["betrag"] > 0]) > 1:
            liste = "; ".join(f"{a.get('adresse') or 'ohne Adresse'} ({dezimal(a['betrag'], 8)} BTC)" for a in tx["ausgaenge"][:12] if a["betrag"] > 0)
            raise Abbruch("Die Transaktion hat mehrere Empfänger. Bitte mit 'adresse' angeben, welcher Zahlung gefolgt werden soll "
                          f"(die andere ist meist das Wechselgeld des Absenders): {liste}")
        if not treffer:
            raise Abbruch(f"Die Transaktion {tx['tx']} zahlt nicht an {adresse}. Empfänger: "
                          + ", ".join(str(a.get("adresse")) for a in tx["ausgaenge"][:12]))
        for a in treffer:
            posten.append((0, tx["tx"], a["nr"], a.get("adresse"), a["betrag"], tx.get("zeit")))
        return posten, wissen
    assert adresse
    seiten, letzte, alle = 0, None, []
    while True:
        _, txs = await btc_txs(v, adresse, letzte, schritt="Transaktionen der Startadresse")
        seiten += 1
        alle += txs
        if len(txs) < 50:
            wissen["vollstaendig"].add(adresse)
            break
        if seiten >= START_SEITEN:
            g.hinweis(f"Die Startadresse hat mehr als {len(alle)} Transaktionen. Verfolgt werden die Eingänge aus den {len(alle)} jüngsten.")
            break
        letzte = txs[-1]["tx"]
    for t in alle:
        for a in t["ausgaenge"]:
            if a["betrag"] > 0 and gleich(g.kette, a.get("adresse"), adresse):
                posten.append((0, t["tx"], a["nr"], adresse, a["betrag"], t.get("zeit")))
        for e in t["eingaenge"]:
            if gleich(g.kette, e.get("adresse"), adresse):
                wissen["ausgegeben_in"][(e["tx"], e["ausgang"])] = t
    if not posten:
        raise Abbruch(f"Auf {adresse} sind keine Eingänge verzeichnet. Es gibt nichts zu verfolgen.")
    return posten, wissen


async def btc_fluss(v: Vorgang, z: Zuordner, g: Graf, posten: list[tuple], grenzen: Grenzen, wissen: dict | None = None) -> None:
    """Folgt Bitcoin-Ausgängen, Ebene um Ebene. posten: [(tiefe, tx, nr, adresse, betrag, zeit)]. wissen: siehe btc_start.

    Verfolgt wird je Zahlungsausgang (Transaktion und Nummer). Was aus mehreren Eingängen in denselben Ausgang
    fliesst, wird erst zusammengezählt und dann beurteilt: Sonst gälte ein grosser Betrag als viele Kleinbeträge,
    nur weil er aus vielen einzelnen Eingängen stammt."""
    ausgegeben_in = (wissen or {}).get("ausgegeben_in") or {}
    vollstaendig = (wissen or {}).get("vollstaendig") or set()
    g.start = sum(p[4] for p in posten)
    klein = max(1, int(g.start * grenzen.min_anteil))
    verbleib: dict[str, list[dict]] = {}
    geholt: dict[str, dict | None] = {}
    ebene: dict[tuple[str, int], dict] = {}
    for _, tx, nr, adresse, betrag, zeit in posten:
        g.station(adresse or f"{tx}:{nr}", adresse, 0)["betrag"] += betrag
        e = ebene.setdefault((tx, nr), {"adresse": adresse, "zeit": zeit, "anteil": 0})
        e["anteil"] += betrag
    tiefe = 0
    while ebene:
        naechste: dict[tuple[str, int], dict] = {}
        je_adresse: Counter = Counter()
        for (tx, nr), e in ebene.items():
            je_adresse[e["adresse"] or f"{tx}:{nr}"] += e["anteil"]
        for (tx, nr), e in sorted(ebene.items(), key=lambda x: (-je_adresse[x[1]["adresse"] or f"{x[0][0]}:{x[0][1]}"], -x[1]["anteil"])):
            adresse, zeit, anteil = e["adresse"], e["zeit"], e["anteil"]
            schluessel = adresse or f"{tx}:{nr}"
            k = g.knoten[schluessel]
            weiter_bei = {"tx": tx, "adresse": adresse}
            if tiefe > 0 and not adresse:
                g.ende(schluessel, "unklar", anteil, "Ausgang ohne gewöhnliche Adresse (Sonderform), nicht weiterverfolgt")
                continue
            if tiefe > grenzen.tiefe:
                g.ende(schluessel, "grenze", anteil, f"Tiefe von {grenzen.tiefe} Stationen erreicht", fortsetzen=weiter_bei)
                continue
            if tiefe > 0 and je_adresse[schluessel] < klein:
                g.ende(schluessel, "grenze", anteil, f"Teilbetrag unter {grenzen.min_anteil:.0%} des Startbetrags", fortsetzen=weiter_bei)
                continue
            if v.erschoepft:
                g.ende(schluessel, "grenze", anteil, "Abfragebudget aufgebraucht", fortsetzen=weiter_bei)
                continue
            try:
                if (tx, nr) in ausgegeben_in:                       # schon bekannt aus den Transaktionen der Startadresse
                    folge = ausgegeben_in[(tx, nr)]
                elif adresse in vollstaendig:
                    g.ende(schluessel, "liegt", anteil, f"unbewegt seit {zeit_iso(zeit) or 'Eingang (noch unbestätigt)'}", seit=zeit)
                    continue
                else:
                    if tx not in verbleib:
                        _, verbleib[tx] = await btc_verbleib(v, tx, schritt=f"Station {k['nr']}: Wurde der Ausgang weitergeleitet?")
                    stand = verbleib[tx][nr] if nr < len(verbleib[tx]) else {"ausgegeben": False}
                    if not stand["ausgegeben"]:
                        g.ende(schluessel, "liegt", anteil, f"unbewegt seit {zeit_iso(zeit) or 'Eingang (noch unbestätigt)'}", seit=zeit)
                        continue
                    if stand["tx"] not in geholt:
                        _, geholt[stand["tx"]] = await btc_tx(v, stand["tx"], schritt=f"Station {k['nr']}: Transaktion, die den Betrag weiterleitet")
                    folge = geholt[stand["tx"]]
                    if folge is None:
                        g.ende(schluessel, "unklar", anteil, f"Die weiterleitende Transaktion {stand['tx']} ist der Quelle nicht bekannt")
                        continue
            except Quellfehler as fehler:
                g.ende(schluessel, "grenze", anteil, f"Abfrage fehlgeschlagen ({fehler.antwort.id}): {fehler.antwort.fehler}", fortsetzen=weiter_bei)
                continue
            art, grund = muster(folge)
            if art:
                g.ende(schluessel, art, anteil, grund, tx=folge["tx"], zeit=folge.get("zeit"))
                if art == "sammel":
                    k["rolle"] = "einzahlung" if k["rolle"] != "start" else k["rolle"]
                    k["sammel_tx"] = folge["tx"]
                continue
            mit = {x["adresse"] for x in folge["eingaenge"] if x.get("adresse") and not gleich(g.kette, x["adresse"], adresse)}
            if mit:
                k.setdefault("mitgenutzt", set()).update(mit)
            summe_ein = sum(x["betrag"] for x in folge["eingaenge"]) or anteil
            if not folge["bestaetigt"]:
                _notiz(k, f"Weiterleitung {folge['tx']} ist noch nicht bestätigt")
            einzeln = len(folge["eingaenge"]) == 1 and len([x for x in folge["ausgaenge"] if x["betrag"] > 0]) == 1
            weiter = 0
            for a in folge["ausgaenge"]:
                teil = anteil * a["betrag"] // summe_ein
                if teil <= 0:
                    continue
                weiter += teil
                ziel_s = a.get("adresse") or f"{folge['tx']}:{a['nr']}"
                if ziel_s not in g.knoten and len(g.knoten) >= grenzen.stationen:
                    g.ende(schluessel, "grenze", teil, f"Höchstzahl von {grenzen.stationen} Stationen erreicht",
                           fortsetzen={"tx": folge["tx"], "adresse": a.get("adresse")})
                    continue
                g.station(ziel_s, a.get("adresse"), tiefe + 1)
                g.fluss(schluessel, ziel_s, teil, folge["tx"], folge.get("zeit"), passgenau=einzeln)
                n = naechste.setdefault((folge["tx"], a["nr"]), {"adresse": a.get("adresse"), "zeit": folge.get("zeit"), "anteil": 0})
                n["anteil"] += teil
            g.ende(None, "gebuehr", anteil - weiter, "anteilige Transaktionsgebühren")
        ebene = naechste
        tiefe += 1
    for k in g.knoten.values():
        if isinstance(k.get("mitgenutzt"), set):
            andere = sorted(k.pop("mitgenutzt"))
            k["mitgenutzt"] = andere[:5]
            _notiz(k, f"zusammen mit {len(andere)} weiteren Adresse(n) ausgegeben: Hinweis auf dieselbe Brieftasche")


# --------------------------------------------------------------------------- Konto-Ketten (Ethereum-Familie, TRON)

def _etikett_ende(g: Graf, z: Zuordner, adresse: str, betrag: int) -> bool:
    """Beendet die Verfolgung an einer Adresse, die laut Etikett einem Mischdienst oder einem Dienst mit Kunden gehört."""
    marken = z.bekannt(g.kette, adresse)
    name = mischer(marken)
    if name:
        g.ende(adresse, "mischer", betrag, "laut Etikett ein Mischdienst", name=name)
        return True
    name = dienst(marken)
    if name:
        g.ende(adresse, "dienst", betrag, "laut Etikett ein Dienst", name=name)
        return True
    return False


async def _konto_stand(v: Vorgang, kette: Kette, wert: Wert, adresse: str, nr: int) -> dict:
    """Vertrag ja/nein, Name und aktuelles Guthaben im verfolgten Wert."""
    schritt = f"Station {nr}: Konto oder Programm, aktuelles Guthaben"
    if kette.familie == "tron":
        _, konto = await tron_konto(v, adresse, schritt=schritt)
        guthaben = konto["guthaben"] if wert.vertrag is None else konto["trc20"].get(wert.vertrag, 0)
        return {"vertrag": konto["vertrag"], "name": None, "guthaben": guthaben, "etiketten": [], "aktiviert": konto["aktiviert"]}
    _, info = await evm_adresse(v, kette, adresse, schritt=schritt, zaehler=False)
    guthaben = info["guthaben"]
    if wert.vertrag is not None:
        guthaben = await evm_token_stand(v, kette, adresse, wert, f"Station {nr}: Guthaben {wert.symbol}")
    return {"vertrag": info["vertrag"], "name": info["name"], "guthaben": guthaben, "etiketten": info["etiketten"], "aktiviert": True}


async def konto_fluss(v: Vorgang, z: Zuordner, g: Graf, start: list[dict], grenzen: Grenzen, alles_ab_start: bool = False) -> None:
    """Folgt einem Betrag über Konto-Ketten. start: [{"adresse", "betrag", "ab": Zahlung oder None}].
    ``alles_ab_start``: Am Start wird nicht ein Eingang verfolgt, sondern alles, was die Adresse verlassen hat."""
    kette, wert = g.kette, g.wert
    g.start = sum(s["betrag"] for s in start)
    for s in start:
        g.station(s["adresse"], s["adresse"], 0)["betrag"] += s["betrag"]
    belegt: Counter = Counter()                # schon zugeordneter Teil jedes Abgangs
    rest_guthaben: dict[str, int] = {}         # Guthaben je Adresse, das noch keinem Eingang zugeordnet ist
    abgaenge: dict[str, tuple[dict | None, list[dict], bool]] = {}
    gedrosselt: str | None = None              # Name der Quelle, sobald sie Abfragen mit HTTP 429 abweist
    ebene = [{"tiefe": 0, **s} for s in start]
    while ebene:
        tiefe = ebene[0]["tiefe"]
        je_adresse: dict[str, list[dict]] = {}
        for p in ebene:
            je_adresse.setdefault(p["adresse"], []).append(p)
        if tiefe > 0:                          # Etiketten für alle Stationen dieser Ebene in einem Zug
            await z.pruefen(kette, list(je_adresse))
        naechste: list[dict] = []
        reihenfolge = sorted(je_adresse, key=lambda a: -sum(p["betrag"] for p in je_adresse[a]))
        for adresse in reihenfolge:
            eingaenge = sorted(je_adresse[adresse], key=lambda p: ((p["ab"] or {}).get("zeit") or 0, (p["ab"] or {}).get("block") or 0))
            summe = sum(p["betrag"] for p in eingaenge)
            k = g.knoten[adresse]
            if tiefe > 0 and _etikett_ende(g, z, adresse, summe):
                continue
            if tiefe > grenzen.tiefe:
                g.ende(adresse, "grenze", summe, f"Tiefe von {grenzen.tiefe} Stationen erreicht",
                       fortsetzen={"adresse": adresse, "tx": (eingaenge[0]["ab"] or {}).get("tx")})
                continue
            if summe < max(1, int(g.start * grenzen.min_anteil)) and tiefe > 0:
                g.ende(adresse, "grenze", summe, f"Teilbetrag unter {grenzen.min_anteil:.0%} des Startbetrags",
                       fortsetzen={"adresse": adresse, "tx": (eingaenge[0]["ab"] or {}).get("tx")})
                continue
            if v.erschoepft:
                g.ende(adresse, "grenze", summe, "Abfragebudget aufgebraucht",
                       fortsetzen={"adresse": adresse, "tx": (eingaenge[0]["ab"] or {}).get("tx")})
                continue
            if gedrosselt:           # die Quelle hat eben erst zweimal abgewinkt: nicht für jede weitere Station erneut anklopfen
                g.ende(adresse, "grenze", summe, f"{gedrosselt} drosselt die Abfragen (HTTP 429)",
                       fortsetzen={"adresse": adresse, "tx": (eingaenge[0]["ab"] or {}).get("tx")})
                continue
            try:
                stand = await _konto_stand(v, kette, wert, adresse, k["nr"])
                for m in stand["etiketten"]:
                    z.merken(kette, adresse, [m])
                if stand["vertrag"]:
                    k["vertrag"] = True
                    if stand["name"]:
                        k["name"] = stand["name"]
                if tiefe > 0 and _etikett_ende(g, z, adresse, summe):
                    continue
                if stand["vertrag"] and wert.vertrag is None and tiefe > 0:
                    g.ende(adresse, "vertrag", summe, "Zahlung an ein Programm auf der Kette" + (f" ({stand['name']})" if stand["name"] else ""),
                           name=stand["name"])
                    continue
                erster = eingaenge[0]["ab"]
                if adresse not in abgaenge or (abgaenge[adresse][0] is not None and (erster is None or not nach(erster, abgaenge[adresse][0]))):
                    _, liste, voll = await konto_zahlungen(v, kette, adresse, wert, "aus", ab=erster,
                                                           schritt=f"Station {k['nr']}: Abgänge seit dem Eingang")
                    liste = [x for x in liste if x["ok"] and not gleich(kette, x["an"], adresse)]
                    gleiche: Counter = Counter()
                    for x in liste:             # Kennung je Abgang, auch wenn eine Transaktion zweimal denselben Betrag zahlt
                        merkmal = (adresse, x["tx"], x["an"], x["betrag"])
                        x["kennung"] = (*merkmal, gleiche[merkmal])
                        gleiche[merkmal] += 1
                    abgaenge[adresse] = (erster, liste, voll)
            except Quellfehler as e:
                weiter = {"adresse": adresse, "tx": (eingaenge[0]["ab"] or {}).get("tx")}
                if e.antwort.status == 429 and not e.nur_hier:
                    gedrosselt = e.antwort.quelle or "Die Quelle"
                    g.ende(adresse, "grenze", summe, f"{gedrosselt} drosselt die Abfragen (HTTP 429)", fortsetzen=weiter)
                    g.hinweis(f"{e.antwort.fehler} Beleg {e.antwort.id}. Die betroffenen Stationen stehen unter «Nicht weiterverfolgt».")
                else:
                    g.ende(adresse, "grenze", summe, f"Abfrage fehlgeschlagen ({e.antwort.id}): {e.antwort.fehler}", fortsetzen=weiter)
                continue
            _, liste, voll = abgaenge[adresse]
            # Bei der eigenen Währung zählt die Liste auch Aufrufe ohne Betrag mit. Der Text sagt, was gezählt wurde
            viele, vielen = ((f"über {SEITE} Abgänge", f"über {SEITE} Abgängen") if wert.vertrag is not None
                             else (f"über {SEITE} ausgehende Transaktionen", f"über {SEITE} ausgehenden Transaktionen"))
            hier_enden = tiefe > 0 or not alles_ab_start      # bei «alles ab der Startadresse» geht es mit dem gelesenen Teil weiter
            if voll and hier_enden and stand["vertrag"]:
                g.ende(adresse, "vertrag", summe, f"Programm auf der Kette mit {vielen} seit dem Eingang (Tauschbörse, Brücke oder Ähnliches)"
                       + (f": {stand['name']}" if stand["name"] else ""), name=stand["name"])
                continue
            if voll and hier_enden:
                g.ende(adresse, "sammel", summe, f"{viele} seit dem Eingang: Sammeladresse, vermutlich ein Dienst")
                continue
            if voll:
                g.hinweis(f"Die Startadresse hat mehr Abgänge, als ein Lauf liest. Verfolgt werden die ersten {len(liste)}.")
            rest_guthaben.setdefault(adresse, stand["guthaben"])
            zuteilung: list[tuple[dict, int, dict]] = []        # (Abgang, Teilbetrag, Eingang)
            for p in eingaenge:
                offen = p["betrag"]
                for x in liste:
                    if offen <= 0:
                        break
                    if not (alles_ab_start and tiefe == 0) and not nach(x, p["ab"]):
                        continue
                    frei = x["betrag"] - belegt[x["kennung"]]
                    if frei <= 0:
                        continue
                    teil = min(offen, frei)
                    belegt[x["kennung"]] += teil
                    offen -= teil
                    zuteilung.append((x, teil, p))
                if offen > 0:
                    liegt = min(offen, max(0, rest_guthaben[adresse]))
                    rest_guthaben[adresse] -= liegt
                    seit = (p["ab"] or {}).get("zeit")
                    g.ende(adresse, "liegt", liegt, f"unbewegt seit {zeit_iso(seit)}" if seit else "aktuelles Guthaben", seit=seit)
                    if offen - liegt > 0:
                        g.ende(adresse, "unklar", offen - liegt,
                               f"kein Abgang in {wert.symbol} gefunden: getauscht, in anderer Form abgeflossen oder als Gebühr verbraucht")
            # Wer bekommt eine eigene Station? Zuerst die grossen Empfänger. Von den Empfängern von Kleinbeträgen zeigt eine
            # Station die grössten einzeln, der Rest steht als Summe. So verbraucht eine Adresse, die an Hunderte zahlt,
            # nicht alle Stationen des Laufs, und die Höchstzahl trifft die kleinsten Beträge, nicht die spätesten.
            je_ziel: Counter = Counter()
            for x, teil, _ in zuteilung:
                je_ziel[x["an"]] += teil
            schwelle = max(1, int(g.start * grenzen.min_anteil))
            neue = sorted((a for a in je_ziel if a not in g.knoten), key=lambda a: -je_ziel[a])
            kleine = [a for a in neue if je_ziel[a] < schwelle]
            gesammelt = set(kleine[KLEIN_JE_STATION:])
            frei_stationen = max(0, grenzen.stationen - len(g.knoten))
            einzeln = [a for a in neue if a not in gesammelt]
            abgewiesen = set(einzeln[frei_stationen:])
            klein_summe = klein_zahl = 0
            for x, teil, p in zuteilung:
                an = x["an"]
                if an in gesammelt:
                    klein_summe += teil
                    klein_zahl += 1
                    continue
                if an in abgewiesen:
                    g.ende(adresse, "grenze", teil, f"Höchstzahl von {grenzen.stationen} Stationen erreicht",
                           fortsetzen={"adresse": einzeln[frei_stationen], "tx": next(y["tx"] for y, _, _ in zuteilung if y["an"] == einzeln[frei_stationen])})
                    continue
                g.station(an, an, tiefe + 1)
                g.fluss(adresse, an, teil, x["tx"], x.get("zeit"), passgenau=teil == x["betrag"] == p["betrag"])
                naechste.append({"tiefe": tiefe + 1, "adresse": an, "betrag": teil, "ab": x})
            if klein_summe:
                groesste = kleine[KLEIN_JE_STATION]
                g.ende(adresse, "grenze", klein_summe,
                       f"{klein_zahl} Zahlungen an {len(gesammelt)} weitere Adressen, je Adresse unter {grenzen.min_anteil:.0%} des Startbetrags",
                       fortsetzen={"adresse": groesste, "tx": next(y["tx"] for y, _, _ in zuteilung if y["an"] == groesste)})
        ebene = naechste


# --------------------------------------------------------------------------- Nacharbeit und Ergebnis

async def nacharbeit(v: Vorgang, z: Zuordner, g: Graf, hoechstens: int = 8) -> None:
    """Fragt für die wichtigsten Enden nach, ob dahinter ein benannter Dienst steht, und kennzeichnet
    mutmassliche Einzahlungsadressen. Kostet je Adresse eine oder mehrere Abfragen, deshalb begrenzt."""
    kandidaten = sorted((e for e in g.enden if e["knoten"] and e["art"] in ("sammel", "liegt", "grenze")
                         and g.knoten[e["knoten"]].get("adresse")), key=lambda e: (e["art"] != "sammel", -e["betrag"]))
    alle = [k["adresse"] for k in g.knoten.values() if k.get("adresse")]
    if alle:
        await z.pruefen(g.kette, alle)           # Listen und Sanktionsprüfung für jede Station, in einem Zug
    gefragt: list[str] = []
    for e in kandidaten:
        adresse = g.knoten[e["knoten"]]["adresse"]
        if adresse in gefragt:
            continue
        if len(gefragt) >= hoechstens or (v.erschoepft and len(gefragt) >= 2):
            break
        gefragt.append(adresse)
        await z.pruefen(g.kette, [adresse], tief=True)
    for e in g.enden:
        if not e["knoten"]:
            continue
        k = g.knoten[e["knoten"]]
        marken = z.bekannt(g.kette, k["adresse"]) if k.get("adresse") else []
        misch = mischer(marken)
        if misch and e["art"] in ("sammel", "liegt", "grenze", "vertrag", "unklar") and k["rolle"] != "start":
            e.update(art="mischer", name=misch, text="laut Etikett ein Mischdienst")
            continue
        name = dienst(marken)
        if name and (e["art"] == "sammel" or e["art"] in ("liegt", "grenze") and k["rolle"] != "start"):
            if e["art"] == "sammel" and k.get("sammel_tx"):
                e["text"] = f"{e['text']}. Die Adresse gehört laut Etikett zu {name}"
            e.update(art="dienst", name=name)
    # Einzahlungsadresse: Station, deren verfolgter Betrag fast ganz bei einem Dienst oder in einer Sammelbewegung landet
    ziel_art = {}
    for e in g.enden:
        if e["knoten"] and e["art"] in ("dienst", "sammel"):
            ziel_art[e["knoten"]] = ziel_art.get(e["knoten"], 0) + e["betrag"]
    for (von, an), kante in g.kanten.items():
        k_von, k_an = g.knoten[von], g.knoten[an]
        if an in ziel_art and not k_an.get("sammel_tx") and k_von["betrag"] and kante["betrag"] * 10 >= k_von["betrag"] * 9:
            if not any(e["knoten"] == von and e["art"] in ("dienst", "sammel") for e in g.enden):
                k_von["einzahlung_bei"] = an
                _notiz(k_von, "leitet den Betrag fast vollständig an einen Dienst weiter: mutmasslich die Einzahlungsadresse eines Kundenkontos")
    for k in g.knoten.values():
        if k.get("sammel_tx"):
            _notiz(k, "mutmasslich die Einzahlungsadresse eines Kundenkontos bei einem Dienst")


def _b(g: Graf, betrag: int) -> str:
    return dezimal(betrag, g.wert.stellen)


def _anteil(g: Graf, betrag: int) -> float:
    return round(betrag * 100 / g.start, 1) if g.start else 0.0


def ansatzpunkte(g: Graf, z: Zuordner) -> list[str]:
    """Wo Ermittler konkret ansetzen können. Benennt Stellen und Massnahmen, keine Personen."""
    punkte: list[str] = []
    s = g.wert.symbol
    for e in sorted(g.enden, key=lambda e: -e["betrag"]):
        k = g.knoten.get(e["knoten"]) if e["knoten"] else None
        adresse = k.get("adresse") if k else None
        if e["art"] == "dienst":
            einzahlung = [x for x in g.knoten.values() if x.get("einzahlung_bei") == e["knoten"]]
            if k and k.get("sammel_tx"):
                punkte.append(f"Editionsbegehren an {e['name']}: Welchem Kundenkonto ist die Einzahlungsadresse {adresse} zugeordnet? "
                              f"Eingang {_b(g, e['betrag'])} {s}, weitergeleitet mit Transaktion {k['sammel_tx']}.")
            elif einzahlung:
                for x in einzahlung[:4]:
                    kante = g.kanten.get((x["schluessel"], e["knoten"]), {})
                    punkte.append(f"Editionsbegehren an {e['name']}: Welchem Kundenkonto ist die Einzahlungsadresse {x['adresse']} zugeordnet? "
                                  f"Von dort gingen {_b(g, kante.get('betrag', 0))} {s} an {adresse}"
                                  + (f" (Transaktion {kante['tx'][0]})." if kante.get("tx") else "."))
            else:
                eingang = next((kante for (von, an), kante in g.kanten.items() if an == e["knoten"]), {})
                punkte.append(f"Editionsbegehren an {e['name']}: Welchem Kundenkonto wurde der Eingang von {_b(g, e['betrag'])} {s} auf {adresse} gutgeschrieben?"
                              + (f" Transaktion {eingang['tx'][0]}." if eingang.get("tx") else ""))
        elif e["art"] == "sammel":
            if k and k.get("sammel_tx"):
                punkte.append(f"{adresse} ist mutmasslich die Einzahlungsadresse bei einem Dienst (weitergeleitet in der Sammeltransaktion {k['sammel_tx']}). "
                              "Den Dienst bestimmen (krypto_zuordnung, kommerzielle Analyse), dann Editionsbegehren zum Kundenkonto.")
            else:
                einzahlung = [x["adresse"] for x in g.knoten.values() if x.get("einzahlung_bei") == e["knoten"]]
                punkte.append(f"{adresse} ist mutmasslich die Sammeladresse eines Dienstes. Den Dienst bestimmen (krypto_zuordnung, kommerzielle Analyse), "
                              "dann Editionsbegehren zum Kundenkonto"
                              + (f" hinter der Einzahlungsadresse {', '.join(einzahlung[:3])}." if einzahlung else "."))
        elif e["art"] == "liegt" and adresse:
            gesperrt = any(m["art"] == "gesperrt" for m in z.bekannt(g.kette, adresse))
            if g.wert.emittent and g.wert.vertrag and not gesperrt:
                punkte.append(f"Auf {adresse} liegen {_b(g, e['betrag'])} {s} unbewegt. Der Emittent ({g.wert.emittent}) kann Guthaben auf Ersuchen "
                              "einer Behörde sperren: Sperrersuchen prüfen, solange das Guthaben dort liegt.")
            elif gesperrt:
                punkte.append(f"Auf {adresse} liegen {_b(g, e['betrag'])} {s}. Die Adresse ist vom Emittenten bereits gesperrt.")
            else:
                punkte.append(f"Auf {adresse} liegen {_b(g, e['betrag'])} {s} unbewegt. Adresse beobachten und die Verfolgung fortsetzen, sobald sich der Betrag bewegt.")
        elif e["art"] == "mischer" and e.get("name"):
            punkte.append(f"{_b(g, e['betrag'])} {s} gingen an {adresse}, laut Etikett ein Mischdienst ({e['name']}). "
                          "Dahinter ist die Zuordnung mit offenen Quellen nicht belastbar.")
        elif e["art"] == "mischer":
            punkte.append(f"{_b(g, e['betrag'])} {s} gingen ab {adresse} durch eine Transaktion mit dem Muster eines Mischdienstes"
                          + (f" ({e['tx']})" if e.get("tx") else "") + ". Dahinter ist die Zuordnung mit offenen Quellen nicht belastbar.")
        elif e["art"] == "vertrag" and adresse:
            punkte.append(f"{_b(g, e['betrag'])} {s} gingen an das Programm {adresse}" + (f" ({e['name']})" if e.get("name") else "")
                          + ". Die Transaktion mit krypto_transaktion ansehen: Dort stehen die Token, die im Gegenzug flossen.")
    offen = [e for e in g.enden if e["art"] == "grenze" and e.get("fortsetzen")]
    if offen:
        groesste = max(offen, key=lambda e: e["betrag"])
        punkte.append(f"{len(offen)} Teilbetrag/Teilbeträge wurden nicht weiterverfolgt (zusammen {_b(g, sum(e['betrag'] for e in offen))} {s}). "
                      f"Fortsetzen mit krypto_geldfluss ab {groesste['fortsetzen'].get('adresse')}"
                      + (f", Transaktion {groesste['fortsetzen']['tx']}." if groesste["fortsetzen"].get("tx") else "."))
    return list(dict.fromkeys(punkte))[:14]


def methode(g: Graf, grenzen: Grenzen) -> str:
    if g.kette.familie == "bitcoin":
        text = ("Bitcoin: Jeder Zahlungsausgang wird genau einmal ausgegeben. Welche Transaktion ihn ausgibt, ist eine Tatsache der Kette. "
                "Legt eine Transaktion mehrere Eingänge zusammen, wird der verfolgte Betrag im Verhältnis der Ausgänge aufgeteilt "
                "(anteilige Zuordnung). Transaktionen mit dem Muster eines Dienstes oder Mischdienstes beenden die Verfolgung.")
    else:
        text = (f"{g.kette.anzeige}: Die Kette führt Kontostände. Ein Eingang wird den zeitlich nächsten Abgängen derselben Währung "
                "zugeordnet, bis er aufgebraucht ist (zuerst herein, zuerst hinaus). Lag auf der Adresse schon Guthaben, ist das eine Annahme. "
                f"Adressen mit über {SEITE} Abgängen seit dem Eingang gelten als Sammeladresse eines Dienstes. Zahlt eine Station "
                f"Kleinbeträge an viele Adressen, stehen die {KLEIN_JE_STATION} grössten Empfänger einzeln da und der Rest als Summe.")
    return (text + f" Grenzen dieses Laufs: {grenzen.tiefe} Stationen ab Start, Teilbeträge unter {grenzen.min_anteil:.0%} des Startbetrags "
            f"und mehr als {grenzen.stationen} Stationen werden nicht weiterverfolgt. Einzelne Zahlungen sind Feststellungen, "
            "die Zuordnung über mehrere Stationen ist eine Bewertung nach diesem Verfahren.")


def einordnen(g: Graf) -> None:
    """Setzt die Tiefe jeder Station auf den längsten Weg vom Start. So stehen im Flussbild Absender links von
    Empfängern, auch wenn Geld eine Station auf zwei verschieden langen Wegen erreicht. Fliesst Geld im Kreis
    zurück, zählt für die Stationen im Kreis der Weg, auf dem sie zuerst erreicht wurden."""
    nachfolger: dict[str, list[str]] = {}
    offen = {s: 0 for s in g.knoten}
    for von, an in g.kanten:
        if von != an:
            nachfolger.setdefault(von, []).append(an)
            offen[an] += 1
    tiefe = {s: (0 if k["rolle"] == "start" else k["tiefe"]) for s, k in g.knoten.items()}
    bereit = [s for s, n in offen.items() if n == 0]
    fertig: set[str] = set()
    while bereit:
        s = bereit.pop()
        fertig.add(s)
        for n in nachfolger.get(s, []):
            tiefe[n] = max(tiefe[n], tiefe[s] + 1)
            offen[n] -= 1
            if offen[n] == 0:
                bereit.append(n)
    rand = sorted((s for s in g.knoten if s not in fertig), key=lambda s: tiefe[s])      # Stationen in oder hinter einem Kreis
    while rand:
        s = rand.pop(0)
        fertig.add(s)
        for n in nachfolger.get(s, []):
            if n not in fertig and tiefe[n] <= tiefe[s]:
                tiefe[n] = tiefe[s] + 1
        rand.sort(key=lambda x: tiefe[x])
    for s, k in g.knoten.items():
        if k["rolle"] != "start":
            k["tiefe"] = tiefe[s]


def ergebnis(g: Graf, z: Zuordner, grenzen: Grenzen) -> tuple[dict, dict]:
    """Baut aus dem Grafen das Ergebnis für den Agenten und die Einzelheiten für das Diagramm im Rapport."""
    einordnen(g)
    stationen = []
    for k in sorted(g.knoten.values(), key=lambda k: k["nr"]):
        marken = z.bekannt(g.kette, k["adresse"]) if k.get("adresse") else []
        eigene = [e for e in g.enden if e["knoten"] == k["schluessel"]]
        abfluss = sum(kante["betrag"] for (von, _), kante in g.kanten.items() if von == k["schluessel"])
        if k["rolle"] == "start":
            art = "start"
        elif eigene and sum(e["betrag"] for e in eigene) >= abfluss:
            art = max(eigene, key=lambda e: e["betrag"])["art"]
        else:
            art = "einzahlung" if k.get("einzahlung_bei") else "station"
        s: dict[str, Any] = {"nr": k["nr"], "adresse": k.get("adresse") or k["schluessel"], "tiefe": k["tiefe"], "art": art,
                             "betrag": _b(g, k["betrag"]), "anteil": _anteil(g, k["betrag"])}
        if marken:
            s["etiketten"] = kurz(marken)[:6]
        name = next((e.get("name") for e in eigene if e.get("name")), None) or k.get("name")
        if name:
            s["name"] = name
        if k.get("vertrag"):
            s["programm"] = True
        if k["hinweise"]:
            s["hinweise"] = k["hinweise"][:4]
        if k.get("mitgenutzt"):
            s["mitgenutzt"] = k["mitgenutzt"]
        if any(m["art"] in ("sanktion", "ransomware", "gesperrt", "meldung") for m in marken):
            s["auffaellig"] = sorted({m["art"] for m in marken if m["art"] in ("sanktion", "ransomware", "gesperrt", "meldung")})
        stationen.append(s)
    nr = {k["schluessel"]: k["nr"] for k in g.knoten.values()}
    fluesse = [{"von": nr[von], "nach": nr[an], "betrag": _b(g, k["betrag"]), "anteil": _anteil(g, k["betrag"]),
                "tx": k["tx"], "zeit": zeit_iso(k["zeit_von"]),
                **({"zeit_bis": zeit_iso(k["zeit_bis"])} if k["zeit_bis"] != k["zeit_von"] else {}),
                **({"zahlungen": k["anzahl"]} if k["anzahl"] > 1 else {}), **({"passgenau": True} if k["passgenau"] else {})}
               for (von, an), k in g.kanten.items()]
    enden = [{"art": e["art"], "bezeichnung": ENDEN[e["art"]][0], "betrag": _b(g, e["betrag"]), "anteil": _anteil(g, e["betrag"]),
              **({"station": nr[e["knoten"]], "adresse": g.knoten[e["knoten"]].get("adresse") or e["knoten"]} if e["knoten"] else {}),
              **({"name": e["name"]} if e.get("name") else {}), **({"grund": e["text"]} if e.get("text") else {}),
              **({"tx": e["tx"]} if e.get("tx") else {}), **({"fortsetzen": e["fortsetzen"]} if e.get("fortsetzen") else {})}
             for e in sorted(g.enden, key=lambda e: -e["betrag"])]
    je_art: Counter = Counter()
    for e in g.enden:
        je_art[e["art"]] += e["betrag"]
    verteilung = [{"art": art, "bezeichnung": ENDEN[art][0], "betrag": _b(g, betrag), "anteil": _anteil(g, betrag)}
                  for art, betrag in je_art.most_common()]
    differenz = g.start - g.verteilt
    befund = {
        "kette": g.kette.name, "wert": g.wert.als_dict(), "startbetrag": _b(g, g.start), "einheit": g.wert.symbol,
        "verteilung": verteilung, "stationen": stationen, "fluesse": fluesse, "enden": enden[:40],
        "ansatzpunkte": ansatzpunkte(g, z), "methode": methode(g, grenzen),
        "summe_geht_auf": differenz == 0,
    }
    if differenz:
        befund["nicht_zugeordnet"] = _b(g, differenz)
    if len(enden) > 40:
        befund["weitere_enden"] = len(enden) - 40
    if g.hinweise:
        befund["hinweise"] = g.hinweise
    details = {"stationen": stationen, "fluesse": fluesse, "enden": enden, "verteilung": verteilung, "erklaerung": {a: t[1] for a, t in ENDEN.items()}}
    return befund, details
