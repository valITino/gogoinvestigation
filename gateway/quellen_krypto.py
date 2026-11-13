"""Blockchain-Analyse: Adressen prüfen und einordnen, Zahlungen lesen, Geldflüsse verfolgen, Gegenwerte.

Abgedeckt sind Bitcoin, die Ethereum-Familie (Ethereum, Optimism und, je nach Anbieter, Polygon, Arbitrum,
Base, Gnosis, BNB Smart Chain) und TRON, jeweils mit den dort gängigen Stablecoins (USDT, USDC).

Alle Werkzeuge sind passiv: Befragt werden Explorer und Listen Dritter. Eine Blockchain ist öffentlich, die
Gegenseite merkt von der Abfrage nichts. Der Betreiber des Explorers sieht aber, für welche Adresse sich
jemand interessiert. Wer das nicht will, fragt über OSINT_PROXY ab oder trägt eine eigene Instanz ein.

Jedes Werkzeug schreibt seine einzelnen Abfragen ins Protokoll und am Ende eine Auswertung, die auf sie
verweist. Die 'protokoll_id' des Ergebnisses ist der Beleg für die Auswertung, unter 'belege' stehen die
Abfragen dahinter.
"""
from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Annotated, Any

from pydantic import Field

from .kern import FREMD, Abbruch, Fall, Vorgang, Zweck, einstellung, werkzeug
from .krypto_adressen import erkennen
from .krypto_fluss import Graf, Grenzen, btc_fluss, btc_start, ergebnis as fluss_ergebnis, konto_fluss, muster, nacharbeit
from .krypto_ketten import (BEGEHRT, BEKANNT, KETTEN, Kette, Quellfehler, Wert, adresse_normal, btc_adresse, btc_tx, btc_txs,
                            btc_verbleib, coin, dezimal, evm_adresse, evm_token_guthaben, evm_tx, evm_zahlungen, gleich,
                            kette_finden, konto_zahlungen, tron_konto, tron_tx, tron_zahlungen, wert_finden, zeit_iso)
from .krypto_kurse import gegenwert, gegenwert_menge, kurs, kurs_als_dict
from .krypto_zuordnung import QUELLEN as ZUORDNUNGSQUELLEN, Zuordner, dienst, kurz, quellen_pruefen

ABRUF = "krypto_abruf"                    # so heissen die einzelnen Abfragen eines Vorgangs im Protokoll
PLATZHALTER = re.compile(r"\[[A-ZÄÖÜ]+(?:_[A-ZÄÖÜ0-9]+)*\]")
AUFFAELLIG = ("sanktion", "ransomware", "gesperrt", "meldung")

KetteAngabe = Annotated[str | None, Field(description=(
    "Kette: bitcoin, ethereum, tron, optimism, polygon, arbitrum, base, gnosis, bsc. Leer lassen, wenn sie sich aus "
    "der Schreibweise ergibt (Bitcoin, TRON). Adressen mit 0x gelten ohne Angabe als Ethereum."))]
WertAngabe = Annotated[str | None, Field(description=(
    "Welcher Wert: leer für die eigene Währung der Kette (BTC, ETH, TRX), ein Kürzel wie USDT oder USDC, oder die "
    "Vertragsadresse eines Tokens."))]


async def _ausfuehren(v: Vorgang, aufgabe: Any) -> dict:
    """Fängt ab, was bei einem Vorgang aus mehreren Abfragen schiefgehen kann, und meldet es mit Beleg."""
    try:
        return await aufgabe
    except Quellfehler as e:
        return v.fehlschlag(e.antwort)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
        if einstellung("OSINT_DEBUG"):
            raise
        return {"ergebnis": "fehler", "belege": list(v.belege),
                "fehler": (f"Eine Quelle hat in einer unerwarteten Form geantwortet ({type(e).__name__}: {e}). Die Antworten sind "
                           "protokolliert und liegen in den Rohdaten. Nicht wiederholen, sondern als Auffälligkeit melden.")}


def _eingabe(wert: str, kette: str | None, art: str) -> tuple[list[Kette], str, list[str]]:
    """Prüft eine Adresse oder Transaktions-ID, bevor sie irgendwohin geht. Rückgabe: (mögliche Ketten,
    Schreibweise für die Abfrage, Hinweise)."""
    if PLATZHALTER.search(wert or ""):
        raise Abbruch("Das ist ein Platzhalter aus der Pseudonymisierung, kein Indikator. Platzhalter werden nie abgefragt.")
    e = erkennen(wert)
    namen = {"adresse": "Adresse", "transaktion": "Transaktions-ID"}
    if e.art != art:
        raise Abbruch(f"'{wert}' ist nicht als {namen[art]} erkennbar"
                      + (f", sondern als {namen[e.art]}. " if e.art in namen else ". ") + " ".join(e.hinweise[:1]))
    if e.gueltig is False:
        raise Abbruch(f"'{wert}' wird nicht abgefragt: {' '.join(e.hinweise[:2])}")
    if not e.ketten:
        raise Abbruch(f"'{wert}' ({e.format}) lässt sich mit den eingebauten Quellen nicht abfragen. {' '.join(e.hinweise[:2])}")
    if kette:
        k = kette_finden(kette)
        if k.name not in e.ketten:
            raise Abbruch(f"'{wert}' ist {e.format} und passt nicht zur Kette {k.anzeige}.")
        ketten = [k]
    elif e.familie == "evm":
        ketten = [KETTEN["ethereum"]]
    else:
        ketten = [KETTEN[n] for n in e.ketten]
    normal = e.normal
    if art == "adresse":
        normal = adresse_normal(ketten[0], e.normal) or e.normal
    elif ketten[0].familie != "evm":
        normal = e.normal.removeprefix("0x")
    hinweise = [h for h in e.hinweise if "Prüfsumme" in h or "keine Prüfsumme" in h]
    if e.familie == "evm" and not kette:
        hinweise.append("Ohne Angabe der Kette wurde Ethereum abgefragt. Dieselbe Adresse gibt es auf allen Ketten der Familie.")
    return ketten, normal, hinweise


def _zahlung(kette: Kette, z: dict, sicht: str | None = None) -> dict:
    """Eine Zahlung in der Form für das Ergebnis."""
    w: Wert = z["wert"]
    d: dict[str, Any] = {"zeit": zeit_iso(z.get("zeit")), "von": z["von"], "an": z["an"],
                         "betrag": dezimal(z["betrag"], w.stellen), "einheit": w.symbol, "tx": z["tx"]}
    if sicht:
        d["richtung"] = "aus" if gleich(kette, z["von"], sicht) else "ein"
    if w.vertrag:
        d["vertrag"] = w.vertrag
        if not w.bekannt:
            d["token_unbestaetigt"] = True
            if w.symbol.upper() in BEGEHRT:
                d["faelschung_moeglich"] = True
        if w.stellen is None:
            d["betrag_in_grundeinheiten"] = True
    if not z.get("ok", True):
        d["fehlgeschlagen"] = True
    if z["betrag"] == 0:
        d["nullwert"] = True
    return d


def _auffaellig(marken: list[dict]) -> list[str]:
    return sorted({m["art"] for m in marken if m["art"] in AUFFAELLIG})


def _etiketten(marken: list[dict]) -> list[dict]:
    return [m for m in marken if not (m["art"] == "hinweis" and not m.get("detail"))][:12]


def _kettenquellen(v: Vorgang) -> list[str]:
    """Quellen, die in diesem Vorgang Daten der Kette geliefert haben (ohne Kurse und Etiketten)."""
    return sorted(q for q in v.genutzt if q.split(" (")[0] in ("mempool.space", "Blockstream", "Bitcoin-Explorer", "Blockscout", "Etherscan", "TronGrid"))


async def _wert_heute(v: Vorgang, w: Wert, betrag: int, ziel: dict) -> None:
    """Hängt den heutigen Gegenwert an, wenn es einen Kurs gibt."""
    if betrag <= 0 or w.stellen is None:
        return
    k = await kurs(v, w)
    wert_ = gegenwert(betrag, w.stellen, k)
    if wert_:
        ziel["gegenwert_heute"] = wert_


# --------------------------------------------------------------------------- Adresse prüfen (ohne Abfrage nach aussen)

@werkzeug
async def krypto_adresse_pruefen(fall: Fall, zweck: Zweck,
                                 wert: Annotated[str, Field(description="Adresse oder Transaktions-ID, wie sie im Dokument steht")]) -> dict:
    """Krypto-Adresse oder Transaktions-ID einordnen, ohne etwas abzufragen: Welche Kette, welches Format,
    stimmt die Prüfsumme? Erkennt Abschreibfehler, bevor eine falsche Adresse abgefragt wird, und sagt,
    ob sich der Wert mit den eingebauten Quellen überhaupt verfolgen lässt (Monero zum Beispiel nicht).
    Immer zuerst aufrufen, wenn ein Wert aus einem Dokument abgetippt oder per Texterkennung gelesen wurde."""
    if PLATZHALTER.search(wert or ""):
        raise Abbruch("Das ist ein Platzhalter aus der Pseudonymisierung, kein Indikator.")
    v = Vorgang(fall, zweck, "krypto_adresse_pruefen", abruf=ABRUF)
    e = erkennen(wert)
    befund = {"eingabe": e.eingabe, "art": e.art, "format": e.format or None, "familie": e.familie or None,
              "pruefsumme": {True: "stimmt", False: "stimmt nicht", None: "keine vorhanden oder nicht prüfbar"}[e.gueltig],
              "abfragbar": e.abfragbar, "ketten": e.ketten, "schreibweise": e.normal if e.art != "unbekannt" else None,
              "hinweise": e.hinweise}
    return v.abschluss(e.normal or wert, "wallet" if e.art != "transaktion" else "transaktion", befund,
                       quellen=["Gateway (Prüfung ohne Abfrage)"], parameter={"wert": wert},
                       ergebnis="ok" if e.art != "unbekannt" else "kein_treffer")


# --------------------------------------------------------------------------- Adresse: Stand und Einordnung

@werkzeug
async def krypto_adresse(fall: Fall, zweck: Zweck,
                         adresse: Annotated[str, Field(description="Krypto-Adresse (Bitcoin, 0x…, TRON)")],
                         kette: KetteAngabe = None) -> dict:
    """Überblick über eine Krypto-Adresse: Guthaben, erhaltene und ausgegebene Beträge, Zahl der Transaktionen,
    erste und letzte Bewegung, Token-Guthaben (USDT, USDC), Etiketten (Börse, Sanktionsliste, bekannte
    Lösegeld-Adresse, gesperrt) und, wo erkennbar, von wem die Adresse zuerst Geld bekam. Passiv.
    Für die einzelnen Zahlungen danach krypto_transaktionen, für den Verbleib eines Betrags krypto_geldfluss."""
    v = Vorgang(fall, zweck, "krypto_adresse", abruf=ABRUF)
    return await _ausfuehren(v, _adresse(v, adresse, kette))


async def _adresse(v: Vorgang, adresse: str, kette: str | None) -> dict:
    ketten, adr, hinweise = _eingabe(adresse, kette, "adresse")
    k = ketten[0]
    z = Zuordner(v)
    befund: dict[str, Any] = {"adresse": adr, "kette": k.name}
    ansatz: list[str] = []
    finanzierer: dict | None = None

    if k.familie == "bitcoin":
        _, stand = await btc_adresse(v, adr)
        befund.update(guthaben={"betrag": dezimal(stand["guthaben"], 8), "einheit": "BTC"}, erhalten=dezimal(stand["erhalten"], 8),
                      ausgegeben=dezimal(stand["ausgegeben"], 8), transaktionen=stand["tx_anzahl"],
                      zahlungseingaenge=stand["eingaenge"], davon_ausgegeben=stand["abgaenge"])
        if stand["unbestaetigt"]:
            befund["unbestaetigt"] = {"transaktionen": stand["unbestaetigt"], "saldo": dezimal(stand["unbestaetigt_saldo"], 8)}
        if stand["tx_anzahl"]:
            _, txs = await btc_txs(v, adr, schritt="Jüngste Transaktionen: erste und letzte Bewegung")
            zeiten = [t["zeit"] for t in txs if t.get("zeit")]
            if zeiten:
                befund["letzte_bewegung"] = zeit_iso(max(zeiten))
                if stand["tx_anzahl"] <= len(txs):
                    befund["erste_bewegung"] = zeit_iso(min(zeiten))
                else:
                    hinweise.append(f"Erste Bewegung nicht bestimmt: Die Quelle liefert die {len(txs)} jüngsten von {stand['tx_anzahl']} "
                                    f"Transaktionen, die älteste davon ist vom {zeit_iso(min(zeiten))}.")
            mit: Counter = Counter()
            for t in txs:
                eigene = [e for e in t["eingaenge"] if gleich(k, e.get("adresse"), adr)]
                if eigene:
                    mit.update({e["adresse"] for e in t["eingaenge"] if e.get("adresse") and not gleich(k, e["adresse"], adr)})
            if mit:
                befund["gemeinsam_ausgegeben_mit"] = {"adressen": len(mit), "beispiele": [a for a, _ in mit.most_common(5)],
                                                      "bedeutung": "Adressen, die in derselben Transaktion als Absender auftreten, gehören in der Regel zur selben Brieftasche."}
        else:
            hinweise.append("Auf dieser Adresse gab es noch keine Transaktion.")
        await _wert_heute(v, coin(k), stand["guthaben"], befund["guthaben"])

    elif k.familie == "evm":
        _, info = await evm_adresse(v, k, adr)
        befund.update(art="Programm auf der Kette (Vertrag)" if info["vertrag"] else "Konto",
                      guthaben={"betrag": dezimal(info["guthaben"], 18), "einheit": k.coin})
        if info["name"]:
            befund["name"] = info["name"]
        if info["tx_anzahl"] is not None:
            befund.update(transaktionen=info["tx_anzahl"], token_zahlungen=info["token_zahlungen"])
        if info["betrug_markiert"]:
            hinweise.append("Blockscout führt die Adresse als Betrug (is_scam).")
        z.merken(k, adr, info["etiketten"])
        if info.get("unbenutzt"):
            hinweise.append("Die Quelle kennt die Adresse nicht: Auf dieser Kette gab es noch keine Bewegung.")
        else:
            _, guthaben = await evm_token_guthaben(v, k, adr)
            befund["token"] = _token_liste(guthaben)
            _, erste, _ = await evm_zahlungen(v, k, adr, None, "alle", aufsteigend=True, anzahl=10, schritt="Erste Transaktionen der Adresse")
            if erste:
                befund["erste_bewegung"] = zeit_iso(erste[0]["zeit"])
                finanzierer = next((x for x in erste if x["ok"] and x["betrag"] > 0 and gleich(k, x["an"], adr)), None)
            _, letzte, _ = await evm_zahlungen(v, k, adr, None, "alle", aufsteigend=False, anzahl=1, schritt="Jüngste Transaktion der Adresse")
            if letzte:
                befund["letzte_bewegung"] = zeit_iso(letzte[0]["zeit"])
                hinweise.append("Erste und letzte Bewegung beziehen sich auf gewöhnliche Transaktionen. Reine Token-Eingänge erscheinen dort nicht.")
            await _wert_heute(v, coin(k), info["guthaben"], befund["guthaben"])
            for eintrag, roh in zip(befund["token"]["bekannte"], [g for g in guthaben if g["wert"].bekannt and g["betrag"] > 0]):
                if roh["wert"].emittent:
                    await _wert_heute(v, roh["wert"], roh["betrag"], eintrag)

    else:  # TRON
        _, konto = await tron_konto(v, adr)
        befund.update(art="Programm auf der Kette (Vertrag)" if konto["vertrag"] else "Konto",
                      guthaben={"betrag": dezimal(konto["guthaben"], 6), "einheit": "TRX"})
        if not konto["aktiviert"]:
            hinweise.append("Das Konto ist nicht aktiviert: Auf TRON entsteht ein Konto erst mit dem ersten Eingang. "
                            "Token-Eingänge sind trotzdem möglich, siehe krypto_transaktionen mit wert=USDT.")
        else:
            befund["erste_bewegung"] = zeit_iso(konto["erstellt"])
            if konto["letzte_aktion"]:
                befund["letzte_eigene_aktion"] = zeit_iso(konto["letzte_aktion"])
            bekannte, andere = [], 0
            for vertrag, stand in konto["trc20"].items():
                w = BEKANNT.get(("tron", vertrag))
                if w and stand > 0:
                    eintrag = {"symbol": w.symbol, "betrag": dezimal(stand, w.stellen), "vertrag": vertrag, "echt": True}
                    await _wert_heute(v, w, stand, eintrag)
                    bekannte.append(eintrag)
                elif stand > 0:
                    andere += 1
            befund["token"] = {"bekannte": bekannte, "weitere_token": andere}
            if andere:
                hinweise.append(f"{andere} weitere Token mit Guthaben. Unverlangt zugeschickte Token sind auf TRON häufig Werbung oder Köder und kein Vermögen.")
            _, eingaenge, _ = await tron_zahlungen(v, adr, None, "ein", aufsteigend=True, anzahl=20, schritt="Erste Eingänge in TRX")
            finanzierer = next((x for x in eingaenge if x["ok"] and x["betrag"] > 0), None)
            await _wert_heute(v, coin(k), konto["guthaben"], befund["guthaben"])

    marken = (await z.pruefen(k, [adr], tief=True))[adr]
    befund["etiketten"] = _etiketten(marken)
    if _auffaellig(marken):
        befund["auffaellig"] = _auffaellig(marken)
    name = dienst(marken)
    if name:
        befund["dienst"] = name
        ansatz.append(f"Die Adresse gehört laut Etikett zu {name}. Der Dienst kann auf ein Editionsbegehren hin sagen, welchem Kunden "
                      "eine bestimmte Einzahlung gutgeschrieben wurde. Dazu die genaue Transaktion angeben.")
    if finanzierer:
        f_marken = (await z.pruefen(k, [finanzierer["von"]], tief=True))[finanzierer["von"]]
        f_name = dienst(f_marken)
        befund["erstfinanzierung"] = {**_zahlung(k, finanzierer), **({"etiketten": kurz(f_marken)[:5]} if f_marken else {}),
                                      "bedeutung": "Erster Eingang in der eigenen Währung der Kette. Damit werden die Gebühren der späteren "
                                                   "Transaktionen bezahlt. Kommt er von einer Börse, hat dort jemand ein Kundenkonto."}
        if f_name:
            befund["erstfinanzierung"]["dienst"] = f_name
            ansatz.append(f"Die Adresse wurde zuerst von {f_name} aus finanziert (Transaktion {finanzierer['tx']}). Das ist in der Regel eine "
                          f"Auszahlung aus einem Kundenkonto: Editionsbegehren an {f_name} zu dieser Transaktion.")
    if any(m["art"] == "gesperrt" for m in marken):
        ansatz.append("Der Emittent hat die Adresse gesperrt. Guthaben in diesem Stablecoin ist eingefroren. Beim Emittenten lässt sich "
                      "erfragen, auf wessen Ersuchen gesperrt wurde.")
    if ansatz:
        befund["ansatzpunkte"] = ansatz
    befund["quellenstand"] = z.stand
    if hinweise:
        befund["hinweise"] = hinweise
    return v.abschluss(adr, "wallet", befund, quellen=set(_kettenquellen(v)) | z.quellen_mit_treffer(),
                       parameter={"adresse": adresse, "kette": k.name}, hinweis=FREMD)


def _token_liste(guthaben: list[dict]) -> dict:
    bekannte = [{"symbol": g["wert"].symbol, "betrag": dezimal(g["betrag"], g["wert"].stellen), "vertrag": g["wert"].vertrag, "echt": True}
                for g in guthaben if g["wert"].bekannt and g["betrag"] > 0]
    andere = [g for g in guthaben if not g["wert"].bekannt and g["betrag"] > 0]
    d: dict[str, Any] = {"bekannte": bekannte, "weitere_token": len(andere)}
    verdaechtig = [{"symbol": g["wert"].symbol, "vertrag": g["wert"].vertrag} for g in andere if g["wert"].symbol.upper() in BEGEHRT][:5]
    if verdaechtig:
        d["gleicher_name_fremder_vertrag"] = verdaechtig
        d["hinweis"] = ("Token, die wie eine bekannte Währung heissen, aber von einem anderen Vertrag stammen, sind fast immer Fälschungen. "
                        "Sie haben keinen Wert und dienen der Täuschung.")
    return d


# --------------------------------------------------------------------------- Zahlungen einer Adresse

@werkzeug
async def krypto_transaktionen(fall: Fall, zweck: Zweck,
                               adresse: Annotated[str, Field(description="Krypto-Adresse")],
                               kette: KetteAngabe = None,
                               wert: Annotated[str | None, Field(description=(
                                   "Leer: eigene Währung der Kette. Kürzel (USDT, USDC) oder Vertragsadresse: dieser Token. "
                                   "'token': Zahlungen aller Token."))] = None,
                               richtung: Annotated[str, Field(description="alle, ein (Eingänge) oder aus (Abgänge)")] = "alle",
                               limit: Annotated[int, Field(ge=1, le=100)] = 40,
                               aelteste_zuerst: Annotated[bool, Field(description="Älteste zuerst statt jüngste zuerst (nicht bei Bitcoin)")] = False) -> dict:
    """Zahlungen einer Krypto-Adresse auflisten: Zeit, Richtung, Gegenpartei, Betrag, Transaktion. Dazu die
    wichtigsten Gegenparteien mit Summen und Etiketten. Passiv. Zahlungen über null und Token mit dem Namen
    einer bekannten Währung, aber fremdem Vertrag, sind gekennzeichnet: Beides sind gängige Täuschungen."""
    v = Vorgang(fall, zweck, "krypto_transaktionen", abruf=ABRUF)
    return await _ausfuehren(v, _transaktionen(v, adresse, kette, wert, richtung, limit, aelteste_zuerst))


async def _transaktionen(v: Vorgang, adresse: str, kette: str | None, wert: str | None, richtung: str, limit: int,
                         aelteste_zuerst: bool) -> dict:
    if richtung not in ("alle", "ein", "aus"):
        raise Abbruch("richtung muss alle, ein oder aus sein.")
    ketten, adr, hinweise = _eingabe(adresse, kette, "adresse")
    k = ketten[0]
    befund: dict[str, Any] = {"adresse": adr, "kette": k.name}
    parteien: dict[str, dict] = {}

    def partei(wer: str | None, ein: int, aus: int, einheit: str, stellen: int | None) -> None:
        if not wer:
            return
        p = parteien.setdefault(wer, {"adresse": wer, "ein": 0, "aus": 0, "zahlungen": 0, "einheit": einheit, "stellen": stellen})
        p["ein"] += ein
        p["aus"] += aus
        p["zahlungen"] += 1

    if k.familie == "bitcoin":
        if wert and wert.strip().lower() not in ("btc", "coin"):
            raise Abbruch("Auf Bitcoin gibt es hier nur den Wert BTC.")
        _, txs = await btc_txs(v, adr)
        zeilen = []
        for t in txs:
            gesendet = sum(e["betrag"] for e in t["eingaenge"] if gleich(k, e.get("adresse"), adr))
            erhalten = sum(a["betrag"] for a in t["ausgaenge"] if gleich(k, a.get("adresse"), adr))
            if gesendet:        # Abgang: Was an fremde Adressen ging. Was an die eigene zurückkam, ist Wechselgeld
                fremd = [(a.get("adresse"), a["betrag"]) for a in t["ausgaenge"] if not gleich(k, a.get("adresse"), adr) and a["betrag"] > 0]
                anteil = gesendet / (sum(e["betrag"] for e in t["eingaenge"]) or 1)
                zeile = {"zeit": zeit_iso(t.get("zeit")), "richtung": "aus", "betrag": dezimal(gesendet - erhalten, 8), "einheit": "BTC", "tx": t["tx"],
                         "an": [{"adresse": a, "betrag": dezimal(b, 8)} for a, b in sorted(fremd, key=lambda x: -x[1])[:4]],
                         "empfaenger": len(fremd), "eigene_eingaenge": sum(1 for e in t["eingaenge"] if gleich(k, e.get("adresse"), adr)),
                         "eingaenge_gesamt": len(t["eingaenge"])}
                if anteil < 0.999:
                    zeile["hinweis"] = "Transaktion mit Eingängen weiterer Adressen: Der Betrag je Empfänger lässt sich dieser Adresse nur anteilig zuordnen."
                for a, b in fremd:
                    partei(a, 0, int(b * anteil), "BTC", 8)
            else:
                absender = Counter()
                for e in t["eingaenge"]:
                    if e.get("adresse"):
                        absender[e["adresse"]] += e["betrag"]
                zeile = {"zeit": zeit_iso(t.get("zeit")), "richtung": "ein", "betrag": dezimal(erhalten, 8), "einheit": "BTC", "tx": t["tx"],
                         "von": [a for a, _ in absender.most_common(4)], "absender": len(absender)}
                summe = sum(absender.values()) or 1
                for a, b in absender.items():
                    partei(a, erhalten * b // summe, 0, "BTC", 8)
            if not t["bestaetigt"]:
                zeile["unbestaetigt"] = True
            art, grund = muster(t)
            if art:
                zeile["muster"] = grund
            if richtung in ("alle", zeile["richtung"]):
                zeilen.append(zeile)
        befund["zahlungen"] = zeilen[:limit]
        if len(txs) >= 50:
            hinweise.append("Die Quelle liefert die 50 jüngsten Transaktionen. Ältere zeigt krypto_geldfluss beim Verfolgen oder der Explorer.")
        if aelteste_zuerst:
            hinweise.append("Bei Bitcoin liefert die Quelle nur jüngste zuerst.")
    else:
        alle_token = (wert or "").strip().lower() == "token"
        w = None if alle_token else wert_finden(k, wert)
        if k.familie == "tron":
            _, zahlungen, mehr = await tron_zahlungen(v, adr, w, richtung, aufsteigend=aelteste_zuerst, anzahl=limit, alle_token=alle_token)
            voll = mehr is not None
        else:
            _, zahlungen, voll = await evm_zahlungen(v, k, adr, w, richtung, aufsteigend=aelteste_zuerst, anzahl=limit, alle_token=alle_token)
        befund["wert"] = "alle Token" if alle_token else w.als_dict()
        befund["zahlungen"] = [_zahlung(k, x, adr) for x in zahlungen[:limit]]
        for x in zahlungen:
            if not x["ok"] or x["betrag"] == 0 or (not x["wert"].bekannt and alle_token):
                continue
            ein = gleich(k, x["an"], adr)
            partei(x["von"] if ein else x["an"], x["betrag"] if ein else 0, 0 if ein else x["betrag"], x["wert"].symbol, x["wert"].stellen)
        if voll:
            hinweise.append(f"Es gibt mehr als die {limit} gelieferten Zahlungen. Mit richtung, wert und aelteste_zuerst eingrenzen.")
        if any(x["betrag"] == 0 for x in zahlungen):
            hinweise.append("Zahlungen über null sind in der Regel Köder: Sie sollen eine fremde, ähnlich aussehende Adresse in die Liste "
                            "der letzten Zahlungen bringen, damit jemand sie versehentlich kopiert («Address Poisoning»).")

    wichtig = sorted(parteien.values(), key=lambda p: -(p["ein"] + p["aus"]))[:8]
    if wichtig:
        z = Zuordner(v)
        marken = await z.pruefen(k, [p["adresse"] for p in wichtig])
        befund["gegenparteien"] = [{"adresse": p["adresse"], "eingang": dezimal(p["ein"], p["stellen"]), "abgang": dezimal(p["aus"], p["stellen"]),
                                    "einheit": p["einheit"], "zahlungen": p["zahlungen"],
                                    **({"etiketten": kurz(marken[p["adresse"]])[:4]} if marken.get(p["adresse"]) else {}),
                                    **({"dienst": dienst(marken[p["adresse"]])} if dienst(marken.get(p["adresse"]) or []) else {})}
                                   for p in wichtig]
        befund["quellenstand"] = z.stand
    if hinweise:
        befund["hinweise"] = hinweise
    return v.abschluss(adr, "wallet", befund, quellen=_kettenquellen(v),
                       parameter={"adresse": adresse, "kette": k.name, "wert": wert, "richtung": richtung, "limit": limit, "aelteste_zuerst": aelteste_zuerst},
                       ergebnis="ok" if befund["zahlungen"] else "kein_treffer", hinweis=FREMD)


# --------------------------------------------------------------------------- Eine Transaktion

@werkzeug
async def krypto_transaktion(fall: Fall, zweck: Zweck,
                             tx: Annotated[str, Field(description="Transaktions-ID (Hash)")],
                             kette: KetteAngabe = None,
                             gegenpruefen: Annotated[bool, Field(description=(
                                 "Dieselbe Transaktion bei einer zweiten, unabhängigen Quelle abrufen und vergleichen. "
                                 "Für Zahlungen, auf die sich der Rapport stützt."))] = False) -> dict:
    """Eine Transaktion im Einzelnen: Zeitpunkt, Absender, Empfänger, Beträge, Gebühr, enthaltene Token-Zahlungen,
    Gegenwert am Tag der Zahlung in CHF, und bei Bitcoin, ob die Ausgänge schon weitergeleitet wurden. Passiv.
    Bei Bitcoin und TRON reicht die ID, die Kette wird gefunden. Mit gegenpruefen wird das Ergebnis bei einer
    zweiten Quelle bestätigt (Bitcoin: Blockstream, Ethereum-Familie: Etherscan, falls eingerichtet)."""
    v = Vorgang(fall, zweck, "krypto_transaktion", abruf=ABRUF)
    return await _ausfuehren(v, _transaktion(v, tx, kette, gegenpruefen))


def _btc_bild(t: dict) -> dict:
    """Vergleichsform einer Bitcoin-Transaktion für die Gegenprüfung."""
    return {"tx": t["tx"], "block": t["block"], "zeit": t["zeit"], "gebuehr": t["gebuehr"],
            "ein": sorted((e.get("adresse") or "", e["betrag"]) for e in t["eingaenge"]),
            "aus": [(a.get("adresse") or "", a["betrag"]) for a in t["ausgaenge"]]}


def _konto_bild(k: Kette, t: dict) -> dict:
    return {"block": t["block"], "ok": t["ok"], "von": (t["von"] or "").lower(), "an": (t["an"] or "").lower(),
            "zahlungen": sorted((z["von"].lower(), z["an"].lower(), z["betrag"], z["wert"].schluessel) for z in t["zahlungen"])}


async def _transaktion(v: Vorgang, tx: str, kette: str | None, gegenpruefen: bool) -> dict:
    ketten, tx_id, hinweise = _eingabe(tx, kette, "transaktion")
    z = Zuordner(v)
    for i, k in enumerate(ketten):
        letzte = i == len(ketten) - 1
        if k.familie == "bitcoin":
            a, t = await btc_tx(v, tx_id)
            if t is None:
                if letzte:
                    return v.fehlschlag(a, hinweis=f"Keine der Quellen kennt eine Transaktion mit dieser ID ({', '.join(x.anzeige for x in ketten)} geprüft).")
                continue
            return await _transaktion_btc(v, z, k, t, a.quelle or "", gegenpruefen, hinweise)
        if k.familie == "tron":
            belege, t = await tron_tx(v, tx_id)
            quelle = "TronGrid"
        else:
            belege, t, quelle = await evm_tx(v, k, tx_id)
        if t is None:
            if letzte:
                return {"protokoll_id": belege[-1], "ergebnis": "kein_treffer", "belege": list(v.belege),
                        "hinweis": f"Keine der Quellen kennt eine Transaktion mit dieser ID ({', '.join(x.anzeige for x in ketten)} geprüft)."
                                   + (" Bei 0x-IDs die Kette angeben, wenn die Zahlung nicht auf Ethereum lief." if k.familie == "evm" and not kette else "")}
            continue
        return await _transaktion_konto(v, z, k, t, quelle, gegenpruefen, hinweise)
    raise Abbruch("Keine Kette für diese Transaktions-ID.")


async def _transaktion_btc(v: Vorgang, z: Zuordner, k: Kette, t: dict, quelle: str, gegenpruefen: bool, hinweise: list[str]) -> dict:
    summe_aus = sum(a["betrag"] for a in t["ausgaenge"])
    befund: dict[str, Any] = {"tx": t["tx"], "kette": "bitcoin", "zeit": zeit_iso(t["zeit"]), "block": t["block"],
                              "bestaetigt": t["bestaetigt"], "gebuehr": dezimal(t["gebuehr"], 8), "einheit": "BTC",
                              "summe": dezimal(summe_aus, 8)}
    if not t["bestaetigt"]:
        hinweise.append("Die Transaktion ist noch nicht in einem Block bestätigt. Bis dahin kann sie verfallen oder ersetzt werden.")
    _, verbleib = await btc_verbleib(v, t["tx"])
    je_absender: Counter = Counter()
    for e in t["eingaenge"]:
        je_absender[e.get("adresse") or ("neu geschürft (Coinbase)" if e.get("coinbase") else "ohne Adresse")] += e["betrag"]
    befund["eingaenge"] = {"anzahl": len(t["eingaenge"]), "adressen": len(je_absender),
                           "groesste": [{"adresse": a, "betrag": dezimal(b, 8)} for a, b in je_absender.most_common(12)]}
    ausgaenge = []
    for a in sorted(t["ausgaenge"], key=lambda a: -a["betrag"])[:25]:
        stand = verbleib[a["nr"]] if a["nr"] < len(verbleib) else {}
        zeile = {"nr": a["nr"], "adresse": a.get("adresse") or f"ohne Adresse ({a.get('typ')})", "betrag": dezimal(a["betrag"], 8),
                 "verbleib": "weitergeleitet" if stand.get("ausgegeben") else "liegt unbewegt"}
        if stand.get("ausgegeben"):
            zeile.update(weitergeleitet_in=stand.get("tx"), weitergeleitet_am=zeit_iso(stand.get("zeit")))
        if a.get("adresse") and a["adresse"] in je_absender:
            zeile["hinweis"] = "geht an eine Absenderadresse zurück (Wechselgeld)"
        ausgaenge.append(zeile)
    befund["ausgaenge"] = ausgaenge
    if len(t["ausgaenge"]) > 25:
        befund["weitere_ausgaenge"] = len(t["ausgaenge"]) - 25
    art, grund = muster(t)
    if art:
        befund["muster"] = grund
    elif len(je_absender) > 1:
        befund["muster"] = (f"{len(je_absender)} Absenderadressen in einer Transaktion: Sie gehören in der Regel zur selben Brieftasche.")
    adressen = [a for a in list(je_absender)[:10] + [x["adresse"] for x in ausgaenge[:10]] if a and " " not in a]
    marken = await z.pruefen(k, adressen)
    etiketten = {a: kurz(m)[:4] for a, m in marken.items() if m}
    if etiketten:
        befund["etiketten"] = etiketten
    if t["zeit"]:
        kurs_ = await kurs(v, coin(k), t["zeit"])
        if "usd" in kurs_:
            befund["kurs_am_tag"] = kurs_als_dict(kurs_)
            befund["gegenwert_summe"] = gegenwert(summe_aus, 8, kurs_)
            for zeile, a in zip(ausgaenge, sorted(t["ausgaenge"], key=lambda a: -a["betrag"])[:25]):
                zeile["gegenwert"] = gegenwert(a["betrag"], 8, kurs_)
    quellen = {quelle} if quelle else set(_kettenquellen(v))
    if gegenpruefen:
        zweite = "Blockstream" if quelle != "Blockstream" else "mempool.space"
        if einstellung("KRYPTO_BITCOIN_API"):
            befund["gegenpruefung"] = {"ergebnis": "nicht möglich", "grund": "Mit eigener Instanz ist keine zweite Quelle eingerichtet."}
        else:
            try:
                b, t2 = await btc_tx(v, t["tx"], schritt="Gegenprüfung bei zweiter Quelle", quelle=zweite)
                if t2 is None:
                    befund["gegenpruefung"] = {"quelle": zweite, "ergebnis": "Transaktion dort nicht bekannt", "beleg": b.id}
                else:
                    gleich_ = _btc_bild(t) == _btc_bild(t2)
                    befund["gegenpruefung"] = {"quelle": zweite, "beleg": b.id,
                                               "ergebnis": "stimmt überein" if gleich_ else "WEICHT AB",
                                               "verglichen": "Block, Zeit, Gebühr, alle Eingänge und Ausgänge mit Adresse und Betrag"}
                    if gleich_:
                        quellen.add(zweite)
                    else:
                        hinweise.append("Die zweite Quelle zeigt andere Angaben. Beide Rohdateien vergleichen, bevor die Transaktion verwendet wird.")
            except Quellfehler as e:
                befund["gegenpruefung"] = {"quelle": zweite, "ergebnis": "nicht erreichbar", "beleg": e.antwort.id}
    if hinweise:
        befund["hinweise"] = hinweise
    return v.abschluss(t["tx"], "transaktion", befund, quellen=quellen,
                       parameter={"tx": t["tx"], "kette": "bitcoin", "gegenpruefen": gegenpruefen}, hinweis=FREMD)


async def _transaktion_konto(v: Vorgang, z: Zuordner, k: Kette, t: dict, quelle: str, gegenpruefen: bool, hinweise: list[str]) -> dict:
    befund: dict[str, Any] = {"tx": t["tx"], "kette": k.name, "zeit": zeit_iso(t["zeit"]), "block": t["block"],
                              "erfolgreich": t["ok"], "von": t["von"], "an": t["an"],
                              "gebuehr": {"betrag": dezimal(t["gebuehr"], k.stellen), "einheit": k.coin}}
    if not t["ok"]:
        befund["status"] = t.get("status_text") or "fehlgeschlagen"
        hinweise.append("Die Transaktion ist fehlgeschlagen. Es wurde nichts übertragen, nur die Gebühr ist angefallen.")
    if t.get("an_vertrag"):
        befund["an_ist_programm"] = True
        if t.get("an_name"):
            befund["an_name"] = t["an_name"]
    if t.get("methode"):
        befund["aufruf"] = t["methode"]
    befund["zahlungen"] = [_zahlung(k, x) for x in t["zahlungen"][:40]]
    if len(t["zahlungen"]) > 40 or t.get("unvollstaendig"):
        hinweise.append("Die Transaktion enthält mehr Zahlungen, als hier gezeigt werden. Vollständig in den Rohdaten.")
    if not t["zahlungen"] and t["ok"]:
        hinweise.append("In dieser Transaktion wurde kein Wert übertragen (zum Beispiel eine Freigabe oder ein Aufruf ohne Zahlung).")
    for adresse, marken in (t.get("etiketten") or {}).items():
        z.merken(k, adresse, marken)
    adressen = list(dict.fromkeys([a for a in (t["von"], t["an"]) if a] + [x[r] for x in t["zahlungen"][:12] for r in ("von", "an")]))
    marken = await z.pruefen(k, adressen[:20])
    etiketten = {a: kurz(m)[:4] for a, m in marken.items() if m}
    if etiketten:
        befund["etiketten"] = etiketten
    if t["zeit"]:
        kurse: dict[str, dict] = {}
        for zeile, x in zip(befund["zahlungen"], t["zahlungen"][:40]):
            w: Wert = x["wert"]
            if x["betrag"] <= 0 or w.stellen is None or not (w.bekannt or len(kurse) < 3):
                continue
            if w.schluessel not in kurse:
                kurse[w.schluessel] = await kurs(v, w, t["zeit"])
            wert_ = gegenwert(x["betrag"], w.stellen, kurse[w.schluessel])
            if wert_:
                zeile["gegenwert"] = wert_
        stand = next((kurs_als_dict(x) for x in kurse.values() if "usd" in x), None)
        if stand:
            befund["kurs_am_tag"] = {k_: v_ for k_, v_ in stand.items() if k_ in ("stand", "wechselkurs_vom", "quellen")}
    quellen = {quelle}
    if gegenpruefen:
        if k.familie == "tron":
            befund["gegenpruefung"] = {"ergebnis": "nicht möglich", "grund": "Für TRON ist keine zweite, unabhängige Quelle eingerichtet."}
        elif not einstellung("ETHERSCAN_API_KEY") or quelle == "Etherscan":
            befund["gegenpruefung"] = {"ergebnis": "nicht möglich",
                                       "grund": "Die Gegenprüfung braucht Blockscout und Etherscan (ETHERSCAN_API_KEY) nebeneinander."}
        else:
            try:
                belege, t2, _ = await evm_tx(v, k, t["tx"], schritt="Gegenprüfung bei zweiter Quelle", nur="etherscan")
                if t2 is None:
                    befund["gegenpruefung"] = {"quelle": "Etherscan", "ergebnis": "Transaktion dort nicht bekannt", "beleg": belege[0]}
                else:
                    gleich_ = _konto_bild(k, t) == _konto_bild(k, t2)
                    befund["gegenpruefung"] = {"quelle": "Etherscan", "beleg": belege[0],
                                               "ergebnis": "stimmt überein" if gleich_ else "WEICHT AB",
                                               "verglichen": "Block, Erfolg, Absender, Empfänger und alle Zahlungen mit Betrag und Token-Vertrag"}
                    if gleich_:
                        quellen.add("Etherscan")
                    else:
                        hinweise.append("Die zweite Quelle zeigt andere Angaben. Beide Rohdateien vergleichen, bevor die Transaktion verwendet wird.")
            except Quellfehler as e:
                befund["gegenpruefung"] = {"quelle": "Etherscan", "ergebnis": "nicht erreichbar", "beleg": e.antwort.id}
    if hinweise:
        befund["hinweise"] = hinweise
    return v.abschluss(t["tx"], "transaktion", befund, quellen=quellen,
                       parameter={"tx": t["tx"], "kette": k.name, "gegenpruefen": gegenpruefen}, hinweis=FREMD)


# --------------------------------------------------------------------------- Geldfluss

@werkzeug
async def krypto_geldfluss(fall: Fall, zweck: Zweck,
                           start: Annotated[str, Field(description=(
                               "Womit die Verfolgung beginnt. Transaktions-ID: Es wird dem Betrag dieser einen Zahlung gefolgt "
                               "(der genaue Weg, zum Beispiel die Zahlung des Geschädigten). Adresse: Es wird allem gefolgt, was die "
                               "Adresse verlassen hat (zum Beispiel eine Lösegeld-Adresse)."))],
                           kette: KetteAngabe = None,
                           adresse: Annotated[str | None, Field(description=(
                               "Nur bei start = Transaktions-ID: der Empfänger, dessen Zahlung verfolgt wird. Nötig, wenn die "
                               "Transaktion mehrere Empfänger hat (bei Bitcoin fast immer: Zahlung und Wechselgeld)."))] = None,
                           wert: WertAngabe = None,
                           tiefe: Annotated[int, Field(ge=1, le=8, description="Wie viele Stationen ab dem Start")] = 4,
                           min_anteil_prozent: Annotated[float, Field(ge=0.1, le=50, description=(
                               "Teilbeträge unter diesem Anteil des Startbetrags werden nicht weiterverfolgt"))] = 2.0,
                           max_abfragen: Annotated[int, Field(ge=10, le=300, description=(
                               "Abfragebudget dieses Laufs. Ist es aufgebraucht, endet die Verfolgung geordnet und nennt, wo sie sich fortsetzen lässt."))] = 80) -> dict:
    """Geldfluss verfolgen: Wohin ist ein Betrag gegangen? Folgt einer Zahlung über mehrere Stationen, bis das Geld
    bei einem Dienst (Börse) ankommt, unbewegt liegt, in einer Sammelbewegung oder einem Mischdienst aufgeht oder
    die Grenzen des Laufs erreicht sind. Liefert Stationen, Flüsse, die Verteilung des Startbetrags auf die Enden
    und Ansatzpunkte (wo ein Editionsbegehren oder ein Sperrersuchen ansetzen kann). Passiv, löst je nach Tiefe
    Dutzende Abfragen aus, jede einzeln protokolliert.

    Einzelne Zahlungen im Ergebnis sind Feststellungen. Die Zuordnung über mehrere Stationen ist eine Bewertung
    nach dem unter 'methode' beschriebenen Verfahren und so im Rapport zu kennzeichnen. Für tragende Zahlungen
    zusätzlich krypto_transaktion mit gegenpruefen aufrufen. Das Diagramm im Rapport entsteht aus der
    protokoll_id dieses Ergebnisses (befunde.json: geldfluesse)."""
    v = Vorgang(fall, zweck, "krypto_geldfluss", abruf=ABRUF, budget=max_abfragen)
    return await _ausfuehren(v, _geldfluss(v, start, kette, adresse, wert, Grenzen(tiefe, min_anteil_prozent / 100)))


async def _geldfluss(v: Vorgang, start: str, kette: str | None, adresse: str | None, wert: str | None, grenzen: Grenzen) -> dict:
    if PLATZHALTER.search(start or ""):
        raise Abbruch("Das ist ein Platzhalter aus der Pseudonymisierung, kein Indikator. Platzhalter werden nie abgefragt.")
    art = erkennen(start).art
    if art == "unbekannt":
        raise Abbruch(f"'{start}' ist weder als Adresse noch als Transaktions-ID erkennbar. Mit krypto_adresse_pruefen einordnen.")
    ketten, kennung, hinweise = _eingabe(start, kette, art)
    z = Zuordner(v)
    start_info: dict[str, Any] = {"art": "zahlung" if art == "transaktion" else "adresse"}
    g: Graf | None = None
    start_zeit: int | None = None

    if art == "adresse":
        k = ketten[0]
        if adresse:
            raise Abbruch("'adresse' gilt nur zusammen mit einer Transaktions-ID als start. Bei einer Adresse als start wird allem gefolgt, was sie verlassen hat.")
        start_info["adresse"] = kennung
        if k.familie == "bitcoin":
            g = Graf(k, wert_finden(k, wert))
            posten, wissen = await btc_start(v, g, tx=None, adresse=kennung)
            start_zeit = min((p[5] for p in posten if p[5]), default=None)
            start_info["eingaenge"] = len(posten)
            await btc_fluss(v, z, g, posten, grenzen, wissen)
        else:
            w = wert_finden(k, wert)
            _, abgaenge, _ = await konto_zahlungen(v, k, kennung, w, "aus", schritt="Station 1: Abgänge der Startadresse")
            abgaenge = [x for x in abgaenge if x["ok"] and x["betrag"] > 0 and not gleich(k, x["an"], kennung)]
            if abgaenge and w.stellen is None:
                w = abgaenge[0]["wert"]
            g = Graf(k, w)
            start_zeit = abgaenge[0]["zeit"] if abgaenge else None
            start_info["abgaenge"] = len(abgaenge)
            await konto_fluss(v, z, g, [{"adresse": kennung, "betrag": sum(x["betrag"] for x in abgaenge), "ab": None}], grenzen, alles_ab_start=True)
            if not abgaenge:
                g.hinweis(f"Von dieser Adresse ist in {w.symbol} nichts abgeflossen. Stand und Eingänge zeigen krypto_adresse und krypto_transaktionen.")
    else:
        if adresse:                    # der Empfänger verrät die Kette, wenn die ID es nicht tut
            _eingabe(adresse, kette, "adresse")
            passend = erkennen(adresse).ketten
            ketten = [k for k in ketten if k.name in passend]
            if not ketten:
                raise Abbruch("Die Adresse des Empfängers und die Transaktions-ID gehören nicht zur selben Kette.")
        for i, k in enumerate(ketten):
            letzte = i == len(ketten) - 1
            empfaenger = adresse_normal(k, erkennen(adresse).normal) if adresse else None
            if k.familie == "bitcoin":
                a, t = await btc_tx(v, kennung, schritt="Startzahlung")
                if t is None:
                    if letzte:
                        return v.fehlschlag(a, hinweis="Keine Quelle kennt eine Transaktion mit dieser ID.")
                    continue
                g = Graf(k, wert_finden(k, wert))
                posten, _ = await btc_start(v, g, tx=t, adresse=empfaenger)
                start_zeit = t.get("zeit")
                start_info.update(tx=t["tx"], adresse=posten[0][3], zeit=zeit_iso(start_zeit))
                await btc_fluss(v, z, g, posten, grenzen)
                break
            if k.familie == "tron":
                belege, t = await tron_tx(v, kennung, schritt="Startzahlung")
            else:
                belege, t, _ = await evm_tx(v, k, kennung, schritt="Startzahlung")
            if t is None:
                if letzte:
                    return {"protokoll_id": belege[-1], "ergebnis": "kein_treffer", "belege": list(v.belege),
                            "hinweis": "Keine Quelle kennt eine Transaktion mit dieser ID."
                                       + (" Bei 0x-IDs die Kette angeben, wenn die Zahlung nicht auf Ethereum lief." if k.familie == "evm" and not kette else "")}
                continue
            if not t["ok"]:
                raise Abbruch(f"Die Transaktion {kennung} ist fehlgeschlagen. Es wurde nichts übertragen, also gibt es nichts zu verfolgen.")
            w = wert_finden(k, wert) if wert else None
            wahl = [x for x in t["zahlungen"] if x["betrag"] > 0 and (w is None or x["wert"].schluessel == w.schluessel)
                    and (empfaenger is None or gleich(k, x["an"], empfaenger))]
            ziele = {(x["an"], x["wert"].schluessel) for x in wahl}
            if len(ziele) != 1:
                liste = "; ".join(f"{dezimal(x['betrag'], x['wert'].stellen)} {x['wert'].symbol} an {x['an']}" for x in t["zahlungen"][:10] if x["betrag"] > 0)
                raise Abbruch(("Die Transaktion enthält mehrere Zahlungen. " if ziele else "In der Transaktion gibt es keine passende Zahlung. ")
                              + f"Mit 'adresse' (Empfänger) und 'wert' angeben, welcher gefolgt werden soll. Enthalten: {liste or 'keine Wertübertragung'}")
            g = Graf(k, wahl[0]["wert"])
            start_zeit = t.get("zeit")
            start_info.update(tx=t["tx"], adresse=wahl[0]["an"], von=wahl[0]["von"], zeit=zeit_iso(start_zeit))
            await konto_fluss(v, z, g, [{"adresse": x["an"], "betrag": x["betrag"], "ab": {**x, "block": t.get("block")}} for x in wahl], grenzen)
            break
    assert g is not None
    await nacharbeit(v, z, g)
    befund, details = fluss_ergebnis(g, z, grenzen)
    if not g.wert.bekannt and g.wert.vertrag:
        hinweise.append(f"Verfolgt wurde der Token mit dem Vertrag {g.wert.vertrag}. Er steht nicht in der eingebauten Liste: "
                        "Ob er der Währung entspricht, nach der er benannt ist, ist nicht bestätigt.")
    start_info["betrag"] = befund["startbetrag"]
    start_info["einheit"] = g.wert.symbol
    if start_zeit and g.start and g.wert.stellen is not None:
        k_ = await kurs(v, g.wert, start_zeit)
        if "usd" in k_:
            start_info["gegenwert"] = gegenwert(g.start, g.wert.stellen, k_)
            start_info["kurs"] = kurs_als_dict(k_)
            for e in befund["verteilung"]:
                e["gegenwert"] = gegenwert_menge(Decimal(e["betrag"]), k_)
            start_info["gegenwert_hinweis"] = "Gegenwerte zum Kurs am Tag der Startzahlung."
    befund = {"start": start_info, **befund}
    befund["abfragen"] = {"ausgefuehrt": v.ausgefuehrt, "aus_fall_cache": v.aus_cache, "budget": v.budget, "budget_aufgebraucht": v.erschoepft}
    befund["quellenstand"] = z.stand
    if hinweise:
        befund["hinweise"] = befund.get("hinweise", []) + hinweise
    details = {**details, "start": start_info, "kette": g.kette.name, "kette_anzeige": g.kette.anzeige, "wert": g.wert.als_dict(),
               "startbetrag": befund["startbetrag"], "methode": befund["methode"], "ansatzpunkte": befund["ansatzpunkte"]}
    return v.abschluss(kennung, "geldfluss", befund, quellen=_kettenquellen(v), details=details,
                       parameter={"start": start, "kette": g.kette.name, "adresse": adresse, "wert": wert, "tiefe": grenzen.tiefe,
                                  "min_anteil_prozent": grenzen.min_anteil * 100, "max_abfragen": v.budget}, hinweis=FREMD)


# --------------------------------------------------------------------------- Zuordnung

@werkzeug
async def krypto_zuordnung(fall: Fall, zweck: Zweck,
                           adressen: Annotated[list[str], Field(description="Eine bis 25 Krypto-Adressen", min_length=1, max_length=25)],
                           kette: KetteAngabe = None,
                           meldungen: Annotated[bool, Field(description=(
                               "Zusätzlich Betrugsmeldungen bei Chainabuse abfragen (braucht CHAINABUSE_API_KEY, knappes "
                               "Kontingent: nur für die wichtigsten Adressen)."))] = False,
                           quellen: Annotated[list[str] | None, Field(description=(
                               "Nur diese Quellen fragen: " + ", ".join(ZUORDNUNGSQUELLEN) + ". Leer: alle eingerichteten."))] = None) -> dict:
    """Wem lässt sich eine Krypto-Adresse zuordnen? Prüft Sanktionslisten (OFAC, TRM Labs), bekannte
    Lösegeld-Adressen (Ransomwhere), Etiketten von Explorern (Börse, Brücke, Mischdienst, vom Emittenten
    gesperrt) und, je nach Kette und Schlüsseln, WalletExplorer, Tronscan, Iknaio und Chainabuse. Passiv.
    'quellenstand' sagt je Quelle, ob sie geprüft werden konnte: Eine ausgefallene Quelle ist kein «kein Eintrag».
    Ein Etikett ist eine Angabe Dritter. Es zeigt, wo ein Editionsbegehren ansetzen kann, nicht wer dahintersteht."""
    v = Vorgang(fall, zweck, "krypto_zuordnung", abruf=ABRUF)
    return await _ausfuehren(v, _zuordnung(v, adressen, kette, meldungen, quellen))


async def _zuordnung(v: Vorgang, adressen: list[str], kette: str | None, meldungen: bool, quellen: list[str] | None) -> dict:
    z = Zuordner(v, quellen_pruefen(quellen))
    gruppen: dict[str, list[str]] = {}
    hinweise: list[str] = []
    for a in adressen:
        ketten, adr, h = _eingabe(a, kette, "adresse")
        gruppen.setdefault(ketten[0].name, []).append(adr)
        hinweise += [x for x in h if x not in hinweise]
    zeilen = []
    for name, liste in gruppen.items():
        k = KETTEN[name]
        marken = await z.pruefen(k, liste, tief=True, meldungen=meldungen)
        for adr in dict.fromkeys(liste):
            m = marken.get(adr) or []
            zeilen.append({"adresse": adr, "kette": name, "etiketten": _etiketten(m),
                           **({"dienst": dienst(m)} if dienst(m) else {}), **({"auffaellig": _auffaellig(m)} if _auffaellig(m) else {})})
    geprueft = [n for n, s in z.stand.items() if s["ergebnis"] == "ok"]
    if not geprueft:
        return {"ergebnis": "fehler", "belege": list(v.belege), "quellenstand": z.stand,
                "fehler": "Keine der Quellen konnte geprüft werden. Das ist kein «kein Eintrag»: Zuordnung später wiederholen."}
    ausgefallen = [n for n, s in z.stand.items() if s["ergebnis"] == "fehler"]
    if ausgefallen:
        hinweise.append(f"Nicht geprüft werden konnte: {', '.join(ausgefallen)}. Für diese Quellen gibt es keine Aussage.")
    befund = {"adressen": zeilen, "quellenstand": z.stand, "geprueft": sorted(geprueft)}
    if hinweise:
        befund["hinweise"] = hinweise
    treffer = any(zeile["etiketten"] for zeile in zeilen)
    return v.abschluss(", ".join(a for liste in gruppen.values() for a in liste)[:200], "wallet", befund, quellen=geprueft,
                       parameter={"adressen": adressen, "kette": kette, "meldungen": meldungen, "quellen": quellen},
                       ergebnis="ok" if treffer else "kein_treffer", hinweis=FREMD)


# --------------------------------------------------------------------------- Kurs

_KURSWERTE = {"btc": ("bitcoin", None), "eth": ("ethereum", None), "trx": ("tron", None), "bnb": ("bsc", None),
              "pol": ("polygon", None), "matic": ("polygon", None), "xdai": ("gnosis", None)}


def _zeitpunkt(datum: str | None) -> int | None:
    """Datum (2024-01-15) oder Zeitpunkt (2024-01-15T10:30:00Z) als Unix-Zeit. Ein blosses Datum gilt als Mittag UTC."""
    if not datum or not datum.strip():
        return None
    t = datum.strip().replace("Z", "+00:00")
    try:
        if len(t) == 10:
            d = datetime.fromisoformat(t).replace(hour=12, tzinfo=timezone.utc)
        else:
            d = datetime.fromisoformat(t)
            d = d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise Abbruch(f"'{datum}' ist kein lesbares Datum. Form: 2024-01-15 oder 2024-01-15T10:30:00Z.") from e
    if d > datetime.now(timezone.utc):
        raise Abbruch("Das Datum liegt in der Zukunft.")
    return int(d.timestamp())


@werkzeug
async def krypto_kurs(fall: Fall, zweck: Zweck,
                      wert: Annotated[str, Field(description="Kürzel (BTC, ETH, TRX, USDT, USDC …) oder Vertragsadresse eines Tokens (dann mit kette)")],
                      datum: Annotated[str | None, Field(description=(
                          "Stichtag (2024-01-15) oder Zeitpunkt (2024-01-15T10:30:00Z, UTC). Leer: aktueller Kurs. "
                          "Ein blosses Datum gilt als 12:00 Uhr UTC."))] = None,
                      betrag: Annotated[str | None, Field(description="Betrag in ganzen Einheiten, zum Beispiel 0.25. Dann kommt der Gegenwert zurück.")] = None,
                      kette: KetteAngabe = None) -> dict:
    """Kurs und Gegenwert eines Krypto-Betrags in CHF, EUR und USD, heute oder an einem Stichtag (zum Beispiel am
    Tag der Zahlung des Geschädigten). Kurs in US-Dollar von DefiLlama, Umrechnung zu den Referenzkursen der
    Europäischen Zentralbank vom letzten Bankwerktag bis zum Stichtag. Passiv. Ein Gegenwert ist eine Bewertung
    zum Tageskurs, kein Betrag, der so ausbezahlt worden wäre."""
    v = Vorgang(fall, zweck, "krypto_kurs", abruf=ABRUF)
    return await _ausfuehren(v, _kurs(v, wert, datum, betrag, kette))


async def _kurs(v: Vorgang, wert: str, datum: str | None, betrag: str | None, kette: str | None) -> dict:
    a = (wert or "").strip()
    if kette:
        w = wert_finden(kette_finden(kette), a)
    elif a.lower() in _KURSWERTE:
        w = coin(KETTEN[_KURSWERTE[a.lower()][0]])
    else:
        w = next((x for (name, _), x in sorted(BEKANNT.items(), key=lambda e: e[0][0] != "ethereum") if x.symbol.lower() == a.lower()), None)
        if w is None:
            raise Abbruch(f"'{wert}' ist kein hinterlegtes Kürzel. Für einen anderen Token die Vertragsadresse und die Kette angeben.")
    zeit = _zeitpunkt(datum)
    menge: Decimal | None = None
    if betrag is not None and str(betrag).strip():
        try:
            menge = Decimal(str(betrag).strip().replace("'", "").replace(",", "."))
        except InvalidOperation as e:
            raise Abbruch(f"'{betrag}' ist kein Betrag. Form: 0.25") from e
        if menge < 0:
            raise Abbruch("Der Betrag darf nicht negativ sein.")
    k = await kurs(v, w, zeit)
    befund: dict[str, Any] = {"wert": w.als_dict(), "zeitpunkt": zeit_iso(zeit) or "aktuell", "kurs_je_einheit": kurs_als_dict(k)}
    if "usd" not in k:
        befund["hinweise"] = k["hinweise"]
        return v.abschluss(f"{w.symbol} {befund['zeitpunkt']}", "kurs", befund, quellen=k["quellen"],
                           parameter={"wert": wert, "datum": datum, "betrag": betrag, "kette": kette}, ergebnis="kein_treffer")
    if menge is not None:
        befund["betrag"] = {"menge": str(menge), "einheit": w.symbol}
        befund["gegenwert"] = {n: str((menge * k[n]).quantize(Decimal("0.01"))) for n in ("chf", "eur", "usd") if n in k}
    return v.abschluss(f"{w.symbol} {befund['zeitpunkt']}", "kurs", befund, quellen=k["quellen"],
                       parameter={"wert": wert, "datum": datum, "betrag": betrag, "kette": kette})
