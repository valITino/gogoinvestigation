#!/usr/bin/env python3
"""Prüft die Blockchain-Werkzeuge gegen die echten Dienste, ohne Schlüssel.

    python3 tools/krypto_live.py                  eine Zeile je Prüfung
    python3 tools/krypto_live.py --ausfuehrlich   dazu die Ergebnisse der Werkzeuge

Die Selbsttests (tools/selbsttest.py) laufen ohne Netz gegen eine erfundene Kette. Sie zeigen, dass die
Werkzeuge richtig rechnen. Diese Prüfung zeigt, dass die Dienste noch so antworten, wie die Werkzeuge es
erwarten: Schnittstellen ändern sich, und ein Dienst, der sein Format umstellt, fiele sonst erst in einem
Fall auf. Abgefragt werden nur Adressen und Transaktionen, die seit Jahren öffentlich bekannt sind
(die erste Bitcoin-Zahlung, eine WannaCry-Adresse, eine sanktionierte Adresse, Adressen einer Börse).

Fallakte: faelle/SELBSTTEST, wie bei tools/pruefen.py --live. Mit gesetzten Schlüsseln (Etherscan, Tronscan)
prüft das Skript nichts Zusätzliches. Dafür ist tools/pruefen.py --live da.
Rückgabewert 0: alles wie erwartet. 1: mindestens eine Abweichung.
"""
from __future__ import annotations

import asyncio
import json
import sys
from decimal import Decimal
from pathlib import Path

PROJEKT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJEKT))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start(venv=True)

try:
    from gateway import kern, krypto_ketten, quellen_krypto as k
    from gateway.akte import FAELLE
    from tools import fall as fallwerkzeug
except ModuleNotFoundError as e:
    sys.exit(f"Paket '{e.name}' fehlt. Bitte zuerst {plattform.SETUP} ausführen.")

FALL = "SELBSTTEST"
ZWECK = "Live-Prüfung der Blockchain-Quellen mit öffentlich bekannten Testwerten"
WANNACRY = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"                                       # eine der drei WannaCry-Adressen von 2017
ERSTE_ZAHLUNG = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"    # erste Bitcoin-Zahlung zwischen zwei Personen, Block 170
RONIN = "0x098B716B8Aaf21512996dC57EB0615e2383E2f96"                                  # Ronin-Bridge-Angriff 2022, auf der Sanktionsliste
RONIN_USDC = "0x55ae6a400fb41abe493f5f70bba0d6aa4386e2b082ad3ffc851bf22a3dfa7e9b"     # 1 Mio. USDC von dieser Adresse
BINANCE_ETH = "0x28C6c06298d514Db089934071355E5743bf21d60"
BINANCE_BTC = "1NDyJtNTjmwk5xPNhjgAMu4HDHigtobu1s"
OFAC_TRX = "TNiq9AXBp9EjUqhDhrwrfvAA8U3GUQZH81"
TRON = "TJmmqjb1DK9TTZbQXzRQ2AuA94z4gKAPFh"
TRON_USDT = "9e9a6aae39bd653da37988c5fe11332dc2a130acf6588d7021785d767655e621"        # 1 USDT an die Adresse oben

ergebnisse: list[tuple[bool, str, str]] = []
AUSFUEHRLICH = "--ausfuehrlich" in sys.argv


def zeigen(r: dict) -> None:
    if AUSFUEHRLICH:
        text = json.dumps(r.get("befund", r), ensure_ascii=False, indent=1)
        print("    " + (text if len(text) < 7000 else text[:7000] + "\n … gekürzt").replace("\n", "\n    "), flush=True)


async def pruefung(name: str, aufruf, erwartung) -> dict | None:
    """Ruft ein Werkzeug auf und prüft das Ergebnis. erwartung(befund, ergebnis) gibt einen Text zurück oder wirft."""
    try:
        r = await aufruf
        if r.get("ergebnis") not in ("ok", "kein_treffer"):
            raise AssertionError(f"{r.get('ergebnis')}: {r.get('fehler')}")
        detail = erwartung(r.get("befund") or {}, r)
        ergebnisse.append((True, name, detail or ""))
    except AssertionError as e:
        r = locals().get("r")
        ergebnisse.append((False, name, str(e) or "Erwartung nicht erfüllt"))
    except Exception as e:      # eine abgestürzte Prüfung ist eine fehlgeschlagene Prüfung
        r = locals().get("r")
        ergebnisse.append((False, name, f"{type(e).__name__}: {e}"))
    ok, _, detail = ergebnisse[-1]
    print(f"{plattform.GUT if ok else plattform.FEHLT} {name}" + (f"\n    {detail}" if detail else ""), flush=True)
    if isinstance(r, dict):
        zeigen(r)
        aus = [f"{f['quelle']}: {f['fehler']}" for f in r.get("fehlgeschlagen") or []]
        if aus:
            print("    Ausfälle unterwegs: " + " | ".join(aus[:4]), flush=True)
    return r if isinstance(r, dict) else None


def verteilung(b: dict) -> str:
    return ", ".join(f"{e['bezeichnung']} {e['anteil']} %" for e in b.get("verteilung") or [])


async def tokenliste() -> None:
    """Gleicht die eingebaute Liste bekannter Token mit DefiLlama ab: Kürzel und Dezimalstellen je Vertrag."""
    v = kern.Vorgang(FALL, ZWECK, "krypto_kurs", abruf="krypto_abruf")
    kennungen = {f"{krypto_ketten.KETTEN[kette].llama}:{w.vertrag}": w for (kette, _), w in krypto_ketten.BEKANNT.items()}
    a = await v.hole("DefiLlama", "eingebaute Tokenliste", "kurs", "https://coins.llama.fi/prices/current/" + ",".join(kennungen), cache_h=0)
    coins = {key.lower(): wert for key, wert in ((a.daten or {}).get("coins") or {}).items()} if isinstance(a.daten, dict) else {}
    falsch, fehlend = [], []
    for kennung, w in kennungen.items():
        eintrag = coins.get(kennung.lower())
        if not eintrag:
            fehlend.append(f"{w.symbol} auf {w.kette}")
        elif str(eintrag.get("symbol", "")).upper().replace("₮", "T") not in (w.symbol.upper(), w.symbol.upper() + ".E", w.symbol.upper() + "0") \
                or eintrag.get("decimals") not in (None, w.stellen):
            falsch.append(f"{w.symbol} auf {w.kette}: DefiLlama nennt {eintrag.get('symbol')} mit {eintrag.get('decimals')} Stellen")
    ok = a.ergebnis == "ok" and not falsch
    detail = (f"{len(kennungen) - len(fehlend) - len(falsch)} von {len(kennungen)} Verträgen bestätigt"
              + (f". Bei DefiLlama nicht geführt: {', '.join(fehlend)}" if fehlend else "") + (f". ABWEICHUNG: {'; '.join(falsch)}" if falsch else "")
              + (f". {a.fehler}" if a.fehler else ""))
    ergebnisse.append((ok, "Eingebaute Tokenliste stimmt mit DefiLlama überein", detail))
    print(f"{plattform.GUT if ok else plattform.FEHLT} Eingebaute Tokenliste stimmt mit DefiLlama überein\n    {detail}", flush=True)


async def alle() -> None:
    def adresse_btc(b: dict, r: dict) -> str:
        assert b["transaktionen"] >= 250 and Decimal(b["erhalten"]) >= Decimal("19.69"), f"Umfang unerwartet: {b.get('transaktionen')}, {b.get('erhalten')}"
        namen = {(e["quelle"], e["name"]) for e in b["etiketten"]}
        assert ("Ransomwhere", "WannaCry") in namen, f"Etikett WannaCry fehlt: {namen}"
        assert b["quellenstand"]["OFAC"]["ergebnis"] == "ok" and b["quellenstand"]["OFAC"]["adressen_in_liste"] > 300, b["quellenstand"]["OFAC"]
        return (f"{b['transaktionen']} Transaktionen, erhalten {b['erhalten']} BTC, Guthaben {b['guthaben']['betrag']} BTC, "
                f"OFAC-Liste mit {b['quellenstand']['OFAC']['adressen_in_liste']} Krypto-Adressen")
    await pruefung("Bitcoin: Adresse mit Stand und Etiketten (mempool.space, OFAC, Ransomwhere, TRM, WalletExplorer)",
                   k.krypto_adresse(FALL, ZWECK, WANNACRY), adresse_btc)

    def zahlung_btc(b: dict, r: dict) -> str:
        assert b["block"] == 170 and b["summe"] == "50" and len(b["ausgaenge"]) == 2, b
        assert b["gegenpruefung"]["ergebnis"] == "stimmt überein", b["gegenpruefung"]
        assert Decimal(b["ausgaenge"][0]["betrag"]) == 40 and b["ausgaenge"][0]["verbleib"] == "weitergeleitet", b["ausgaenge"]
        return f"Block 170, 10 und 40 BTC, {b['gegenpruefung']['quelle']} zeigt dasselbe" + (", Kurs fehlt wie erwartet (2009)" if "kurs_am_tag" not in b else "")
    await pruefung("Bitcoin: Transaktion, Verbleib der Ausgänge, Gegenprüfung bei Blockstream",
                   k.krypto_transaktion(FALL, ZWECK, ERSTE_ZAHLUNG, gegenpruefen=True), zahlung_btc)

    def fluss(b: dict, r: dict) -> str:
        assert b["summe_geht_auf"], f"Summe geht nicht auf: {b.get('nicht_zugeordnet')}"
        assert b["stationen"] and b["verteilung"], "keine Stationen"
        return (f"Start {b['startbetrag']} {b['einheit']}, {len(b['stationen'])} Stationen, {b['abfragen']['ausgefuehrt']} Abfragen: {verteilung(b)}"
                + (f"\n    Ansatzpunkt: {b['ansatzpunkte'][0]}" if b.get("ansatzpunkte") else ""))
    await pruefung("Bitcoin: Geldfluss ab einer Lösegeld-Adresse",
                   k.krypto_geldfluss(FALL, ZWECK, WANNACRY, tiefe=3, max_abfragen=90), fluss)

    def zahlung_eth(b: dict, r: dict) -> str:
        usdc = [z for z in b["zahlungen"] if z["einheit"] == "USDC"]
        assert len(usdc) == 1 and usdc[0]["betrag"] == "1000000" and usdc[0]["von"] == RONIN and "token_unbestaetigt" not in usdc[0], b["zahlungen"]
        assert usdc[0]["an"].lower() == "0xe708f17240732bbfa1baa8513f66b665fbc7ce10" and b["zeit"] == "2022-03-23T13:54:53Z", (usdc[0]["an"], b["zeit"])
        return f"1'000'000 USDC am {b['zeit']}, Gegenwert CHF {usdc[0].get('gegenwert', {}).get('chf')}, Etiketten: {list(b.get('etiketten', {}).values())[:1]}"
    await pruefung("Ethereum: Transaktion mit Token-Zahlung (Blockscout), Gegenwert am Tag",
                   k.krypto_transaktion(FALL, ZWECK, RONIN_USDC, kette="ethereum"), zahlung_eth)

    def adresse_eth(b: dict, r: dict) -> str:
        quellen = {e["quelle"] for e in b["etiketten"] if e["art"] == "sanktion"}
        assert {"OFAC", "TRM Labs", "Blockscout"} <= quellen, f"Sanktion nicht von allen drei Quellen gemeldet: {quellen}"
        assert b["art"] == "Konto" and b.get("erste_bewegung", "").startswith("2022-03-23"), b.get("erste_bewegung")
        return (f"sanktioniert laut {', '.join(sorted(quellen))}; {b.get('transaktionen')} Transaktionen; "
                f"Erstfinanzierung von {b.get('erstfinanzierung', {}).get('von')} {b.get('erstfinanzierung', {}).get('etiketten', '')}")
    await pruefung("Ethereum: Adresse mit Sanktions-Etiketten aus drei Quellen, Erstfinanzierung",
                   k.krypto_adresse(FALL, ZWECK, RONIN), adresse_eth)
    await pruefung("Ethereum: Geldfluss einer USDC-Zahlung",
                   k.krypto_geldfluss(FALL, ZWECK, RONIN_USDC, kette="ethereum", wert="USDC", tiefe=3, max_abfragen=60), fluss)

    def zuordnung_eth(b: dict, r: dict) -> str:
        assert b["adressen"][0].get("dienst") == "Binance", b["adressen"][0]
        return f"Dienst {b['adressen'][0]['dienst']}, Etiketten: {[e['name'] for e in b['adressen'][0]['etiketten']][:4]}"
    await pruefung("Ethereum: Börsen-Adresse wird als Dienst erkannt (Blockscout-Etiketten)",
                   k.krypto_zuordnung(FALL, ZWECK, [BINANCE_ETH]), zuordnung_eth)

    def zuordnung_mix(b: dict, r: dict) -> str:
        je = {x["adresse"]: x for x in b["adressen"]}
        assert any(e["quelle"] == "OFAC" for e in je[OFAC_TRX]["etiketten"]), f"OFAC-Eintrag der TRON-Adresse fehlt: {je[OFAC_TRX]}"
        assert je[BINANCE_BTC].get("dienst") == "Binance.com", je[BINANCE_BTC]
        assert b["quellenstand"]["Tether (Sperrliste)"]["ergebnis"] == "ok", b["quellenstand"]
        return (f"TRON-Adresse laut OFAC: {next(e['name'] for e in je[OFAC_TRX]['etiketten'] if e['quelle'] == 'OFAC')}; "
                f"von Tether gesperrt: {'gesperrt' in je[OFAC_TRX].get('auffaellig', [])}; Bitcoin-Adresse laut WalletExplorer: Binance.com")
    await pruefung("Zuordnung über Ketten hinweg: OFAC für TRON, WalletExplorer für Bitcoin, Sperrliste von Tether",
                   k.krypto_zuordnung(FALL, ZWECK, [OFAC_TRX, BINANCE_BTC]), zuordnung_mix)

    def adresse_tron(b: dict, r: dict) -> str:
        assert b["art"] == "Konto" and b["erste_bewegung"].startswith("2018-08-23"), b
        return f"Konto seit {b['erste_bewegung']}, {b['guthaben']['betrag']} TRX, Erstfinanzierung von {b.get('erstfinanzierung', {}).get('von')}"
    await pruefung("TRON: Adresse (TronGrid)", k.krypto_adresse(FALL, ZWECK, TRON), adresse_tron)

    def liste_tron(b: dict, r: dict) -> str:
        treffer = [z for z in b["zahlungen"] if z["tx"] == TRON_USDT]
        assert treffer and treffer[0]["betrag"] == "1" and treffer[0]["richtung"] == "ein" and "token_unbestaetigt" not in treffer[0], b["zahlungen"][:3]
        return f"{len(b['zahlungen'])} Eingänge in USDT, darunter die Testzahlung über 1 USDT"
    await pruefung("TRON: Eingänge in USDT", k.krypto_transaktionen(FALL, ZWECK, TRON, wert="USDT", richtung="ein", limit=20), liste_tron)

    def zahlung_tron(b: dict, r: dict) -> str:
        assert b["kette"] == "tron" and b["zahlungen"][0]["betrag"] == "1" and b["zahlungen"][0]["einheit"] == "USDT", b
        assert b["zahlungen"][0]["an"] == TRON and b["zahlungen"][0]["von"] == "TQguVRm3tDmZG7AeZ47Mk6qi6GTF1ZDqkZ", b["zahlungen"][0]
        return f"Kette selbst gefunden (Bitcoin kennt die ID nicht), 1 USDT am {b['zeit']}, Gebühr {b['gebuehr']['betrag']} TRX"
    await pruefung("TRON: Transaktion ohne Angabe der Kette", k.krypto_transaktion(FALL, ZWECK, TRON_USDT), zahlung_tron)
    await pruefung("TRON: Geldfluss einer USDT-Zahlung", k.krypto_geldfluss(FALL, ZWECK, TRON_USDT, tiefe=2, max_abfragen=30), fluss)

    def kurs(b: dict, r: dict) -> str:
        je = b["kurs_je_einheit"]
        assert 30000 < float(je["usd"]) < 40000 and je["wechselkurs_vom"] == "2023-11-14" and 0.85 < float(je["chf"]) / float(je["usd"]) < 0.95, je
        return f"1 BTC am 14.11.2023: USD {je['usd']}, CHF {je['chf']}, EUR {je['eur']}"
    await pruefung("Kurs am Stichtag (DefiLlama, EZB)", k.krypto_kurs(FALL, ZWECK, "BTC", datum="2023-11-14", betrag="1"), kurs)

    def kurs_wochenende(b: dict, r: dict) -> str:
        assert b["kurs_je_einheit"]["wechselkurs_vom"] == "2023-11-10", b["kurs_je_einheit"]
        return f"Samstag, 11.11.2023: Wechselkurs vom Freitag ({b['kurs_je_einheit']['wechselkurs_vom']}), 25'000 USDT = CHF {b['gegenwert']['chf']}"
    await pruefung("Kurs am Wochenende: letzter Referenzkurs davor", k.krypto_kurs(FALL, ZWECK, "USDT", datum="2023-11-11", betrag="25000"), kurs_wochenende)

    def optimism(b: dict, r: dict) -> str:
        assert b["art"].startswith("Programm"), b
        return f"{b.get('name')}, {b['guthaben']['betrag']} ETH"
    await pruefung("Optimism über Blockscout", k.krypto_adresse(FALL, ZWECK, "0x4200000000000000000000000000000000000006", kette="optimism"), optimism)
    await tokenliste()


def main() -> int:
    pfad = FAELLE / FALL
    if not (pfad / "fall.json").is_file():
        for ordner in fallwerkzeug.UNTERORDNER:
            (pfad / ordner).mkdir(parents=True, exist_ok=True)
        fallwerkzeug.schreiben(pfad / "fall.json", {"fall_id": FALL, "titel": "Live-Test der Quellen", "freigaben": {}})
    asyncio.run(alle())
    fehler = sum(1 for ok, _, _ in ergebnisse if not ok)
    print(f"\n{len(ergebnisse) - fehler} von {len(ergebnisse)} Prüfungen gegen die echten Dienste bestanden.")
    if fehler:
        print("Abweichungen können an einer Störung des Dienstes liegen (später wiederholen) oder an einer geänderten Schnittstelle.")
    return 1 if fehler else 0


if __name__ == "__main__":
    sys.exit(main())
