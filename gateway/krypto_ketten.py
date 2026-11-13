"""Zugriff auf die Ketten: Bitcoin, die Ethereum-Familie und TRON, mit einheitlichen Datensätzen.

Jede Kette hat ihre eigene Schnittstelle und ihre eigenen Einheiten. Dieses Modul fragt sie ab und
liefert für alle dieselbe Form zurück, damit Werkzeuge und Geldfluss-Verfolgung nur eine kennen müssen:

    Zahlung auf einer Konto-Kette (Ethereum-Familie, TRON)
        {"tx", "zeit", "block", "pos", "von", "an", "betrag", "wert": Wert, "ok"}
    Bitcoin-Transaktion
        {"tx", "zeit", "block", "bestaetigt", "gebuehr", "eingaenge": [...], "ausgaenge": [...]}

Beträge sind ganze Zahlen in der kleinsten Einheit (Satoshi, Wei, Sun, Token-Grundeinheit). Erst die
Ausgabe rechnet mit ``dezimal()`` um, ohne Gleitkommazahlen. Zeiten sind Unix-Sekunden in UTC.

Quellen (alle ohne Schlüssel nutzbar, Stand der Prüfung siehe README):
    Bitcoin     mempool.space, bei Störung Blockstream (gleiche Schnittstelle «Esplora»)
    Ethereum    Blockscout. Mit ETHERSCAN_API_KEY zusätzlich Etherscan, auch für weitere Ketten
    TRON        TronGrid, mit TRONGRID_API_KEY weniger gedrosselt
Eigene Instanzen lassen sich über KRYPTO_BITCOIN_API, KRYPTO_<KETTE>_API und KRYPTO_TRON_API eintragen.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from .kern import Abbruch, Antwort, Vorgang, einstellung, saeubern
from .krypto_adressen import eip55, tron_aus_hex, tron_zu_hex

SEITE = 200          # Zahlungen je Abruf auf Konto-Ketten. Wer mehr Abgänge hat, gilt als Sammeladresse
TRANSFER = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"     # Ereignis Transfer(address,address,uint256)


class Quellfehler(Exception):
    """Eine Abfrage, auf die es ankam, ist fehlgeschlagen. Trägt die Antwort samt Beleg."""

    nur_hier = False      # True: Der Fehler betrifft nur diese eine Abfrage, nicht die Quelle im Ganzen

    def __init__(self, antwort: Antwort, was: str = "") -> None:
        super().__init__(antwort.fehler or was)
        self.antwort, self.was = antwort, was


# --------------------------------------------------------------------------- Ketten und Werte

@dataclass(frozen=True)
class Kette:
    name: str
    anzeige: str
    familie: str                 # bitcoin | evm | tron
    coin: str                    # Kürzel der eigenen Währung
    stellen: int
    kurs_id: str                 # Kennung bei DefiLlama
    chain_id: int | None = None
    blockscout: str | None = None
    llama: str = ""              # Kettenname bei DefiLlama, für Token-Kurse


KETTEN: dict[str, Kette] = {k.name: k for k in (
    Kette("bitcoin", "Bitcoin", "bitcoin", "BTC", 8, "coingecko:bitcoin"),
    Kette("ethereum", "Ethereum", "evm", "ETH", 18, "coingecko:ethereum", 1, "https://eth.blockscout.com", "ethereum"),
    Kette("optimism", "Optimism", "evm", "ETH", 18, "coingecko:ethereum", 10, "https://optimism.blockscout.com", "optimism"),
    Kette("base", "Base", "evm", "ETH", 18, "coingecko:ethereum", 8453, "https://base.blockscout.com", "base"),
    Kette("arbitrum", "Arbitrum One", "evm", "ETH", 18, "coingecko:ethereum", 42161, "https://arbitrum.blockscout.com", "arbitrum"),
    Kette("polygon", "Polygon", "evm", "POL", 18, "coingecko:polygon-ecosystem-token", 137, "https://polygon.blockscout.com", "polygon"),
    Kette("gnosis", "Gnosis", "evm", "xDAI", 18, "coingecko:xdai", 100, "https://gnosis.blockscout.com", "xdai"),
    Kette("bsc", "BNB Smart Chain", "evm", "BNB", 18, "coingecko:binancecoin", 56, None, "bsc"),
    Kette("tron", "TRON", "tron", "TRX", 6, "coingecko:tron", llama="tron"),
)}


@dataclass(frozen=True)
class Wert:
    """Ein Vermögenswert auf einer Kette: die eigene Währung oder ein Token, bestimmt durch seinen Vertrag."""
    kette: str
    symbol: str
    stellen: int | None          # None: noch unbekannt, ergibt sich aus der ersten Zahlung
    vertrag: str | None = None   # None: eigene Währung der Kette
    bekannt: bool = False        # steht in der eingebauten Liste, ist also der echte Token dieses Namens
    kurs_id: str | None = None
    emittent: str = ""

    @property
    def schluessel(self) -> str:
        return (self.vertrag or "coin") if KETTEN[self.kette].familie == "tron" else (self.vertrag or "coin").lower()

    def als_dict(self) -> dict:
        d: dict[str, Any] = {"symbol": self.symbol, "kette": self.kette}
        if self.vertrag:
            d.update(vertrag=self.vertrag, echt=self.bekannt)
            if self.emittent:
                d["emittent"] = self.emittent
        return d


# Bekannte Token: (Kette, Vertrag, Kürzel, Dezimalstellen, Kurskennung, Emittent). Ein Token wird am Vertrag
# erkannt, nie am Namen: Jeder kann einen Token «USDT» nennen. tools/pruefen.py --live gleicht die Liste mit
# DefiLlama ab (Kürzel und Dezimalstellen).
_BEKANNT = (
    ("ethereum", "0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT", 6, "coingecko:tether", "Tether"),
    ("ethereum", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC", 6, "coingecko:usd-coin", "Circle"),
    ("ethereum", "0x6B175474E89094C44Da98b954EedeAC495271d0F", "DAI", 18, "coingecko:dai", ""),
    ("ethereum", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "WETH", 18, "coingecko:weth", ""),
    ("tron", "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "USDT", 6, "coingecko:tether", "Tether"),
    ("tron", "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8", "USDC", 6, "coingecko:usd-coin", "Circle"),
    ("bsc", "0x55d398326f99059fF775485246999027B3197955", "USDT", 18, "coingecko:tether", "Binance (Abbild von USDT)"),
    ("bsc", "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d", "USDC", 18, "coingecko:usd-coin", "Binance (Abbild von USDC)"),
    ("polygon", "0xc2132D05D31c914a87C6611C10748AEb04B58e8F", "USDT", 6, "coingecko:tether", "Tether"),
    ("polygon", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "USDC", 6, "coingecko:usd-coin", "Circle"),
    ("arbitrum", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", "USDT", 6, "coingecko:tether", "Tether"),
    ("arbitrum", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "USDC", 6, "coingecko:usd-coin", "Circle"),
    ("optimism", "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58", "USDT", 6, "coingecko:tether", "Tether"),
    ("optimism", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "USDC", 6, "coingecko:usd-coin", "Circle"),
    ("base", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "USDC", 6, "coingecko:usd-coin", "Circle"),
)
BEKANNT: dict[tuple[str, str], Wert] = {
    (k, v if k == "tron" else v.lower()): Wert(k, s, n, v, True, kurs, emittent) for k, v, s, n, kurs, emittent in _BEKANNT}
# Kürzel, unter denen Fälschungen üblich sind: Ein Token mit diesem Namen, aber fremdem Vertrag, wird markiert.
BEGEHRT = {"USDT", "USDC", "DAI", "BUSD", "TUSD", "WETH", "WBTC", "ETH", "BTC", "TRX", "BNB"}


def coin(kette: Kette) -> Wert:
    return Wert(kette.name, kette.coin, kette.stellen, None, True, kette.kurs_id)


_ALIAS = {"btc": "bitcoin", "eth": "ethereum", "bnb": "bsc", "binance": "bsc", "trx": "tron", "matic": "polygon",
          "op": "optimism", "arb": "arbitrum", "xdai": "gnosis"}


def kette_finden(name: str | None) -> Kette:
    n = (name or "").strip().lower()
    k = KETTEN.get(_ALIAS.get(n, n))
    if not k:
        raise Abbruch(f"Unbekannte Kette '{name}'. Möglich: {', '.join(KETTEN)}.")
    return k


def wert_finden(kette: Kette, angabe: str | None) -> Wert:
    """Wert aus der Angabe des Aufrufers: leer oder 'coin' für die eigene Währung, ein bekanntes Kürzel
    (USDT, USDC …) oder die Vertragsadresse eines Tokens."""
    a = (angabe or "").strip()
    if not a or a.lower() in ("coin", kette.coin.lower()):
        return coin(kette)
    if kette.familie == "bitcoin":
        raise Abbruch("Auf Bitcoin gibt es hier nur den Wert BTC.")
    for (k, _), w in BEKANNT.items():
        if k == kette.name and w.symbol.lower() == a.lower():
            return w
    vertrag = adresse_normal(kette, a)
    if not vertrag:
        kuerzel = sorted({w.symbol for (k, _), w in BEKANNT.items() if k == kette.name})
        raise Abbruch(f"'{angabe}' ist auf {kette.anzeige} weder ein bekanntes Kürzel ({', '.join(kuerzel) or 'keines hinterlegt'}) "
                      "noch eine Vertragsadresse. Für einen anderen Token dessen Vertragsadresse angeben.")
    return token(kette, vertrag)


def token(kette: Kette, vertrag: str, symbol: str = "", stellen: int | None = None) -> Wert:
    """Wert zu einem Vertrag. Bekannte Verträge kommen aus der eingebauten Liste, bei anderen gelten die
    Angaben der Quelle, und der Name wird als unbestätigt geführt."""
    norm = adresse_normal(kette, vertrag) or vertrag
    b = BEKANNT.get((kette.name, norm if kette.familie == "tron" else norm.lower()))
    if b:
        return b
    return Wert(kette.name, saeubern(symbol, 24) or "Token", stellen, norm, False,
                f"{kette.llama}:{norm}" if kette.llama else None)


def adresse_normal(kette: Kette, adresse: str) -> str | None:
    """Einheitliche Schreibweise einer Adresse auf dieser Kette, oder None wenn sie dort nicht gültig ist."""
    a = (adresse or "").strip()
    if kette.familie == "evm":
        h = a.lower()
        if len(h) == 42 and h.startswith("0x") and all(z in "0123456789abcdef" for z in h[2:]):
            return eip55(h)
        return None
    if kette.familie == "tron":
        if tron_zu_hex(a):
            return a
        return tron_aus_hex(a) if a.lower().startswith(("41", "0x")) else None
    return a or None


def gleich(kette: Kette, a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return a.lower() == b.lower() if kette.familie == "evm" or a.lower().startswith("bc1") else a == b


def dezimal(n: int, stellen: int | None) -> str:
    """Ganzzahl der kleinsten Einheit als Dezimalzahl, exakt und ohne überflüssige Nullen."""
    if not stellen:
        return str(n)
    vz, n = ("-" if n < 0 else ""), abs(n)
    ganz, rest = divmod(n, 10 ** stellen)
    nach = str(rest).rjust(stellen, "0").rstrip("0")
    return f"{vz}{ganz}" + (f".{nach}" if nach else "")


def zeit_iso(sekunden: int | float | None) -> str | None:
    if not sekunden:
        return None
    return datetime.fromtimestamp(int(sekunden), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _zeit_aus_iso(text: str | None) -> int | None:
    if not text:
        return None
    try:
        return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _zahl(wert: Any, basis: int = 10) -> int:
    """Zahl aus den Schreibweisen der Schnittstellen: 123, "123", "0x7b". Unlesbares zählt als 0."""
    if isinstance(wert, bool) or wert is None:
        return 0
    if isinstance(wert, int):
        return wert
    try:
        t = str(wert).strip()
        return int(t, 16) if t.lower().startswith("0x") or basis == 16 else int(t)
    except ValueError:
        return 0


def _gesperrt(v: Vorgang) -> set[str]:
    """Quellen, die in diesem Vorgang schon ausgefallen sind. Sie werden nicht erneut versucht."""
    if not hasattr(v, "ausgefallen"):
        v.ausgefallen = set()       # type: ignore[attr-defined]
    return v.ausgefallen            # type: ignore[attr-defined]


async def _reihum(v: Vorgang, anbieter: list[dict], ziel: str, ziel_typ: str, schritt: str, **angaben: Any) -> Antwort:
    """Fragt die Anbieter der Reihe nach, bis einer antwortet. Ein ausgefallener Anbieter wird für den Rest
    des Vorgangs übersprungen, solange es einen anderen gibt."""
    aus = _gesperrt(v)
    kandidaten = [a for a in anbieter if a["quelle"] not in aus] or anbieter[-1:]
    antwort: Antwort | None = None
    for i, a in enumerate(kandidaten):
        letzter = i == len(kandidaten) - 1
        antwort = await v.hole(a["quelle"], ziel, ziel_typ, a["url"], schritt=schritt, nochmal=letzter,
                               **{**angaben, **a.get("angaben", {})})
        if antwort.ergebnis != "fehler":
            return antwort
        if len(anbieter) > 1:
            aus.add(a["quelle"])
    assert antwort is not None
    return antwort


# --------------------------------------------------------------------------- Bitcoin (Esplora: mempool.space, Blockstream)

def _btc_basen() -> list[tuple[str, str]]:
    eigen = einstellung("KRYPTO_BITCOIN_API")
    if eigen:
        return [("Bitcoin-Explorer (eigene Instanz)", eigen.rstrip("/"))]
    return [("mempool.space", "https://mempool.space/api"), ("Blockstream", "https://blockstream.info/api")]


def _btc_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    if status == 400:
        return "fehler", f"Die Quelle weist die Anfrage zurück: {saeubern(text, 120) or 'HTTP 400'}."
    if status == 200 and daten is None:
        return "fehler", "Die Quelle hat kein lesbares JSON geliefert. Details in den Rohdaten."
    return None


async def _btc(v: Vorgang, pfad: str, ziel: str, ziel_typ: str, schritt: str, cache_h: float = 24.0,
               quelle: str | None = None) -> Antwort:
    anbieter = [{"quelle": name, "url": basis + pfad} for name, basis in _btc_basen() if quelle in (None, name)]
    if not anbieter:
        raise Abbruch(f"Die Quelle '{quelle}' ist für Bitcoin nicht eingerichtet.")
    return await _reihum(v, anbieter, ziel, ziel_typ, schritt, cache_h=cache_h, deutung=_btc_deutung)


def _btc_tx(d: dict) -> dict:
    status = d.get("status") or {}
    ein = []
    for e in d.get("vin") or []:
        vor = e.get("prevout") or {}
        ein.append({"adresse": vor.get("scriptpubkey_address"), "betrag": _zahl(vor.get("value")), "tx": e.get("txid"),
                    "ausgang": e.get("vout"), "coinbase": bool(e.get("is_coinbase"))})
    aus = [{"nr": i, "adresse": a.get("scriptpubkey_address"), "betrag": _zahl(a.get("value")),
            "typ": a.get("scriptpubkey_type")} for i, a in enumerate(d.get("vout") or [])]
    return {"tx": d.get("txid"), "zeit": status.get("block_time"), "block": status.get("block_height"),
            "bestaetigt": bool(status.get("confirmed")), "gebuehr": _zahl(d.get("fee")), "eingaenge": ein, "ausgaenge": aus}


async def btc_adresse(v: Vorgang, adresse: str, schritt: str = "Stand der Adresse") -> tuple[Antwort, dict]:
    a = await _btc(v, f"/address/{adresse}", adresse, "wallet", schritt, cache_h=1)
    if a.ergebnis != "ok" or not isinstance(a.daten, dict):
        raise Quellfehler(a, "Adresse")
    kette, offen = a.daten.get("chain_stats") or {}, a.daten.get("mempool_stats") or {}
    erhalten, ausgegeben = _zahl(kette.get("funded_txo_sum")), _zahl(kette.get("spent_txo_sum"))
    return a, {"erhalten": erhalten, "ausgegeben": ausgegeben, "guthaben": erhalten - ausgegeben,
               "tx_anzahl": _zahl(kette.get("tx_count")), "eingaenge": _zahl(kette.get("funded_txo_count")),
               "abgaenge": _zahl(kette.get("spent_txo_count")), "unbestaetigt": _zahl(offen.get("tx_count")),
               "unbestaetigt_saldo": _zahl(offen.get("funded_txo_sum")) - _zahl(offen.get("spent_txo_sum"))}


async def btc_tx(v: Vorgang, txid: str, schritt: str = "Transaktion", quelle: str | None = None) -> tuple[Antwort, dict | None]:
    a = await _btc(v, f"/tx/{txid}", txid, "transaktion", schritt, quelle=quelle)
    if a.ergebnis == "kein_treffer":
        return a, None
    if a.ergebnis != "ok" or not isinstance(a.daten, dict):
        raise Quellfehler(a, "Transaktion")
    return a, _btc_tx(a.daten)


async def btc_verbleib(v: Vorgang, txid: str, schritt: str = "Verbleib der Ausgänge") -> tuple[Antwort, list[dict]]:
    """Für jeden Ausgang einer Transaktion: noch unbewegt, oder von welcher Transaktion ausgegeben."""
    a = await _btc(v, f"/tx/{txid}/outspends", txid, "transaktion", schritt, cache_h=1)
    if a.ergebnis != "ok" or not isinstance(a.daten, list):
        raise Quellfehler(a, "Verbleib")
    return a, [{"ausgegeben": bool(e.get("spent")), "tx": e.get("txid"), "eingang": e.get("vin"),
                "zeit": (e.get("status") or {}).get("block_time"), "bestaetigt": bool((e.get("status") or {}).get("confirmed"))}
               for e in a.daten]


async def btc_txs(v: Vorgang, adresse: str, nach: str | None = None,
                  schritt: str = "Transaktionen der Adresse") -> tuple[Antwort, list[dict]]:
    """Transaktionen einer Adresse, jüngste zuerst, 50 je Abruf. ``nach``: ID der letzten schon bekannten."""
    pfad = f"/address/{adresse}/txs" + (f"?after_txid={nach}" if nach else "")
    a = await _btc(v, pfad, adresse, "wallet", schritt, cache_h=1)
    if a.ergebnis != "ok" or not isinstance(a.daten, list):
        raise Quellfehler(a, "Transaktionen")
    return a, [_btc_tx(d) for d in a.daten if isinstance(d, dict)]


# --------------------------------------------------------------------------- Ethereum-Familie (Blockscout, Etherscan)

BLOCKSCOUT_API = "https://api.blockscout.com"       # Zugang mit Schlüssel, eine Adresse für alle Ketten: …/{chain_id}/api/…
_BLOCKSCOUT_403 = ("Blockscout weist diesen Anschluss ab (HTTP 403, Schutz vor automatischen Abfragen). Abhilfe: "
                   "BLOCKSCOUT_API_KEY eintragen (kostenlos, https://dev.blockscout.com) oder ETHERSCAN_API_KEY, über "
                   "OSINT_PROXY einen anderen Ausgang wählen oder eine eigene Instanz angeben (KRYPTO_<KETTE>_API).")
_BLOCKSCOUT_429 = ("Blockscout drosselt Abfragen ohne Schlüssel (HTTP 429). Abhilfe: BLOCKSCOUT_API_KEY eintragen "
                   "(kostenlos, https://dev.blockscout.com), oder später an derselben Stelle fortsetzen.")
_BLOCKSCOUT_KEY = ("Blockscout nimmt den Schlüssel nicht an oder das Tageskontingent ist aufgebraucht (HTTP {status}). "
                   "BLOCKSCOUT_API_KEY in .env prüfen, Verbrauch auf https://dev.blockscout.com ansehen.")


def _blockscout_fehler(status: int) -> str | None:
    """Fehlertext für die Zustände, die bei Blockscout am Zugang liegen und nicht an der Frage."""
    mit_schluessel = bool(einstellung("BLOCKSCOUT_API_KEY"))
    if status in (401, 402) or (status in (403, 429) and mit_schluessel):
        return _BLOCKSCOUT_KEY.format(status=status)
    if status == 403:
        return _BLOCKSCOUT_403
    if status == 429:
        return _BLOCKSCOUT_429
    return None


def evm_anbieter(kette: Kette) -> list[dict]:
    """Anbieter für eine Kette der Ethereum-Familie, in der Reihenfolge der Abfrage."""
    liste = []
    eigen = einstellung(f"KRYPTO_{kette.name.upper()}_API")
    schluessel = einstellung("BLOCKSCOUT_API_KEY")
    if eigen:
        liste.append({"quelle": "Blockscout (eigene Instanz)", "art": "blockscout", "basis": eigen.rstrip("/")})
    elif schluessel and kette.blockscout:       # der Weg, den Blockscout für Programme vorsieht: eine Adresse, Kette in der Zahl
        liste.append({"quelle": "Blockscout", "art": "blockscout", "basis": f"{BLOCKSCOUT_API}/{kette.chain_id}", "apikey": schluessel})
    elif kette.blockscout:
        liste.append({"quelle": "Blockscout", "art": "blockscout", "basis": kette.blockscout})
    if einstellung("ETHERSCAN_API_KEY"):
        liste.append({"quelle": "Etherscan", "art": "etherscan", "basis": "https://api.etherscan.io/v2/api"})
    if not liste:
        raise Abbruch(f"{kette.anzeige} lässt sich nur mit einem Etherscan-Schlüssel abfragen (ETHERSCAN_API_KEY in .env, "
                      "https://etherscan.io/apidashboard). BNB Smart Chain und Base verlangen dort ein bezahltes Abo.")
    return liste


def _liste_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    """Blockscout in der Form von Etherscan: erst die Zustände, die am Zugang liegen, dann der Inhalt."""
    if _blockscout_fehler(status):
        return "fehler", _blockscout_fehler(status)
    return _etherscan_form(status, daten, text)


def _etherscan_form(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    """Schnittstelle nach Art von Etherscan: Fehler und leere Listen kommen mit HTTP 200."""
    if status != 200:
        return None
    if not isinstance(daten, dict):
        return "fehler", "Die Quelle hat kein lesbares JSON geliefert. Details in den Rohdaten."
    ergebnis = daten.get("result")
    if "jsonrpc" in daten:
        if daten.get("error"):
            return "fehler", f"Die Quelle meldet: {saeubern(str((daten['error'] or {}).get('message') or daten['error']), 200)}"
        return ("kein_treffer", None) if ergebnis in (None, "0x") else None
    if str(daten.get("status")) == "1":
        return None
    if isinstance(ergebnis, list) or str(daten.get("message") or "").lower().startswith("no "):
        return "kein_treffer", None
    if ergebnis is None:
        return "kein_treffer", None
    return "fehler", f"Die Quelle meldet: {saeubern(str(ergebnis or daten.get('message')), 240)}"


def _v2_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    if _blockscout_fehler(status):
        return "fehler", _blockscout_fehler(status)
    if status == 422:
        return "fehler", "Blockscout weist die Anfrage zurück (HTTP 422): Adresse oder Transaktions-ID hat nicht die erwartete Form."
    if status == 200 and daten is None:
        return "fehler", "Blockscout hat kein lesbares JSON geliefert. Details in den Rohdaten."
    return None


async def _evm_liste(v: Vorgang, kette: Kette, modul: str, aktion: str, ziel: str, ziel_typ: str, schritt: str,
                     cache_h: float = 1.0, nur: str | None = None, **params: Any) -> tuple[Antwort, Any]:
    """Abfrage nach Art von Etherscan (module/action). Blockscout und Etherscan verstehen dieselbe Form."""
    anbieter = []
    for a in evm_anbieter(kette):
        if nur and a["art"] != nur:
            continue
        if a["art"] == "etherscan":
            anbieter.append({"quelle": a["quelle"], "url": a["basis"], "angaben": {
                "params": {"chainid": kette.chain_id, "module": modul, "action": aktion, **params,
                           "apikey": einstellung("ETHERSCAN_API_KEY")}, "geheim": ("apikey",), "deutung": _etherscan_form}})
        else:
            anbieter.append({"quelle": a["quelle"], "url": a["basis"] + "/api", "angaben": {
                "params": {"module": modul, "action": aktion, **params, **({"apikey": a["apikey"]} if a.get("apikey") else {})},
                **({"geheim": ("apikey",)} if a.get("apikey") else {})}})
    if not anbieter:
        raise Abbruch(f"Für {kette.anzeige} ist kein passender Anbieter eingerichtet.")
    a = await _reihum(v, anbieter, ziel, ziel_typ, schritt, cache_h=cache_h, deutung=_liste_deutung)
    if a.ergebnis == "fehler":
        raise Quellfehler(a, aktion)
    ergebnis = (a.daten or {}).get("result") if isinstance(a.daten, dict) else None
    return a, ergebnis


async def _evm_v2(v: Vorgang, kette: Kette, pfad: str, ziel: str, ziel_typ: str, schritt: str,
                  cache_h: float = 1.0, params: dict | None = None, geduld: bool = True) -> Antwort | None:
    """Abfrage der Blockscout-Schnittstelle v2. None, wenn für die Kette kein Blockscout eingerichtet ist
    oder Blockscout in diesem Vorgang schon ausgefallen ist."""
    bs = [a for a in evm_anbieter(kette) if a["art"] == "blockscout"]
    if not bs or bs[0]["quelle"] in _gesperrt(v):
        return None
    hat_ersatz = len(evm_anbieter(kette)) > 1
    zugang: dict[str, Any] = {"params": dict(params)} if params else {}
    if bs[0].get("apikey"):
        zugang = {"params": {**(params or {}), "apikey": bs[0]["apikey"]}, "geheim": ("apikey",)}
    if not geduld:               # für Abfragen, die einen zweiten Weg haben: kurz warten, nicht wiederholen
        zugang["zeitlimit"] = 25.0
    a = await v.hole(bs[0]["quelle"], ziel, ziel_typ, bs[0]["basis"] + "/api/v2" + pfad, schritt=schritt,
                     cache_h=cache_h, deutung=_v2_deutung, nochmal=geduld and not hat_ersatz, **zugang)
    if a.ergebnis == "fehler" and hat_ersatz:
        _gesperrt(v).add(bs[0]["quelle"])
        return None
    return a


def _evm_etiketten(objekt: dict | None) -> list[dict]:
    """Etiketten, die Blockscout an eine Adresse hängt (in Transaktionen eingebettet)."""
    from .krypto_zuordnung import blockscout_etiketten      # spät, die Module brauchen einander
    return blockscout_etiketten(((objekt or {}).get("metadata") or {}).get("tags") or [])


async def evm_adresse(v: Vorgang, kette: Kette, adresse: str, schritt: str = "Stand der Adresse",
                      zaehler: bool = True) -> tuple[list[str], dict]:
    """Guthaben der eigenen Währung, Vertrag ja/nein, Name, Zahl der Transaktionen."""
    belege: list[str] = []
    a = await _evm_v2(v, kette, f"/addresses/{adresse}", adresse, "wallet", schritt)
    if a is not None and a.ergebnis == "fehler":
        raise Quellfehler(a, "Adresse")
    if a is not None and a.ergebnis == "ok" and isinstance(a.daten, dict):
        d = a.daten
        belege.append(a.id)
        info = {"guthaben": _zahl(d.get("coin_balance")), "vertrag": bool(d.get("is_contract")),
                "name": saeubern(d.get("name"), 80) or None, "geprueft": bool(d.get("is_verified")),
                "betrug_markiert": bool(d.get("is_scam")), "etiketten": _evm_etiketten(d),
                "token": None, "tx_anzahl": None, "token_zahlungen": None, "quelle": "Blockscout"}
        if isinstance(d.get("token"), dict):
            t = d["token"]
            info["token"] = token(kette, adresse, t.get("symbol") or "", _zahl(t.get("decimals")) if t.get("decimals") else None)
        if zaehler:
            z = await _evm_v2(v, kette, f"/addresses/{adresse}/counters", adresse, "wallet", "Zahl der Transaktionen")
            if z is not None and z.ergebnis == "ok" and isinstance(z.daten, dict):
                belege.append(z.id)
                info["tx_anzahl"] = _zahl(z.daten.get("transactions_count"))
                info["token_zahlungen"] = _zahl(z.daten.get("token_transfers_count"))
        return belege, info
    if a is not None and a.ergebnis == "kein_treffer":       # Blockscout kennt die Adresse nicht: nie benutzt
        return [a.id], {"guthaben": 0, "vertrag": False, "name": None, "geprueft": False, "betrug_markiert": False,
                        "etiketten": [], "token": None, "tx_anzahl": 0, "token_zahlungen": 0, "quelle": "Blockscout",
                        "unbenutzt": True}
    # Ohne Blockscout: Guthaben und Vertragscode über die Etherscan-Schnittstelle
    g, stand = await _evm_liste(v, kette, "account", "balance", adresse, "wallet", schritt, nur="etherscan",
                                address=adresse, tag="latest")
    c, code = await _evm_liste(v, kette, "proxy", "eth_getCode", adresse, "wallet", "Vertrag oder Konto?", cache_h=24,
                               nur="etherscan", address=adresse, tag="latest")
    return [g.id, c.id], {"guthaben": _zahl(stand), "vertrag": isinstance(code, str) and len(code) > 2, "name": None,
                          "geprueft": False, "betrug_markiert": False, "etiketten": [], "token": None,
                          "tx_anzahl": None, "token_zahlungen": None, "quelle": "Etherscan"}


async def evm_token_guthaben(v: Vorgang, kette: Kette, adresse: str) -> tuple[list[str], list[dict]]:
    """Token-Guthaben einer Adresse: [{"wert": Wert, "betrag": int}]. Über Blockscout alle, sonst nur die bekannten."""
    a = await _evm_v2(v, kette, f"/addresses/{adresse}/token-balances", adresse, "wallet", "Token-Guthaben")
    if a is not None and a.ergebnis == "ok" and isinstance(a.daten, list):
        liste = []
        for e in a.daten:
            t = e.get("token") or {}
            if t.get("type") not in (None, "ERC-20") or not t.get("address_hash"):
                continue
            w = token(kette, t["address_hash"], t.get("symbol") or "", _zahl(t.get("decimals")) if t.get("decimals") else None)
            liste.append({"wert": w, "betrag": _zahl(e.get("value"))})
        return [a.id], liste
    if a is not None and a.ergebnis == "fehler":
        raise Quellfehler(a, "Token-Guthaben")
    belege, liste = [], []
    for (k, _), w in BEKANNT.items():
        if k != kette.name:
            continue
        b, stand = await _evm_liste(v, kette, "account", "tokenbalance", adresse, "wallet", f"Guthaben {w.symbol}",
                                    nur="etherscan", contractaddress=w.vertrag, address=adresse, tag="latest")
        belege.append(b.id)
        if _zahl(stand):
            liste.append({"wert": w, "betrag": _zahl(stand)})
    return belege, liste


async def evm_token_stand(v: Vorgang, kette: Kette, adresse: str, wert: Wert, schritt: str) -> int:
    """Aktuelles Guthaben einer Adresse in einem bestimmten Token."""
    a = await _evm_v2(v, kette, f"/addresses/{adresse}/token-balances", adresse, "wallet", schritt)
    if a is not None:
        if a.ergebnis == "fehler":
            raise Quellfehler(a, "Token-Guthaben")
        for e in a.daten if isinstance(a.daten, list) else []:
            t = (e.get("token") or {}) if isinstance(e, dict) else {}
            if str(t.get("address_hash") or t.get("address") or "").lower() == str(wert.vertrag).lower():
                return _zahl(e.get("value"))
        return 0
    _, stand = await _evm_liste(v, kette, "account", "tokenbalance", adresse, "wallet", schritt,
                                contractaddress=wert.vertrag, address=adresse, tag="latest")
    return _zahl(stand)


def _evm_zahlung(kette: Kette, e: dict, w: Wert | None) -> dict | None:
    """Eine Zeile aus txlist oder tokentx als Zahlung. None, wenn die Zeile keine Wertbewegung ist."""
    von, an = adresse_normal(kette, e.get("from") or ""), adresse_normal(kette, e.get("to") or "")
    if w is None or w.vertrag is None:                           # eigene Währung
        an = an or adresse_normal(kette, e.get("contractAddress") or "")
        wert_ = coin(kette)
        ok = str(e.get("isError", "0")) == "0" and str(e.get("txreceipt_status", "1")) != "0"
    else:
        vertrag = adresse_normal(kette, e.get("contractAddress") or "")
        if not vertrag:
            return None
        wert_ = token(kette, vertrag, e.get("tokenSymbol") or "", _zahl(e.get("tokenDecimal")) if e.get("tokenDecimal") not in (None, "") else None)
        ok = True
    if not von or not an:
        return None
    return {"tx": e.get("hash"), "zeit": _zahl(e.get("timeStamp")) or None, "block": _zahl(e.get("blockNumber")) or None,
            "pos": _zahl(e.get("transactionIndex")), "von": von, "an": an, "betrag": _zahl(e.get("value")), "wert": wert_, "ok": ok}


async def evm_zahlungen(v: Vorgang, kette: Kette, adresse: str, wert: Wert | None, richtung: str = "alle", *,
                        ab_block: int = 0, aufsteigend: bool = True, seite: int = 1, anzahl: int = SEITE,
                        alle_token: bool = False, schritt: str = "Zahlungen der Adresse") -> tuple[Antwort, list[dict], bool]:
    """Zahlungen einer Adresse in einem Wert. ``wert`` None oder eigene Währung: gewöhnliche Transaktionen.
    ``alle_token``: Zahlungen aller Token. Rückgabe: (Antwort, Zahlungen, voll). ``voll`` heisst, die Seite war
    ausgeschöpft und es gibt vermutlich weitere.

    Zwei Wege. Blockscout liefert über seine REST-Schnittstelle jüngste zuerst, 50 je Seite: Das genügt für alles
    ab einem Block, für die jüngsten Zahlungen und für Adressen mit höchstens 200 Einträgen, deren ganze Liste
    gelesen wird. Nur für die ältesten Zahlungen einer Adresse mit mehr Einträgen und bei Etherscan läuft die
    Abfrage in der Listenform von Etherscan. Diese drosselt Blockscout ohne Schlüssel stark (gesehen: zehn
    Abfragen, dann rund 40 Minuten Pause)."""
    ersatzweise = False
    if seite == 1 and _v2_moeglich(v, kette):
        try:
            ergebnis = await _v2_zahlungen(v, kette, adresse, wert, richtung, ab_block=ab_block, aufsteigend=aufsteigend,
                                           anzahl=anzahl, alle_token=alle_token, schritt=schritt)
        except Quellfehler as fehler:
            if fehler.antwort.status in (401, 402, 403, 429):       # liegt am Zugang, die Listenform träfe dasselbe
                raise
            # Zeitüberschreitung oder Störung: Bei Adressen mit sehr vielen Zahlungen (Börse, Tauschprogramm) kommt das vor.
            # Die Listenform fragt gezielt ab einem Block und antwortet dort eher.
            ergebnis, ersatzweise = None, True
        if ergebnis is not None:
            return ergebnis
    try:
        return await _liste_zahlungen(v, kette, adresse, wert, richtung, ab_block=ab_block, aufsteigend=aufsteigend, seite=seite,
                                      anzahl=anzahl, alle_token=alle_token, schritt=schritt + (" (Listenform)" if ersatzweise else ""))
    except Quellfehler as fehler:
        fehler.nur_hier = ersatzweise        # der Ersatzweg ist eigens gedrosselt: Sein Ausfall sagt nichts über die nächste Station
        raise


async def _liste_zahlungen(v: Vorgang, kette: Kette, adresse: str, wert: Wert | None, richtung: str, *, ab_block: int, aufsteigend: bool,
                           seite: int, anzahl: int, alle_token: bool, schritt: str) -> tuple[Antwort, list[dict], bool]:
    """Zahlungen einer Adresse in der Listenform von Etherscan (txlist, tokentx), die auch Blockscout versteht."""
    params: dict[str, Any] = {"address": adresse, "page": seite, "offset": anzahl, "sort": "asc" if aufsteigend else "desc"}
    if ab_block:
        params["startblock"] = ab_block
    ist_token = alle_token or (wert is not None and wert.vertrag is not None)
    if ist_token:
        if wert is not None and wert.vertrag and not alle_token:
            params["contractaddress"] = wert.vertrag
        a, zeilen = await _evm_liste(v, kette, "account", "tokentx", adresse, "wallet", schritt, **params)
    else:
        if richtung == "aus":
            params["filter_by"] = "from"         # versteht Blockscout, Etherscan übergeht es. Gefiltert wird ohnehin unten
        elif richtung == "ein":
            params["filter_by"] = "to"
        a, zeilen = await _evm_liste(v, kette, "account", "txlist", adresse, "wallet", schritt, **params)
    zeilen = zeilen if isinstance(zeilen, list) else []
    marke = wert if ist_token and not alle_token else (Wert(kette.name, "", None, "x") if alle_token else None)
    zahlungen = []
    for e in zeilen:
        z = _evm_zahlung(kette, e, marke) if isinstance(e, dict) else None
        if not z:
            continue
        if richtung == "aus" and not gleich(kette, z["von"], adresse) or richtung == "ein" and not gleich(kette, z["an"], adresse):
            continue
        zahlungen.append(z)
    return a, zahlungen, len(zeilen) >= anzahl


def _v2_moeglich(v: Vorgang, kette: Kette) -> bool:
    bs = [a for a in evm_anbieter(kette) if a["art"] == "blockscout"]
    return bool(bs) and bs[0]["quelle"] not in _gesperrt(v)


def _v2_zeile(kette: Kette, d: dict, token_zeile: bool) -> dict | None:
    """Ein Eintrag aus /addresses/{a}/transactions oder /token-transfers als Zahlung."""
    a_von = adresse_normal(kette, (d.get("from") or {}).get("hash") or "")
    a_an = adresse_normal(kette, (d.get("to") or d.get("created_contract") or {}).get("hash") or "")
    block = d.get("block_number") if d.get("block_number") is not None else d.get("block")
    if not a_von or not a_an or not isinstance(block, int):          # ohne Block: noch nicht bestätigt
        return None
    zeit = _zeit_aus_iso(d.get("timestamp"))
    if not token_zeile:
        return {"tx": d.get("hash"), "zeit": zeit, "block": block, "pos": d.get("position"), "von": a_von, "an": a_an,
                "betrag": _zahl(d.get("value")), "wert": coin(kette), "ok": d.get("status") == "ok"}
    tk, summe = d.get("token") or {}, d.get("total") or {}
    vertrag = tk.get("address_hash") or tk.get("address") or ""
    if tk.get("type") not in (None, "ERC-20") or "value" not in summe or not adresse_normal(kette, vertrag):
        return None
    stellen = tk.get("decimals") if tk.get("decimals") not in (None, "") else summe.get("decimals")
    w = token(kette, vertrag, tk.get("symbol") or "", _zahl(stellen) if stellen not in (None, "") else None)
    return {"tx": d.get("transaction_hash") or d.get("tx_hash"), "zeit": zeit, "block": block, "pos": None, "log": d.get("log_index"),
            "von": a_von, "an": a_an, "betrag": _zahl(summe.get("value")), "wert": w, "ok": True}


async def _v2_zahlungen(v: Vorgang, kette: Kette, adresse: str, wert: Wert | None, richtung: str, *, ab_block: int, aufsteigend: bool,
                        anzahl: int, alle_token: bool, schritt: str) -> tuple[Antwort, list[dict], bool] | None:
    """Zahlungen einer Adresse über die REST-Schnittstelle von Blockscout. Sie liefert jüngste zuerst. Gelesen wird
    Seite um Seite, bis der gesuchte Block unterschritten ist, die Liste endet oder ``anzahl`` Einträge beisammen
    sind. Sind die ältesten Zahlungen gefragt (aufsteigend, ohne Block), wird die ganze Liste gelesen, höchstens
    ``SEITE`` Einträge. None, wenn dieser Weg die Frage nicht beantworten kann: Blockscout fällt aus, oder die
    Adresse hat für «älteste zuerst» zu viele Einträge. Dann übernimmt die Listenform."""
    von_anfang = aufsteigend and not ab_block
    lesen = max(anzahl, SEITE) if von_anfang else anzahl
    ist_token = alle_token or (wert is not None and wert.vertrag is not None)
    pfad = f"/addresses/{adresse}/{'token-transfers' if ist_token else 'transactions'}"
    fest: dict[str, Any] = {}
    if richtung in ("aus", "ein"):
        fest["filter"] = "from" if richtung == "aus" else "to"
    if ist_token:
        fest["type"] = "ERC-20"
        if wert is not None and wert.vertrag and not alle_token:
            fest["token"] = wert.vertrag
    zeilen: list[dict] = []
    marke: dict | None = None
    antwort: Antwort | None = None
    weitere, erreicht, seiten = True, False, 0
    while weitere and not erreicht and len(zeilen) < lesen:
        seiten += 1
        a = await _evm_v2(v, kette, pfad, adresse, "wallet", schritt if seiten == 1 else f"{schritt} (Seite {seiten})",
                          params={**fest, **(marke or {})}, geduld=False)
        if a is None:
            return None
        antwort = a
        if a.ergebnis == "kein_treffer":             # Blockscout kennt die Adresse nicht: keine Zahlungen
            break
        if a.ergebnis != "ok" or not isinstance(a.daten, dict) or not isinstance(a.daten.get("items"), list):
            raise Quellfehler(a, "Zahlungen")
        for d in a.daten["items"]:
            z = _v2_zeile(kette, d, ist_token) if isinstance(d, dict) else None
            if z is None:
                continue
            if ab_block and z["block"] < ab_block:
                erreicht = True
                continue
            if richtung == "aus" and not gleich(kette, z["von"], adresse) or richtung == "ein" and not gleich(kette, z["an"], adresse):
                continue
            zeilen.append(z)
        marke = a.daten.get("next_page_params") if isinstance(a.daten.get("next_page_params"), dict) else None
        weitere = bool(marke) and bool(a.daten["items"])
    assert antwort is not None
    if von_anfang and weitere:               # die ältesten Einträge liegen hinter dem Gelesenen
        return None
    voll = weitere and not erreicht          # es gibt weitere Einträge im gesuchten Bereich, die nicht gelesen wurden
    zeilen.sort(key=lambda z: (z["block"], z.get("log") or z["pos"] or 0), reverse=not aufsteigend)
    if len(zeilen) > anzahl:
        # zu viele: Bei «ab einem Block» zählen die ältesten (nächst am Eingang), sonst die jüngsten
        zeilen, voll = zeilen[:anzahl], True
    return antwort, zeilen, voll


def _v2_tx(kette: Kette, d: dict) -> dict:
    von, an = d.get("from") or {}, d.get("to") or d.get("created_contract") or {}
    zahlungen, etiketten = [], {}
    zeit, betrag = _zeit_aus_iso(d.get("timestamp")), _zahl(d.get("value"))
    a_von, a_an = adresse_normal(kette, von.get("hash") or ""), adresse_normal(kette, an.get("hash") or "")
    ok = d.get("status") == "ok"
    for objekt in (von, an):
        marken = _evm_etiketten(objekt)
        if marken and objekt.get("hash"):
            etiketten[adresse_normal(kette, objekt["hash"])] = marken
    if betrag and a_von and a_an:
        zahlungen.append({"tx": d.get("hash"), "zeit": zeit, "block": d.get("block_number"), "pos": d.get("position"),
                          "von": a_von, "an": a_an, "betrag": betrag, "wert": coin(kette), "ok": ok})
    for t in d.get("token_transfers") or []:
        tk, summe = t.get("token") or {}, t.get("total") or {}
        if tk.get("type") not in (None, "ERC-20") or "value" not in summe:
            continue
        stellen = tk.get("decimals") if tk.get("decimals") not in (None, "") else summe.get("decimals")
        w = token(kette, tk.get("address_hash") or "", tk.get("symbol") or "", _zahl(stellen) if stellen not in (None, "") else None)
        t_von, t_an = adresse_normal(kette, (t.get("from") or {}).get("hash") or ""), adresse_normal(kette, (t.get("to") or {}).get("hash") or "")
        if t_von and t_an:
            zahlungen.append({"tx": d.get("hash"), "zeit": zeit, "block": d.get("block_number"), "pos": d.get("position"),
                              "von": t_von, "an": t_an, "betrag": _zahl(summe.get("value")), "wert": w, "ok": ok})
            for objekt in (t.get("from") or {}, t.get("to") or {}):
                marken = _evm_etiketten(objekt)
                if marken:
                    etiketten[adresse_normal(kette, objekt["hash"])] = marken
    return {"tx": d.get("hash"), "zeit": zeit, "block": d.get("block_number"), "ok": ok,
            "status_text": d.get("result") if not ok else None, "von": a_von, "an": a_an,
            "an_vertrag": bool(an.get("is_contract")), "an_name": saeubern(an.get("name"), 80) or None,
            "betrag": betrag, "gebuehr": _zahl((d.get("fee") or {}).get("value")), "methode": saeubern(d.get("method"), 60) or None,
            "zahlungen": zahlungen, "etiketten": etiketten, "unvollstaendig": bool(d.get("token_transfers_overflow")),
            "bestaetigungen": d.get("confirmations")}


def _logs_zahlungen(kette: Kette, logs: list, tx: str, zeit: int | None, block: int | None, ok: bool) -> list[dict]:
    """Token-Zahlungen aus den Ereignissen einer Transaktion (Transfer mit drei Themen, also ERC-20)."""
    zahlungen = []
    for log in logs or []:
        themen = [str(t or "").lower().removeprefix("0x") for t in (log.get("topics") or []) if t]
        if len(themen) != 3 or themen[0] != TRANSFER:
            continue
        vertrag = adresse_normal(kette, log.get("address") or "")
        von, an = adresse_normal(kette, "0x" + themen[1][-40:]), adresse_normal(kette, "0x" + themen[2][-40:])
        if vertrag and von and an:
            zahlungen.append({"tx": tx, "zeit": zeit, "block": block, "pos": None, "von": von, "an": an,
                              "betrag": _zahl(log.get("data") or "0x0", 16), "wert": token(kette, vertrag), "ok": ok})
    return zahlungen


async def evm_tx(v: Vorgang, kette: Kette, tx: str, schritt: str = "Transaktion",
                 nur: str | None = None) -> tuple[list[str], dict | None, str]:
    """Eine Transaktion samt aller Zahlungen darin. Rückgabe: (Belege, Transaktion oder None, Quelle)."""
    if nur != "etherscan":
        a = await _evm_v2(v, kette, f"/transactions/{tx}", tx, "transaktion", schritt, cache_h=24)
        if a is not None:
            if a.ergebnis == "kein_treffer":
                return [a.id], None, "Blockscout"
            if a.ergebnis != "ok" or not isinstance(a.daten, dict):
                raise Quellfehler(a, "Transaktion")
            return [a.id], _v2_tx(kette, a.daten), "Blockscout"
        if nur == "blockscout":
            raise Abbruch(f"Blockscout steht für {kette.anzeige} nicht zur Verfügung.")
    # Etherscan: Transaktion, Quittung und Blockzeit über die Knotenschnittstelle
    a, t = await _evm_liste(v, kette, "proxy", "eth_getTransactionByHash", tx, "transaktion", schritt, cache_h=24,
                            nur="etherscan", txhash=tx)
    if a.ergebnis == "kein_treffer" or not isinstance(t, dict):
        return [a.id], None, "Etherscan"
    q, quittung = await _evm_liste(v, kette, "proxy", "eth_getTransactionReceipt", tx, "transaktion", "Quittung der Transaktion",
                                   cache_h=24, nur="etherscan", txhash=tx)
    quittung = quittung if isinstance(quittung, dict) else {}
    block = _zahl(t.get("blockNumber"), 16) or None
    belege, zeit = [a.id, q.id], None
    if block:
        b, kopf = await _evm_liste(v, kette, "proxy", "eth_getBlockByNumber", str(block), "block", "Zeit des Blocks", cache_h=720,
                                   nur="etherscan", tag=hex(block), boolean="false")
        belege.append(b.id)
        zeit = _zahl((kopf or {}).get("timestamp"), 16) or None if isinstance(kopf, dict) else None
    ok = _zahl(quittung.get("status"), 16) == 1 if quittung else block is not None
    von, an = adresse_normal(kette, t.get("from") or ""), adresse_normal(kette, t.get("to") or quittung.get("contractAddress") or "")
    betrag = _zahl(t.get("value"), 16)
    zahlungen = []
    if betrag and von and an:
        zahlungen.append({"tx": tx, "zeit": zeit, "block": block, "pos": _zahl(t.get("transactionIndex"), 16), "von": von,
                          "an": an, "betrag": betrag, "wert": coin(kette), "ok": ok})
    zahlungen += _logs_zahlungen(kette, quittung.get("logs") or [], tx, zeit, block, ok)
    gebuehr = _zahl(quittung.get("gasUsed"), 16) * _zahl(quittung.get("effectiveGasPrice") or t.get("gasPrice"), 16)
    return belege, {"tx": tx, "zeit": zeit, "block": block, "ok": ok, "status_text": None if ok else "fehlgeschlagen",
                    "von": von, "an": an, "an_vertrag": len(str(t.get("input") or "0x")) > 2, "an_name": None,
                    "betrag": betrag, "gebuehr": gebuehr, "methode": (str(t.get("input") or "")[:10] or None) if len(str(t.get("input") or "0x")) > 2 else None,
                    "zahlungen": zahlungen, "etiketten": {}, "unvollstaendig": False, "bestaetigungen": None}, "Etherscan"


# --------------------------------------------------------------------------- TRON (TronGrid)

USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
_TRON_NULL = "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb"       # Nulladresse, dient bei Leseaufrufen als Absender


def _tron_basis() -> tuple[str, str]:
    eigen = einstellung("KRYPTO_TRON_API")
    return ("TronGrid (eigene Instanz)", eigen.rstrip("/")) if eigen else ("TronGrid", "https://api.trongrid.io")


def _tron_kopf() -> dict:
    key = einstellung("TRONGRID_API_KEY")
    return {"TRON-PRO-API-KEY": key} if key else {}


def _tron_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    if status == 403:
        return "fehler", ("TronGrid weist die Anfrage ab (HTTP 403): Kontingent ohne Schlüssel erschöpft oder Anschluss gesperrt. "
                          "Einige Minuten warten oder TRONGRID_API_KEY eintragen (kostenlos, https://www.trongrid.io).")
    if isinstance(daten, dict) and (daten.get("success") is False or daten.get("Error")):
        return "fehler", f"TronGrid meldet: {saeubern(str(daten.get('error') or daten.get('Error')), 200)}"
    if status == 200 and daten is None:
        return "fehler", "TronGrid hat kein lesbares JSON geliefert. Details in den Rohdaten."
    if status == 200 and daten == {}:
        return "kein_treffer", None
    return None


async def _tron(v: Vorgang, pfad: str, ziel: str, ziel_typ: str, schritt: str, *, params: dict | None = None,
                koerper: dict | None = None, cache_h: float = 1.0) -> Antwort:
    quelle, basis = _tron_basis()
    return await v.hole(quelle, ziel, ziel_typ, basis + pfad, schritt=schritt, params=params, kopf=_tron_kopf(),
                        methode="POST" if koerper is not None else "GET", json_koerper=koerper, cache_h=cache_h,
                        deutung=_tron_deutung)


async def tron_konto(v: Vorgang, adresse: str, schritt: str = "Stand der Adresse") -> tuple[Antwort, dict]:
    a = await _tron(v, f"/v1/accounts/{adresse}", adresse, "wallet", schritt)
    if a.ergebnis != "ok" or not isinstance(a.daten, dict):
        raise Quellfehler(a, "Adresse")
    daten = a.daten.get("data") or []
    if not daten:
        return a, {"aktiviert": False, "guthaben": 0, "erstellt": None, "letzte_aktion": None, "vertrag": False, "trc20": {}}
    d = daten[0]
    trc20: dict[str, int] = {}
    for eintrag in d.get("trc20") or []:
        for vertrag, stand in (eintrag or {}).items():
            trc20[vertrag] = _zahl(stand)
    return a, {"aktiviert": True, "guthaben": _zahl(d.get("balance")), "erstellt": _zahl(d.get("create_time")) // 1000 or None,
               "letzte_aktion": _zahl(d.get("latest_opration_time")) // 1000 or None,
               "vertrag": d.get("type") == "Contract", "trc20": trc20}


def _tron_zahlung_trx(e: dict) -> dict | None:
    vertrag = ((e.get("raw_data") or {}).get("contract") or [{}])[0]
    if vertrag.get("type") != "TransferContract":
        return None
    w = (vertrag.get("parameter") or {}).get("value") or {}
    von, an = tron_aus_hex(str(w.get("owner_address") or "")), tron_aus_hex(str(w.get("to_address") or ""))
    if not von or not an:
        return None
    ret = (e.get("ret") or [{}])[0]
    return {"tx": e.get("txID"), "zeit": _zahl(e.get("block_timestamp")) // 1000 or None, "block": e.get("blockNumber"),
            "pos": None, "von": von, "an": an, "betrag": _zahl(w.get("amount")), "wert": coin(KETTEN["tron"]),
            "ok": ret.get("contractRet", "SUCCESS") == "SUCCESS", "zeit_ms": _zahl(e.get("block_timestamp"))}


def _tron_zahlung_trc20(e: dict) -> dict | None:
    if e.get("type") != "Transfer":
        return None
    info = e.get("token_info") or {}
    if not info.get("address") or not e.get("from") or not e.get("to"):
        return None
    w = token(KETTEN["tron"], info["address"], info.get("symbol") or "", info.get("decimals") if isinstance(info.get("decimals"), int) else None)
    return {"tx": e.get("transaction_id"), "zeit": _zahl(e.get("block_timestamp")) // 1000 or None, "block": None, "pos": None,
            "von": e["from"], "an": e["to"], "betrag": _zahl(e.get("value")), "wert": w, "ok": True,
            "zeit_ms": _zahl(e.get("block_timestamp"))}


async def tron_zahlungen(v: Vorgang, adresse: str, wert: Wert | None, richtung: str = "alle", *, ab_ms: int = 0,
                         aufsteigend: bool = True, anzahl: int = SEITE, weiter: str | None = None, alle_token: bool = False,
                         schritt: str = "Zahlungen der Adresse") -> tuple[Antwort, list[dict], str | None]:
    """Zahlungen einer TRON-Adresse. Rückgabe: (Antwort, Zahlungen, Marke für die nächste Seite oder None)."""
    params: dict[str, Any] = {"limit": min(anzahl, 200), "only_confirmed": "true",
                              "order_by": f"block_timestamp,{'asc' if aufsteigend else 'desc'}"}
    if richtung == "aus":
        params["only_from"] = "true"
    elif richtung == "ein":
        params["only_to"] = "true"
    if ab_ms:
        params["min_timestamp"] = ab_ms
    if weiter:
        params["fingerprint"] = weiter
    ist_token = alle_token or (wert is not None and wert.vertrag is not None)
    if ist_token:
        if wert is not None and wert.vertrag and not alle_token:
            params["contract_address"] = wert.vertrag
        a = await _tron(v, f"/v1/accounts/{adresse}/transactions/trc20", adresse, "wallet", schritt, params=params)
    else:
        a = await _tron(v, f"/v1/accounts/{adresse}/transactions", adresse, "wallet", schritt, params=params)
    if a.ergebnis == "fehler" or not isinstance(a.daten, dict):
        raise Quellfehler(a, "Zahlungen")
    zeilen = a.daten.get("data") or []
    zahlungen = [z for z in ((_tron_zahlung_trc20(e) if ist_token else _tron_zahlung_trx(e)) for e in zeilen if isinstance(e, dict)) if z]
    if richtung == "aus":
        zahlungen = [z for z in zahlungen if z["von"] == adresse]
    elif richtung == "ein":
        zahlungen = [z for z in zahlungen if z["an"] == adresse]
    marke = ((a.daten.get("meta") or {}).get("fingerprint")) if len(zeilen) >= params["limit"] else None
    return a, zahlungen, marke


def _abi_text(hexwert: str) -> str:
    """Zeichenkette aus einer ABI-kodierten Antwort (string) oder aus 32 Bytes mit Nullen aufgefüllt."""
    try:
        roh = bytes.fromhex(hexwert)
    except ValueError:
        return ""
    if len(roh) >= 96 and int.from_bytes(roh[:32], "big") == 32:
        laenge = int.from_bytes(roh[32:64], "big")
        roh = roh[64:64 + min(laenge, 64)]
    return saeubern(roh.rstrip(b"\x00").decode("utf-8", "replace"), 24)


async def _tron_lesen(v: Vorgang, vertrag: str, funktion: str, parameter: str, schritt: str, cache_h: float = 24.0) -> tuple[Antwort, str | None]:
    """Leseaufruf an einen Vertrag (verändert nichts, kostet nichts). Gibt das erste Ergebnis als Hex zurück."""
    a = await _tron(v, "/wallet/triggerconstantcontract", f"{vertrag} {funktion}", "vertrag", schritt, cache_h=cache_h,
                    koerper={"owner_address": _TRON_NULL, "contract_address": vertrag, "function_selector": funktion,
                             "parameter": parameter, "visible": True})
    werte = (a.daten or {}).get("constant_result") if isinstance(a.daten, dict) else None
    return a, (werte[0] if isinstance(werte, list) and werte else None)


async def tron_token(v: Vorgang, vertrag: str) -> tuple[list[str], Wert]:
    """Kürzel und Dezimalstellen eines TRC-20-Tokens. Bekannte aus der Liste, andere fragt der Vertrag selbst an."""
    w = token(KETTEN["tron"], vertrag)
    if w.bekannt:
        return [], w
    a, stellen = await _tron_lesen(v, vertrag, "decimals()", "", "Dezimalstellen des Tokens", cache_h=720)
    b, kuerzel = await _tron_lesen(v, vertrag, "symbol()", "", "Kürzel des Tokens", cache_h=720)
    return [a.id, b.id], replace(w, symbol=_abi_text(kuerzel or "") or "Token", stellen=_zahl(stellen, 16) if stellen else None)


async def tron_gesperrt(v: Vorgang, adresse: str) -> tuple[Antwort, bool | None]:
    """Hat Tether die Adresse gesperrt (USDT eingefroren)? Liest die Sperrliste im USDT-Vertrag."""
    h = tron_zu_hex(adresse)
    if not h:
        raise Abbruch(f"'{adresse}' ist keine TRON-Adresse.")
    a, wert = await _tron_lesen(v, USDT_TRON, "isBlackListed(address)", h[2:].rjust(64, "0"), "Sperrliste von Tether (USDT)", cache_h=1)
    return a, (None if wert is None else _zahl(wert, 16) == 1)


async def tron_tx(v: Vorgang, tx: str, schritt: str = "Transaktion") -> tuple[list[str], dict | None]:
    a = await _tron(v, "/wallet/gettransactionbyid", tx, "transaktion", schritt, koerper={"value": tx}, cache_h=24)
    if a.ergebnis == "kein_treffer":
        return [a.id], None
    if a.ergebnis != "ok" or not isinstance(a.daten, dict):
        raise Quellfehler(a, "Transaktion")
    b = await _tron(v, "/wallet/gettransactioninfobyid", tx, "transaktion", "Block, Gebühr und Ereignisse", koerper={"value": tx}, cache_h=24)
    if b.ergebnis == "fehler":
        raise Quellfehler(b, "Transaktion")
    d, info = a.daten, (b.daten if isinstance(b.daten, dict) else {})
    vertrag = ((d.get("raw_data") or {}).get("contract") or [{}])[0]
    w = (vertrag.get("parameter") or {}).get("value") or {}
    ok = ((d.get("ret") or [{}])[0]).get("contractRet", "SUCCESS") == "SUCCESS"
    zeit = _zahl(info.get("blockTimeStamp")) // 1000 or None
    block = info.get("blockNumber")
    von = tron_aus_hex(str(w.get("owner_address") or ""))
    belege, zahlungen, an = [a.id, b.id], [], None
    if vertrag.get("type") == "TransferContract":
        an = tron_aus_hex(str(w.get("to_address") or ""))
        if von and an:
            zahlungen.append({"tx": tx, "zeit": zeit, "block": block, "pos": None, "von": von, "an": an,
                              "betrag": _zahl(w.get("amount")), "wert": coin(KETTEN["tron"]), "ok": ok})
    elif vertrag.get("type") == "TriggerSmartContract":
        an = tron_aus_hex(str(w.get("contract_address") or ""))
        if _zahl(w.get("call_value")) and von and an:
            zahlungen.append({"tx": tx, "zeit": zeit, "block": block, "pos": None, "von": von, "an": an,
                              "betrag": _zahl(w.get("call_value")), "wert": coin(KETTEN["tron"]), "ok": ok})
    token_cache: dict[str, Wert] = {}
    for log in info.get("log") or []:
        themen = [str(t or "").lower() for t in (log.get("topics") or [])]
        if len(themen) != 3 or themen[0] != TRANSFER:
            continue
        t_vertrag = tron_aus_hex(str(log.get("address") or ""))
        t_von, t_an = tron_aus_hex(themen[1][-40:]), tron_aus_hex(themen[2][-40:])
        if not (t_vertrag and t_von and t_an):
            continue
        if t_vertrag not in token_cache:
            weitere, token_cache[t_vertrag] = await tron_token(v, t_vertrag)
            belege += weitere
        zahlungen.append({"tx": tx, "zeit": zeit, "block": block, "pos": None, "von": t_von, "an": t_an,
                          "betrag": _zahl(log.get("data") or "0", 16), "wert": token_cache[t_vertrag], "ok": ok})
    return belege, {"tx": tx, "zeit": zeit, "block": block, "ok": ok,
                    "status_text": None if ok else ((d.get("ret") or [{}])[0]).get("contractRet"),
                    "von": von, "an": an, "an_vertrag": vertrag.get("type") == "TriggerSmartContract", "an_name": None,
                    "betrag": sum(z["betrag"] for z in zahlungen if z["wert"].vertrag is None), "gebuehr": _zahl(info.get("fee")),
                    "methode": vertrag.get("type"), "zahlungen": zahlungen, "etiketten": {}, "unvollstaendig": False,
                    "bestaetigungen": None, "bestaetigt": block is not None}


# --------------------------------------------------------------------------- Gemeinsame Sicht für Konto-Ketten

async def konto_zahlungen(v: Vorgang, kette: Kette, adresse: str, wert: Wert, richtung: str, *, ab: dict | None = None,
                          aufsteigend: bool = True, anzahl: int = SEITE, schritt: str = "") -> tuple[str, list[dict], bool]:
    """Zahlungen eines Werts auf einer Konto-Kette, ab einem Zeitpunkt. ``ab``: die Zahlung, nach der gesucht wird
    (ihre Blocknummer oder Zeit). Rückgabe: (Beleg, Zahlungen mit Betrag, voll). ``voll`` heisst: Es gibt mehr
    Zahlungen als die gelieferten ``anzahl``, oder das Ende der Liste war nicht zu sehen.

    Bei der eigenen Währung mischen die Quellen Zahlungen mit Aufrufen von Programmen, die keinen Wert bewegen
    (auf TRON ist jede USDT-Zahlung ein solcher Aufruf). Deshalb werden bis zu drei Seiten gelesen, und gezählt
    wird nur, was einen Betrag trägt."""
    schritt = schritt or "Zahlungen der Adresse"
    gefunden: list[dict] = []
    beleg, mehr, seiten = "", True, 0
    marke: str | None = None
    # Über die REST-Schnittstelle von Blockscout deckt ein Aufruf schon alle Seiten ab
    rest = kette.familie != "tron" and bool((ab or {}).get("block")) and _v2_moeglich(v, kette)
    hoechstens = 1 if wert.vertrag is not None or rest else 3
    while mehr and seiten < hoechstens and len(gefunden) < anzahl:
        seiten += 1
        text = schritt if seiten == 1 else f"{schritt} (Seite {seiten})"
        if kette.familie == "tron":
            a, zahlungen, marke = await tron_zahlungen(v, adresse, wert, richtung, ab_ms=(ab or {}).get("zeit_ms") or ((ab or {}).get("zeit") or 0) * 1000,
                                                       aufsteigend=aufsteigend, anzahl=anzahl, weiter=marke, schritt=text)
            mehr = marke is not None
        else:
            a, zahlungen, mehr = await evm_zahlungen(v, kette, adresse, wert, richtung, ab_block=(ab or {}).get("block") or 0,
                                                     aufsteigend=aufsteigend, anzahl=anzahl, seite=seiten, schritt=text)
        beleg = a.id
        gefunden += [z for z in zahlungen if z["betrag"] > 0]
    return beleg, gefunden[:anzahl], mehr or len(gefunden) > anzahl


def nach(z: dict, ab: dict | None) -> bool:
    """Liegt die Zahlung z zeitlich nach der Zahlung ``ab`` (und ist nicht diese selbst)?"""
    if not ab:
        return True
    if z.get("tx") == ab.get("tx"):      # dieselbe Transaktion: nur eine andere Zahlung darin zählt (Weiterleitung im selben Zug)
        return (z.get("von"), z.get("an")) != (ab.get("von"), ab.get("an"))
    if z.get("block") and ab.get("block"):
        if z["block"] != ab["block"]:
            return z["block"] > ab["block"]
        for feld in ("log", "pos"):              # Stelle im Block: Nummer des Ereignisses oder der Transaktion
            if z.get(feld) is not None and ab.get(feld) is not None:
                return z[feld] >= ab[feld]
        return True                              # selber Block, Reihenfolge nicht vergleichbar: als Weiterleitung gewertet
    return (z.get("zeit_ms") or (z.get("zeit") or 0) * 1000) >= (ab.get("zeit_ms") or (ab.get("zeit") or 0) * 1000)
