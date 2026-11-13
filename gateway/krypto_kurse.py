"""Gegenwert von Krypto-Beträgen in CHF, EUR und USD, heute oder an einem Stichtag.

Der Kurs in US-Dollar kommt von DefiLlama (Sammelkurs aus mehreren Handelsplätzen), die Umrechnung in
Franken und Euro aus den Referenzkursen der Europäischen Zentralbank. Die EZB veröffentlicht Kurse nur an
Bankwerktagen, deshalb gilt der letzte Kurs vor oder am Stichtag. Ein Gegenwert ist eine Bewertung zum
Tageskurs, kein Betrag, der so auf einem Konto eingegangen wäre.
"""
from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from . import kern
from .kern import Vorgang
from .krypto_ketten import KETTEN, Wert, zeit_iso

LLAMA = "https://coins.llama.fi"
EZB = "https://data-api.ecb.europa.eu/service/data/EXR/D.USD+CHF.EUR.SP00.A"
_POL_AB = 1725408000        # 4. September 2024: Polygon stellt von MATIC auf POL um


def _llama_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    if status == 200 and isinstance(daten, dict) and not daten.get("coins"):
        return "kein_treffer", None
    if status == 200 and not isinstance(daten, dict):
        return "fehler", "DefiLlama hat kein lesbares JSON geliefert. Details in den Rohdaten."
    return None


def _ezb_deutung(status: int, daten: Any, text: str | None) -> tuple[str, str | None] | None:
    if status == 200 and not (text or "").strip():
        return "kein_treffer", None
    return None


def kurs_kennung(wert: Wert, zeit: int | None) -> str | None:
    if wert.vertrag is None and wert.kette == "polygon" and zeit and zeit < _POL_AB:
        return "coingecko:matic-network"
    return wert.kurs_id


async def wechselkurse(v: Vorgang, zeit: int | None) -> dict | None:
    """Referenzkurse der EZB zum Stichtag: {"tag", "usd_je_eur", "chf_je_eur", "beleg"}. None, wenn nicht abrufbar."""
    tag = (datetime.fromtimestamp(zeit, timezone.utc) if zeit else kern.uhr()).date()
    a = await v.hole("EZB", f"USD und CHF je EUR, {tag.isoformat()}", "kurs", EZB, schritt="Referenzkurse der EZB", endung="csv",
                     params={"startPeriod": (tag - timedelta(days=10)).isoformat(), "endPeriod": tag.isoformat(), "format": "csvdata"},
                     deutung=_ezb_deutung, cache_h=24 if zeit else 6)
    if a.ergebnis != "ok" or not a.text:
        return None
    letzte: dict[str, tuple[str, Decimal]] = {}
    for zeile in csv.DictReader(io.StringIO(a.text)):
        waehrung, datum = (zeile.get("CURRENCY") or "").strip(), (zeile.get("TIME_PERIOD") or "").strip()
        try:
            kurs = Decimal((zeile.get("OBS_VALUE") or "").strip())
        except InvalidOperation:
            continue
        if waehrung in ("USD", "CHF") and datum and kurs > 0 and (waehrung not in letzte or datum > letzte[waehrung][0]):
            letzte[waehrung] = (datum, kurs)
    if "USD" not in letzte or "CHF" not in letzte:
        return None
    return {"tag": min(letzte["USD"][0], letzte["CHF"][0]), "usd_je_eur": letzte["USD"][1], "chf_je_eur": letzte["CHF"][1], "beleg": a.id}


async def kurs(v: Vorgang, wert: Wert, zeit: int | None = None) -> dict:
    """Kurs eines Werts zum Zeitpunkt (oder jetzt). Rückgabe mit Decimal-Werten:
    {"usd", "chf", "eur", "kurs_zeit", "wechselkurs_tag", "belege", "quellen", "hinweise"}. Fehlt ein Kurs, fehlt der Schlüssel."""
    ergebnis: dict[str, Any] = {"belege": [], "quellen": [], "hinweise": []}
    kennung = kurs_kennung(wert, zeit)
    if not kennung:
        ergebnis["hinweise"].append(f"Für {wert.symbol} ist keine Kursquelle hinterlegt.")
        return ergebnis
    url = f"{LLAMA}/prices/historical/{int(zeit)}/{kennung}" if zeit else f"{LLAMA}/prices/current/{kennung}"
    a = await v.hole("DefiLlama", f"{wert.symbol} {zeit_iso(zeit) or 'aktuell'}", "kurs", url, schritt=f"Kurs {wert.symbol} in US-Dollar",
                     deutung=_llama_deutung, cache_h=720 if zeit else 0.25)
    ergebnis["belege"].append(a.id)
    eintrag = ((a.daten or {}).get("coins") or {}).get(kennung) if a.ergebnis == "ok" and isinstance(a.daten, dict) else None
    if not isinstance(eintrag, dict) or not isinstance(eintrag.get("price"), (int, float)) or eintrag["price"] <= 0:
        ergebnis["hinweise"].append(
            f"DefiLlama hat für {wert.symbol} zu diesem Zeitpunkt keinen Kurs." if a.ergebnis != "fehler"
            else f"Kursabfrage fehlgeschlagen: {a.fehler}")
        return ergebnis
    usd = Decimal(str(eintrag["price"]))
    ergebnis.update(usd=usd, kurs_zeit=eintrag.get("timestamp"))
    ergebnis["quellen"].append("DefiLlama")
    if not wert.bekannt and wert.vertrag:
        ergebnis["hinweise"].append("Kurs eines Tokens, der nicht in der eingebauten Liste steht: Bei wenig gehandelten Token ist der Kurs wenig belastbar.")
    if isinstance(eintrag.get("confidence"), (int, float)) and eintrag["confidence"] < 0.8:
        ergebnis["hinweise"].append(f"DefiLlama stuft die Verlässlichkeit dieses Kurses als gering ein ({eintrag['confidence']}).")
    if zeit and isinstance(eintrag.get("timestamp"), (int, float)) and abs(eintrag["timestamp"] - zeit) > 86400:
        ergebnis["hinweise"].append(f"Der nächstliegende Kurs stammt vom {zeit_iso(eintrag['timestamp'])}, nicht vom angefragten Zeitpunkt.")
    fx = await wechselkurse(v, zeit)
    if fx:
        ergebnis["belege"].append(fx["beleg"])
        ergebnis["quellen"].append("EZB")
        ergebnis.update(eur=usd / fx["usd_je_eur"], chf=usd * fx["chf_je_eur"] / fx["usd_je_eur"], wechselkurs_tag=fx["tag"])
    else:
        ergebnis["hinweise"].append("Referenzkurse der EZB nicht abrufbar: Gegenwert nur in US-Dollar.")
    return ergebnis


def _runden(d: Decimal, stellen: int = 2) -> str:
    return str(d.quantize(Decimal(1).scaleb(-stellen), rounding=ROUND_HALF_UP))


def kurs_als_dict(k: dict) -> dict:
    """Kurs je Einheit für die Ausgabe: sinnvoll gerundet, mit Stand."""
    d: dict[str, Any] = {}
    for w in ("chf", "eur", "usd"):
        if w in k:
            d[w] = _runden(k[w], 2 if k[w] >= 1 else 6)
    if k.get("kurs_zeit"):
        d["stand"] = zeit_iso(k["kurs_zeit"])
    if k.get("wechselkurs_tag"):
        d["wechselkurs_vom"] = k["wechselkurs_tag"]
    if k.get("quellen"):
        d["quellen"] = list(k["quellen"])
    if k.get("hinweise"):
        d["hinweise"] = list(k["hinweise"])
    return d


def gegenwert(betrag: int, stellen: int | None, k: dict) -> dict:
    """Gegenwert eines Betrags (kleinste Einheit) zum Kurs k, auf zwei Stellen gerundet."""
    if stellen is None:
        return {}
    return gegenwert_menge(Decimal(betrag).scaleb(-stellen), k)


def gegenwert_menge(menge: Decimal, k: dict) -> dict:
    """Gegenwert einer Menge in ganzen Einheiten zum Kurs k."""
    return {w: _runden(menge * k[w]) for w in ("chf", "eur", "usd") if w in k}


__all__ = ["gegenwert", "gegenwert_menge", "kurs", "kurs_als_dict", "kurs_kennung", "wechselkurse", "KETTEN"]
