"""Krypto-Adressen und Transaktions-IDs erkennen und prüfen. Ohne Netz, nur Standardbibliothek.

Eine Adresse aus einem Rapport ist oft abgetippt oder aus einem Bildschirmfoto übernommen. Die meisten
Formate tragen eine Prüfsumme: Ein vertauschtes oder falsch gelesenes Zeichen fällt damit auf, bevor
eine Abfrage zur falschen Adresse hinausgeht.

    erkennen("12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw")
    -> Erkennung(art="adresse", familie="bitcoin", ketten=["bitcoin"], gueltig=True, …)

Geprüft werden: Bitcoin (Base58Check, Bech32, Bech32m), Ethereum und verwandte Ketten (EIP-55),
TRON (Base58Check). Erkannt, aber nicht abfragbar: Monero, Litecoin, Dogecoin, Bitcoin Cash, Solana.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field

# --------------------------------------------------------------------------- Keccak-256

_RC = (0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008)
_ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
_M64 = (1 << 64) - 1


def keccak256(daten: bytes) -> bytes:
    """Keccak-256, wie Ethereum es verwendet. Das ist nicht hashlib.sha3_256: Die Auffüllung ist eine andere."""
    rate = 136
    polster = bytearray(rate - len(daten) % rate)       # 1 bis 136 Füllbytes: erstes mit 0x01, letztes mit 0x80
    polster[0] |= 0x01
    polster[-1] |= 0x80
    daten = daten + bytes(polster)
    a = [[0] * 5 for _ in range(5)]             # a[x][y]
    for start in range(0, len(daten), rate):
        block = daten[start:start + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        for runde in range(24):
            c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
            d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
            a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
            b = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    r = _ROT[x][y]
                    b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M64 if r else a[x][y]
            a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y] & _M64) for y in range(5)] for x in range(5)]
            a[0][0] ^= _RC[runde]
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# --------------------------------------------------------------------------- Base58, Bech32

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_RE = re.compile(f"[{_B58}]+")


def base58_dekodieren(text: str) -> bytes | None:
    if not text or not _B58_RE.fullmatch(text):
        return None
    zahl = 0
    for z in text:
        zahl = zahl * 58 + _B58.index(z)
    koerper = zahl.to_bytes((zahl.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(text) - len(text.lstrip("1"))) + koerper


def base58_kodieren(daten: bytes) -> str:
    zahl, text = int.from_bytes(daten, "big"), ""
    while zahl:
        zahl, rest = divmod(zahl, 58)
        text = _B58[rest] + text
    return "1" * (len(daten) - len(daten.lstrip(b"\x00"))) + text


def base58check(text: str) -> tuple[bytes, bool] | None:
    """(Nutzdaten samt Versionsbyte, Prüfsumme stimmt). None, wenn es kein Base58 ist oder zu kurz."""
    roh = base58_dekodieren(text)
    if roh is None or len(roh) < 5:
        return None
    nutz, pruef = roh[:-4], roh[-4:]
    return nutz, hashlib.sha256(hashlib.sha256(nutz).digest()).digest()[:4] == pruef


def base58check_kodieren(nutz: bytes) -> str:
    return base58_kodieren(nutz + hashlib.sha256(hashlib.sha256(nutz).digest()).digest()[:4])


_B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(werte: list[int]) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in werte:
        oben = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (oben >> i) & 1 else 0
    return chk


def bech32(text: str) -> tuple[str, int, bytes, str] | None:
    """Zerlegt eine Segwit-Adresse: (Präfix, Witness-Version, Programm, "bech32" | "bech32m").
    None, wenn Aufbau oder Prüfsumme nicht stimmen (BIP 173, BIP 350)."""
    if text.lower() != text and text.upper() != text:
        return None                              # gemischte Schreibweise ist nicht erlaubt
    t = text.lower()
    pos = t.rfind("1")
    if pos < 1 or pos + 7 > len(t) or len(t) > 90 or any(z not in _B32 for z in t[pos + 1:]):
        return None
    hrp, daten = t[:pos], [_B32.index(z) for z in t[pos + 1:]]
    summe = _polymod([ord(z) >> 5 for z in hrp] + [0] + [ord(z) & 31 for z in hrp] + daten)
    art = {1: "bech32", 0x2BC830A3: "bech32m"}.get(summe)
    if not art or len(daten) < 7:
        return None
    version, bits, wert, programm = daten[0], 0, 0, bytearray()
    for v in daten[1:-6]:                        # je fünf Bit zu Bytes zusammensetzen
        wert, bits = (wert << 5) | v, bits + 5
        while bits >= 8:
            bits -= 8
            programm.append((wert >> bits) & 0xFF)
    if bits >= 5 or (wert & ((1 << bits) - 1)):
        return None                              # unzulässige Füllbits
    if version > 16 or not 2 <= len(programm) <= 40 or (art == "bech32") != (version == 0):
        return None
    if version == 0 and len(programm) not in (20, 32):
        return None
    return hrp, version, bytes(programm), art


# --------------------------------------------------------------------------- EVM, TRON

def eip55(adresse: str) -> str:
    """Schreibt eine 0x-Adresse mit der Prüfsumme nach EIP-55 (gemischte Gross- und Kleinschreibung)."""
    klein = adresse[2:].lower()
    pruef = keccak256(klein.encode("ascii")).hex()
    return "0x" + "".join(z.upper() if z in "abcdef" and int(pruef[i], 16) >= 8 else z for i, z in enumerate(klein))


def tron_aus_hex(wert: str) -> str | None:
    """TRON-Adresse aus der Hex-Form der Schnittstellen (41 + 20 Bytes, oder 0x + 20 Bytes) in die lesbare Form T…"""
    h = wert.lower().removeprefix("0x")
    if len(h) == 40:
        h = "41" + h
    if len(h) != 42 or not h.startswith("41") or not re.fullmatch(r"[0-9a-f]+", h):
        return None
    return base58check_kodieren(bytes.fromhex(h))


def tron_zu_hex(adresse: str) -> str | None:
    """Lesbare TRON-Adresse in die Hex-Form mit führendem 41."""
    ergebnis = base58check(adresse)
    if not ergebnis or not ergebnis[1] or len(ergebnis[0]) != 21 or ergebnis[0][0] != 0x41:
        return None
    return ergebnis[0].hex()


# --------------------------------------------------------------------------- Erkennung

EVM_KETTEN = ("ethereum", "bsc", "polygon", "arbitrum", "optimism", "base", "gnosis")
ABFRAGBAR = ("bitcoin", "tron") + EVM_KETTEN


@dataclass
class Erkennung:
    eingabe: str
    art: str = "unbekannt"              # adresse | transaktion | unbekannt
    familie: str = ""                   # bitcoin | evm | tron | monero | litecoin | dogecoin | bitcoin-cash | solana
    ketten: list[str] = field(default_factory=list)     # worauf die Adresse abfragbar ist
    format: str = ""
    gueltig: bool | None = None         # True: Prüfsumme stimmt. False: stimmt nicht. None: Format hat keine oder sie fehlt
    normal: str = ""                    # Schreibweise für Abfragen
    hinweise: list[str] = field(default_factory=list)

    @property
    def abfragbar(self) -> bool:
        return bool(self.ketten) and self.gueltig is not False

    def als_dict(self) -> dict:
        return {**asdict(self), "abfragbar": self.abfragbar}


_UNSICHTBAR = re.compile(r"[\s​-‏‪-‮⁦-⁩﻿]")
_ABSCHREIBEN = ("Prüfsumme stimmt nicht. Vermutlich ein Abschreib- oder Lesefehler: Wert mit dem Original vergleichen "
                "(häufig verwechselt: 0 und O, 1 und l und I, 5 und S, 8 und B).")


def erkennen(wert: str) -> Erkennung:
    """Ordnet einen Wert ein: Adresse oder Transaktions-ID, welche Kette, stimmt die Prüfsumme?"""
    roh = _UNSICHTBAR.sub("", wert or "").strip("<>\"'`.,;")
    e = Erkennung(eingabe=wert, normal=roh)
    if not roh:
        return e
    klein = roh.lower()

    # Transaktions-IDs
    if re.fullmatch(r"0x[0-9a-fA-F]{64}", roh):
        e.art, e.familie, e.ketten, e.format, e.normal = "transaktion", "evm", list(EVM_KETTEN), "Transaktions-ID (EVM)", klein
        e.hinweise.append("Auf welcher Kette die Transaktion liegt, sagt die ID nicht. Die Kette steht im Rapport oder "
                          "ergibt sich aus der Abfrage (zuerst ethereum).")
        return e
    if re.fullmatch(r"[0-9a-fA-F]{64}", roh):
        e.art, e.familie, e.ketten, e.format, e.normal = "transaktion", "", ["bitcoin", "tron"], "Transaktions-ID (64 Hex-Zeichen)", klein
        e.hinweise.append("Bitcoin und TRON schreiben Transaktions-IDs gleich. Die Kette steht im Rapport oder ergibt "
                          "sich aus der Abfrage. Auch ein SHA-256-Wert einer Datei sieht so aus.")
        return e

    # Ethereum und verwandte Ketten
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", roh):
        e.art, e.familie, e.ketten, e.format = "adresse", "evm", list(EVM_KETTEN), "EVM-Adresse (0x und 40 Hex-Zeichen)"
        e.normal = eip55(roh)
        rumpf = roh[2:]
        if rumpf in (rumpf.lower(), rumpf.upper()):
            e.gueltig = None
            e.hinweise.append("Einheitliche Gross- oder Kleinschreibung: Die Adresse trägt keine Prüfsumme, ein "
                              "Abschreibfehler fiele nicht auf. Wert mit dem Original vergleichen.")
        else:
            e.gueltig = roh == e.normal
            if not e.gueltig:
                e.hinweise.append(_ABSCHREIBEN)
        e.hinweise.append("Dieselbe Adresse gilt auf allen Ketten dieser Familie (Ethereum, BNB Smart Chain, Polygon, "
                          "Arbitrum, Optimism, Base, Gnosis). Auf welcher Kette gezahlt wurde, steht im Rapport.")
        return e

    # Bitcoin Segwit und Taproot, Litecoin Segwit
    if re.match(r"(bc|tb|bcrt|ltc)1", klein):
        teile = bech32(roh)
        hrp = klein.split("1")[0]
        e.art, e.familie = "adresse", "litecoin" if hrp == "ltc" else "bitcoin"
        if not teile:
            e.format, e.gueltig = "Segwit-Adresse (Bech32)", False
            e.hinweise.append(_ABSCHREIBEN)
            return e
        _, version, programm, art = teile
        e.normal, e.gueltig = klein, True
        e.format = ("Taproot (P2TR, Bech32m)" if version == 1 and len(programm) == 32 else
                    f"Segwit Version {version} (Bech32m)" if version else
                    "Segwit P2WPKH (Bech32)" if len(programm) == 20 else "Segwit P2WSH (Bech32)")
        if hrp == "bc":
            e.ketten = ["bitcoin"]
        elif hrp == "ltc":
            e.hinweise.append("Litecoin wird von den eingebauten Quellen nicht abgedeckt.")
        else:
            e.hinweise.append("Adresse eines Testnetzes, nicht des Bitcoin-Hauptnetzes. Dort liegt kein echtes Geld.")
        return e

    # Base58Check: Bitcoin, TRON, Litecoin, Dogecoin
    if _B58_RE.fullmatch(roh) and 26 <= len(roh) <= 35:
        ergebnis = base58check(roh)
        if ergebnis and len(ergebnis[0]) == 21:
            nutz, stimmt = ergebnis
            arten = {0x00: ("bitcoin", "Bitcoin P2PKH (beginnt mit 1)"), 0x05: ("bitcoin", "Bitcoin P2SH (beginnt mit 3)"),
                     0x41: ("tron", "TRON-Adresse (beginnt mit T)"), 0x30: ("litecoin", "Litecoin P2PKH (beginnt mit L)"),
                     0x32: ("litecoin", "Litecoin P2SH (beginnt mit M)"), 0x1E: ("dogecoin", "Dogecoin (beginnt mit D)"),
                     0x6F: ("bitcoin-testnetz", "Bitcoin-Testnetz"), 0xC4: ("bitcoin-testnetz", "Bitcoin-Testnetz")}
            if stimmt and nutz[0] in arten:
                e.art, e.gueltig = "adresse", True
                e.familie, e.format = arten[nutz[0]]
                if e.familie in ("bitcoin", "tron"):
                    e.ketten = [e.familie]
                elif e.familie == "bitcoin-testnetz":
                    e.hinweise.append("Adresse eines Testnetzes, nicht des Bitcoin-Hauptnetzes. Dort liegt kein echtes Geld.")
                else:
                    e.hinweise.append(f"{e.familie.capitalize()} wird von den eingebauten Quellen nicht abgedeckt.")
                if nutz[0] == 0x05:
                    e.hinweise.append("Adressen mit 3 gibt es in gleicher Form auch bei Litecoin (ältere Schreibweise).")
                return e
        # sieht aus wie eine Bitcoin- oder TRON-Adresse, aber die Prüfsumme passt nicht
        if roh[0] in "13" and 26 <= len(roh) <= 35 or roh[0] == "T" and len(roh) == 34:
            e.art, e.gueltig = "adresse", False
            e.familie = "tron" if roh[0] == "T" else "bitcoin"
            e.format = "TRON-Adresse (beginnt mit T)" if roh[0] == "T" else "Bitcoin-Adresse (Base58)"
            e.hinweise.append(_ABSCHREIBEN)
            return e

    # Aufbau einer Bitcoin- oder TRON-Adresse, aber mit Zeichen, die es in Base58 nicht gibt (0, O, I, l)
    if re.fullmatch(r"[13][A-Za-z0-9]{25,34}|T[A-Za-z0-9]{33}", roh) and not _B58_RE.fullmatch(roh):
        fremd = sorted({z for z in roh if z not in _B58})
        e.art, e.gueltig = "adresse", False
        e.familie = "tron" if roh[0] == "T" else "bitcoin"
        e.format = "TRON-Adresse (beginnt mit T)" if roh[0] == "T" else "Bitcoin-Adresse (Base58)"
        e.hinweise.append(f"Enthält Zeichen, die in diesem Format nicht vorkommen: {' '.join(fremd)}. Die Ziffer 0 und die "
                          "Buchstaben O, I und l gibt es dort nicht, damit man sie nicht verwechselt. Wert mit dem Original vergleichen.")
        return e

    # erkannt, aber nicht abfragbar
    if re.fullmatch(f"[48][{_B58}]{{94}}", roh) or re.fullmatch(f"4[{_B58}]{{105}}", roh):
        e.art, e.familie, e.format = "adresse", "monero", "Monero-Adresse"
        e.hinweise.append("Monero verbirgt Absender, Empfänger und Betrag. Zahlungen lassen sich mit offenen Quellen "
                          "nicht verfolgen. Ansatzpunkt ist die Stelle, an der getauscht wurde (Börse, Wechseldienst).")
        return e
    if re.fullmatch(r"(bitcoincash:)?[qp][a-z0-9]{41}", klein):
        e.art, e.familie, e.format = "adresse", "bitcoin-cash", "Bitcoin-Cash-Adresse (CashAddr)"
        e.hinweise.append("Bitcoin Cash wird von den eingebauten Quellen nicht abgedeckt.")
        return e
    if _B58_RE.fullmatch(roh) and 32 <= len(roh) <= 44 and len(base58_dekodieren(roh) or b"") == 32:
        e.art, e.familie, e.format = "adresse", "solana", "vermutlich Solana-Adresse (32 Bytes in Base58)"
        e.hinweise.append("Solana wird von den eingebauten Quellen nicht abgedeckt. Das Format hat keine Prüfsumme, "
                          "die Zuordnung ist deshalb nur eine Vermutung.")
        return e
    e.hinweise.append("Kein bekanntes Format einer Krypto-Adresse oder Transaktions-ID. Wert mit dem Original vergleichen.")
    return e
