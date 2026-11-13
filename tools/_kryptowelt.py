"""Eine kleine erfundene Blockchain-Welt für Selbsttest und Musterfall.

Sie beantwortet die Abfragen des Gateways so, wie es die echten Dienste tun: gleiche Adressen der
Schnittstellen, gleiche Felder, gleiche Eigenheiten (Fehler mit HTTP 200, leere Antwort der EZB am
Wochenende, Fortsetzung langer Bemerkungen in der Kommentardatei von OFAC). Die Formen sind den Antworten
der echten Dienste nachgebildet, die Inhalte sind erfunden: Adressen und Transaktions-IDs entstehen aus
Namen und haben gültige Prüfsummen, gehören aber niemandem.

    welt = Welt()
    welt.btc_zahlung("t1", [("extern", "opfer", 60_000_000)], [("erpresser", 50_000_000), ("opfer2", 9_990_000)], zeit)
    kern.transport = httpx.MockTransport(welt.antwort)
"""
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from gateway.krypto_adressen import base58check_kodieren, eip55, tron_zu_hex  # noqa: E402

USDT_TRON = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_ETH = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
TRANSFER = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _h(name: str) -> bytes:
    return hashlib.sha256(f"osint-gateway-muster|{name}".encode()).digest()


def btc(name: str) -> str:
    """Erfundene Bitcoin-Adresse (beginnt mit 1) zu einem Namen."""
    return base58check_kodieren(b"\x00" + _h(name)[:20])


def tron(name: str) -> str:
    return base58check_kodieren(b"\x41" + _h(name)[:20])


def evm(name: str) -> str:
    return eip55("0x" + _h(name)[:20].hex())


def txid(name: str) -> str:
    return _h("tx|" + name).hex()


def _json(inhalt: object, status: int = 200) -> httpx.Response:
    """Antwort mit festgelegter Bytefolge, unabhängig von der httpx-Version: Der Musterfall soll überall gleich ausfallen."""
    return httpx.Response(status, content=json.dumps(inhalt, ensure_ascii=False, separators=(",", ":")).encode(),
                          headers={"content-type": "application/json"})


class Welt:
    def __init__(self) -> None:
        self.btc_tx: dict[str, dict] = {}
        self.trc20: list[dict] = []
        self.trx: list[dict] = []
        self.tron_konten: dict[str, dict] = {}
        self.tron_gesperrt: set[str] = set()
        self.tronscan: dict[str, dict] = {}
        self.evm_tx: list[dict] = []
        self.evm_token: list[dict] = []
        self.evm_konten: dict[str, dict] = {}
        self.marken: dict[str, list[dict]] = {}              # Blockscout-Etiketten je Adresse (klein geschrieben)
        self.walletexplorer: dict[str, str] = {}
        # Ein Eintrag steht immer in der Liste: Eine SDN-Liste ganz ohne Krypto-Adressen wertet das Gateway als Störung
        self.ofac: list[tuple[str, str, str, list[tuple[str, str]]]] = [
            ("90000", "MUSTER HANDELS AG", "CYBER2", [("XBT", btc("ofac-fest")), ("ETH", evm("ofac-fest")), ("TRX", tron("ofac-fest"))])]
        self.ransomwhere: dict[str, str] = {}
        self.trm: set[str] = set()
        self.kurse: dict[str, float] = {"coingecko:bitcoin": 61250.0, "coingecko:ethereum": 2410.5, "coingecko:tron": 0.1512,
                                        "coingecko:tether": 1.0003, "coingecko:usd-coin": 0.9998}
        self.aus: set[str] = set()           # Hosts, die gerade «gestört» sind
        self.gestoert: set[str] = set()      # Teile einer Adresse (Host, Pfad, Anfrage), bei denen nur dieser eine Abruf scheitert
        self.abweichend: set[str] = set()    # Hosts, die eine Bitcoin-Transaktion leicht anders zeigen (für die Gegenprüfung)
        self.aufrufe: list[str] = []

    # ----- Bitcoin

    def btc_zahlung(self, name: str, ein: list[tuple], aus: list[tuple[str, int]], zeit: int, hoehe: int = 860000) -> str:
        """ein: ("extern", name, betrag) für Geld von ausserhalb der Welt, oder (tx-name, ausgang) für einen Ausgang
        einer früheren Zahlung. aus: (name der Adresse, Betrag in Satoshi)."""
        vin, summe = [], 0
        for e in ein:
            if e[0] == "extern":
                adresse, betrag, vor_tx, vor_nr = btc(e[1]), e[2], txid(f"extern|{name}|{e[1]}"), 0
            else:
                vor = self.btc_tx[txid(e[0])]["vout"][e[1]]
                adresse, betrag, vor_tx, vor_nr = vor["scriptpubkey_address"], vor["value"], txid(e[0]), e[1]
            summe += betrag
            vin.append({"txid": vor_tx, "vout": vor_nr, "is_coinbase": False, "sequence": 4294967293, "scriptsig": "",
                        "prevout": {"scriptpubkey_type": "p2pkh", "scriptpubkey_address": adresse, "value": betrag}})
        vout = [{"scriptpubkey_type": "p2pkh", "scriptpubkey_address": btc(n), "value": b} for n, b in aus]
        t = txid(name)
        self.btc_tx[t] = {"txid": t, "version": 2, "locktime": 0, "vin": vin, "vout": vout, "size": 200 + 60 * len(vin), "weight": 800,
                          "fee": summe - sum(b for _, b in aus),
                          "status": {"confirmed": True, "block_height": hoehe + len(self.btc_tx), "block_hash": _h("block|" + name).hex(),
                                     "block_time": zeit}}
        return t

    def _btc(self, pfad: str, frage: dict, host: str = "") -> httpx.Response:
        teile = pfad.strip("/").split("/")          # api, address|tx, wert, ...
        if teile[1] == "tx":
            t = self.btc_tx.get(teile[2])
            if not t:
                return httpx.Response(404, text="Transaction not found")
            if len(teile) == 3:
                if host in self.abweichend:
                    t = json.loads(json.dumps(t))
                    t["vout"][0]["value"] += 1
                return _json(t)
            verbleib = []
            for nr in range(len(t["vout"])):
                folge = next(((x, i) for x in self.btc_tx.values() for i, e in enumerate(x["vin"]) if e["txid"] == t["txid"] and e["vout"] == nr), None)
                verbleib.append({"spent": True, "txid": folge[0]["txid"], "vin": folge[1], "status": folge[0]["status"]} if folge else {"spent": False})
            return _json(verbleib)
        adresse = teile[2]
        beteiligt = [t for t in self.btc_tx.values() if any(a["scriptpubkey_address"] == adresse for a in t["vout"])
                     or any(e["prevout"]["scriptpubkey_address"] == adresse for e in t["vin"])]
        beteiligt.sort(key=lambda t: -t["status"]["block_height"])
        if len(teile) == 3:
            erhalten = [a["value"] for t in beteiligt for a in t["vout"] if a["scriptpubkey_address"] == adresse]
            ausgegeben = [e["prevout"]["value"] for t in beteiligt for e in t["vin"] if e["prevout"]["scriptpubkey_address"] == adresse]
            return _json({"address": adresse, "chain_stats": {"funded_txo_count": len(erhalten), "funded_txo_sum": sum(erhalten),
                                                             "spent_txo_count": len(ausgegeben), "spent_txo_sum": sum(ausgegeben),
                                                             "tx_count": len(beteiligt)},
                          "mempool_stats": {"funded_txo_count": 0, "funded_txo_sum": 0, "spent_txo_count": 0, "spent_txo_sum": 0, "tx_count": 0}})
        if frage.get("after_txid"):
            ab = next((i for i, t in enumerate(beteiligt) if t["txid"] == frage["after_txid"][0]), len(beteiligt))
            beteiligt = beteiligt[ab + 1:]
        return _json(beteiligt[:50])

    # ----- TRON

    def tron_zahlung(self, name: str, von: str, an: str, betrag: int, zeit: int, vertrag: str | None = USDT_TRON) -> str:
        """Zahlung auf TRON. vertrag None: TRX (Betrag in Sun), sonst ein TRC-20-Token (Betrag in Grundeinheiten)."""
        t = txid(name)
        eintrag = {"tx": t, "von": tron(von), "an": tron(an), "betrag": betrag, "zeit_ms": zeit * 1000, "vertrag": vertrag,
                   "block": 60_000_000 + len(self.trc20) + len(self.trx)}
        (self.trx if vertrag is None else self.trc20).append(eintrag)
        return t

    def tron_konto(self, name: str, trx: int = 5_000_000, usdt: int = 0, vertrag: bool = False, erstellt: int = 1_700_000_000) -> None:
        self.tron_konten[tron(name)] = {"trx": trx, "usdt": usdt, "vertrag": vertrag, "erstellt": erstellt}

    def _tron(self, anfrage: httpx.Request, pfad: str, frage: dict) -> httpx.Response:
        if pfad == "/wallet/triggerconstantcontract":
            k = json.loads(anfrage.content)
            if k["function_selector"] == "isBlackListed(address)":
                gesperrt = any(tron_zu_hex(a)[2:] == k["parameter"][-40:] for a in self.tron_gesperrt)
                return _json({"result": {"result": True}, "energy_used": 4658, "constant_result": [("1" if gesperrt else "0").rjust(64, "0")]})
            if k["function_selector"] == "decimals()":
                return _json({"result": {"result": True}, "constant_result": ["6".rjust(64, "0")]})
            text = b"FAKE".hex()
            return _json({"result": {"result": True}, "constant_result": ["20".rjust(64, "0") + "4".rjust(64, "0") + text.ljust(64, "0")]})
        if pfad in ("/wallet/gettransactionbyid", "/wallet/gettransactioninfobyid"):
            t = json.loads(anfrage.content)["value"]
            z = next((x for x in self.trc20 + self.trx if x["tx"] == t), None)
            if not z:
                return _json({})
            von_h, an_h = tron_zu_hex(z["von"]), tron_zu_hex(z["an"])
            if pfad.endswith("gettransactionbyid"):
                if z["vertrag"] is None:
                    wert = {"amount": z["betrag"], "owner_address": von_h, "to_address": an_h}
                    art = "TransferContract"
                else:
                    wert = {"owner_address": von_h, "contract_address": tron_zu_hex(z["vertrag"]),
                            "data": "a9059cbb" + an_h[2:].rjust(64, "0") + f"{z['betrag']:064x}"}
                    art = "TriggerSmartContract"
                return _json({"ret": [{"contractRet": "SUCCESS"}], "signature": ["00"], "txID": t,
                              "raw_data": {"contract": [{"parameter": {"value": wert, "type_url": f"type.googleapis.com/protocol.{art}"}, "type": art}],
                                           "timestamp": z["zeit_ms"] - 3000, "expiration": z["zeit_ms"] + 57000}})
            info = {"id": t, "blockNumber": z["block"], "blockTimeStamp": z["zeit_ms"], "fee": 13_844_850 if z["vertrag"] else 1_100_000}
            if z["vertrag"]:
                info.update(contract_address=tron_zu_hex(z["vertrag"]), receipt={"result": "SUCCESS", "energy_usage_total": 130285},
                            log=[{"address": tron_zu_hex(z["vertrag"])[2:], "data": f"{z['betrag']:064x}",
                                  "topics": [TRANSFER, von_h[2:].rjust(64, "0"), an_h[2:].rjust(64, "0")]}])
            return _json(info)
        teile = pfad.strip("/").split("/")          # v1, accounts, adresse, [transactions, [trc20]]
        adresse = teile[2]
        if tron_zu_hex(adresse) is None:
            return _json({"success": False, "error": "A valid account address is required.", "statusCode": 400}, 400)
        if len(teile) == 3:
            k = self.tron_konten.get(adresse)
            if not k:
                return _json({"data": [], "success": True, "meta": {"at": 1794594478509, "page_size": 0}})
            daten = {"address": tron_zu_hex(adresse), "balance": k["trx"], "create_time": k["erstellt"] * 1000,
                     "latest_opration_time": (k["erstellt"] + 86400) * 1000, "trc20": [{USDT_TRON: str(k["usdt"])}] if k["usdt"] else []}
            if k["vertrag"]:
                daten["type"] = "Contract"
            return _json({"data": [daten], "success": True, "meta": {"at": 1794594478509, "page_size": 1}})
        token = len(teile) == 5
        if token:
            zeilen = [z for z in self.trc20 if adresse in (z["von"], z["an"])]
        else:       # wie bei TronGrid: Token-Zahlungen stehen beim Absender als Aufruf des Token-Vertrags in der Liste, ohne Betrag
            zeilen = [z for z in self.trx if adresse in (z["von"], z["an"])] + [{**z, "aufruf": True} for z in self.trc20 if z["von"] == adresse]
        if frage.get("only_from"):
            zeilen = [z for z in zeilen if z["von"] == adresse]
        if frage.get("only_to"):
            zeilen = [z for z in zeilen if z["an"] == adresse and not z.get("aufruf")]
        if frage.get("contract_address"):
            zeilen = [z for z in zeilen if z["vertrag"] == frage["contract_address"][0]]
        if frage.get("min_timestamp"):
            zeilen = [z for z in zeilen if z["zeit_ms"] >= int(frage["min_timestamp"][0])]
        zeilen.sort(key=lambda z: z["zeit_ms"], reverse="desc" in frage.get("order_by", ["block_timestamp,desc"])[0])
        start = int(frage["fingerprint"][0]) if frage.get("fingerprint") else 0
        grenze = int(frage.get("limit", ["20"])[0])
        seite = zeilen[start:start + grenze]
        if token:
            daten = [{"transaction_id": z["tx"], "token_info": {"symbol": "USDT" if z["vertrag"] == USDT_TRON else "USDT", "address": z["vertrag"],
                                                                "decimals": 6, "name": "Tether USD"},
                      "block_timestamp": z["zeit_ms"], "from": z["von"], "to": z["an"], "type": "Transfer", "value": str(z["betrag"])} for z in seite]
        else:
            daten = [{"ret": [{"contractRet": "SUCCESS", "fee": 13_844_850}], "txID": z["tx"], "blockNumber": z["block"], "block_timestamp": z["zeit_ms"],
                      "raw_data": {"contract": [{"type": "TriggerSmartContract", "parameter": {
                          "type_url": "type.googleapis.com/protocol.TriggerSmartContract",
                          "value": {"owner_address": tron_zu_hex(z["von"]), "contract_address": tron_zu_hex(z["vertrag"]),
                                    "data": "a9059cbb" + tron_zu_hex(z["an"])[2:].rjust(64, "0") + f"{z['betrag']:064x}"}}}]}}
                     if z.get("aufruf") else
                     {"ret": [{"contractRet": "SUCCESS", "fee": 1_100_000}], "txID": z["tx"], "blockNumber": z["block"], "block_timestamp": z["zeit_ms"],
                      "raw_data": {"contract": [{"type": "TransferContract", "parameter": {
                          "type_url": "type.googleapis.com/protocol.TransferContract",
                          "value": {"amount": z["betrag"], "owner_address": tron_zu_hex(z["von"]), "to_address": tron_zu_hex(z["an"])}}}]}}
                     for z in seite]
        meta = {"at": 1794594478509, "page_size": len(daten)}
        if start + grenze < len(zeilen):
            meta["fingerprint"] = str(start + grenze)
        return _json({"data": daten, "success": True, "meta": meta})

    # ----- Ethereum (Blockscout)

    def evm_zahlung(self, name: str, von: str, an: str, betrag: int, zeit: int, block: int, vertrag: str | None = None, pos: int = 7) -> str:
        """Zahlung auf Ethereum. vertrag None: ETH (Betrag in Wei), sonst ERC-20 (Grundeinheiten)."""
        h = "0x" + txid(name)
        (self.evm_tx if vertrag is None else self.evm_token).append(
            {"hash": h, "von": evm(von), "an": evm(an), "betrag": betrag, "zeit": zeit, "block": block, "vertrag": vertrag, "pos": pos})
        return h

    def evm_konto(self, name: str, wei: int = 0, vertrag: bool = False, bezeichnung: str | None = None, usdt: int = 0) -> None:
        self.evm_konten[evm(name).lower()] = {"wei": wei, "vertrag": vertrag, "name": bezeichnung, "usdt": usdt}

    def _adresse_v2(self, adresse: str, mit_marken: bool = False) -> dict:
        k = self.evm_konten.get(adresse.lower(), {"wei": 0, "vertrag": False, "name": None, "usdt": 0})
        marken = self.marken.get(adresse.lower())
        return {"hash": eip55(adresse), "is_contract": k["vertrag"], "is_scam": False, "is_verified": k["vertrag"], "name": k["name"],
                "ens_domain_name": None, "implementations": [], "private_tags": [], "public_tags": [], "proxy_type": None,
                "reputation": "ok", "watchlist_names": [],
                "metadata": {"tags": [{**m, "meta": json.loads(m["meta"])} for m in marken]} if mit_marken and marken else None}

    def _blockscout(self, pfad: str, frage: dict) -> httpx.Response:
        if pfad.startswith("/api/v2/addresses/"):
            teile = pfad.split("/")
            adresse = teile[4]
            if len(adresse) != 42:
                return _json({"errors": [{"title": "Invalid value", "source": {"pointer": "/address_hash_param"},
                                          "detail": "Invalid format. Expected ~r/^0x([A-Fa-f0-9]{40})$/"}]}, 422)
            k = self.evm_konten.get(adresse.lower(), {"wei": 0, "vertrag": False, "name": None, "usdt": 0})
            if len(teile) == 5:
                return _json({**self._adresse_v2(adresse), "coin_balance": str(k["wei"]), "token": None, "has_tokens": bool(k["usdt"]),
                              "has_token_transfers": True, "has_logs": False, "exchange_rate": "2410.5", "block_number_balance_updated_at": 26407505,
                              "creation_transaction_hash": None, "creator_address_hash": None})
            if teile[5] == "counters":
                n = sum(1 for t in self.evm_tx if adresse.lower() in (t["von"].lower(), t["an"].lower()))
                m = sum(1 for t in self.evm_token if adresse.lower() in (t["von"].lower(), t["an"].lower()))
                return _json({"transactions_count": str(n), "token_transfers_count": str(m), "gas_usage_count": "21000", "validations_count": "0"})
            if teile[5] == "token-balances":
                return _json([{"value": str(k["usdt"]), "token_id": None, "token_instance": None,
                               "token": {"address_hash": USDT_ETH, "symbol": "USDT", "decimals": "6", "name": "Tether", "type": "ERC-20"}}] if k["usdt"] else [])
        if pfad.startswith("/api/v2/transactions/"):
            h = pfad.split("/")[4]
            t = next((x for x in self.evm_tx + self.evm_token if x["hash"] == h), None)
            if not t:
                return _json({"message": "Not found"}, 404)
            token = t["vertrag"] is not None
            an = t["vertrag"] if token else t["an"]
            return _json({"hash": h, "status": "ok", "result": "success", "block_number": t["block"], "position": t["pos"], "confirmations": 12345,
                          "timestamp": datetime.fromtimestamp(t["zeit"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000000Z"),
                          "value": "0" if token else str(t["betrag"]), "fee": {"type": "actual", "value": "441000000000000"},
                          "method": "transfer" if token else None, "from": self._adresse_v2(t["von"], True),
                          "to": {**self._adresse_v2(an, True), **({"is_contract": True, "name": "TetherToken"} if token else {})},
                          "created_contract": None, "token_transfers_overflow": False,
                          "transaction_types": ["contract_call", "token_transfer"] if token else ["coin_transfer"],
                          "token_transfers": [{"from": self._adresse_v2(t["von"], True), "to": self._adresse_v2(t["an"], True), "type": "token_transfer",
                                               "token": {"address_hash": t["vertrag"], "symbol": "USDT", "decimals": "6", "name": "Tether", "type": "ERC-20"},
                                               "total": {"decimals": "6", "value": str(t["betrag"])}, "transaction_hash": h}] if token else []})
        aktion, adresse = frage.get("action", [""])[0], frage.get("address", [""])[0].lower()
        k = self.evm_konten.get(adresse, {"wei": 0, "usdt": 0})
        if aktion == "balance":
            return _json({"message": "OK", "result": str(k["wei"]), "status": "1"})
        if aktion == "tokenbalance":
            return _json({"message": "OK", "result": str(k["usdt"]), "status": "1"})
        if aktion in ("txlist", "tokentx"):
            if aktion == "txlist":      # wie bei Blockscout: Token-Zahlungen stehen beim Absender als Aufruf des Token-Vertrags in der Liste, Wert 0
                zeilen = [t for t in self.evm_tx if adresse in (t["von"].lower(), t["an"].lower())] \
                    + [{**t, "an": t["vertrag"], "betrag": 0, "aufruf": True} for t in self.evm_token if t["von"].lower() == adresse]
            else:
                zeilen = [t for t in self.evm_token if adresse in (t["von"].lower(), t["an"].lower())]
            if frage.get("contractaddress"):
                zeilen = [t for t in zeilen if t["vertrag"].lower() == frage["contractaddress"][0].lower()]
            if frage.get("startblock"):
                zeilen = [t for t in zeilen if t["block"] >= int(frage["startblock"][0])]
            if frage.get("filter_by") == ["from"]:
                zeilen = [t for t in zeilen if t["von"].lower() == adresse]
            if frage.get("filter_by") == ["to"]:
                zeilen = [t for t in zeilen if t["an"].lower() == adresse]
            zeilen.sort(key=lambda t: (t["block"], t["pos"]), reverse=frage.get("sort") == ["desc"])
            seite, anzahl = int(frage.get("page", ["1"])[0]), int(frage.get("offset", ["50"])[0])
            zeilen = zeilen[(seite - 1) * anzahl: seite * anzahl]
            if not zeilen:
                return _json({"message": "No transactions found" if aktion == "txlist" else "No token transfers found", "result": [], "status": "0"})
            if aktion == "txlist":
                return _json({"message": "OK", "status": "1", "result": [
                    {"blockNumber": str(t["block"]), "timeStamp": str(t["zeit"]), "hash": t["hash"], "from": t["von"].lower(), "to": t["an"].lower(),
                     "value": str(t["betrag"]), "isError": "0", "txreceipt_status": "1", "contractAddress": "",
                     "input": "0xa9059cbb" if t.get("aufruf") else "0x", "methodId": "0xa9059cbb" if t.get("aufruf") else "0x",
                     "transactionIndex": str(t["pos"]), "gasUsed": "21000", "gasPrice": "21000000000", "confirmations": "100", "nonce": "1"}
                    for t in zeilen]})
            return _json({"message": "OK", "status": "1", "result": [
                {"blockNumber": str(t["block"]), "timeStamp": str(t["zeit"]), "hash": t["hash"], "from": t["von"].lower(), "to": t["an"].lower(),
                 "value": str(t["betrag"]), "contractAddress": t["vertrag"].lower(), "tokenDecimal": "6", "tokenName": "Tether", "tokenSymbol": "USDT",
                 "transactionIndex": str(t["pos"]), "input": "0xa9059cbb", "methodId": "", "functionName": "", "confirmations": "100"} for t in zeilen]})
        return _json({"message": "Unknown module", "result": None, "status": "0"}, 400)

    # ----- Zuordnung und Kurse

    def ofac_dateien(self) -> tuple[str, str]:
        """SDN.CSV und SDN_COMMENTS.CSV. Bemerkungen über 250 Zeichen laufen in der Kommentardatei weiter, mitten im Wort."""
        null = "-0- "
        sdn = [f'36,"AEROCARIBBEAN AIRLINES",{null},"CUBA",{null},{null},{null},{null},{null},{null},{null},{null}']
        kommentare = []
        for nr, name, programm, adressen in self.ofac:
            bemerkung = "; ".join(("" if i == 0 else "alt. ") + f"Digital Currency Address - {w} {a}" for i, (w, a) in enumerate(adressen)) + "."
            vorn, hinten = bemerkung[:250], bemerkung[250:]
            sdn.append(f'{nr},"{name}",{null},"{programm}",{null},{null},{null},{null},{null},{null},{null},"{vorn}"')
            if hinten:
                kommentare.append(f'{nr},"{hinten}"')
        return "\r\n".join(sdn) + "\r\n", "\r\n".join(kommentare) + ("\r\n" if kommentare else "")

    def antwort(self, anfrage: httpx.Request) -> httpx.Response:
        host, pfad = anfrage.url.host, anfrage.url.path
        frage = parse_qs(anfrage.url.query.decode())
        self.aufrufe.append(f"{anfrage.method} {host}{pfad}")
        if host in self.aus or any(teil in str(anfrage.url) for teil in self.gestoert):
            return httpx.Response(503, text="Service Unavailable")
        if host in ("mempool.space", "blockstream.info"):
            return self._btc(pfad, frage, host)
        if host == "api.trongrid.io":
            return self._tron(anfrage, pfad, frage)
        if host == "eth.blockscout.com":
            return self._blockscout(pfad, frage)
        if host == "metadata.services.blockscout.com":
            adressen = frage.get("addresses", [""])[0].split(",")
            return _json({"addresses": {eip55(a): {"tags": self.marken[a.lower()]} for a in adressen if a.lower() in self.marken}})
        if host == "www.walletexplorer.com":
            adresse = frage["address"][0]
            return _json({"found": True, **({"label": self.walletexplorer[adresse]} if adresse in self.walletexplorer else {}),
                          "wallet_id": _h("wallet|" + self.walletexplorer.get(adresse, adresse)).hex()[:16], "updated_to_block": 975592})
        if host in ("sanctionslistservice.ofac.treas.gov", "www.treasury.gov"):
            sdn, kommentare = self.ofac_dateien()
            return httpx.Response(200, text=kommentare if "comments" in pfad.lower() else sdn, headers={"content-type": "text/csv"})
        if host == "api.ransomwhe.re":
            return _json({"result": [{"address": a, "balance": 1, "blockchain": "bitcoin", "createdAt": "2021-07-08T06:43:11.496Z",
                                      "updatedAt": "2021-09-22T20:54:04.279Z", "family": f, "balanceUSD": 1.0,
                                      "transactions": [{"hash": txid("rw|" + a), "time": 1587839053, "amount": 43577930, "amountUSD": 3298.82}]}
                                     for a, f in self.ransomwhere.items()]})
        if host == "api.trmlabs.com":
            if len(anfrage.content) > 1000:          # wie der echte Dienst: höchstens 1 KB je Anfrage
                return httpx.Response(413, text="Payload Too Large")
            return _json([{"address": e["address"], "isSanctioned": e["address"] in self.trm} for e in json.loads(anfrage.content)], 201)
        if host == "apilist.tronscanapi.com":
            if anfrage.headers.get("TRON-PRO-API-KEY") is None:
                return _json({"Error": "missing api key"}, 401)
            adresse = frage["address"][0]
            if pfad.endswith("/accountv2"):
                return _json({"address": adresse, "balance": 1, **self.tronscan.get(adresse, {})})
            return _json({"send_ad_by_memo": False, "is_black_list": adresse in self.tron_gesperrt, "has_fraud_transaction": False, "fraud_token_creator": False})
        if host == "coins.llama.fi":
            kennungen = pfad.rsplit("/", 1)[1].split(",")
            zeit = int(pfad.split("/")[3]) if "/historical/" in pfad else 1794594000
            return _json({"coins": {k: {"symbol": k.split(":")[1][:4].upper(), "price": self.kurse[k], "timestamp": zeit + 60, "confidence": 0.99}
                                    for k in kennungen if k in self.kurse}})
        if host == "data-api.ecb.europa.eu":
            ende = frage["endPeriod"][0]
            if ende.endswith("-00"):
                return httpx.Response(200, content=b"")
            kopf = "KEY,FREQ,CURRENCY,CURRENCY_DENOM,EXR_TYPE,EXR_SUFFIX,TIME_PERIOD,OBS_VALUE,OBS_STATUS"
            zeilen = [f"EXR.D.CHF.EUR.SP00.A,D,CHF,EUR,SP00,A,{frage['startPeriod'][0]},0.9401,A", f"EXR.D.CHF.EUR.SP00.A,D,CHF,EUR,SP00,A,{ende},0.9412,A",
                      f"EXR.D.USD.EUR.SP00.A,D,USD,EUR,SP00,A,{frage['startPeriod'][0]},1.0850,A", f"EXR.D.USD.EUR.SP00.A,D,USD,EUR,SP00,A,{ende},1.0875,A"]
            return httpx.Response(200, text="\r\n".join([kopf] + zeilen) + "\r\n", headers={"content-type": "text/csv"})
        return _json({"error": f"Die erfundene Welt kennt {host}{pfad} nicht"}, 404)
