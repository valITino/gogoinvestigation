"""Wem lässt sich eine Krypto-Adresse zuordnen? Sanktionslisten, bekannte Ransomware-Adressen und
Etiketten, die Explorer und Auswerter an Adressen hängen (Börse, Mischdienst, gesperrt).

Ohne Schlüssel:
    OFAC             Sanktionsliste des US-Finanzministeriums (SDN) mit den dort genannten Krypto-Adressen
    TRM Labs         Sanktionsprüfung (öffentliche Schnittstelle)
    Ransomwhere      von Freiwilligen gepflegter Datensatz bekannter Lösegeld-Adressen (Bitcoin)
    Blockscout       Etiketten für Adressen der Ethereum-Familie (Börsen, Brücken, gesperrte Adressen)
    WalletExplorer   Bitcoin: Zuordnung zu benannten Diensten über gemeinsam genutzte Adressen
    Tether           TRON: Hat Tether die Adresse gesperrt? (Leseaufruf am USDT-Vertrag über TronGrid)
Mit Schlüssel:
    Tronscan         Etiketten und Risikohinweise für TRON-Adressen
    Chainabuse       Betrugsmeldungen Geschädigter (knappes Kontingent, nur auf Wunsch)
    Iknaio           GraphSense: Etiketten und Cluster für Bitcoin, Ethereum, TRON

Ein Etikett ist eine Angabe Dritter, kein Beweis. Es sagt, wo ein Editionsbegehren ansetzen kann, nicht
wer hinter einer Adresse steht. Fällt eine Quelle aus, steht das im Ergebnis: «nicht geprüft» ist etwas
anderes als «kein Eintrag».
"""
from __future__ import annotations

import base64
import csv
import io
import json
import re
from collections import Counter
from typing import Any

from .kern import Abbruch, Vorgang, einstellung, saeubern
from .krypto_ketten import KETTEN, Kette, Quellfehler, gleich, tron_gesperrt

OFAC_URLS = (
    ("https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV",
     "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_COMMENTS.CSV"),
    ("https://www.treasury.gov/ofac/downloads/sdn.csv", "https://www.treasury.gov/ofac/downloads/sdn_comments.csv"),
)
_OFAC_ADRESSE = re.compile(r"Digital Currency Address - ([A-Z0-9]{2,8}) ([A-Za-z0-9]{20,110})")
# Ein «Dienst» im Sinn dieses Moduls führt Guthaben für Kunden: Börse, Zahlungsdienst, Verwahrer. Dort endet eine
# Verfolgung, weil der Dienst die Gelder zusammenlegt und nur er weiss, wem eine Einzahlung gutgeschrieben wurde.
# Massgebend ist die Kategorie, die die Quelle vergibt. Ein Name allein genügt nicht: Namen tragen auch Adressen
# von Tätern («… Exploiter 3») und von Sanktionierten. Tauschprogramme, Brücken und Mischdienste haben keine Kunden,
# die sich erfragen liessen. Sie gelten nicht als Dienst.
_KUNDEN_MARKEN = {"exchange", "cex", "centralized-exchange", "hot-wallet", "cold-wallet", "deposit-wallet", "deposit-address",
                  "otc", "payment", "payments", "payment-processor", "custody", "custodian", "gambling", "casino"}
_MISCH_MARKEN = {"mixer", "mixing", "mixing-service", "tumbler", "coinjoin"}
_MISCH_NAME = re.compile(r"tornado[ .]?cash|mixer|mixing|tumbler|coin ?join|joinmarket|wasabi|samourai|whirlpool|bitcoin ?fog|blender\.io|sinbad|railgun",
                         re.IGNORECASE)
_IKNAIO_DIENST = {"exchange", "service", "gambling", "payment_processor", "wallet_service", "hosted_wallet", "atm", "mining_pool"}
_IKNAIO_MISCHER = {"mixing_service", "mixer", "coinjoin"}
TRM_KOERPER = 900          # TRM nimmt je Anfrage höchstens 1 KB an. Grössere Listen gehen in mehreren Anfragen
QUELLEN = ("ofac", "trm", "ransomwhere", "blockscout", "walletexplorer", "tether", "tronscan", "chainabuse", "iknaio")


def etikett(quelle: str, art: str, name: str, detail: str = "", dienst: bool = False, beleg: str = "", betreiber: str = "",
            mischer: bool = False) -> dict:
    """art: sanktion | ransomware | gesperrt | meldung | name | kategorie | hinweis.
    ``dienst``: Die Adresse gehört einem Dienst mit Kunden. ``betreiber``: dessen Name, wenn die Quelle ihn nennt.
    ``mischer``: Die Adresse gehört einem Mischdienst. Beides zugleich gibt es nicht."""
    d: dict[str, Any] = {"quelle": quelle, "art": art, "name": saeubern(name, 90)}
    if detail:
        d["detail"] = saeubern(detail, 260)
    if mischer:
        d["mischer"] = True
    elif dienst:
        d["dienst"] = True
    if betreiber:
        d["betreiber"] = saeubern(betreiber, 60)
    if beleg:
        d["beleg"] = beleg
    return d


def _schluessel(adresse: str) -> str:
    """Vergleichsform: Adressen der Ethereum-Familie und Bech32 unabhängig von Gross- und Kleinschreibung."""
    a = adresse.strip()
    return a.lower() if a.lower().startswith(("0x", "bc1")) else a


def blockscout_etiketten(tags: list, beleg: str = "") -> list[dict]:
    """Etiketten aus der Form, in der Blockscout sie liefert, in die einheitliche Form."""
    ergebnis, ist_dienst, ist_mischer = [], False, False
    marken = []
    for t in tags or []:
        if not isinstance(t, dict):
            continue
        meta = t.get("meta")
        if isinstance(meta, str):
            try:
                meta = json.loads(meta)
            except json.JSONDecodeError:
                meta = {}
        meta = meta if isinstance(meta, dict) else {}
        slug, typ = str(t.get("slug") or "").lower(), str(t.get("tagType") or "")
        if typ in ("generic", "classifier") and slug in _KUNDEN_MARKEN:
            ist_dienst = True
        if slug in _MISCH_MARKEN or typ in ("name", "protocol") and _MISCH_NAME.search(str(t.get("name") or "")):
            ist_mischer = True
        marken.append((slug, typ, str(t.get("name") or ""), meta, int(t.get("ordinal") or 0)))
    for slug, typ, name, meta, _ in sorted(marken, key=lambda m: -m[4]):
        info = ", ".join(str(x) for x in meta.get("info") or [] if x)
        if slug == "sanctioned":
            ergebnis.append(etikett("Blockscout", "sanktion", "Sanktioniert", info, beleg=beleg))
        elif slug == "blocked":
            ergebnis.append(etikett("Blockscout", "gesperrt", "Vom Emittenten gesperrt", info, beleg=beleg))
        elif typ == "note":
            ergebnis.append(etikett("Blockscout", "hinweis", "Hinweis", str(meta.get("data") or ""), beleg=beleg))
        elif typ == "name":
            ergebnis.append(etikett("Blockscout", "name", name, dienst=ist_dienst, mischer=ist_mischer, beleg=beleg,
                                    betreiber=str(meta.get("main_entity") or "") if ist_dienst else ""))
        elif typ in ("generic", "classifier", "protocol"):
            ergebnis.append(etikett("Blockscout", "kategorie", name, dienst=slug in _KUNDEN_MARKEN and typ != "protocol",
                                    mischer=slug in _MISCH_MARKEN, beleg=beleg))
    return ergebnis


def ofac_lesen(sdn: str, kommentare: str) -> dict[str, list[dict]]:
    """Krypto-Adressen der SDN-Liste: Vergleichsform der Adresse -> Einträge. Lange Bemerkungen setzt die
    Liste in der Kommentardatei fort, mitten im Wort. Deshalb wird erst zusammengefügt, dann gesucht."""
    rest: dict[str, str] = {}
    for zeile in csv.reader(io.StringIO(kommentare or "")):
        if len(zeile) >= 2:
            rest[zeile[0].strip()] = rest.get(zeile[0].strip(), "") + zeile[1]
    index: dict[str, list[dict]] = {}
    for zeile in csv.reader(io.StringIO(sdn or "")):
        if len(zeile) < 12:
            continue
        nr = zeile[0].strip()
        bemerkung = zeile[11] + rest.get(nr, "")
        if "Digital Currency Address" not in bemerkung:
            continue
        for waehrung, adresse in _OFAC_ADRESSE.findall(bemerkung):
            index.setdefault(_schluessel(adresse), []).append({
                "name": zeile[1].strip(), "programm": zeile[3].strip().replace("] [", ", "), "waehrung": waehrung, "nr": nr,
                "typ": "" if zeile[2].strip().startswith("-0-") else zeile[2].strip()})
    return index


class Zuordner:
    """Sammelt die Etiketten zu Adressen innerhalb eines Vorgangs. Listen werden einmal geladen, jede Adresse
    wird je Quelle einmal gefragt. ``stand`` hält je Quelle fest, ob sie geprüft werden konnte."""

    def __init__(self, v: Vorgang, nur: set[str] | None = None) -> None:
        self.v, self.nur = v, nur
        self.stand: dict[str, dict] = {}
        self._ofac: dict[str, list[dict]] | None = None
        self._rw: dict[str, dict] | None = None
        self._marken: dict[tuple[str, str], list[dict]] = {}
        self._flach: set[tuple[str, str]] = set()     # gegen Listen und Sammelabfragen geprüft
        self._tief: set[tuple[str, str]] = set()      # zusätzlich einzeln abgefragt
        self.cluster: dict[str, str] = {}            # Bitcoin-Adresse -> Wallet-Kennung von WalletExplorer
        self._ofac_beleg = self._rw_beleg = ""

    def _an(self, quelle: str) -> bool:
        return self.nur is None or quelle in self.nur

    def _melden(self, name: str, ergebnis: str, beleg: str = "", hinweis: str = "", **mehr: Any) -> None:
        alt = self.stand.get(name)
        if alt and alt["ergebnis"] == "fehler" and ergebnis != "fehler":
            return                                # ein Ausfall bleibt sichtbar, auch wenn spätere Abrufe gelingen
        self.stand[name] = {"ergebnis": ergebnis, **({"beleg": beleg} if beleg else {}),
                            **({"hinweis": hinweis} if hinweis else {}), **mehr}

    # ----- Listen

    async def _ofac_laden(self) -> None:
        if self._ofac is not None or not self._an("ofac"):
            return
        self._ofac = {}
        for i, (sdn_url, kommentar_url) in enumerate(OFAC_URLS):
            letzter = i == len(OFAC_URLS) - 1
            a = await self.v.hole("OFAC", "SDN-Liste", "liste", sdn_url, schritt="Sanktionsliste laden", endung="csv",
                                  zeitlimit=120, nochmal=letzter)
            if a.ergebnis != "ok" or not a.text:
                if letzter:
                    self._melden("OFAC", "fehler", a.id, a.fehler or "Liste nicht lesbar")
                continue
            b = await self.v.hole("OFAC", "SDN-Liste, Fortsetzung der Bemerkungen", "liste", kommentar_url,
                                  schritt="Sanktionsliste laden", endung="csv", zeitlimit=120)
            if b.ergebnis != "ok":
                self._melden("OFAC", "fehler", b.id, "Die Fortsetzungsdatei der Liste fehlt. Ohne sie wären Adressen unvollständig.")
                return
            self._ofac = ofac_lesen(a.text, b.text or "")
            self._ofac_beleg = a.id
            if not self._ofac:
                self._melden("OFAC", "fehler", a.id, "In der Liste wurde keine einzige Krypto-Adresse gefunden. Das Format hat sich vermutlich geändert.")
            else:
                self._melden("OFAC", "ok", a.id, adressen_in_liste=len(self._ofac))
            return

    async def _ransomwhere_laden(self) -> None:
        if self._rw is not None or not self._an("ransomwhere"):
            return
        self._rw = {}
        a = await self.v.hole("Ransomwhere", "Datensatz", "liste", "https://api.ransomwhe.re/export",
                              schritt="Bekannte Lösegeld-Adressen laden", zeitlimit=120)
        zeilen = (a.daten or {}).get("result") if isinstance(a.daten, dict) else None
        if a.ergebnis != "ok" or not isinstance(zeilen, list):
            self._melden("Ransomwhere", "fehler", a.id, a.fehler or "Datensatz nicht lesbar")
            return
        for z in zeilen:
            if isinstance(z, dict) and z.get("address"):
                self._rw[_schluessel(str(z["address"]))] = z
        self._rw_beleg = a.id
        self._melden("Ransomwhere", "ok", a.id, adressen_in_liste=len(self._rw))

    def _aus_listen(self, adresse: str) -> list[dict]:
        ergebnis = []
        for e in (self._ofac or {}).get(_schluessel(adresse), []):
            ergebnis.append(etikett("OFAC", "sanktion", e["name"],
                                    f"SDN-Liste, Programm {e['programm']}, Eintrag {e['nr']}, geführt als {e['waehrung']}",
                                    beleg=self._ofac_beleg))
        z = (self._rw or {}).get(_schluessel(adresse))
        if z:
            zahlungen = z.get("transactions") or []
            ergebnis.append(etikett("Ransomwhere", "ransomware", str(z.get("family") or "Ransomware"),
                                    f"{len(zahlungen)} erfasste Zahlung(en), im Datensatz seit {str(z.get('createdAt') or '')[:10]}",
                                    beleg=self._rw_beleg))
        return ergebnis

    # ----- Sammelabfragen

    async def _trm(self, adressen: list[str]) -> dict[str, list[dict]]:
        ergebnis: dict[str, list[dict]] = {}
        teile: list[list[str]] = [[]]
        for x in adressen:
            if teile[-1] and len(json.dumps([{"address": y} for y in teile[-1] + [x]])) > TRM_KOERPER:
                teile.append([])
            teile[-1].append(x)
        for teil in teile if adressen else []:
            a = await self.v.hole("TRM Labs", f"{len(teil)} Adresse(n)", "wallet", "https://api.trmlabs.com/public/v1/sanctions/screening",
                                  schritt="Sanktionsprüfung", methode="POST", json_koerper=[{"address": x} for x in teil])
            if a.ergebnis != "ok" or not isinstance(a.daten, list):
                self._melden("TRM Labs", "fehler", a.id, a.fehler or "Antwort nicht lesbar")
                continue
            self._melden("TRM Labs", "ok", a.id)
            for z in a.daten:
                if isinstance(z, dict) and z.get("isSanctioned") is True and z.get("address"):
                    ergebnis.setdefault(_schluessel(str(z["address"])), []).append(
                        etikett("TRM Labs", "sanktion", "Sanktioniert", "laut Sanktionsprüfung von TRM Labs", beleg=a.id))
        return ergebnis

    async def _blockscout(self, kette: Kette, adressen: list[str]) -> dict[str, list[dict]]:
        ergebnis: dict[str, list[dict]] = {}
        for i in range(0, len(adressen), 20):
            teil = adressen[i:i + 20]
            a = await self.v.hole("Blockscout", f"{len(teil)} Adresse(n)", "wallet", "https://metadata.services.blockscout.com/api/v1/metadata",
                                  schritt="Etiketten der Adressen", params={"addresses": ",".join(teil), "chainId": kette.chain_id, "tagsLimit": 20})
            daten = (a.daten or {}).get("addresses") if isinstance(a.daten, dict) else None
            if a.ergebnis == "fehler" or (a.ergebnis == "ok" and not isinstance(daten, dict)):
                self._melden("Blockscout (Etiketten)", "fehler", a.id, a.fehler or "Antwort nicht lesbar")
                continue
            self._melden("Blockscout (Etiketten)", "ok", a.id)
            for adresse, inhalt in (daten or {}).items():
                marken = blockscout_etiketten((inhalt or {}).get("tags") or [], a.id)
                if marken:
                    ergebnis[_schluessel(adresse)] = marken
        return ergebnis

    # ----- Einzelabfragen

    async def _walletexplorer(self, adresse: str) -> list[dict]:
        a = await self.v.hole("WalletExplorer", adresse, "wallet", "https://www.walletexplorer.com/api/1/address-lookup",
                              schritt="Gehört die Adresse zu einem benannten Dienst?", params={"address": adresse, "caller": "osint-gateway"})
        if a.ergebnis != "ok" or not isinstance(a.daten, dict):
            self._melden("WalletExplorer", "fehler", a.id, a.fehler or "Antwort nicht lesbar")
            return []
        self._melden("WalletExplorer", "ok", a.id)
        if a.daten.get("wallet_id"):
            self.cluster[adresse] = str(a.daten["wallet_id"])
        if a.daten.get("label"):
            return [etikett("WalletExplorer", "name", str(a.daten["label"]),
                            f"Wallet-Kennung {a.daten.get('wallet_id')}: Zuordnung über gemeinsam ausgegebene Adressen", dienst=True,
                            mischer=bool(_MISCH_NAME.search(str(a.daten["label"]))), beleg=a.id)]
        return []

    async def _tether(self, adresse: str) -> list[dict]:
        try:
            a, gesperrt = await tron_gesperrt(self.v, adresse)
        except Quellfehler as e:
            self._melden("Tether (Sperrliste)", "fehler", e.antwort.id, e.antwort.fehler or "")
            return []
        if gesperrt is None:
            self._melden("Tether (Sperrliste)", "fehler", a.id, a.fehler or "Antwort nicht lesbar")
            return []
        self._melden("Tether (Sperrliste)", "ok", a.id)
        return [etikett("Tether", "gesperrt", "Von Tether gesperrt", "USDT auf dieser Adresse ist eingefroren (Sperrliste im USDT-Vertrag)",
                        beleg=a.id)] if gesperrt else []

    async def _tronscan(self, adresse: str) -> list[dict]:
        key = einstellung("TRONSCAN_API_KEY")
        if not key:
            self._melden("Tronscan", "aus", hinweis="TRONSCAN_API_KEY fehlt. Ohne ihn gibt es für TRON keine Namen von Börsen und Diensten.")
            return []
        kopf, ergebnis = {"TRON-PRO-API-KEY": key}, []
        a = await self.v.hole("Tronscan", adresse, "wallet", "https://apilist.tronscanapi.com/api/accountv2", schritt="Etikett der Adresse",
                              params={"address": adresse}, kopf=kopf)
        if a.ergebnis != "ok" or not isinstance(a.daten, dict):
            self._melden("Tronscan", "fehler", a.id, a.fehler or "Antwort nicht lesbar")
            return []
        self._melden("Tronscan", "ok", a.id)
        d = a.daten
        for feld in ("addressTag", "publicTag", "blueTag"):
            name = str(d.get(feld) or "").strip()
            if name and name != adresse and not any(e["name"] == saeubern(name, 90) for e in ergebnis):
                ergebnis.append(etikett("Tronscan", "name", name, dienst=True, mischer=bool(_MISCH_NAME.search(name)), beleg=a.id))
        if str(d.get("redTag") or "").strip():
            ergebnis.append(etikett("Tronscan", "meldung", str(d["redTag"]), "Warnhinweis von Tronscan", beleg=a.id))
        if str(d.get("greyTag") or "").strip():
            ergebnis.append(etikett("Tronscan", "hinweis", str(d["greyTag"]), beleg=a.id))
        b = await self.v.hole("Tronscan", adresse, "wallet", "https://apilist.tronscanapi.com/api/security/account/data",
                              schritt="Risikohinweise zur Adresse", params={"address": adresse}, kopf=kopf)
        if b.ergebnis == "ok" and isinstance(b.daten, dict):
            for feld, text in (("is_black_list", "Auf der Sperrliste eines Stablecoin-Emittenten"),
                               ("has_fraud_transaction", "Betrugsverdächtige Transaktionen gemeldet"),
                               ("fraud_token_creator", "Hat betrügerische Token erstellt"),
                               ("send_ad_by_memo", "Verschickt Werbung über Transaktionsvermerke")):
                if b.daten.get(feld) is True:
                    ergebnis.append(etikett("Tronscan", "gesperrt" if feld == "is_black_list" else "meldung", text, beleg=b.id))
        return ergebnis

    async def _chainabuse(self, adresse: str) -> list[dict]:
        key = einstellung("CHAINABUSE_API_KEY")
        if not key:
            self._melden("Chainabuse", "aus", hinweis="CHAINABUSE_API_KEY fehlt.")
            return []
        kopf = {"Authorization": "Basic " + base64.b64encode(f"{key}:{key}".encode()).decode()}
        a = await self.v.hole("Chainabuse", adresse, "wallet", "https://api.chainabuse.com/v0/reports", schritt="Betrugsmeldungen zur Adresse",
                              params={"address": adresse, "perPage": 50}, kopf=kopf)
        meldungen = (a.daten or {}).get("reports") if isinstance(a.daten, dict) else None
        if a.ergebnis != "ok" or not isinstance(meldungen, list):
            self._melden("Chainabuse", "fehler", a.id, a.fehler or "Antwort nicht lesbar")
            return []
        self._melden("Chainabuse", "ok", a.id)
        if not meldungen:
            return []
        arten = Counter(str(m.get("scamCategory") or "ohne Angabe") for m in meldungen if isinstance(m, dict))
        daten = sorted(str(m.get("createdAt") or "")[:10] for m in meldungen if isinstance(m, dict) and m.get("createdAt"))
        gesamt = (a.daten or {}).get("count") or len(meldungen)
        geprueft = sum(1 for m in meldungen if isinstance(m, dict) and (m.get("checked") or m.get("trusted")))
        detail = (", ".join(f"{n}× {art}" for art, n in arten.most_common(5))
                  + (f"; erste {daten[0]}, letzte {daten[-1]}" if daten else "")
                  + f"; {geprueft} davon von Chainabuse geprüft oder von anerkannten Meldern")
        return [etikett("Chainabuse", "meldung", f"{gesamt} Betrugsmeldung(en)", detail, beleg=a.id)]

    async def _iknaio(self, kette: Kette, adresse: str) -> list[dict]:
        key = einstellung("IKNAIO_API_KEY")
        kuerzel = {"bitcoin": "btc", "ethereum": "eth", "tron": "trx"}.get(kette.name)
        if not key or not kuerzel:
            if not key:
                self._melden("Iknaio", "aus", hinweis="IKNAIO_API_KEY fehlt.")
            return []
        kopf, ergebnis = {"Authorization": key}, []
        a = await self.v.hole("Iknaio", adresse, "wallet", f"https://api.ikna.io/{kuerzel}/addresses/{adresse}/tag_summary",
                              schritt="Etiketten der Adresse und ihres Clusters", params={"include_best_cluster_tag": "true"}, kopf=kopf)
        if a.ergebnis == "fehler" or (a.ergebnis == "ok" and not isinstance(a.daten, dict)):
            self._melden("Iknaio", "fehler", a.id, a.fehler or "Antwort nicht lesbar")
            return []
        self._melden("Iknaio", "ok", a.id)
        d = a.daten if isinstance(a.daten, dict) else {}
        name = str(d.get("best_label") or d.get("best_actor") or "").strip()
        kategorie = str(d.get("broad_category") or "").strip()
        if name:
            ergebnis.append(etikett("Iknaio", "name", name, f"Kategorie {kategorie or 'ohne Angabe'}, {d.get('tag_count') or 0} Etikett(en)",
                                    dienst=kategorie.lower() in _IKNAIO_DIENST, mischer=kategorie.lower() in _IKNAIO_MISCHER, beleg=a.id))
        elif kategorie and kategorie.lower() not in ("user", "unknown"):
            ergebnis.append(etikett("Iknaio", "kategorie", kategorie, dienst=kategorie.lower() in _IKNAIO_DIENST,
                                    mischer=kategorie.lower() in _IKNAIO_MISCHER, beleg=a.id))
        if kette.familie == "bitcoin":
            b = await self.v.hole("Iknaio", adresse, "wallet", f"https://api.ikna.io/{kuerzel}/addresses/{adresse}/entity",
                                  schritt="Cluster der Adresse", kopf=kopf)
            if b.ergebnis == "ok" and isinstance(b.daten, dict) and b.daten.get("no_addresses"):
                ergebnis.append(etikett("Iknaio", "hinweis", "Cluster",
                                        f"gehört zu einer Gruppe von {b.daten['no_addresses']} Adressen, die gemeinsam ausgegeben wurden", beleg=b.id))
        return ergebnis

    # ----- Abfrage

    def _dazu(self, kette: Kette, adresse: str, marken: list[dict]) -> None:
        vorhanden = self._marken.setdefault((kette.name, adresse), [])
        for m in marken:
            if not any(x["quelle"] == m["quelle"] and x["name"] == m["name"] and x["art"] == m["art"] for x in vorhanden):
                vorhanden.append(m)

    async def pruefen(self, kette: Kette, adressen: list[str], *, tief: bool = False, meldungen: bool = False) -> dict[str, list[dict]]:
        """Etiketten zu Adressen einer Kette. ``tief`` fragt zusätzlich die Quellen, die je Adresse eine eigene
        Abfrage brauchen (WalletExplorer, Tether-Sperrliste, Tronscan, Iknaio). ``meldungen``: auch Chainabuse."""
        adressen = list(dict.fromkeys(a for a in adressen if a))
        offen = [a for a in adressen if (kette.name, a) not in self._flach]
        if offen:
            await self._ofac_laden()
            if kette.familie == "bitcoin":
                await self._ransomwhere_laden()
            trm = await self._trm(offen) if self._an("trm") else {}
            marken = await self._blockscout(kette, offen) if kette.familie == "evm" and self._an("blockscout") else {}
            for a in offen:
                self._dazu(kette, a, self._aus_listen(a) + trm.get(_schluessel(a), []) + marken.get(_schluessel(a), []))
                self._flach.add((kette.name, a))
        for a in adressen if tief else []:
            if (kette.name, a) in self._tief:
                continue
            self._tief.add((kette.name, a))
            if kette.familie == "bitcoin" and self._an("walletexplorer"):
                self._dazu(kette, a, await self._walletexplorer(a))
            if kette.familie == "tron" and self._an("tether"):
                self._dazu(kette, a, await self._tether(a))
            if kette.familie == "tron" and self._an("tronscan"):
                self._dazu(kette, a, await self._tronscan(a))
            if self._an("iknaio"):
                self._dazu(kette, a, await self._iknaio(kette, a))
        for a in adressen if meldungen and self._an("chainabuse") else []:
            self._dazu(kette, a, await self._chainabuse(a))
        return {a: list(self._marken.get((kette.name, a), [])) for a in adressen}

    def merken(self, kette: Kette, adresse: str, marken: list[dict]) -> None:
        """Etiketten, die schon mit einer anderen Antwort kamen (Blockscout hängt sie an Transaktionen)."""
        if marken:
            self._dazu(kette, adresse, marken)

    def bekannt(self, kette: Kette, adresse: str) -> list[dict]:
        return list(self._marken.get((kette.name, adresse), []))

    def tief_geprueft(self, kette: Kette, adresse: str) -> bool:
        return (kette.name, adresse) in self._tief

    def quellen_mit_treffer(self) -> set[str]:
        return {e["quelle"] for liste in self._marken.values() for e in liste}


def mischer(marken: list[dict]) -> str | None:
    """Name des Mischdienstes, wenn ein Etikett die Adresse einem zuordnet. Sonst None."""
    namen = [m["name"] for m in marken if m.get("mischer")]
    return (next((m["name"] for m in marken if m.get("mischer") and m["art"] == "name"), None) or namen[0]) if namen else None


def dienst(marken: list[dict]) -> str | None:
    """Name des Dienstes mit Kunden (Börse, Zahlungsdienst), wenn die Etiketten die Adresse einem zuordnen. Sonst None."""
    if mischer(marken):
        return None
    namen = [m.get("betreiber") or m["name"] for m in marken if m.get("dienst") and m["art"] == "name"]
    if namen:
        return namen[0]
    arten = [m["name"] for m in marken if m.get("dienst")]
    return arten[0] if arten else None


def kurz(marken: list[dict]) -> list[str]:
    """Etiketten als kurze Texte für Listen und Diagramme: «Binance: Hot Wallet (Blockscout)»."""
    texte = []
    for m in marken:
        if m["art"] == "hinweis" and m["name"] == "Hinweis":
            continue
        t = f"{m['name']} ({m['quelle']})"
        if t not in texte:
            texte.append(t)
    return texte


def quellen_pruefen(namen: list[str] | None) -> set[str] | None:
    if not namen:
        return None
    gewaehlt = {n.strip().lower() for n in namen if n and n.strip()}
    fremd = gewaehlt - set(QUELLEN)
    if fremd:
        raise Abbruch(f"Unbekannte Quelle(n): {', '.join(sorted(fremd))}. Möglich: {', '.join(QUELLEN)}.")
    return gewaehlt


__all__ = ["Zuordner", "blockscout_etiketten", "dienst", "etikett", "kurz", "ofac_lesen", "quellen_pruefen", "KETTEN", "gleich"]
