#!/usr/bin/env python3
"""Die lokale Etikettenliste für Krypto-Adressen (GraphSense TagPacks): Stand zeigen, prüfen, Massenlisten laden, neuen Stand bauen.

    python3 tools/listen.py stand        welcher Stand gilt, was ist geladen
    python3 tools/listen.py pruefen      Tabellen gegen die Prüfsummen im Verzeichnis prüfen
    python3 tools/listen.py laden        die elf Massenlisten einmal holen (rund 24 MB), prüfen und ablegen
    python3 tools/listen.py holen --stand <Commit> --nach <Ordner>                         alle Dateien eines Standes holen
    python3 tools/listen.py bauen --stand <Commit> --datum JJJJ-MM-TT --aus <Ordner>       Tabellen und Verzeichnis neu bauen

Der Kern der Liste liegt im Repo und braucht keinen Schritt. «laden» holt die Dateien, die für das Repo zu gross sind,
einzeln von raw.githubusercontent.com: genau den Stand, den das Verzeichnis nennt, jede Datei gegen ihre Prüfsumme
geprüft. Dabei geht keine Adresse und nichts aus einem Fall hinaus. GitHub sieht nur, dass dieser Rechner die
öffentlichen TagPacks abruft. Der Schritt läuft am Terminal, nicht aus einer Ermittlung heraus.

«holen» und «bauen» sind Schritte des Entwicklers für einen neuen Stand. «bauen» braucht das Paket PyYAML (nur dafür,
das Gateway selbst braucht es nicht), liest jede Datei, wendet die Auslassungen an, schreibt die Tabellen und das
Verzeichnis ``gateway/listen/tagpacks.json``. Der neue Stand kommt als Änderung per Pull Request ins Repo.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway import krypto_listen as kl  # noqa: E402

REPO = "graphsense/graphsense-tagpacks"
ROH = "https://raw.githubusercontent.com/{repo}/{commit}/packs/{name}.yaml"

# Alle Dateien unter packs/ im Stand 83754852 vom 5.11.2026. Ein neuer Stand kann Dateien hinzufügen: dann hier nachtragen.
NAMEN = """Alt-Right BITB_etf africrypt-hack aft-alqaeda-forfeit_vc aidecisions_ofac binance binance_hack bitzillions_ltc blender_io chaininfo
coinjoin_bounty defi-fraud-masterthesis defi-protocols-csh demo electrum_phishing eosio-gambling_part1 eosio-gambling_part2 eosio-gambling_part3
eosio-gambling_part4 eosio-gambling_part5 eosio-gambling_part6 eosio-gambling_part7 eosio-gambling_part8 eosio-gambling_part9 etherhiding
etherscamdb_tagpack etherscan-label-word-cloud etherscan-wordcloud-exchange etherscan-wordcloud-gambling etherscan-wordcloud-market
etherscan-wordcloud-miner etherscan-wordcloud-mixing_service exchange-wallets-binance exchange-wallets-bitfinexcom exchange-wallets-bitmex_0
exchange-wallets-bitmex_1 exchange-wallets-bitmex_2 exchange-wallets-bitmex_3 exchange-wallets-bitmex_4 exchange-wallets-bitmex_5
exchange-wallets-bitmex_6 exchange-wallets-bybit exchange-wallets-cryptocom exchange-wallets-deribit exchange-wallets-huobi exchange-wallets-kucoin
exchange-wallets-okx exchange-wallets-swissborg forsage hacks hydra interpol-real_services lazarus lazarus2 lockbit_tattoos miners miners_additional
mixing_fc2021 ofac plustoken ponzi_scheme protonmail ransomware ransomwhere richest_addresses ronin_bridge samourai satoshidice_bch
service-wallets-checksig sextortion_excello sextortion_talos sinbad_io suidlanders tornado_cash twitter_hack_scam usdt_blacklist walletexplorer
wasabi_collector defi_updated/defi-protocols_1inch defi_updated/defi-protocols_aave defi_updated/defi-protocols_compound
defi_updated/defi-protocols_curve defi_updated/defi-protocols_instadapp defi_updated/defi-protocols_sushiswap defi_updated/defi-protocols_synthetix
defi_updated/defi-protocols_uniswap defi_updated/defi-protocols_uniswap_pools""".split()

_PERSONEN = "Nennt natürliche Personen. Die Sanktionsliste (OFAC) lädt das Gateway selbst, tagesaktuell."
_ETHERSCAN = "Abgeleitet aus den Etiketten von Etherscan. Dessen Nutzungsbedingungen untersagen die Wiedergabe."
AUSGELASSEN = {
    "aidecisions_ofac": _PERSONEN, "ofac": _PERSONEN,
    "Alt-Right": "Spendenadressen, die Personen und politischen Gruppen zugeschrieben werden. Personenbezug ohne Nutzen für die Verfolgung von Geld.",
    "suidlanders": "Politische Zuschreibung an eine Gruppe, ohne Nutzen für die Verfolgung von Geld.",
    "lockbit_tattoos": "Adressen von Privatpersonen (Kategorie «user»).",
    "demo": "Beispieldatei des Projekts ohne echte Angaben.",
    **{f"etherscan-{n}": _ETHERSCAN for n in ("label-word-cloud", "wordcloud-exchange", "wordcloud-gambling", "wordcloud-market", "wordcloud-miner",
                                              "wordcloud-mixing_service")},
}
MASSE = (*[f"exchange-wallets-bitmex_{n}" for n in range(7)], "sextortion_talos", "sextortion_excello", "miners", "samourai")
MASSE_INHALT = "Reserve-Adressen der Börse BitMEX, Adressen aus Erpresser-Spam, Mining-Adressen, CoinJoin-Adressen von Samourai"


def _datei(ordner: Path, name: str) -> Path:
    return ordner / (name.replace("/", "__") + ".yaml")


def holen(commit: str, namen: list[str], ordner: Path, soll: dict[str, dict] | None = None) -> None:
    """Holt Dateien eines Standes einzeln. ``soll``: erwartete Prüfsummen. Weicht eine ab, wird abgebrochen."""
    ordner.mkdir(parents=True, exist_ok=True)
    for nr, name in enumerate(namen, 1):
        ziel = _datei(ordner, name)
        erwartet = (soll or {}).get(name, {}).get("sha256")
        if ziel.is_file() and (not erwartet or hashlib.sha256(ziel.read_bytes()).hexdigest() == erwartet):
            continue
        url = ROH.format(repo=REPO, commit=commit, name=name)
        try:
            with urllib.request.urlopen(url, timeout=180) as r:       # noqa: S310 (feste Adresse, kein Wert aus einem Fall)
                inhalt = r.read()
        except urllib.error.HTTPError as e:
            if e.code in (403, 407):
                raise SystemExit(f"FEHLER: raw.githubusercontent.com ist von hier aus nicht erreichbar (HTTP {e.code}). Nicht wiederholen: "
                                 "Netzwerkfreigabe für diesen Host klären.") from e
            raise SystemExit(f"FEHLER: {name}.yaml liess sich nicht holen (HTTP {e.code}).") from e
        except (urllib.error.URLError, OSError) as e:
            raise SystemExit(f"FEHLER: {name}.yaml liess sich nicht holen ({type(e).__name__}: {e}).") from e
        if erwartet and hashlib.sha256(inhalt).hexdigest() != erwartet:
            raise SystemExit(f"FEHLER: {name}.yaml passt nicht zur Prüfsumme im Verzeichnis. Nichts übernommen.")
        ziel.write_bytes(inhalt)
        print(f"  {nr:>3}/{len(namen)}  {name}.yaml  ({len(inhalt) // 1024} KB)", flush=True)
        time.sleep(0.2)


def stand() -> int:
    v = kl.verzeichnis()
    gross = kl.ablage() / kl.GROSS_NAME
    print(f"Etikettenliste {kl.QUELLE}\n  Stand        Commit {v['commit']} vom {v['datum']} ({v['lizenz']})")
    print(f"  Kern         {v['tabelle']['eintraege']} Einträge aus {len(v['packs'])} Dateien, im Repo ({kl.KERN.stat().st_size // 1024} KB)")
    print(f"  Massenlisten {v['massenlisten']['tabelle']['eintraege']} Einträge aus {len(v['massenlisten']['dateien'])} Dateien: "
          + (f"geladen ({gross})" if gross.is_file() else "nicht geladen. Nachholen: python3 tools/listen.py laden"))
    print(f"  Ausgelassen  {len(v['ausgelassen'])} Dateien, Gründe in gateway/listen/tagpacks.json")
    return 0


def pruefen() -> int:
    try:
        liste = kl.Liste()
    except kl.Listenfehler as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 1
    print(f"In Ordnung: {liste.eintraege} Einträge ({liste.umfang}), Stand {liste.stand['stand']} vom {liste.stand['datum']}, "
          f"Prüfsumme {liste.stand['sha256'][:16]}…")
    if liste.hinweis:
        print(f"Hinweis: {liste.hinweis}")
    return 0


def laden() -> int:
    v = kl.verzeichnis()
    m = v["massenlisten"]
    ziel = kl.ablage()
    roh = ziel / "roh"
    print(f"Hole {len(m['dateien'])} Dateien des Standes {v['commit'][:12]} nach {roh}")
    holen(v["commit"], list(m["dateien"]), roh, m["dateien"])
    zeilen: list[tuple] = []
    for name in m["dateien"]:
        zeilen += kl.zeilen_aus_pack(name, kl.flach_lesen(_datei(roh, name).read_text(encoding="utf-8")))[0]
    inhalt = kl.tabelle_bytes(zeilen)
    if hashlib.sha256(inhalt).hexdigest() != m["tabelle"]["sha256"]:
        print("FEHLER: Die gebaute Tabelle passt nicht zur Prüfsumme im Verzeichnis. Nichts abgelegt.", file=sys.stderr)
        return 1
    (ziel / kl.GROSS_NAME).write_bytes(inhalt)
    for datei in roh.glob("*.yaml"):
        datei.unlink()
    roh.rmdir()
    print(f"Abgelegt: {ziel / kl.GROSS_NAME} ({len(inhalt) // 1024} KB, {m['tabelle']['eintraege']} Einträge). Das Gateway nimmt sie beim nächsten Aufruf dazu.")
    return 0


def bauen(commit: str, datum: str, ordner: Path) -> int:
    try:
        import yaml
    except ModuleNotFoundError:
        print("FEHLER: «bauen» braucht das Paket PyYAML (pip install pyyaml). Nur dieser Schritt braucht es.", file=sys.stderr)
        return 2
    packs, ausgelassen, masse, kern, gross = {}, {}, {}, [], []
    for name in NAMEN:
        datei = _datei(ordner, name)
        if not datei.is_file():
            print(f"FEHLER: {datei} fehlt. Zuerst: python3 tools/listen.py holen --stand {commit} --nach {ordner}", file=sys.stderr)
            return 2
        roh = datei.read_bytes()
        angaben = {"sha256": hashlib.sha256(roh).hexdigest(), "bytes": len(roh)}
        kurz = name.split("/")[-1]
        if kurz in AUSGELASSEN:
            ausgelassen[name] = {**angaben, "grund": AUSGELASSEN[kurz]}
            continue
        daten = yaml.safe_load(roh.decode("utf-8"))
        zeilen, anzahl = kl.zeilen_aus_pack(name, daten)
        kopf = {k: " ".join(str(daten[k]).split())[:200] for k in ("title", "creator", "source", "lastmod") if daten.get(k)}
        if kurz in MASSE:
            if kl.zeilen_aus_pack(name, kl.flach_lesen(roh.decode("utf-8")))[0] != zeilen:
                print(f"FEHLER: Der einfache Leser liest {name}.yaml anders als PyYAML. Die Datei taugt nicht als Massenliste.", file=sys.stderr)
                return 1
            masse[name] = {**angaben, **kopf, "eintraege": anzahl, "uebernommen": len(zeilen)}
            gross += zeilen
        elif not zeilen:
            ausgelassen[name] = {**angaben, "grund": "Enthält keine Adresse einer Kette, die das Gateway verfolgt (Bitcoin, Ethereum, TRON)."}
        else:
            packs[name] = {**angaben, **kopf, "eintraege": anzahl, "uebernommen": len(zeilen)}
            kern += zeilen
    kl.ORDNER.mkdir(exist_ok=True)
    tabelle, tabelle_gross = kl.tabelle_bytes(kern), kl.tabelle_bytes(gross)
    kl.KERN.write_bytes(tabelle)
    verzeichnis = {
        "quelle": kl.QUELLE, "repo": f"https://github.com/{REPO}", "commit": commit, "datum": datum,
        "lizenz": "MIT (Copyright 2022 Iknaio Cryptoasset Analytics GmbH, 2018-2022 AIT Austrian Institute of Technology)",
        "hinweis": "Etiketten sind Angaben Dritter, kein Beweis. Sie geben den Stand ihres Datums wieder.",
        "tabelle": {"datei": kl.KERN.name, "sha256": hashlib.sha256(tabelle).hexdigest(), "bytes": len(tabelle), "eintraege": len(set(kern))},
        "packs": packs,
        "massenlisten": {"inhalt": MASSE_INHALT, "dateien": masse,
                         "tabelle": {"datei": kl.GROSS_NAME, "sha256": hashlib.sha256(tabelle_gross).hexdigest(), "bytes": len(tabelle_gross),
                                     "eintraege": len(set(gross))}},
        "ausgelassen": ausgelassen}
    plattform.text_schreiben(kl.VERZEICHNIS, json.dumps(verzeichnis, ensure_ascii=False, indent=1) + "\n")
    print(f"Kern: {len(set(kern))} Einträge aus {len(packs)} Dateien, {len(tabelle) // 1024} KB. Massenlisten: {len(set(gross))} Einträge aus {len(masse)} "
          f"Dateien, {len(tabelle_gross) // 1024} KB (nicht im Repo). Ausgelassen: {len(ausgelassen)} Dateien.")
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="befehl", required=True)
    for name in ("stand", "pruefen", "laden"):
        sub.add_parser(name)
    h = sub.add_parser("holen")
    h.add_argument("--stand", required=True)
    h.add_argument("--nach", required=True)
    b = sub.add_parser("bauen")
    b.add_argument("--stand", required=True)
    b.add_argument("--datum", required=True)
    b.add_argument("--aus", required=True)
    a = p.parse_args(argv)
    try:
        if a.befehl == "stand":
            return stand()
        if a.befehl == "pruefen":
            return pruefen()
        if a.befehl == "laden":
            return laden()
        if a.befehl == "holen":
            holen(a.stand, NAMEN, Path(a.nach).expanduser())
            return 0
        return bauen(a.stand, a.datum, Path(a.aus).expanduser())
    except kl.Listenfehler as e:
        print(f"FEHLER: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
