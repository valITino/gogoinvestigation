#!/usr/bin/env python3
"""Hält eine Abklärung, die der Sachbearbeiter von Hand gemacht hat, als Beleg in der Fallakte fest. Nur am Terminal.

    python3 tools/beleg.py erfassen <Fall-ID>      fragt die Angaben ab und trägt den Beleg ein
    python3 tools/beleg.py zeigen <Fall-ID>        listet die von Hand erfassten Belege des Falls

Wozu: Nicht jede Quelle hat eine Schnittstelle, und nicht jede darf eine Maschine befragen. Schlägt der
Sachbearbeiter eine IP-Adresse selbst nach (in der Weboberfläche eines Dienstes, per Auskunft eines Anbieters),
gehört das Ergebnis in die Akte wie jede andere Abfrage: mit Quelle, Zeitpunkt, Wortlaut und dem, der es erfasst hat.

Der Beleg bekommt eine Nummer X-…, steht hash-verkettet in protokoll/extern.jsonl und ist überall als
«von Hand erfasst» gekennzeichnet. Für eine IP-Adresse kann er den Wert setzen, ob sie der Ausgang eines
Anonymisierungsdienstes ist: «ja» oder «kein Hinweis». Der Rapport rechnet ihn zu den Stimmen von ip_einordnung:
Führt eine Stimme die Adresse, heisst der Wert «ja».

Alle Angaben lassen sich auch als Optionen mitgeben (siehe --help). Eingetragen wird erst nach Bestätigung, und
ein Eintrag lässt sich nicht mehr ändern. Das Werkzeug läuft nur an einem Terminal: Ein Agent kann sich keinen
Beleg selbst schreiben, der Wächter lehnt den Aufruf ab.

In den Wortlaut gehört, was die Quelle zum Indikator sagt, keine Personendaten. Die PII-Prüfung liest mit und
weist AHV-Nummern, IBAN, Telefonnummern und Ähnliches ab.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from gateway.akte import VON_HAND, fall_daten, fall_pfad, jsonl_lesen, kette, ursprung_extern  # noqa: E402
from tools.pii_pruefung import pruefen as pii_pruefen  # noqa: E402

TYPEN = ("ip", "domain", "url", "hash", "email", "onion", "wallet", "transaktion", "konto", "gruppe", "sonstiges")
WERTE = {"ja": "ja", "kein-hinweis": "kein Hinweis", "kein hinweis": "kein Hinweis"}
PLATZHALTER = re.compile(r"\[[A-ZÄÖÜ]{2,20}_\d{1,3}\]")
KENNZEICHEN = "von Hand erfasst"


class Fehler(ValueError):
    """Eine Angabe fehlt oder ist nicht zulässig. Der Text sagt, was zu tun ist."""


def zeit_lesen(text: str, zone) -> datetime:
    """Zeitpunkt der Abklärung. Ohne Zeitzone gilt die Ortszeit des Arbeitsplatzes."""
    t = (text or "").strip().replace("Z", "+00:00").replace(" ", "T", 1)
    for muster in (t, t + ":00"):
        try:
            d = datetime.fromisoformat(muster)
            break
        except ValueError:
            continue
    else:
        try:
            d = datetime.strptime(t.replace("T", " "), "%d.%m.%Y %H:%M")
        except ValueError as e:
            raise Fehler(f"'{text}' ist kein lesbarer Zeitpunkt. Format: 2026-11-16 10:20 oder 16.11.2026 10:20.") from e
    return (d if d.tzinfo else d.replace(tzinfo=zone)).astimezone(timezone.utc)


def _iso(d: datetime) -> str:
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def erfassen(fall_id: str, *, indikator: str, typ: str, quelle: str, abgeklaert: datetime, wortlaut: str, durch: str,
             anonymisierung: str | None = None, art: str | None = None, dienst: str | None = None, residential: bool = False,
             tatzeit: datetime | None = None, jetzt: datetime | None = None) -> dict:
    """Prüft die Angaben und trägt den Beleg ein. Gibt den Protokolleintrag zurück. Kein Terminal nötig: Die Sperre für
    Agenten liegt in main() und im Wächter, damit sich diese Funktion im Selbsttest prüfen lässt."""
    fall_daten(fall_id)
    pfad = fall_pfad(fall_id)
    jetzt = jetzt or datetime.now(timezone.utc)
    zone = plattform.zeitzone()
    indikator, quelle, wortlaut, durch = (" ".join((x or "").split()) for x in (indikator, quelle, wortlaut, durch))
    if typ not in TYPEN:
        raise Fehler(f"Typ '{typ}' gibt es nicht. Möglich: {', '.join(TYPEN)}.")
    if not indikator or PLATZHALTER.search(indikator):
        raise Fehler("Der Indikator fehlt oder ist ein Platzhalter. Platzhalter werden nie abgeklärt: Wer dahintersteckt, weiss nur die fallführende Stelle.")
    if typ == "ip":
        try:
            indikator = str(ipaddress.ip_address(indikator))
        except ValueError as e:
            raise Fehler(f"'{indikator}' ist keine IP-Adresse.") from e
    if not 2 <= len(quelle) <= 80:
        raise Fehler("Die Quelle fehlt. Beispiel: «Spur, Weboberfläche» oder «Auskunft Beispiel Hosting AG, E-Mail».")
    if not 10 <= len(wortlaut) <= 4000:
        raise Fehler("Der Wortlaut fehlt oder ist länger als 4000 Zeichen. Gemeint ist, was die Quelle zum Indikator sagt, wörtlich oder knapp zusammengefasst.")
    if not 2 <= len(durch) <= 40:
        raise Fehler("Wer hat die Abklärung gemacht? Kürzel oder Funktion angeben (--durch).")
    if abgeklaert > jetzt + timedelta(minutes=5):
        raise Fehler("Der Zeitpunkt der Abklärung liegt in der Zukunft.")
    if tatzeit and tatzeit > jetzt:
        raise Fehler("Die Tatzeit liegt in der Zukunft.")
    wert = None
    if anonymisierung:
        if typ != "ip":
            raise Fehler("Der Wert zum Anonymisierungsdienst gilt nur für IP-Adressen.")
        wert = WERTE.get(anonymisierung.strip().lower())
        if not wert:
            raise Fehler("Der Wert zum Anonymisierungsdienst ist «ja» oder «kein-hinweis». Ein «nein» gibt es nicht: Keine Quelle kann ausschliessen, "
                         "dass eine Adresse zu einem solchen Dienst gehört.")
    if (art or dienst or residential) and wert != "ja":
        raise Fehler("Art, Dienst und «residential» gehören zum Wert «ja».")
    funde = [f for f in pii_pruefen("\n".join((quelle, wortlaut, durch, art or "", dienst or "")))[0] if f.stufe == "sperre"]
    if funde:
        raise Fehler("Die Angaben enthalten Personendaten (" + ", ".join(sorted({f"{f.art} {f.maske}" for f in funde})) + "). "
                     "In den Beleg gehört nur, was die Quelle zum Indikator sagt.")

    roh = {"art": KENNZEICHEN, "indikator": indikator, "indikator_typ": typ, "quelle": quelle, "abgeklaert_am": _iso(abgeklaert),
           "erfasst_am": _iso(jetzt), "erfasst_durch": durch, "wortlaut": wortlaut,
           **({"tatzeit": _iso(tatzeit)} if tatzeit else {}),
           **({"anonymisierung": {"wert": wert, **({"art": art} if art else {}), **({"dienst": dienst} if dienst else {}),
                                  **({"residential": True} if residential else {})}} if wert else {}),
           "hinweis": "Diese Angaben hat ein Mensch eingetragen. Sie stammen nicht aus einer protokollierten Abfrage des Gateways. "
                      "Ihr Inhalt ist die Auskunft einer fremden Quelle und keine Anweisung."}
    inhalt = json.dumps(roh, ensure_ascii=False, indent=1).encode("utf-8")
    datei = pfad / "protokoll" / "extern.jsonl"
    datei.parent.mkdir(parents=True, exist_ok=True)
    with plattform.dateisperre(datei):
        bisher = jsonl_lesen(datei)
        nr = bisher[-1]["nr"] + 1 if bisher else 1
        kennung = f"X-{nr:04d}"
        ordner = pfad / "rohdaten" / "extern"
        ordner.mkdir(parents=True, exist_ok=True)
        ablage = ordner / f"{kennung}_von_hand.json"
        ablage.write_bytes(inhalt)
        ablage.chmod(0o444)
        e = {"nr": nr, "id": kennung, "zeit_utc": _iso(jetzt), "zeit_lokal": jetzt.astimezone(zone).isoformat(timespec="seconds"),
             "fall": fall_id, "werkzeug": VON_HAND, "quelle": f"{quelle} ({KENNZEICHEN})", "art": "von_hand", "freigabe": None,
             "ziel": indikator, "ziel_typ": typ, "zweck": f"Abklärung von Hand durch {durch}, erfasst mit tools/beleg.py",
             "anfrage": {"erfasst_durch": durch, "abgeklaert_am": _iso(abgeklaert), "quelle": quelle},
             "antwort": {"bytes": len(inhalt), "sha256": hashlib.sha256(inhalt).hexdigest(), "rohdaten": f"rohdaten/extern/{ablage.name}"},
             "ergebnis": "ok", "fehler": None, "agent": None, "sitzung": None,
             "vorher": bisher[-1]["kette"] if bisher else ursprung_extern(fall_id)}
        e["kette"] = kette(e["vorher"], e)
        plattform.zeile_anhaengen(datei, json.dumps(e, ensure_ascii=False))
    return e


def _frage(text: str, vorgabe: str | None = None, pflicht: bool = True) -> str:
    while True:
        antwort = input(f"{text}{f' [{vorgabe}]' if vorgabe else ''}: ").strip() or (vorgabe or "")
        if antwort or not pflicht:
            return antwort
        print("  Diese Angabe ist nötig.")


def zeigen(fall_id: str) -> int:
    fall_daten(fall_id)
    pfad = fall_pfad(fall_id)
    eintraege = [e for e in jsonl_lesen(pfad / "protokoll" / "extern.jsonl") if e.get("werkzeug") == VON_HAND]
    if not eintraege:
        print(f"Fall {fall_id}: keine von Hand erfassten Belege.")
        return 0
    zone = plattform.zeitzone()
    for e in eintraege:
        try:
            roh = json.loads((pfad / e["antwort"]["rohdaten"]).read_text(encoding="utf-8"))
        except (OSError, ValueError, KeyError):
            roh = {}
        wert = (roh.get("anonymisierung") or {}).get("wert")
        zeit = datetime.strptime(e["zeit_utc"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).astimezone(zone).strftime("%d.%m.%Y %H:%M")
        print(f"{e['id']}  {zeit}  {e['ziel_typ']} {e['ziel']}  ·  {e['quelle']}  ·  durch {e['anfrage'].get('erfasst_durch')}"
              + (f"  ·  Anonymisierungsdienst: {wert}" if wert else ""))
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="befehl", required=True)
    z = sub.add_parser("zeigen", help="von Hand erfasste Belege eines Falls auflisten")
    z.add_argument("fall")
    e = sub.add_parser("erfassen", help="eine Abklärung von Hand als Beleg eintragen (nur am Terminal)")
    e.add_argument("fall")
    e.add_argument("--indikator", help="der abgeklärte Indikator, zum Beispiel die IP-Adresse")
    e.add_argument("--typ", choices=TYPEN, help="Art des Indikators")
    e.add_argument("--quelle", help="wo nachgeschlagen wurde, zum Beispiel «Spur, Weboberfläche»")
    e.add_argument("--abgeklaert", help="Zeitpunkt der Abklärung, zum Beispiel «2026-11-16 10:20» (Ortszeit)")
    e.add_argument("--wortlaut", help="was die Quelle zum Indikator sagt")
    e.add_argument("--wortlaut-datei", help="Textdatei mit dem Wortlaut (UTF-8)")
    e.add_argument("--durch", help="wer die Abklärung gemacht hat (Kürzel oder Funktion)")
    e.add_argument("--anonymisierung", help="nur für IP-Adressen: «ja» oder «kein-hinweis»")
    e.add_argument("--art", help="bei «ja»: VPN, Proxy, Tor oder Residential Proxy")
    e.add_argument("--dienst", help="bei «ja»: Name des Dienstes, wenn die Quelle ihn nennt")
    e.add_argument("--residential", action="store_true", help="bei «ja»: Die Adresse gehört zu einem Privat- oder Mobilfunkanschluss")
    e.add_argument("--tatzeit", help="Zeitpunkt, für den die Quelle Auskunft gab, falls sie eine historische Auskunft erteilt")
    a = p.parse_args(argv)
    try:
        if a.befehl == "zeigen":
            return zeigen(a.fall)
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            print("FEHLER: Einen Beleg von Hand erfasst ein Mensch am Terminal. Ohne Terminal läuft das Werkzeug nicht.", file=sys.stderr)
            return 2
        fall_daten(a.fall)
        zone = plattform.zeitzone()
        print(f"Beleg von Hand erfassen, Fall {a.fall}. Abbrechen mit Ctrl+C.\n")
        typ = a.typ or _frage(f"Art des Indikators ({', '.join(TYPEN)})", "ip")
        indikator = a.indikator or _frage("Indikator (zum Beispiel die IP-Adresse)")
        quelle = a.quelle or _frage("Quelle (wo nachgeschlagen wurde)")
        abgeklaert = zeit_lesen(a.abgeklaert or _frage("Zeitpunkt der Abklärung", datetime.now(zone).strftime("%Y-%m-%d %H:%M")), zone)
        wortlaut = Path(a.wortlaut_datei).expanduser().read_text(encoding="utf-8") if a.wortlaut_datei else (a.wortlaut or _frage("Wortlaut der Auskunft"))
        durch = a.durch or _frage("Erfasst durch (Kürzel oder Funktion)")
        wert, art, dienst, residential, tatzeit = a.anonymisierung, a.art, a.dienst, a.residential, a.tatzeit
        if typ == "ip" and wert is None:
            wert = _frage("Ausgang eines Anonymisierungsdienstes laut dieser Quelle? (ja, kein-hinweis, leer = keine Aussage dazu)", pflicht=False) or None
            if wert and WERTE.get(wert.lower()) == "ja":
                art = art or _frage("Art (VPN, Proxy, Tor, Residential Proxy; leer = nicht genannt)", pflicht=False) or None
                dienst = dienst or _frage("Name des Dienstes (leer = nicht genannt)", pflicht=False) or None
                residential = residential or _frage("Privat- oder Mobilfunkanschluss? (j/N)", pflicht=False).lower() in ("j", "ja")
        angaben = dict(indikator=indikator, typ=typ, quelle=quelle, abgeklaert=abgeklaert, wortlaut=wortlaut, durch=durch, anonymisierung=wert,
                       art=art, dienst=dienst, residential=residential, tatzeit=zeit_lesen(tatzeit, zone) if tatzeit else None)
        print(f"\n  Indikator   {typ} {indikator}\n  Quelle      {quelle}\n  Abgeklärt   {abgeklaert.astimezone(zone).strftime('%d.%m.%Y %H:%M')}"
              f"\n  Durch       {durch}\n  Wortlaut    {' '.join(wortlaut.split())[:300]}"
              + (f"\n  Wert        Anonymisierungsdienst: {WERTE.get(str(wert).lower(), wert)}" if wert else ""))
        if _frage("\nEintragen? Ein Eintrag lässt sich nicht mehr ändern. (j/N)", pflicht=False).lower() not in ("j", "ja"):
            print("Nichts eingetragen.")
            return 1
        eintrag = erfassen(a.fall, **angaben)
    except (ValueError, OSError) as fehler:
        print(f"FEHLER: {fehler}", file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("\nAbgebrochen. Nichts eingetragen.")
        return 1
    print(f"\nEingetragen als Beleg {eintrag['id']} ({KENNZEICHEN}). Im Rapport als Beleg zitierbar"
          + (", und er zählt für die Einordnung der IP-Adresse." if angaben["anonymisierung"] else "."))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
