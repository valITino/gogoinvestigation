#!/usr/bin/env python3
"""Sicherheitsnetz vor der Aufnahme eines Dokuments: Sucht nach Personendaten, die der
Pseudonymisierung entgangen sind.

Die Prüfung erkennt Muster (AHV-Nummer, IBAN, Telefonnummer, Geburtsdatum, Kontrollschild,
Kreditkarte, E-Mail, Strassenadresse). Namen erkennt sie NICHT. Sie ersetzt die
Pseudonymisierung nicht, sie fängt deren Ausrutscher ab.

Die Ausgabe zeigt Fundstellen nur maskiert, damit sie gefahrlos in einem Agenten-Kontext
landen kann.

    python3 tools/pii_pruefung.py DATEI [DATEI …]
Rückgabewert: 0 sauber, 1 Sperrfunde, 2 Datei nicht lesbar.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

PLATZHALTER = re.compile(r"\[([A-ZÄÖÜ]{2,20})_(\d{1,3})\]")
KANTONE = "AG|AI|AR|BE|BL|BS|FR|GE|GL|GR|JU|LU|NE|NW|OW|SG|SH|SO|SZ|TG|TI|UR|VD|VS|ZG|ZH"


def _iban_gueltig(text: str) -> bool:
    s = re.sub(r"\s", "", text).upper()
    if not 15 <= len(s) <= 34:
        return False
    umgestellt = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in umgestellt)) % 97 == 1
    except ValueError:
        return False


def _luhn(text: str) -> bool:
    nur = re.sub(r"\D", "", text)
    ziffern = [int(c) for c in nur]
    if not 13 <= len(ziffern) <= 19 or len(set(ziffern)) < 3:
        return False
    if re.fullmatch(r"(19|20)\d{12}", nur) or re.fullmatch(r"1\d{12}", nur):
        return False    # Zeitstempel (JJJJMMTThhmmss, Unix-Millisekunden) sind keine Kartennummern
    summe = 0
    for i, z in enumerate(reversed(ziffern)):
        if i % 2:
            z = z * 2 - 9 if z > 4 else z * 2
        summe += z
    return summe % 10 == 0


# (Bezeichnung, Stufe, Muster, optionale Zusatzprüfung)
MUSTER = [
    ("AHV-Nummer", "sperre", re.compile(r"(?<!\d)756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}(?!\d)"), None),
    ("IBAN", "sperre", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b"), _iban_gueltig),
    ("Telefonnummer", "sperre", re.compile(
        r"(?<![\w.:/])(?:\+|00)\d{2}[\s.]?(?:\(0\))?[\s.]?\d{2}(?:[\s.]?\d{2,3}){3}(?!\d)"
        r"|(?<![\w.:/-])0\d{2}[\s.]\d{3}[\s.]\d{2}[\s.]\d{2}(?!\d)"), None),
    ("Geburtsdatum", "sperre", re.compile(
        r"(?i)(?:\bgeb\.?|\bgeboren(?:\s+am)?|\bgeburtsdatum:?|\bjg\.?|\*)\s*\d{1,2}\.\s?\d{1,2}\.\s?(?:19|20)\d{2}\b"), None),
    ("Kontrollschild", "sperre", re.compile(rf"\b(?:{KANTONE})[ ·-]?\d{{3,6}}\b"), None),
    ("Kreditkartennummer", "sperre", re.compile(r"(?<![\w.])(?:\d[ -]?){13,19}(?![\w.])"), _luhn),
    ("E-Mail-Adresse", "hinweis", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("Strassenadresse", "hinweis", re.compile(
        r"\b[A-ZÄÖÜ][a-zäöüéèà]+(?:strasse|straße|gasse|weg|platz|allee|rain|ring|quai|gässli|matte)\s+\d{1,4}[a-z]?\b"
        r"|\b(?:Rue|Avenue|Chemin|Route|Via|Viale|Piazza)\s+[A-Za-zÀ-ÿ' -]{3,30}\s+\d{1,4}\b"), None),
]


@dataclass
class Fund:
    art: str
    stufe: str      # sperre | hinweis
    zeile: int
    maske: str


def maskieren(text: str) -> str:
    t = text.strip()
    if len(t) <= 4:
        return "•" * len(t)
    return f"{t[:2]}{'•' * min(len(t) - 3, 10)}{t[-1]}"


class NichtLesbar(Exception):
    pass


def text_lesen(datei: Path) -> str:
    """Liest Text aus txt/md/csv/json/html/eml, aus .docx (ohne Zusatzpakete) und aus .pdf (pdftotext)."""
    endung = datei.suffix.lower()
    if endung == ".docx":
        try:
            with zipfile.ZipFile(datei) as z:
                teile = [z.read(n).decode("utf-8", "replace") for n in z.namelist()
                         if re.fullmatch(r"word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml", n)]
        except (zipfile.BadZipFile, KeyError) as e:
            raise NichtLesbar(f"{datei.name}: keine gültige .docx-Datei ({e}).") from e
        xml = "\n".join(teile)
        xml = re.sub(r"</w:p>|<w:br[^>]*/>|</w:tr>", "\n", xml)
        xml = re.sub(r"<w:tab[^>]*/>|</w:tc>", "\t", xml)
        text = re.sub(r"<[^>]+>", "", xml)
        for kurz, zeichen in (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&apos;", "'")):
            text = text.replace(kurz, zeichen)
        return text
    if endung == ".pdf":
        if not shutil.which("pdftotext"):
            raise NichtLesbar(f"{datei.name}: Für PDF fehlt 'pdftotext' (Paket poppler-utils). "
                              "Entweder installieren oder das Dokument als .txt/.md/.docx exportieren.")
        r = subprocess.run(["pdftotext", "-layout", str(datei), "-"], capture_output=True, timeout=120)
        if r.returncode != 0:
            raise NichtLesbar(f"{datei.name}: pdftotext meldet einen Fehler: {r.stderr.decode('utf-8', 'replace')[:200]}")
        text = r.stdout.decode("utf-8", "replace")
        if len(text.strip()) < 20:
            raise NichtLesbar(f"{datei.name}: PDF enthält keinen Text (gescannt?). Bitte zuerst OCR im Haus.")
        return text
    if endung in (".doc", ".odt", ".rtf", ".xlsx", ".xls", ".msg", ".zip", ".png", ".jpg", ".jpeg"):
        raise NichtLesbar(f"{datei.name}: Format {endung} wird nicht geprüft. Bitte als .txt, .md, .docx oder .pdf liefern.")
    roh = datei.read_bytes()
    if b"\x00" in roh[:4096]:
        raise NichtLesbar(f"{datei.name}: sieht nach Binärdatei aus. Bitte als Text liefern.")
    return roh.decode("utf-8", "replace")


def pruefen(text: str) -> tuple[list[Fund], dict[str, int]]:
    """Gibt Funde und die Zahl der gefundenen Platzhalter je Typ zurück."""
    funde: list[Fund] = []
    for nr, zeile in enumerate(text.splitlines(), 1):
        belegt: list[tuple[int, int]] = []
        for art, stufe, muster, zusatz in MUSTER:
            for m in muster.finditer(zeile):
                if zusatz and not zusatz(m.group()):
                    continue
                if any(a < m.end() and m.start() < b for a, b in belegt):
                    continue    # dieselbe Stelle nicht doppelt melden
                belegt.append(m.span())
                funde.append(Fund(art, stufe, nr, maskieren(m.group())))
    platzhalter: dict[str, set] = {}
    for typ, nummer in PLATZHALTER.findall(text):
        platzhalter.setdefault(typ, set()).add(nummer)
    return funde, {typ: len(n) for typ, n in sorted(platzhalter.items())}


def bericht(name: str, funde: list[Fund], platzhalter: dict[str, int]) -> str:
    sperren = [f for f in funde if f.stufe == "sperre"]
    hinweise = [f for f in funde if f.stufe == "hinweis"]
    zeilen = [f"PII-Prüfung: {name}"]
    if platzhalter:
        zeilen.append("  Platzhalter gefunden: " + ", ".join(f"{t} ×{n}" for t, n in platzhalter.items()))
    else:
        zeilen.append("  ! Keine Platzhalter wie [PERSON_01] gefunden. Wurde das Dokument pseudonymisiert?")
    for titel, gruppe in (("SPERRE", sperren), ("Hinweis", hinweise)):
        for f in gruppe[:40]:
            zeilen.append(f"  {titel:7} Zeile {f.zeile:>4}  {f.art:<20} {f.maske}")
        if len(gruppe) > 40:
            zeilen.append(f"  … und {len(gruppe) - 40} weitere ({titel}).")
    if sperren:
        zeilen.append(f"  Ergebnis: {len(sperren)} Sperrfund(e). Dokument wird NICHT aufgenommen.")
    elif hinweise:
        zeilen.append(f"  Ergebnis: keine Sperrfunde, {len(hinweise)} Hinweis(e). E-Mail-Adressen und Adressen der "
                      "Täterinfrastruktur dürfen bleiben, solche von Personen nicht.")
    else:
        zeilen.append("  Ergebnis: keine Funde.")
    zeilen.append("  Namen erkennt diese Prüfung nicht. Dafür ist die Pseudonymisierung zuständig.")
    return "\n".join(zeilen)


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    code = 0
    for arg in argv:
        datei = Path(arg)
        try:
            if not datei.is_file():
                raise NichtLesbar(f"{arg}: Datei nicht gefunden.")
            funde, platzhalter = pruefen(text_lesen(datei))
        except NichtLesbar as e:
            print(f"FEHLER: {e}", file=sys.stderr)
            code = max(code, 2)
            continue
        print(bericht(datei.name, funde, platzhalter))
        if any(f.stufe == "sperre" for f in funde):
            code = max(code, 1)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
