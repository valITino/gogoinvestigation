#!/usr/bin/env python3
"""Sicherheitsnetz vor der Aufnahme eines Dokuments: Sucht nach Personendaten, die der
Pseudonymisierung entgangen sind.

Die Prüfung erkennt Muster (AHV-Nummer, IBAN, Telefonnummer, Geburtsdatum, Kontrollschild,
Kreditkarte, E-Mail, Strassenadresse). Namen erkennt sie NICHT. Sie ersetzt die
Pseudonymisierung nicht, sie fängt deren Ausrutscher ab.

Gesperrt wird nach der Vorgabe des Eigentümers (tools/schutzumfang.py): was zur Dienststelle, zur
Verfasserin oder zum Verfasser und zu Geschädigten gehört. Die Seite erkennt die Prüfung am Aufbau
des Dokuments (Abschnitt «Geschädigte/-r», Feld «Dienstort»). Angaben der Täterseite und Angaben
ohne Abschnitt bleiben stehen: Die Prüfung zeigt sie an und sperrt nicht. Zwei Dinge sperren
immer: ein Dokument ganz ohne Platzhalter (es ist offenbar nicht pseudonymisiert) und der Rest
einer Word-Feldfunktion mit Klartext. Mit OSINT_SCHUTZ=streng sperrt jede Angabe wie früher.

Die Ausgabe zeigt Fundstellen nur maskiert, damit sie gefahrlos in einem Agenten-Kontext
landen kann.

    python3 tools/pii_pruefung.py DATEI [DATEI …]
Rückgabewert: 0 sauber, 1 Sperrfunde, 2 Datei nicht lesbar.
"""
from __future__ import annotations

import io
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

PLATZHALTER = re.compile(r"\[([A-ZÄÖÜ]{2,20})_(\d{1,3})\]")
# Platzhalter von anderer Hand stehen manchmal ohne Klammern da: ADRESSE_02. Sie gelten hier als Platzhalter, damit ein Werkzeug
# im Haus nicht umgestellt werden muss. Neue Platzhalter dieses Arbeitsplatzes haben immer Klammern.
PLATZHALTER_OHNE = re.compile(r"(?<![\w\[])([A-ZÄÖÜ]{3,20})_(\d{2,3})(?![\w\]])")
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
        r"|(?<![\w.:/-])0\d{2}[\s./]\d{3}[\s.]\d{2}[\s.]\d{2}(?!\d)"       # 079 123 45 67, 079/123 45 67
        r"|(?<![\w.:/+-])0[1-9]\d{8}(?![\w-]|\.\d)"), None),                    # 0791234567, ohne Trennzeichen
    ("Geburtsdatum", "sperre", re.compile(
        r"(?i)(?:\bgeb\.?|\bgeboren(?:\s+am)?|\bgeburtsdatum:?|\bjg\.?|\*)\s*\d{1,2}\.\s?\d{1,2}\.\s?(?:19|20)\d{2}\b"), None),
    ("Kontrollschild", "sperre", re.compile(rf"\b(?:{KANTONE})[ ·-]?\d{{3,6}}\b"), None),
    ("Kreditkartennummer", "sperre", re.compile(r"(?<![\w.])(?:\d[ -]?){13,19}(?![\w.])"), _luhn),
    ("E-Mail-Adresse", "hinweis", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("Strassenadresse", "hinweis", re.compile(
        r"\b[A-ZÄÖÜ][a-zäöüéèà]+(?:strasse|straße|gasse|weg|platz|allee|rain|ring|quai|gässli|matte)\s+\d{1,4}[a-z]?\b"
        r"|\b(?:Rue|Avenue|Chemin|Route|Via|Viale|Piazza)\s+[A-Za-zÀ-ÿ' -]{3,30}\s+\d{1,4}\b"), None),
]


# Reste von Word-Feldfunktionen in einem Text: «IF "Musterweg 12" = "" "" "Musterweg 12, "». Die Anweisung eines Felds wiederholt
# den Wert, den es zeigt. Ersetzt jemand nur den sichtbaren Text, steht er hier noch im Klartext (gesehen am 19.11.2026). Aus
# einem Word-Dokument liest dieser Arbeitsplatz die Anweisungen gar nicht erst mit. In einem Text von anderswo erkennt er sie
# an ihrer Form: Bedingung in Anführungszeichen, danach mindestens ein Text in Anführungszeichen. Eine Zeile aus einem Skript
# («if "$a" = "" ; then») hat das nicht und bleibt stehen.
_ANF = "\"“”„«»"
FELDREST = re.compile(
    rf"(?i)(?<![\w{_ANF}])(?:\{{\s*)?\b(?:IF|COMPARE)[ \t]+[{_ANF}][^{_ANF}\n]{{0,200}}[{_ANF}][ \t]*(?:=|<>|<=|>=|<|>)[ \t]*[{_ANF}][^{_ANF}\n]{{0,200}}[{_ANF}]"
    rf"(?:[ \t]+[{_ANF}][^{_ANF}\n]{{0,400}}[{_ANF}]){{1,2}}(?:[ \t]*\}})?")
_FELDWERT = re.compile(rf"[{_ANF}]([^{_ANF}\n]*)[{_ANF}]")


def feldrest_klartext(rest: str) -> str:
    """Der erste Wert in einem Feldrest, der kein Platzhalter und nicht leer ist. Leer, wenn der Rest nichts verrät."""
    for wert in _FELDWERT.findall(rest):
        kern = PLATZHALTER_OHNE.sub("", PLATZHALTER.sub("", wert)).strip(" ,;.:-")
        if re.search(r"[^\W_]", kern):
            return wert.strip()
    return ""


def feldreste_entfernen(text: str) -> tuple[str, int]:
    """Der Text ohne die Reste von Feldfunktionen, die Klartext wiederholen, und ihre Zahl. Der sichtbare Text bleibt stehen."""
    zahl = 0

    def weg(m: re.Match) -> str:
        nonlocal zahl
        if not feldrest_klartext(m.group()):
            return m.group()
        zahl += 1
        return ""
    neu = FELDREST.sub(weg, text)
    if zahl:
        neu = re.sub(r"[ \t]{2,}(?=\S)", lambda m: m.group() if "\t" in m.group() else " ", neu)      # die Lücke, die der Rest hinterlässt
        neu = re.sub(r"[ \t]+$", "", neu, flags=re.M)
    return neu, zahl


@dataclass
class Fund:
    art: str
    stufe: str      # sperre | hinweis
    zeile: int
    maske: str
    rolle: str = ""         # Seite laut Aufbau des Dokuments: dienst, verfasser, geschaedigte, taeter, dritte. Leer: kein Abschnitt


def maskieren(text: str) -> str:
    t = text.strip()
    if len(t) <= 4:
        return "•" * len(t)
    return f"{t[:2]}{'•' * min(len(t) - 3, 10)}{t[-1]}"


class NichtLesbar(Exception):
    pass


# Formate, aus denen eine Textfassung entsteht. Geprüft und pseudonymisiert wird der Text, nie das Original.
GEWANDELT = (".docx", ".pdf", ".odt", ".ods", ".odp", ".xlsx", ".pptx", ".rtf", ".eml")
BILDER = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".heic", ".svg")
NICHT_LESBAR = {
    **{e: "Bild. Was auf einem Bild steht, kann nicht geprüft werden (keine Texterkennung)." for e in BILDER},
    **{e: "Ton- oder Videodatei. Ihr Inhalt kann nicht geprüft werden." for e in (".mp3", ".wav", ".m4a", ".ogg", ".flac", ".mp4", ".mov", ".avi", ".mkv", ".webm")},
    **{e: "Archiv. Die Oberfläche entpackt .zip beim Hochladen. Andere Archive bitte vorher entpacken." for e in (".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz")},
    ".doc": "altes Word-Format. Bitte als .docx oder .pdf speichern.",
    ".xls": "altes Excel-Format. Bitte als .xlsx oder .csv speichern.",
    ".ppt": "altes PowerPoint-Format. Bitte als .pptx oder .pdf speichern.",
    ".msg": "Outlook-Nachricht. Bitte aus Outlook als .eml oder .txt speichern.",
    ".pages": "Pages-Dokument. Bitte als .docx oder .pdf exportieren.",
    ".numbers": "Numbers-Tabelle. Bitte als .xlsx oder .csv exportieren.",
}
ZIP_TEIL = 60 * 1024 * 1024         # grösster Teil eines Office-Dokuments, der entpackt wird
_XML_ZEICHEN = (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&apos;", "'"), ("&amp;", "&"))


def _xml_text(xml: str) -> str:
    """Entfernt die Marken und löst die fünf XML-Kürzel auf. Bewusst ohne XML-Parser: Ein Dokument kann ihn nicht überlasten."""
    text = re.sub(r"<[^>]+>", "", xml)
    for kurz, zeichen in _XML_ZEICHEN:
        text = text.replace(kurz, zeichen)
    return re.sub(r"&#(x[0-9a-fA-F]{1,6}|\d{1,7});", lambda m: _zeichen(m.group(1)), text)


def _zeichen(kode: str) -> str:
    try:
        return chr(int(kode[1:], 16) if kode.startswith("x") else int(kode))
    except (ValueError, OverflowError):
        return ""


def _zip_teile(name: str, roh: bytes, muster: str) -> list[tuple[str, str]]:
    """Die Teile eines Office-Dokuments (ZIP), deren Name zum Muster passt, als Text. Begrenzt die Grösse je Teil."""
    try:
        with zipfile.ZipFile(io.BytesIO(roh)) as z:
            teile = []
            for info in z.infolist():
                if not re.fullmatch(muster, info.filename):
                    continue
                if info.file_size > ZIP_TEIL:
                    raise NichtLesbar(f"{name}: Ein Teil des Dokuments ist entpackt grösser als {ZIP_TEIL // (1024 * 1024)} MB.")
                teile.append((info.filename, z.read(info).decode("utf-8", "replace")))
            return teile
    except (zipfile.BadZipFile, KeyError, RuntimeError, OSError, EOFError) as e:
        raise NichtLesbar(f"{name}: keine gültige {Path(name).suffix.lower()}-Datei ({type(e).__name__}). Ist sie mit einem Passwort geschützt?") from e


def _nummer(name: str) -> int:
    m = re.search(r"(\d+)\.xml$", name)
    return int(m.group(1)) if m else 0


# Was in einem Word-Dokument steht, aber nicht zu seinem sichtbaren Text gehört. Es bliebe sonst in der Textfassung stehen, auch
# wenn der sichtbare Text längst durch Platzhalter ersetzt ist. Gesehen am 19.11.2026: Die Anweisung eines Seriendruckfelds
# («IF "Musterweg 12" = "" …») wiederholt den Wert, den das Feld zeigt.
_DOCX_NICHT_TEXT = re.compile(
    r"<w:(instrText|delInstrText|delText|fldData)\b[^>]*(?<!/)>.*?</w:\1>"       # Feldanweisungen, Felddaten, gelöschter Text (Änderungen nachverfolgen)
    r"|<w:(del|moveFrom)(?=[\s>])[^>]*(?<!/)>.*?</w:\2>"                         # gelöschte und an ihrer alten Stelle verschobene Abschnitte
    r"|<w:r\b(?:(?!</w:r>).)*?<w:vanish(?:\s+w:val=\"(?:1|true|on)\")?\s*/>(?:(?!</w:r>).)*?</w:r>",      # ausgeblendeter Text
    re.S)


_DOCX_FELDZEICHEN = re.compile(r'<w:fldChar\b[^>]*\bw:fldCharType="(begin|separate|end)"[^>]*>')
_DOCX_TEXT = re.compile(r"<w:t\b[^>]*(?<!/)>.*?</w:t>", re.S)


def _docx_sichtbar(xml: str) -> str:
    """Ein Teil eines Word-Dokuments ohne das, was man im Dokument nicht sieht. Ein Feld besteht aus Beginn, Anweisung,
    Trennmarke, Ergebnis und Ende. Die Anweisung kann selbst Felder enthalten: Deren Ergebnisse sind dann Teil der Anweisung
    («IF "Musterweg 12" = "" …») und erscheinen im Dokument nicht. Sichtbar ist nur, was in keinem Feld im Anweisungsteil steht."""
    stuecke, lage, pos = [], [], 0
    for m in _DOCX_FELDZEICHEN.finditer(xml):
        stueck = xml[pos:m.start()]
        stuecke.append(_DOCX_TEXT.sub("", stueck) if "anweisung" in lage else stueck)
        if m.group(1) == "begin":
            lage.append("anweisung")
        elif m.group(1) == "separate" and lage:
            lage[-1] = "ergebnis"
        elif m.group(1) == "end" and lage:
            lage.pop()
        pos = m.end()
    if not lage:        # gehen die Felder nicht auf (beschädigtes Dokument), bleibt der Text stehen: lieber zu viel als ein halbes Dokument
        xml = "".join(stuecke) + xml[pos:]
    return _DOCX_NICHT_TEXT.sub("", xml)


def _docx(name: str, roh: bytes) -> str:
    """Der sichtbare Text: Dokument, Kopf- und Fusszeilen, Fuss- und Endnoten. Kommentare, Feldanweisungen, gelöschter und
    ausgeblendeter Text gehören nicht dazu. Ausgeblendet über eine Formatvorlage erkennt das nicht: Die Vorlagen werden nicht gelesen."""
    xml = "\n".join(_docx_sichtbar(text) for _n, text in _zip_teile(name, roh, r"word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml"))
    xml = re.sub(r"</w:p>|<w:br[^>]*/>|</w:tr>", "\n", xml)
    xml = re.sub(r"<w:tab[^>]*/>|</w:tc>", "\t", xml)
    return _xml_text(xml)


def _odf(name: str, roh: bytes) -> str:
    xml = "\n".join(text for _n, text in _zip_teile(name, roh, r"content\.xml"))
    # Aufgezeichnete Änderungen (darin steht der gelöschte Text) und Kommentare gehören nicht zum sichtbaren Text
    xml = re.sub(r"<text:tracked-changes\b[^>]*(?<!/)>.*?</text:tracked-changes>|<office:annotation\b[^>]*(?<!/)>.*?</office:annotation>", "", xml, flags=re.S)
    xml = re.sub(r"<text:s text:c=\"(\d{1,3})\"\s*/>", lambda m: " " * int(m.group(1)), xml)
    xml = re.sub(r"</text:p>|</text:h>|<text:line-break\s*/>|</table:table-row>", "\n", xml)
    xml = re.sub(r"<text:tab\s*/>|</table:table-cell>", "\t", xml)
    return _xml_text(xml)


def _xlsx(name: str, roh: bytes) -> str:
    gemeinsam = [_xml_text("".join(re.findall(r"<t\b[^>]*>(.*?)</t>", re.sub(r"<rPh\b.*?</rPh>", "", si, flags=re.S), flags=re.S)))
                 for _n, xml in _zip_teile(name, roh, r"xl/sharedStrings\.xml") for si in re.findall(r"<si\b[^>]*>(.*?)</si>", xml, flags=re.S)]
    namen = [_xml_text(n) for _n, xml in _zip_teile(name, roh, r"xl/workbook\.xml") for n in re.findall(r"<sheet\b[^>]*\bname=\"([^\"]*)\"", xml)]
    aus = []
    for nr, (_name, xml) in enumerate(sorted(_zip_teile(name, roh, r"xl/worksheets/sheet\d+\.xml"), key=lambda x: _nummer(x[0]))):
        aus.append(f"Tabelle: {namen[nr] if nr < len(namen) else nr + 1}")
        for zeile in re.findall(r"<row\b[^>]*>(.*?)</row>", xml, flags=re.S):
            zellen = []
            for kopf, inhalt in re.findall(r"<c\b([^>]*?)(?:/>|>(.*?)</c>)", zeile, flags=re.S):
                wert = re.search(r"<v\b[^>]*>(.*?)</v>", inhalt or "", flags=re.S)
                if 't="s"' in kopf and wert and wert.group(1).strip().isdigit() and int(wert.group(1)) < len(gemeinsam):
                    zellen.append(gemeinsam[int(wert.group(1))])
                elif 't="inlineStr"' in kopf:
                    zellen.append(_xml_text("".join(re.findall(r"<t\b[^>]*>(.*?)</t>", inhalt or "", flags=re.S))))
                else:
                    zellen.append(_xml_text(wert.group(1)) if wert else "")
            if any(z.strip() for z in zellen):
                aus.append("\t".join(zellen))
        aus.append("")
    return "\n".join(aus)


def _pptx(name: str, roh: bytes) -> str:
    aus = []
    for teil, xml in sorted(_zip_teile(name, roh, r"ppt/(slides/slide|notesSlides/notesSlide)\d+\.xml"), key=lambda x: (x[0].startswith("ppt/notes"), _nummer(x[0]))):
        aus.append(("Notizen zu Folie " if "notesSlide" in teil else "Folie ") + str(_nummer(teil)))
        aus.append(_xml_text(re.sub(r"</a:p>|<a:br\s*/>", "\n", xml)).strip())
        aus.append("")
    return "\n".join(aus)


_RTF = re.compile(r"\\([a-z]{1,32})(-?\d{1,10})?[ ]?|\\'([0-9a-f]{2})|\\([^a-z])|([{}])|[\r\n]+|(.)", re.I)
_RTF_ZIELE = frozenset("fonttbl colortbl stylesheet info pict object datastore themedata colorschememapping latentstyles datafield fldinst generator "
                       "header headerl headerr headerf footer footerl footerr footerf footnote ftnsep ftnsepc aftnsep aftnsepc listtable listoverridetable "
                       "rsidtbl mmathPr xmlnstbl pgdsctbl revtbl bkmkstart bkmkend shpinst nonshppict filetbl operator author title subject keywords "
                       "company doccomm manager category".split())
_RTF_ZEICHEN = {"par": "\n", "sect": "\n\n", "page": "\n\n", "line": "\n", "tab": "\t", "cell": "\t", "row": "\n", "emdash": "—", "endash": "–", "emspace": " ",
                "enspace": " ", "qmspace": " ", "bullet": "•", "lquote": "‘", "rquote": "’", "ldblquote": "“", "rdblquote": "”"}


def _rtf(roh: str) -> str:
    """Text aus RTF: Steuerwörter fallen weg, Zeichen in Hex- und Unicode-Schreibweise werden gelesen, Absätze werden Zeilen.
    Schrifttabelle, Bilder, Kopf- und Fusszeilen und die Angaben zum Verfasser gehören nicht zum Text. Auch nicht, was im
    Dokument nicht zu sehen ist: Feldanweisungen, gelöschter Text (Änderungen nachverfolgen) und ausgeblendeter Text."""
    stapel: list[tuple[int, bool, bool]] = []
    aus: list[str] = []
    ignorieren, ucskip, rest, unsichtbar = False, 1, 0, False
    for m in _RTF.finditer(roh):
        wort, zahl, hexa, zeichen, klammer, sonst = m.groups()
        if klammer:
            rest = 0
            if klammer == "{":
                stapel.append((ucskip, ignorieren, unsichtbar))
            elif stapel:
                ucskip, ignorieren, unsichtbar = stapel.pop()
        elif zeichen:
            rest = 0
            if zeichen == "*":
                ignorieren = True
            elif not ignorieren and not unsichtbar:
                aus.append("\xa0" if zeichen == "~" else zeichen if zeichen in "{}\\" else "")
        elif wort:
            rest = 0
            if wort in _RTF_ZIELE:
                ignorieren = True
            elif ignorieren:
                continue
            elif wort in ("deleted", "v"):      # gelöscht oder ausgeblendet: gilt bis zum Ende der Gruppe oder bis zur Null dahinter
                unsichtbar = zahl != "0"
            elif wort == "plain":               # setzt die Zeichenformate zurück, auch «ausgeblendet»
                unsichtbar = False
            elif unsichtbar:
                continue
            elif wort in _RTF_ZEICHEN:
                aus.append(_RTF_ZEICHEN[wort])
            elif wort == "uc" and zahl:
                ucskip = max(0, int(zahl))
            elif wort == "u" and zahl:
                kode = int(zahl)
                aus.append(_zeichen(str(kode + 0x10000 if kode < 0 else kode)))
                rest = ucskip
        elif hexa:
            if rest > 0:
                rest -= 1
            elif not ignorieren and not unsichtbar:
                aus.append(bytes.fromhex(hexa).decode("cp1252", "replace"))
        elif sonst:
            if rest > 0:
                rest -= 1
            elif not ignorieren and not unsichtbar:
                aus.append(sonst)
    return "".join(aus)


def html_text(html: str) -> str:
    """Der sichtbare Text einer HTML-Seite: ohne Skripte, Stile und Marken."""
    text = re.sub(r"(?is)<(script|style|head)\b.*?</\1\s*>", " ", html)
    text = re.sub(r"(?i)<br\s*/?>|</(p|div|tr|li|h[1-6]|table|blockquote)\s*>", "\n", text)
    text = re.sub(r"(?i)</t[dh]\s*>", "\t", text)
    import html as html_modul
    return re.sub(r"[ \t\xa0]{2,}", " ", html_modul.unescape(re.sub(r"<[^>]+>", "", text)))


def mail_lesen(roh: bytes) -> tuple[str, list[tuple[str, bytes]]]:
    """Eine E-Mail (.eml): Kopfzeilen und Text als Lesefassung, dazu die Anhänge als (Name, Inhalt).
    Anhänge sind eigene Dokumente: Sie werden einzeln geprüft, ihr Inhalt steht nicht in der Lesefassung."""
    import email
    import email.policy
    try:
        nachricht = email.message_from_bytes(roh, policy=email.policy.default)
    except Exception as e:      # eine kaputte Nachricht ist kein Grund für einen Absturz
        raise NichtLesbar(f"Die E-Mail liess sich nicht lesen ({type(e).__name__}).") from e
    # Die Kopfzeilen im Wortlaut der Nachricht: Ein Platzhalter wie [PERSON_01] ist keine gültige Adresse und ginge beim Zerlegen verloren
    import email.header
    zeilen = []
    for name, roh_wert in nachricht.raw_items():
        if name.lower() in ("from", "to", "cc", "bcc", "reply-to", "date", "subject", "message-id"):
            wert = " ".join(str(roh_wert).split())
            try:
                wert = str(email.header.make_header(email.header.decode_header(wert)))
            except Exception:       # eine kaputte Kodierung bleibt stehen, wie sie ist
                pass
            zeilen.append(f"{name}: {wert}")
    texte: list[str] = []
    anhaenge: list[tuple[str, bytes]] = []
    for teil in nachricht.walk():
        if teil.is_multipart():
            continue
        name = teil.get_filename()
        if name or teil.get_content_disposition() == "attachment":
            try:
                inhalt = teil.get_payload(decode=True) or b""
            except Exception:
                inhalt = b""
            anhaenge.append((str(name or f"anhang-{len(anhaenge) + 1}"), inhalt))
            continue
        try:
            inhalt = teil.get_content()
        except Exception:       # unbekannter Zeichensatz, kaputte Kodierung
            inhalt = (teil.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if not isinstance(inhalt, str):
            continue
        if teil.get_content_type() == "text/plain":
            texte.append(inhalt)
        elif teil.get_content_type() == "text/html" and not any(texte):
            texte.append(html_text(inhalt))
    if anhaenge:
        zeilen.append("Anhänge: " + ", ".join(name for name, _ in anhaenge))
    return "\n".join(zeilen) + "\n\n" + "\n\n".join(t.strip() for t in texte if t.strip()) + "\n", anhaenge


def text_aus(name: str, roh: bytes, datei: Path | None = None) -> str:
    """Die Textfassung eines Dokuments aus seinem Inhalt, ohne dass er dafür auf die Platte muss. Liest Textdateien
    (txt, md, csv, json, html und ähnliche), ohne Zusatzpakete .docx, .odt, .ods, .odp, .xlsx, .pptx, .rtf und .eml,
    und .pdf mit pdftotext. Was sich nicht lesen lässt, lässt sich nicht prüfen: NichtLesbar."""
    endung = Path(name).suffix.lower()
    if endung in NICHT_LESBAR:
        raise NichtLesbar(f"{name}: Format {endung} wird nicht geprüft: {NICHT_LESBAR[endung]}")
    if endung == ".docx":
        return _docx(name, roh)
    if endung in (".odt", ".ods", ".odp"):
        return _odf(name, roh)
    if endung == ".xlsx":
        return _xlsx(name, roh)
    if endung == ".pptx":
        return _pptx(name, roh)
    if endung == ".pdf":
        pdftotext = plattform.programm("pdftotext")
        if not pdftotext:
            woher = ("winget install oschwartz10612.Poppler, danach ein neues Terminal" if plattform.WINDOWS
                     else "Paket poppler-utils, unter macOS 'brew install poppler'")
            raise NichtLesbar(f"{name}: Für PDF fehlt 'pdftotext' ({woher}). {plattform.SETUP} holt es nach. "
                              "Oder das Dokument als .txt/.md/.docx exportieren.")
        try:        # mit Datei wie bisher, ohne Datei über die Standardeingabe
            r = subprocess.run([pdftotext, "-layout", "-enc", "UTF-8", str(datei) if datei is not None else "-", "-"],
                               input=None if datei is not None else roh, capture_output=True, timeout=120)
        except subprocess.TimeoutExpired as e:
            raise NichtLesbar(f"{name}: pdftotext wurde nach 120 Sekunden nicht fertig.") from e
        if r.returncode != 0:
            raise NichtLesbar(f"{name}: pdftotext meldet einen Fehler: {r.stderr.decode('utf-8', 'replace')[:200]}")
        text = r.stdout.decode("utf-8", "replace")
        if len(text.strip()) < 20:
            raise NichtLesbar(f"{name}: PDF enthält keinen Text (gescannt?). Bitte zuerst OCR im Haus.")
        return text
    if endung == ".eml":
        try:
            return mail_lesen(roh)[0]
        except NichtLesbar as e:
            raise NichtLesbar(f"{name}: {e}") from e
    utf16 = roh.startswith((b"\xff\xfe", b"\xfe\xff"))
    if b"\x00" in roh[:4096] and not utf16:
        raise NichtLesbar(f"{name}: sieht nach Binärdatei aus. Bitte als Text liefern.")
    text = roh.decode("utf-16", "replace") if utf16 else roh.decode("utf-8-sig", "replace")
    return _rtf(text) if endung == ".rtf" else text


def text_lesen(datei: Path) -> str:
    """Die Textfassung einer Datei. Siehe text_aus."""
    return text_aus(datei.name, datei.read_bytes(), datei)


def pruefen(text: str, strenge: str | None = None) -> tuple[list[Fund], dict[str, int]]:
    """Gibt Funde und die Zahl der gefundenen Platzhalter je Typ zurück. `strenge` ist «vorgabe» oder «streng», ohne Angabe gilt
    die Einstellung des Arbeitsplatzes (tools/schutzumfang.py). Nach der Vorgabe sperrt, was in einem geschützten Abschnitt
    steht. Was auf der Täterseite oder in keinem Abschnitt steht, ist ein Hinweis. Ein Text ganz ohne Platzhalter wird streng
    geprüft: Er ist offenbar nicht pseudonymisiert."""
    from tools import schutzumfang as su
    streng = (strenge or su.modus()) == "streng"
    zeilen = text.splitlines()
    platzhalter: dict[str, set] = {}
    for typ, nummer in PLATZHALTER.findall(text) + PLATZHALTER_OHNE.findall(text):
        platzhalter.setdefault(typ, set()).add(nummer)
    seiten = [""] * len(zeilen) if streng else su.rollen(text)
    nach_vorgabe = not streng and bool(platzhalter)
    funde: list[Fund] = []
    for nr, zeile in enumerate(zeilen, 1):
        rolle = seiten[nr - 1]
        belegt: list[tuple[int, int]] = []
        for m in FELDREST.finditer(zeile):
            klar = feldrest_klartext(m.group())
            if klar:
                belegt.append(m.span())
                funde.append(Fund("Rest einer Feldfunktion", "sperre", nr, maskieren(klar), rolle))
        for art, stufe, muster, zusatz in MUSTER:
            for m in muster.finditer(zeile):
                if zusatz and not zusatz(m.group()):
                    continue
                if any(a < m.end() and m.start() < b for a, b in belegt):
                    continue    # dieselbe Stelle nicht doppelt melden
                belegt.append(m.span())
                if su.geschuetzt(rolle):
                    stufe = "sperre"        # auch eine Adresse oder E-Mail-Adresse: In diesem Abschnitt gehört sie ersetzt
                elif nach_vorgabe:
                    stufe = "hinweis"
                funde.append(Fund(art, stufe, nr, maskieren(m.group()), rolle))
        marke = "" if streng else su.klartextfeld(zeile, rolle)
        if marke and not any(f.zeile == nr and f.stufe == "sperre" for f in funde):
            wert = zeile.split(marke, 1)[-1].lstrip(" :\t")
            funde.append(Fund("Feld im Klartext", "sperre", nr, f"{marke}: {maskieren(wert)}", rolle))
    return funde, {typ: len(n) for typ, n in sorted(platzhalter.items())}


def bericht(name: str, funde: list[Fund], platzhalter: dict[str, int]) -> str:
    from tools import schutzumfang as su
    sperren = [f for f in funde if f.stufe == "sperre"]
    hinweise = [f for f in funde if f.stufe == "hinweis"]
    zeilen = [f"PII-Prüfung: {name}"]
    if platzhalter:
        zeilen.append("  Platzhalter gefunden: " + ", ".join(f"{t} ×{n}" for t, n in platzhalter.items()))
    else:
        zeilen.append("  ! Keine Platzhalter wie [PERSON_01] gefunden. Wurde das Dokument pseudonymisiert?")
    for titel, gruppe in (("SPERRE", sperren), ("Hinweis", hinweise)):
        for f in gruppe[:40]:
            wo = f"  ({su.bezeichnung(f.rolle)})" if f.rolle or titel == "Hinweis" and platzhalter else ""
            zeilen.append(f"  {titel:7} Zeile {f.zeile:>4}  {f.art:<20} {f.maske}{wo}")
        if len(gruppe) > 40:
            zeilen.append(f"  … und {len(gruppe) - 40} weitere ({titel}).")
    if sperren:
        zeilen.append(f"  Ergebnis: {len(sperren)} Sperrfund(e). Dokument wird NICHT aufgenommen.")
        if any(f.rolle for f in sperren):
            zeilen.append("  Gesperrt ist, was nach der Vorgabe ersetzt sein muss: Angaben zur Dienststelle, zur Verfasserin oder zum "
                          "Verfasser und zu Geschädigten.")
    elif hinweise:
        zeilen.append(f"  Ergebnis: keine Sperrfunde, {len(hinweise)} Hinweis(e). Diese Angaben bleiben im Klartext stehen: Nach der Vorgabe "
                      "sind es Angaben der Täterseite, die die Ermittlung braucht. Gehört eine davon zu einer geschädigten Person, bitte ersetzen.")
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
