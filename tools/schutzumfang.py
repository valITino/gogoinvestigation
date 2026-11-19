"""Was an diesem Arbeitsplatz pseudonymisiert sein muss, und woran ein Werkzeug die Stelle im Dokument erkennt.

Vorgabe des Eigentümers (19.11.2026). Ersetzt werden:

    Dienststelle      Dienstabteilung, Dienstort, Dienst-Rufnummer, Dienst-E-Mail
    Verfasser/in      Verfasserin oder Verfasser und EL-Fall, samt Geburtsdatum, Ort, Heimatort, Adresse, E-Mail
    Geschädigte       samt Heimatort, Adresse, Geburtsdatum und allem, was sie erreichbar macht

Alles andere bleibt stehen, weil die Ermittlung es braucht. Das gilt vor allem für die Angaben der Täterseite: Rufnummern,
Konten, E-Mail-Adressen, Benutzernamen. Wer das strenger will, setzt OSINT_SCHUTZ=streng: Dann sperrt die PII-Prüfung wie
bis zum 19.11.2026 jede Angabe, die nach Personendaten aussieht, gleich auf welcher Seite sie steht.

Erkannt wird die Seite am Aufbau des Dokuments, nicht am Inhalt: an der Überschrift eines Abschnitts («Geschädigte/-r»,
«Beschuldigte/-r») und an der Marke vor einem Feld («Dienstort:»). Ein Abschnitt reicht bis zur nächsten Überschrift.
Was in keinem solchen Abschnitt steht (der Sachverhalt, eine Liste von Zahlungen), hat keine Seite: Dort sperrt die Prüfung
nach der Vorgabe nicht, sie zeigt die Angabe nur an. Namen erkennt hier niemand. Dafür ist die Pseudonymisierung zuständig.

Bibliothek ohne Bedienung, ohne Netz, nur Standardbibliothek. Genutzt von tools/pii_pruefung.py und tools/_pseudo.py.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ROLLEN = {"dienst": "Dienststelle", "verfasser": "Verfasser/in und EL-Fall", "geschaedigte": "Geschädigte",
          "taeter": "Täterseite", "dritte": "Zeugen und Auskunftspersonen"}
GESCHUETZT = ("dienst", "verfasser", "geschaedigte")
VORGABE = ("Dienstabteilung", "Dienstort", "Verfasser/in und EL-Fall samt persönlichen Angaben", "Dienst-Rufnummer", "Dienst-E-Mail",
           "Geschädigte samt Heimatort, Adresse und Geburtsdatum")

_UML = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "é": "e", "è": "e", "ê": "e", "à": "a", "â": "a", "ç": "c", "î": "i", "ô": "o", "û": "u"})
_GESCHLECHT = r"(?:/-?(?:r|in|innen|n|e)|\((?:r|in|n|e)\)|\*in|:in|in|r|n|e)?"     # Geschädigte/-r, Verfasser/in, Beschuldigte(r), Zeugin


def falten(s: str) -> str:
    return " ".join(s.casefold().translate(_UML).split())


# Überschriften von Abschnitten, je Seite. Reguläre Ausdrücke auf dem gefalteten Text (klein, ohne Umlaute).
_ABSCHNITT = {
    "geschaedigte": (rf"geschaedigte{_GESCHLECHT}(?: person(?:en)?| firma| organisation| partei)?", rf"anzeigeerstatter{_GESCHLECHT}", rf"anzeiger{_GESCHLECHT}",
                     rf"privatklaeger{_GESCHLECHT}(?:schaft)?", r"opfer", r"verletzte person", r"geschaedigtenseite", r"angaben zur geschaedigten person",
                     r"lese(?:/e|e)?", r"personne lesee", r"partie plaignante", r"plaignant(?:/e|e)?", r"parte lesa", r"danneggiat[oa](?:/a)?"),
    "verfasser": (rf"verfasser{_GESCHLECHT}(?: ?/ ?el-fall)?", r"el-fall", rf"rapportierende{_GESCHLECHT}", rf"sachbearbeiter{_GESCHLECHT}", rf"fallfuehrende{_GESCHLECHT}",
                  r"fallfuehrung", rf"einsatzleiter{_GESCHLECHT}", r"einsatzleitung", r"redacteur(?:/trice|trice)?", r"redattore(?:/trice|trice)?"),
    "dienst": (r"dienststelle", r"dienstabteilung", r"polizeiposten", r"angaben zur dienststelle"),
    "taeter": (rf"beschuldigte{_GESCHLECHT}(?: person(?:en)?| firma| organisation)?", rf"tatverdaechtige{_GESCHLECHT}(?: person(?:en)?)?", rf"verdaechtige{_GESCHLECHT}(?: person(?:en)?)?",
               r"(?:unbekannte )?taeterschaft", r"taeterseite", rf"(?:unbekannte{_GESCHLECHT} )?taeter{_GESCHLECHT}", r"gegenpartei", r"tatmittel", r"taeterkonto", r"taeterkonten",
               r"empfaengerkonto", r"empfaengerkonten", r"zahlungsempfaenger(?:in)?", r"prevenu(?:/e|e)?", r"auteur(?:/e|e)? inconnu(?:/e|e)?", r"imputat[oa](?:/a)?", r"autore ignoto"),
    "dritte": (rf"auskunftsperson(?:en)?", rf"zeug(?:e|in|en|innen|e/-?in)", r"drittperson(?:en)?", r"weitere personen", r"temoin(?:s)?", r"testimone", r"testimoni"),
}
# Überschriften, die einen Abschnitt beenden, ohne einen neuen mit einer Seite zu beginnen
_NEUTRAL = (r"sachverhalt", r"tatbestand(?:e)?", r"ereignis", r"tatort", r"tatzeit", r"tatzeitraum", r"delikt(?:e)?", r"deliktsgut", r"schaden", r"schadenssumme",
            r"massnahmen", r"ermittlungen", r"feststellungen", r"technische feststellungen", r"spuren", r"beilagen", r"beilage", r"bemerkungen", r"verteiler",
            r"weitere angaben", r"zahlungen", r"transaktionen", r"kryptowaehrungen", r"aussagen", r"antraege", r"rechtliches", r"zusammenfassung", r"auftrag",
            r"faits", r"etat de fait", r"mesures", r"annexes", r"fatti", r"misure", r"allegati")
# Marken, deren Zeile für sich zu einer Seite gehört, gleich in welchem Abschnitt sie steht
_FELD = {
    "dienst": (r"dienstabteilung", r"dienstort", r"dienst-?rufnummer", r"dienst-?telefon", r"dienst-?tel\.?", r"dienst-?e-?mail", r"dienststelle", r"dienstadresse"),
    "verfasser": (rf"verfasser{_GESCHLECHT}(?: ?/ ?el-fall)?", r"el-fall", rf"rapportierende{_GESCHLECHT}", rf"sachbearbeiter{_GESCHLECHT}", r"visum", r"kuerzel"),
}
# Marken, hinter denen in einem geschützten Abschnitt eine Angabe zur Person steht. Steht dort Klartext, sperrt die Prüfung.
# Bewusst eine eigene, kurze Liste: tools/feldmarken.txt dient dem Ersetzen und ist breiter (Firma, Konto, Ausweis).
_PERSONENFELD = (r"name", r"nachname", r"familienname", r"vorname(?:n)?", r"name ?[/,] ?vorname", r"vorname ?[/,] ?name", r"name und vorname", r"ledigname", r"geburtsname",
                 r"geburtsdatum", r"geb\.?-? ?datum", r"geboren(?: am)?", r"geburtsort", r"heimatort", r"buergerort", r"nationalitaet ?[,/] ?heimatort",
                 r"adresse", r"wohnadresse", r"anschrift", r"domizil", r"wohnhaft", r"strasse(?: ?[/,] ?nr\.?)?", r"plz(?: ?[/,]? ?ort)?", r"ort", r"wohnort",
                 r"telefon(?: privat| geschaeft)?", r"tel\.?(?: [pg])?", r"mobile", r"mobiltelefon", r"natel", r"handy", r"e-?mail(?:-adresse)?", r"ahv-?n(?:r\.?|ummer)",
                 r"nom", r"prenom", r"date de naissance", r"lieu d'origine", r"origine", r"domicile", r"rue", r"npa ?/ ?localite", r"telephone", r"courriel",
                 r"cognome", r"nome", r"data di nascita", r"luogo d'origine", r"attinenza", r"indirizzo", r"domicilio", r"telefono")
# Was hinter einer Marke stehen darf, ohne eine Angabe zu sein
_NICHTS = frozenset("unbekannt unbek unbek. keine keiner kein nein dito siehe oben s.o. offen pendent folgt nicht bekannt na n/a k.a. ka - -- --- – — ? ./. "
                    "inconnu inconnue aucun aucune sconosciuto sconosciuta nessuno nessuna".split())
_NUMMER = r"(?:(?:\d{1,2}|[ivx]{1,4}|[a-z])[.)]?(?:\d{1,2}[.)]?){0,3}\s+)?"       # «1.», «2.3», «a)» vor einer Überschrift
_NACH = r"(?:\s*(?:nr\.?\s*)?\d{1,2})?(?:\s*\([^)]{0,40}\))?\s*:?"              # «Geschädigte/-r 2:», «Beschuldigte Person Nr. 1 (Firma)»
_UEBERSCHRIFT = {rolle: re.compile(rf"{_NUMMER}(?:{'|'.join(muster)}){_NACH}") for rolle, muster in _ABSCHNITT.items()}
_UEBERSCHRIFT_NEUTRAL = re.compile(rf"{_NUMMER}(?:{'|'.join(_NEUTRAL)}){_NACH}")
_FELDMARKE = {rolle: re.compile(rf"(?:{'|'.join(muster)})\s*(?::|\t| {{2,}}|$)") for rolle, muster in _FELD.items()}
_PERSONENMARKE = re.compile(rf"({'|'.join(sorted(_PERSONENFELD, key=len, reverse=True))})\s*(?::|\t| {{2,}})\s*(.*)")
_ZIER = re.compile(r"^[\s#*_=|>•·–—-]+|[\s#*_=|]+$")        # Zeichen, mit denen Text- und Markdown-Fassungen Überschriften schmücken
# Irgendeine Überschrift, die diese Datei nicht kennt: kurz, ohne Doppelpunkt und Satzzeichen, nach einer Leerzeile. Sie beendet
# einen Abschnitt. Sonst reichte «Geschädigte/-r» bis ans Ende des Dokuments, und alles dahinter gälte als geschützt.
_IRGENDEINE = re.compile(r"(?:\d{1,2}(?:\.\d{1,2}){0,3}\.?\s+)?[^\W\d_a-zäöü][^:;.!?\t]{2,58}")
ABSCHNITT_HOECHSTENS = 60       # Zeilen. Ein Abschnitt zu einer Person ist kürzer: Danach gilt die Seite nicht mehr
_PLATZHALTER = re.compile(r"\[[A-ZÄÖÜ]{2,20}_\d{1,3}\]|(?<![\w\[])[A-ZÄÖÜ]{3,20}_\d{2,3}(?![\w\]])")


def modus() -> str:
    """«vorgabe» (gesperrt wird, was nach der Vorgabe geschützt ist) oder «streng» (jede Angabe, die nach Personendaten aussieht)."""
    from gateway import plattform
    wert = (os.environ.get("OSINT_SCHUTZ") or plattform.einstellung("OSINT_SCHUTZ") or "").strip().casefold()
    return "streng" if wert == "streng" else "vorgabe"


def ueberschrift(zeile: str) -> str | None:
    """Die Seite, die mit dieser Zeile beginnt: eine der ROLLEN, "" für eine Überschrift ohne Seite, None für eine gewöhnliche Zeile."""
    kern = falten(_ZIER.sub("", zeile))
    if not kern or len(kern) > 70:
        return None
    for rolle, muster in _UEBERSCHRIFT.items():
        if muster.fullmatch(kern):
            return rolle
    return "" if _UEBERSCHRIFT_NEUTRAL.fullmatch(kern) else None


def feldrolle(zeile: str) -> str:
    """Die Seite, zu der eine Zeile schon wegen der Marke an ihrem Anfang gehört («Dienstort: …»), sonst ""."""
    kern = falten(_ZIER.sub("", zeile))
    return next((rolle for rolle, muster in _FELDMARKE.items() if muster.match(kern)), "")


def rollen(text: str) -> list[str]:
    """Je Zeile des Texts die Seite, zu der sie gehört: eine der ROLLEN oder "". Die Überschrift selbst gehört zu ihrem Abschnitt.
    Ein Abschnitt endet an der nächsten Überschrift, auch an einer, die hier niemand kennt, und spätestens nach ABSCHNITT_HOECHSTENS Zeilen."""
    aus, lage, seit, leer = [], "", 0, True
    for zeile in text.splitlines():
        kern = _ZIER.sub("", zeile)
        neu = ueberschrift(zeile)
        if neu is None and lage and leer and kern and _IRGENDEINE.fullmatch(kern) and len(kern.split()) <= 6 and not _PERSONENMARKE.fullmatch(falten(kern) + ":"):
            neu = ""
        if neu is not None:
            lage, seit = neu, 0
        elif lage:
            seit += 1
            if seit > ABSCHNITT_HOECHSTENS:
                lage = ""
        aus.append(feldrolle(zeile) or lage)
        leer = not kern
    return aus


def klartextfeld(zeile: str, rolle: str) -> str:
    """Steht in dieser Zeile hinter einer Marke eine Angabe zur Person im Klartext, gibt die Funktion die Marke zurück, sonst "".
    Gefragt wird nur in geschützten Abschnitten und bei den Marken der Dienststelle und der Verfasserin. Ein Platzhalter im Wert
    genügt: Was daneben steht («Schweiz, [HEIMATORT_01]»), gehört zur Marke und nicht zur Person."""
    if rolle not in GESCHUETZT:
        return ""
    roh = _ZIER.sub("", zeile)
    kern = falten(roh)
    eigene = next((m for r, muster in _FELDMARKE.items() if r == rolle for m in [muster.match(kern)] if m), None)
    if eigene is not None:
        marke, wert = roh[:eigene.end()].rstrip(" :\t"), roh[eigene.end():]
    else:
        m = _PERSONENMARKE.fullmatch(kern)
        if m is None:
            return ""
        marke, wert = roh[:len(roh) - len(roh.lstrip())] + roh.lstrip()[:m.end(1)], kern[m.start(2):]
        if "heimatort" in m.group(1) and "nationalitaet" in m.group(1) and len([t for t in wert.split(",") if t.strip()]) < 2:
            return ""       # «Nationalität, Heimatort: Deutschland»: Wer keinen Heimatort hat, nennt nur das Land
    if _PLATZHALTER.search(roh[len(marke):]):
        return ""
    rest = falten(wert).strip(" .:;,")
    if not rest or rest in _NICHTS or not re.search(r"[^\W_]", rest):
        return ""
    return marke.strip()


def geschuetzt(rolle: str) -> bool:
    return rolle in GESCHUETZT


def bezeichnung(rolle: str) -> str:
    return ROLLEN.get(rolle, "ohne Abschnitt")
