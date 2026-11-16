#!/usr/bin/env python3
"""Prüfsatz für die lokale Pseudonymisierung: synthetische Schweizer Polizeirapporte mit bekannter Lösung.

    python3 tools/pseudo_pruefsatz.py                    Zahlen zum Prüfsatz
    python3 tools/pseudo_pruefsatz.py --zeigen 17        ein Dokument mit seiner Lösung ansehen
    python3 tools/pseudo_pruefsatz.py --nach /tmp/satz   alle Dokumente als Dateien schreiben (ausserhalb des Projektordners)

Jedes Dokument entsteht aus seiner Nummer, immer gleich. Im Kopf stehen genau die Marken aus
tools/feldmarken.txt, reihum, damit jede Marke vorkommt. Im Fliesstext stehen dieselben Personen in allen
Schreibweisen, dazu Drittpersonen und Firmen, die in keinem Feld stehen, und technische Indikatoren, die stehen
bleiben müssen. Zu jeder Stelle kennt der Prüfsatz die Lösung: Typ, Angabe, Schreibweise, Feld oder Fliesstext.

Alles ist erfunden und so gewählt, dass es niemandem gehören kann:
  - Namen sind zufällige Paare aus häufigen und seltenen Vor- und Nachnamen.
  - AHV-Nummern tragen absichtlich eine falsche Prüfziffer. Eine echte Nummer kann so nicht entstehen.
  - IBAN haben eine gültige Prüfsumme, aber die Banknummer 00000, die es nicht gibt.
  - Kontrollschilder: sechsstellige Nummern ab 900000 in kleinen Kantonen, die so viele Schilder nicht ausgeben.
  - Telefonnummern: ungebräuchliche Vorwahlen (070, 072, 073) und der Block 555 01.
  - E-Mail-Adressen, Domains und IP-Adressen: nur reservierte Beispielbereiche (example.com, .example, 192.0.2.0/24 …).
  - Wallet-Adressen, Hashes und Transaktions-IDs: Zufallszeichen in der richtigen Form.

Der Prüfsatz stammt vom selben Verfasser wie die Erkennung. Er misst, ob die Schichten tun, was sie sollen, und
wo sie nichts sehen. Er misst nicht, wie eure echten Rapporte aussehen. Nur Standardbibliothek.
"""
from __future__ import annotations

import argparse
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from gateway import plattform  # noqa: E402

if __name__ == "__main__":
    plattform.start()

from tools import _pseudo as ps  # noqa: E402

ANZAHL = 240


@dataclass
class Gold:
    start: int
    ende: int
    typ: str
    wer: str            # welche Angabe: «P1», «P1.adr», «D2», «F1»
    im_feld: bool       # diese Stelle steht hinter einer Feldmarke
    form: str           # Schreibweise


@dataclass
class Dokument:
    nr: int
    text: str
    gold: list
    technik: list                   # (Beginn, Ende, Art): muss stehen bleiben
    namen: dict = field(default_factory=dict)       # Angabe -> (Typ, Klartext), für die Namensliste
    sprache: str = "de"
    aufbau: str = ""

    def in_feld(self) -> set:
        """Angaben, die mindestens einmal in einem Feld stehen."""
        return {g.wer for g in self.gold if g.im_feld}


# --------------------------------------------------------------------------- Vorrat

VOR = {
    "de": ("Hans Peter Daniel Thomas Andreas Markus Martin Stefan Urs Marcel Bruno Werner Kurt Roland Beat Patrick Rolf Heinz Marco Roger "
           "Jürg Felix Adrian Fabian Florian Jonas Lukas Simon Tobias Reto Sandro Pascal Remo Ueli Maria Anna Ursula Ruth Sandra Monika "
           "Claudia Verena Nicole Barbara Silvia Andrea Daniela Karin Marianne Erika Brigitte Susanne Rita Esther Heidi Doris Katharina "
           "Franziska Regula Martina Sabine Petra Nadia Sarah Laura Lea Julia Nina Selina Melanie Rahel Ramona Vreni").split(),
    "fr": ("Jean Pierre Michel André Philippe Jacques Claude François Bernard Alain Olivier Laurent Pascal Stéphane Thierry Christophe "
           "Frédéric Didier Julien Sébastien Vincent Yves Antoine Guillaume Marie Anne Catherine Françoise Monique Nathalie Isabelle "
           "Sylvie Chantal Martine Véronique Sandrine Valérie Céline Sophie Caroline Florence Aurélie Camille Chloé Émilie Julie").split(),
    "it": ("Giuseppe Giovanni Antonio Mario Luigi Francesco Angelo Pietro Carlo Franco Paolo Marco Roberto Stefano Alessandro Luca Massimo "
           "Giorgio Sergio Fabio Daniele Davide Matteo Lorenzo Maria Anna Rosa Angela Giovanna Teresa Lucia Francesca Elena Paola Laura "
           "Carla Daniela Sara Chiara Valentina Giulia Martina Silvia Roberta Monica Cristina").split(),
    "zu": ("Arben Agim Besnik Driton Ilir Valon Arta Blerta Drita Teuta Dragan Goran Zoran Milan Dejan Jelena Milica Dragana Ivana Mehmet "
           "Mustafa Ahmet Murat Fatma Ayşe Elif José João Carlos Pedro Ana Sónia Mohamed Karim Fatima Leila").split(),
}
# Vornamen, die bewusst NICHT in tools/vornamen.txt stehen: Hier sieht die Vornamenliste nichts.
VOR_SELTEN = ("Gieri Balz Kilian Lorin Malin Enya Jorin Nevio Leandro Elin Yara Milo Juna Laurin Mattéo Timéo Maëlle Lou Eloïse Capucine "
              "Ginette Ottavio Remigio Fiorenzo Lidia Ambra Zeno Tullio Besart Leutrim Arjeta Dardan Vlora Zlatko Ratko Svetlana Hamza "
              "Sinan Aylin Kandiah Nirosha Chinedu Ngozi Kwame Mei Hiroshi Bogdan Ionela").split()
DOPPEL_VOR = ["Hans Peter", "Hans-Peter", "Hans Rudolf", "Anna Maria", "Anna-Maria", "Jean-Pierre", "Jean-Claude", "Marie-Claire",
              "Gian Andri", "Gian-Luca", "Maria Grazia", "Pier Luigi", "Karl Heinz", "Eva-Maria", "Rosa Maria", "Jean-Marc"]
NACH = {
    "de": ("Müller Meier Schmid Keller Weber Huber Schneider Meyer Steiner Fischer Gerber Brunner Baumann Frei Zimmermann Moser Widmer "
           "Wyss Graf Roth Suter Baumgartner Bachmann Kunz Studer Bucher Hofer Lüthi Kaufmann Bühler Marti Koch Egli Arnold Zürcher "
           "Stalder Aebischer Ammann Bieri Christen Flückiger Gasser Hug Imhof Jenni Kälin Leuenberger Mäder Näf Odermatt Portmann Rüegg "
           "Schärer Tschudi Ulrich Vogel Wüthrich Zbinden Sommer Winter Klein Lang Stucki Aeschlimann Bänziger Hürlimann").split(),
    "fr": "Favre Rochat Dubois Martin Blanc Chappuis Jaquet Bonvin Pittet Rey Monnier Girard Roulin Cuennet Barbey Perret Vuilleumier".split(),
    "it": "Bernasconi Rossi Bianchi Ferrari Crivelli Pedrazzini Cavalli Lepori Fontana Colombo Gianinazzi Ambrosini Rezzonico".split(),
    "zu": "Krasniqi Shala Berisha Gashi Jovanović Petrović Marković Yılmaz Öztürk Pereira Ferreira García Nguyen Hoxha".split(),
}
PARTIKEL_NACH = ["von Allmen", "von Känel", "von Gunten", "De Luca", "Della Santa", "Di Stefano", "de Weck", "Du Pasquier", "dos Santos",
                 "da Silva", "Le Coultre", "van der Meer"]
STRASSEN = {
    "de": ("Bahnhofstrasse Dorfstrasse Hauptstrasse Kirchweg Schulhausstrasse Birkenweg Rosenweg Lindenstrasse Seestrasse Bergstrasse "
           "Mühlegasse Oberdorfstrasse Sonnenrain Postplatz Industriestrasse Zürcherstrasse Kirchgasse Feldweg Gartenstrasse Ringstrasse").split(),
    "fr": ["Rue de la Gare", "Avenue de la Paix", "Chemin des Vignes", "Route de Berne", "Rue du Lac", "Rue Saint-Martin", "Chemin du Stand"],
    "it": ["Via Cantonale", "Via San Gottardo", "Via alla Chiesa", "Viale Stazione", "Piazza Grande", "Via Lugano", "Via dei Mulini"],
}
STRASSEN_OHNE = ["Im Baumgarten", "Unterdorf", "Auf der Egg", "Am Bach", "Hinter den Gärten", "Sur la Ville", "Al Ronco"]   # kein Strassenwort
ORTE = {
    "de": ["8000 Zürich", "8400 Winterthur", "3011 Bern", "3600 Thun", "4051 Basel", "6003 Luzern", "9000 St. Gallen", "5000 Aarau",
           "8200 Schaffhausen", "7000 Chur", "6300 Zug", "2502 Biel/Bienne", "8910 Affoltern am Albis", "9500 Wil SG", "3250 Lyss",
           "4600 Olten", "8640 Rapperswil SG", "3900 Brig", "8706 Meilen", "3550 Langnau im Emmental", "6460 Altdorf UR", "8750 Glarus"],
    "fr": ["1003 Lausanne", "1201 Genève", "1700 Fribourg", "2000 Neuchâtel", "1950 Sion", "2300 La Chaux-de-Fonds",
           "1400 Yverdon-les-Bains", "1820 Montreux", "2800 Delémont", "1630 Bulle"],
    "it": ["6900 Lugano", "6500 Bellinzona", "6600 Locarno", "6850 Mendrisio", "6830 Chiasso", "6710 Biasca", "6512 Giubiasco"],
}
FIRMEN_KERN = ["Treuhand", "Immobilien", "Consulting", "Logistik", "Elektro", "Bau", "Holzbau", "Transporte", "Informatik", "Gartenbau",
               "Metallbau", "Reisen", "Optik", "Druck", "Haustechnik", "Vermögensverwaltung", "Architektur", "Sanitär"]
RECHTSFORMEN = {"de": ["AG", "GmbH", "AG", "GmbH", "& Co. KG", "Genossenschaft"], "fr": ["SA", "Sàrl", "SA", "& Cie"], "it": ["SA", "Sagl", "SA"]}
GEWERBE = {"de": ["Bäckerei", "Garage", "Metzgerei", "Schreinerei", "Restaurant", "Coiffeur", "Apotheke", "Velo", "Blumen", "Gasthof"],
           "fr": ["Boulangerie", "Garage", "Café", "Restaurant", "Fleurs"], "it": ["Ristorante", "Pizzeria", "Garage", "Bar", "Osteria"]}
KANTON_KLEIN = ["AI", "AR", "GL", "NW", "OW", "UR", "JU", "SH"]
BEHOERDEN = ["Kantonspolizei Zürich", "Kantonspolizei Bern", "Police cantonale vaudoise", "Polizia cantonale", "Stadtpolizei Winterthur",
             "Kantonspolizei Aargau", "Kantonspolizei St. Gallen", "Luzerner Polizei"]
SCHADSOFTWARE = ["LockBit", "Akira", "Emotet", "QakBot", "AgentTesla", "RedLine", "Play", "BlackCat", "Rhysida", "Lumma"]
BOERSEN = ["Binance", "Kraken", "Coinbase", "Bitfinex", "OKX", "Bybit"]
MONATE = ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"]
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


@dataclass
class Person:
    wer: str
    vorname: str
    nachname: str
    weiblich: bool
    sprache: str
    geb: tuple = (1, 1, 1980)
    strasse: str = ""
    ort: str = ""
    tel: str = ""           # Ziffern in nationaler Schreibung, «0701234567»
    email: str = ""
    ahv: str = ""           # 13 Ziffern
    iban: str = ""          # ohne Leerzeichen
    kfz: tuple = ("", "")
    ausweis: str = ""       # erfundene Ausweisnummer

    @property
    def voll(self) -> str:
        return f"{self.vorname} {self.nachname}"


# --------------------------------------------------------------------------- Bausteine

def _iban(rng: random.Random) -> str:
    konto = "00000" + "".join(rng.choice("0123456789") for _ in range(12))
    rest = int("".join(str(int(c, 36)) for c in konto + "CH00")) % 97
    return f"CH{98 - rest:02d}{konto}"


def _ahv_falsch(rng: random.Random) -> str:
    """Sieht aus wie eine AHV-Nummer, hat aber eine falsche Prüfziffer."""
    zwoelf = "756" + "".join(rng.choice("0123456789") for _ in range(9))
    summe = sum(int(z) * (3 if i % 2 else 1) for i, z in enumerate(zwoelf))
    richtig = (10 - summe % 10) % 10
    return zwoelf + str((richtig + rng.randint(1, 9)) % 10)


def _klein(s: str) -> str:
    tabelle = str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "é": "e", "è": "e", "ë": "e", "ê": "e", "à": "a", "â": "a", "ç": "c", "ï": "i",
                             "î": "i", "ô": "o", "ó": "o", "ñ": "n", "ć": "c", "č": "c", "š": "s", "ž": "z", "ı": "i", "ş": "s", "ğ": "g",
                             "ã": "a", "õ": "o", "í": "i", "á": "a", "ú": "u", "ù": "u", "û": "u"})
    return "".join(c for c in s.lower().translate(tabelle) if c.isalnum() or c in ".-")


def _person(rng: random.Random, wer: str, sprache: str, selten: bool = False) -> Person:
    art = rng.random()
    s = sprache if art < 0.75 else rng.choice(["de", "fr", "it", "zu"])
    weiblich = rng.random() < 0.5
    if selten:
        vorname = rng.choice(VOR_SELTEN)
    elif rng.random() < 0.12:
        vorname = rng.choice(DOPPEL_VOR)
    else:
        vorname = rng.choice(VOR[s])
    wurf = rng.random()
    if wurf < 0.10:
        nachname = rng.choice(NACH[s]) + "-" + rng.choice(NACH["de"])
    elif wurf < 0.14:
        nachname = rng.choice(NACH[s]) + " " + rng.choice(NACH["de"])
    elif wurf < 0.22:
        nachname = rng.choice(PARTIKEL_NACH)
    else:
        nachname = rng.choice(NACH[s])
    p = Person(wer, vorname, nachname, weiblich, sprache)
    p.geb = (rng.randint(1, 28), rng.randint(1, 12), rng.randint(1942, 2004))
    region = sprache if sprache in STRASSEN else "de"
    strasse = rng.choice(STRASSEN_OHNE) if rng.random() < 0.06 else rng.choice(STRASSEN[region])
    p.strasse = f"{strasse} {rng.randint(1, 148)}{rng.choice(['', '', '', 'a', 'b'])}"
    p.ort = rng.choice(ORTE[region])
    p.tel = rng.choice(["070", "072", "073"]) + "".join(rng.choice("0123456789") for _ in range(7)) if rng.random() < 0.8 \
        else rng.choice(["044", "031", "061", "021", "091"]) + "55501" + f"{rng.randint(0, 99):02d}"
    lokal = rng.choice([f"{_klein(vorname.split()[0])}.{_klein(nachname).replace(' ', '')}", f"{_klein(vorname)[0]}.{_klein(nachname).replace(' ', '')}",
                        f"{_klein(nachname).replace(' ', '')}{rng.randint(60, 99)}", f"{_klein(vorname.split()[0])}{rng.randint(1, 99)}"])
    p.email = f"{lokal}@{rng.choice(['example.com', 'example.org', 'example.net', 'post.example', 'mail.example'])}"
    p.ahv, p.iban = _ahv_falsch(rng), _iban(rng)
    p.kfz = (rng.choice(KANTON_KLEIN), str(rng.randint(900000, 999999)))
    p.ausweis = rng.choice("CXSE") + "".join(rng.choice("0123456789") for _ in range(7))
    return p


class Bau:
    """Setzt den Text zusammen und merkt sich, wo was steht."""

    def __init__(self) -> None:
        self.teile: list[str] = []
        self.pos = 0
        self.gold: list[Gold] = []
        self.technik: list[tuple[int, int, str]] = []

    def t(self, s: str) -> "Bau":
        self.teile.append(s)
        self.pos += len(s)
        return self

    def g(self, s: str, typ: str, wer: str, form: str, im_feld: bool = False) -> "Bau":
        self.gold.append(Gold(self.pos, self.pos + len(s), typ, wer, im_feld, form))
        return self.t(s)

    def k(self, s: str, art: str) -> "Bau":
        self.technik.append((self.pos, self.pos + len(s), art))
        return self.t(s)

    def stueck(self, teil, im_feld: bool = False) -> "Bau":
        """Ein Stück ist Text oder (Text, Typ, Angabe, Form) oder (Text, "T", Art) für einen technischen Indikator."""
        if isinstance(teil, str):
            return self.t(teil)
        if teil[1] == "T":
            return self.k(teil[0], teil[2])
        return self.g(teil[0], teil[1], teil[2], teil[3], im_feld)

    def alle(self, teile, im_feld: bool = False) -> "Bau":
        for teil in teile:
            self.stueck(teil, im_feld)
        return self


def _tel(p: Person, form: str) -> str:
    z = p.tel
    a, b, c, d = z[:3], z[3:6], z[6:8], z[8:10]
    return {"national": f"{a} {b} {c} {d}", "plus": f"+41 {a[1:]} {b} {c} {d}", "null": f"0041 {a[1:]} {b} {c} {d}", "schraeg": f"{a}/{b} {c} {d}",
            "eng": z, "klammer": f"+41 (0){a[1:]} {b} {c} {d}", "punkt": f"{a}.{b}.{c}.{d}"}[form]


def _datum(p: Person, form: str) -> str:
    t, m, j = p.geb
    return {"punkt": f"{t:02d}.{m:02d}.{j}", "kurz": f"{t}.{m}.{j}", "lang": f"{t}. {MONATE[m - 1]} {j}", "iso": f"{j}-{m:02d}-{t:02d}",
            "zwei": f"{t:02d}.{m:02d}.{j % 100:02d}"}[form]


def _ahv(p: Person, form: str) -> str:
    z = p.ahv
    return {"punkt": f"{z[:3]}.{z[3:7]}.{z[7:11]}.{z[11:]}", "eng": z, "leer": f"{z[:3]} {z[3:7]} {z[7:11]} {z[11:]}"}[form]


def _ibanf(p: Person, form: str) -> str:
    return p.iban if form == "eng" else " ".join(p.iban[i:i + 4] for i in range(0, len(p.iban), 4))


def _kfz(p: Person, form: str) -> str:
    k, n = p.kfz
    return {"leer": f"{k} {n}", "eng": f"{k}{n}", "strich": f"{k}-{n}", "gruppe": f"{k} {n[:3]} {n[3:]}"}[form]


def _strasse(p: Person, form: str) -> str:
    if form == "kurz" and "strasse" in p.strasse:
        return p.strasse.replace("strasse", "str.")
    return p.strasse


def nennung(p: Person, form: str, im_feld: bool = False) -> list:
    """Eine Person in einer bestimmten Schreibweise, als Stücke für den Bau."""
    v, n, w = p.vorname, p.nachname, p.wer
    herr = {"de": "Frau" if p.weiblich else "Herr", "fr": "Madame" if p.weiblich else "Monsieur", "it": "Signora" if p.weiblich else "Signor"}[p.sprache]
    kurz = {"de": "Fr." if p.weiblich else "Hr.", "fr": "Mme" if p.weiblich else "M.", "it": "Sig.ra" if p.weiblich else "Sig."}[p.sprache]
    initiale = "".join(f"{teil[0]}." for teil in v.replace("-", " ").split()[:1])
    if form == "voll":
        return [(f"{v} {n}", "PERSON", w, form)]
    if form == "umgekehrt":
        return [(f"{n} {v}", "PERSON", w, form)]
    if form == "komma":
        return [(f"{n}, {v}", "PERSON", w, form)]
    if form == "gross":
        return [(f"{n.upper()} {v}", "PERSON", w, form)]
    if form == "initial":
        return [(f"{initiale} {n}", "PERSON", w, form)]
    if form == "anrede":
        return [f"{herr} ", (n, "PERSON", w, form)]
    if form == "anrede_kurz":
        return [f"{kurz} ", (n, "PERSON", w, form)]
    if form == "anrede_voll":
        return [f"{herr} ", (f"{v} {n}", "PERSON", w, form)]
    if form == "nachname":
        return [(n, "PERSON", w, form)]
    if form == "genitiv":
        return [(n, "PERSON", w, form), "'" if n[-1] in "sxzß" else "s"]
    if form == "umbruch":
        return [(f"{v}\n   {n}", "PERSON", w, form)]
    if form == "trennung":
        lang = max(n.replace("-", " ").split(), key=len)
        if len(lang) < 6:
            return [(n, "PERSON", w, "nachname")]
        halb = len(lang) // 2
        return [(n.replace(lang, f"{lang[:halb]}-\n   {lang[halb:]}", 1), "PERSON", w, form)]
    if form == "vorname":
        return [(v, "PERSON", w, form)]
    if form == "klein":
        return [(f"{v} {n}".lower(), "PERSON", w, form)]
    if form == "umlaut":
        anders = n.translate(str.maketrans({"ä": "ae", "ö": "oe", "ü": "ue", "é": "e", "è": "e", "ć": "c", "ı": "i", "Ö": "Oe", "ñ": "n", "í": "i"}))
        return [(f"{v} {anders}", "PERSON", w, form if anders != n else "voll")]
    raise ValueError(form)


FORMEN = ["voll", "anrede", "nachname", "umgekehrt", "gross", "initial", "genitiv", "komma", "umbruch", "trennung", "vorname", "klein",
          "umlaut", "anrede_kurz", "anrede_voll"]

RAHMEN = {
    "de": ["Am {tag} erschien {p} auf dem Posten und erstattete Anzeige.",
           "Gemäss den Angaben von {p} wurde der Betrag ohne Wissen der Bank ausgelöst.",
           "{p} gab zu Protokoll, die Nachricht habe echt gewirkt.",
           "Auf Nachfrage erklärte {p}, das Passwort nie weitergegeben zu haben.",
           "Die Abklärungen bei der Bank ergaben, dass das Konto von {p} am {tag} belastet wurde.",
           "Der Zugang wurde nach Rücksprache mit {p} gesperrt.",
           "Im Chatverlauf schrieb die Gegenseite: «hallo {p}, bitte bestätigen sie die zahlung noch heute».",
           "Die Unterlagen wurden von {p} per Post nachgereicht.",
           "Rückfragen sind an {p} zu richten.",
           "Laut {p} begann der Kontakt über eine Anzeige in den sozialen Medien.",
           "Der Schaden für {p} beläuft sich auf CHF {betrag}.",
           "Das Mobiltelefon von {p} wurde gesichtet, es fanden sich keine weiteren Nachrichten.",
           "Zum Zeitpunkt der Zahlung befand sich {p} nach eigenen Angaben zu Hause.",
           "Ein weiterer Kontakt mit {p} ist für den {tag} vereinbart.",
           "Nach Aussage von {p} verlangte der Anrufer die sofortige Installation einer Fernwartung."],
    "fr": ["Le {tag}, {p} s'est présenté au poste pour déposer plainte.",
           "Selon les déclarations de {p}, le montant a été débité sans autorisation.",
           "Interrogé à ce sujet, {p} a indiqué n'avoir jamais transmis le mot de passe.",
           "Le compte de {p} a été débité le {tag}.",
           "Les documents ont été transmis par {p} par courrier.",
           "Le dommage subi par {p} s'élève à CHF {betrag}."],
    "it": ["Il {tag} {p} si è presentato allo sportello per sporgere denuncia.",
           "Secondo le dichiarazioni di {p}, l'importo è stato addebitato senza autorizzazione.",
           "Il conto di {p} è stato addebitato il {tag}.",
           "I documenti sono stati trasmessi da {p} per posta.",
           "Il danno subito da {p} ammonta a CHF {betrag}."],
}
RAHMEN_DRITT = {
    "de": ["Den Kontakt zur Plattform hatte {d} hergestellt.",
           "Als Auskunftsperson wurde {d} telefonisch befragt.",
           "Die Buchhaltung führt {d}, die den Abfluss als Erste bemerkte.",
           "Der Nachbar, {d}, hatte eine ähnliche Nachricht erhalten.",
           "Vom Arbeitgeber meldete sich {d} und bestätigte die Angaben.",
           "Die Schwester der geschädigten Person, {d}, begleitete sie auf den Posten.",
           "{d} von der Hausbank sperrte die Karte noch am selben Tag."],
    "fr": ["La comptabilité est tenue par {d}, qui a remarqué le débit en premier.", "Le voisin, {d}, avait reçu un message semblable.",
           "{d}, de la banque, a bloqué la carte le jour même."],
    "it": ["La contabilità è tenuta da {d}, che ha notato per primo l'addebito.", "Il vicino, {d}, aveva ricevuto un messaggio simile.",
           "{d}, della banca, ha bloccato la carta il giorno stesso."],
}
RAHMEN_FIRMA = {
    "de": ["Die Rechnung war angeblich von der {f} ausgestellt.", "Bei der {f} gingen am selben Tag drei gleichlautende Nachrichten ein.",
           "Ein Mitarbeiter der {f} bestätigte, dass keine solche Bestellung vorliegt.", "Die Ware sollte an die {f} geliefert werden.",
           "Der Lohn wird von der {f} jeweils am 25. überwiesen."],
    "fr": ["La facture aurait été émise par {f}.", "Un collaborateur de {f} a confirmé qu'aucune commande n'existait."],
    "it": ["La fattura sarebbe stata emessa dalla {f}.", "Un collaboratore della {f} ha confermato che non esiste alcun ordine."],
}
UEBERSCHRIFT = {"de": ("RAPPORT", "Sachverhalt", "Technische Feststellungen", "Weitere Angaben", "Massnahmen"),
                "fr": ("RAPPORT", "Faits", "Constatations techniques", "Autres indications", "Mesures"),
                "it": ("RAPPORTO", "Fatti", "Accertamenti tecnici", "Altre indicazioni", "Misure")}


def _hex(rng: random.Random, n: int) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def _technik(rng: random.Random) -> list:
    """Sätze mit technischen Indikatoren. Alles darin muss stehen bleiben."""
    ip = rng.choice([f"192.0.2.{rng.randint(1, 254)}", f"198.51.100.{rng.randint(1, 254)}", f"203.0.113.{rng.randint(1, 254)}"])
    ip6 = f"2001:db8:{rng.randint(1, 0xffff):x}::{rng.randint(1, 0xffff):x}"
    name = rng.choice(["sichere-zahlung", "kundenportal-login", "paket-verfolgung", "e-banking-update", "invest-pro", "konto-pruefung"])
    domain = rng.choice([f"{name}.example", f"{name}.example.com", f"login.{name}.example.net", f"{name}.example.org"])
    url = rng.choice([f"https://{domain}/login.php?id={rng.randint(1000, 99999)}", f"http://{domain}/konto/bestaetigen",
                      f"hxxps://{domain.replace('.', '[.]')}/auth"])
    btc = "bc1q" + "".join(rng.choice(B32) for _ in range(38))
    alt = "1" + "".join(rng.choice(B58) for _ in range(33))
    eth = "0x" + _hex(rng, 40)
    tron = "T" + "".join(rng.choice(B58) for _ in range(33))
    absender = f"{rng.choice(['support', 'service', 'kundendienst', 'info', 'no-reply', 'sicherheit'])}@{domain}"
    onion = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(56)) + ".onion"
    datei = rng.choice(["Rechnung_2026.pdf.exe", "Lieferschein.docm", "update_setup.msi", "Zahlungsbeleg.zip", "scan0042.js"])
    saetze = [
        ["Die Anmeldung erfolgte ab der IP-Adresse ", (ip, "T", "IP-Adresse"), f" am {rng.randint(1, 28):02d}.0{rng.randint(1, 9)}.2026 um "
         f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d} Uhr."],
        ["Der Link in der Nachricht führte auf ", (url, "T", "URL"), "."],
        ["Die Domain ", (domain, "T", "Domain"), " wurde wenige Tage zuvor registriert."],
        ["Als Absender war ", (absender, "T", "E-Mail Täterseite"), " angegeben."],
        ["Die Zahlung ging an die Adresse ", (rng.choice([btc, alt]), "T", "Wallet-Adresse"), " (Bitcoin), Transaktion ",
         (_hex(rng, 64), "T", "Transaktions-ID"), "."],
        ["Ein weiterer Betrag in USDT ging an ", (rng.choice([tron, eth]), "T", "Wallet-Adresse"), "."],
        ["Der Anhang ", (datei, "T", "Dateiname"), " hat den SHA-256-Wert ", (_hex(rng, 64), "T", "Hash"), "."],
        ["Im Protokoll der Firewall erscheint zusätzlich ", (ip6, "T", "IP-Adresse"), "."],
        ["Die Gruppe verweist auf ihre Seite ", (onion, "T", "Onion-Adresse"), "."],
        [f"Die Schadsoftware wird der Familie {rng.choice(SCHADSOFTWARE)} zugeordnet, MD5 ", (_hex(rng, 32), "T", "Hash"), "."],
        [f"Das Geld wurde laut Auskunft bei {rng.choice(BOERSEN)} in Bitcoin gewechselt."],
        [f"Die Statistik des Kantons weist für {rng.choice(['ZH', 'BE', 'SG', 'AG'])} {rng.choice([2024, 2025])} einen Anstieg solcher Fälle aus."],
    ]
    koeder = saetze.pop()       # sieht aus wie ein Kontrollschild, ist aber Kanton und Jahr: nur in jedem siebten Dokument
    rng.shuffle(saetze)
    return saetze[:rng.randint(5, 9)] + ([koeder] if rng.random() < 0.15 else [])


# --------------------------------------------------------------------------- Kopf mit den Feldmarken

def _kopf(b: Bau, rng: random.Random, marken: ps.Marken, nr: int, aufbau: str, personen: list, firma: tuple | None, sb: Person) -> None:
    """Schreibt die Felder. Die Marken kommen reihum aus der Datei, damit jede vorkommt."""
    zaehler = [nr]

    def marke(typ: str, teil: str = "") -> str | None:
        liste = marken.nach_typ(typ, teil)
        if not liste:
            return None
        zaehler[0] += 1
        return liste[zaehler[0] % len(liste)].marke

    def feld(m: str | None, wert: list, art: str | None = None) -> None:
        if m is None:
            return
        art = art or aufbau
        if art == "punkt":
            b.t(f"{m}: ")
        elif art == "ohne":
            b.t(m.ljust(max(len(m) + 2, 26)))
        elif art == "einfach":
            b.t(f"{m} ")
        elif art == "naechste":
            b.t(f"{m}{rng.choice([':', ''])}\n")
        elif art == "tabelle":
            b.t(f"| {m} | ")
        elif art == "tab":
            b.t(f"{m}{rng.choice([':', ''])}\t")
        b.alle(wert, im_feld=True)
        b.t(" |\n" if art == "tabelle" else "\n")

    def person_felder(p: Person, voll: bool) -> None:
        wie = rng.random()
        zusammen = marke("PERSON", "nachname-vorname")
        einzeln_n, einzeln_v, ganz = marke("PERSON", "nachname"), marke("PERSON", "vorname"), marke("PERSON", "name")
        andersherum = marke("PERSON", "vorname-nachname")
        if wie < 0.12 and andersherum:
            feld(andersherum, [(f"{p.vorname}{' / ' if '/' in andersherum and rng.random() < 0.5 else ' '}{p.nachname}", "PERSON", p.wer, "feld")])
        elif wie < 0.45 and einzeln_n and einzeln_v:
            feld(einzeln_n, [(p.nachname.upper() if rng.random() < 0.15 else p.nachname, "PERSON", p.wer, "feld")])
            feld(einzeln_v, [(p.vorname, "PERSON", p.wer, "feld")])
        elif wie < 0.75 and zusammen:
            trenner = rng.choice([" ", ", ", " / "]) if ("/" in zusammen or "," in zusammen) else rng.choice([" ", ", "])
            feld(zusammen, [(f"{p.nachname}{trenner}{p.vorname}", "PERSON", p.wer, "feld")])
        elif ganz:
            form = rng.choice([f"{p.vorname} {p.nachname}", f"{p.nachname} {p.vorname}", f"{p.nachname.upper()} {p.vorname}", f"{p.nachname}, {p.vorname}"])
            feld(ganz, [(form, "PERSON", p.wer, "feld")])
        if not voll:
            return
        feld(marke("GEBDAT"), [(_datum(p, rng.choice(["punkt", "punkt", "kurz", "lang"])), "GEBDAT", p.wer + ".geb", "feld")])
        if rng.random() < 0.6 or not marken.nach_typ("ADRESSE", "strasse") or not marken.nach_typ("ADRESSE", "ort"):
            m = marke("ADRESSE", "adresse")
            if m and rng.random() < 0.25 and aufbau in ("punkt", "ohne"):      # Ort auf der Folgezeile
                einzug = " " * (len(m) + 2 if aufbau == "punkt" else max(len(m) + 2, 26))
                feld(m, [(p.strasse, "ADRESSE", p.wer + ".adr", "feld"), "\n" + einzug, (p.ort, "ADRESSE", p.wer + ".adr", "feld")])
            else:
                feld(m, [(f"{p.strasse}, {p.ort}", "ADRESSE", p.wer + ".adr", "feld")])
        else:
            feld(marke("ADRESSE", "strasse"), [(p.strasse, "ADRESSE", p.wer + ".adr", "feld")])
            feld(marke("ADRESSE", "ort"), [(p.ort, "ADRESSE", p.wer + ".adr", "feld")])
        feld(marke("TEL"), [(_tel(p, rng.choice(["national", "national", "plus", "schraeg", "eng"])), "TEL", p.wer + ".tel", "feld")])
        feld(marke("EMAIL"), [(p.email, "EMAIL", p.wer + ".mail", "feld")])
        if rng.random() < 0.7:
            feld(marke("AHV"), [(_ahv(p, rng.choice(["punkt", "punkt", "eng"])), "AHV", p.wer + ".ahv", "feld")])
        if rng.random() < 0.7:
            feld(marke("KONTO"), [(_ibanf(p, rng.choice(["gruppe", "gruppe", "eng"])), "KONTO", p.wer + ".iban", "feld")])
        if rng.random() < 0.4:
            feld(marke("KFZ"), [(_kfz(p, rng.choice(["leer", "leer", "strich"])), "KFZ", p.wer + ".kfz", "feld")])
        if rng.random() < 0.5:
            feld(marke("AUSWEIS"), [(p.ausweis, "AUSWEIS", p.wer + ".ausweis", "feld")])

    rang = rng.choice(["Wm ", "Kpl ", "Gfr ", "Wm mbA ", ""])
    m = marke("PERSON", "name")
    if m:
        feld(m, [rang, (rng.choice([sb.voll, f"{sb.nachname} {sb.vorname}"]), "PERSON", sb.wer, "feld")], "punkt" if aufbau in ("spalten", "mehrfach") else None)
    if rng.random() < 0.3 and marken.nach_typ("PERSON", "kuerzel"):
        kuerzel = (_klein(sb.nachname)[:2] + _klein(sb.vorname)[:1]).replace("-", "")
        feld(marke("PERSON", "kuerzel"), [(kuerzel, "PERSON", sb.wer + ".kz", "kuerzel")], "punkt")
    b.t("\n")
    if aufbau == "spalten" and marken.nach_typ("PERSON", "nachname") and marken.nach_typ("PERSON", "vorname") and marken.nach_typ("GEBDAT"):
        spalten = [marke("PERSON", "nachname"), marke("PERSON", "vorname"), marke("GEBDAT"), marke("TEL")]
        b.t("| " + " | ".join(s for s in spalten if s) + " |\n|" + "---|" * len([s for s in spalten if s]) + "\n")
        for p in personen:
            b.t("| ").g(p.nachname, "PERSON", p.wer, "feld", True).t(" | ").g(p.vorname, "PERSON", p.wer, "feld", True).t(" | ")
            b.g(_datum(p, "punkt"), "GEBDAT", p.wer + ".geb", "feld", True)
            if spalten[3]:
                b.t(" | ").g(_tel(p, "national"), "TEL", p.wer + ".tel", "feld", True)
            b.t(" |\n")
        b.t("\n")
        rest = "punkt"
        for p in personen[:1]:
            m = marke("ADRESSE", "adresse")
            feld(m, [(f"{p.strasse}, {p.ort}", "ADRESSE", p.wer + ".adr", "feld")], rest)
            feld(marke("EMAIL"), [(p.email, "EMAIL", p.wer + ".mail", "feld")], rest)
            feld(marke("KONTO"), [(_ibanf(p, "gruppe"), "KONTO", p.wer + ".iban", "feld")], rest)
    elif aufbau == "mehrfach" and marken.nach_typ("PERSON", "nachname") and marken.nach_typ("PERSON", "vorname"):
        for p in personen:
            b.t(f"{marke('PERSON', 'nachname')}: ").g(p.nachname, "PERSON", p.wer, "feld", True)
            b.t(f"    {marke('PERSON', 'vorname')}: ").g(p.vorname, "PERSON", p.wer, "feld", True)
            g = marke("GEBDAT")
            if g:
                b.t(f"    {g}: ").g(_datum(p, "punkt"), "GEBDAT", p.wer + ".geb", "feld", True)
            b.t("\n")
            feld(marke("ADRESSE", "adresse"), [(f"{p.strasse}, {p.ort}", "ADRESSE", p.wer + ".adr", "feld")], "punkt")
            t, e = marke("TEL"), marke("EMAIL")
            if t and e:
                b.t(f"{t}: ").g(_tel(p, "national"), "TEL", p.wer + ".tel", "feld", True).t(f"    {e}: ").g(p.email, "EMAIL", p.wer + ".mail", "feld", True).t("\n")
            b.t("\n")
    else:
        for i, p in enumerate(personen):
            b.t({"de": ["Geschädigte Person", "Weitere beteiligte Person"], "fr": ["Personne lésée", "Autre personne concernée"],
                 "it": ["Persona lesa", "Altra persona coinvolta"]}[p.sprache][min(i, 1)] + "\n")
            person_felder(p, voll=True)
            b.t("\n")
    if firma:
        wer, name, strasse, ort = firma
        feld(marke("ORG"), [(name, "ORG", wer, "feld")], "punkt" if aufbau in ("spalten", "mehrfach") else None)
        if rng.random() < 0.6:
            feld(marke("ADRESSE", "adresse"), [(f"{strasse}, {ort}", "ADRESSE", wer + ".adr", "feld")], "punkt" if aufbau in ("spalten", "mehrfach") else None)
        b.t("\n")


# --------------------------------------------------------------------------- Ein Rapport

AUFBAUTEN = ["punkt", "punkt", "ohne", "naechste", "tabelle", "tab", "spalten", "mehrfach", "einfach"]


def rapport(nr: int, marken: ps.Marken | None = None) -> Dokument:
    marken = marken or ps.feldmarken_lesen()
    rng = random.Random(nr * 7919 + 17)
    sprache = "de" if nr % 10 < 7 else ("fr" if nr % 10 < 9 else "it")
    aufbau = AUFBAUTEN[nr % len(AUFBAUTEN)]
    b = Bau()
    namen: dict[str, tuple[str, str]] = {}
    titel, sachverhalt, technisch, weiteres, massnahmen = UEBERSCHRIFT[sprache]
    sb = _person(rng, "S", sprache)
    personen = [_person(rng, "P1", sprache)]
    if rng.random() < 0.4:
        zweite = _person(rng, "P2", sprache)
        if rng.random() < 0.5:      # Ehepaar: gleicher Nachname, gleiche Adresse
            zweite.nachname, zweite.strasse, zweite.ort = personen[0].nachname, personen[0].strasse, personen[0].ort
            zweite.weiblich = not personen[0].weiblich
        personen.append(zweite)
    firma = None
    if rng.random() < 0.4:
        region = sprache if sprache in STRASSEN else "de"
        kern = f"{rng.choice(NACH[region])} {rng.choice(FIRMEN_KERN)}"
        firma = ("F1", f"{kern} {rng.choice(RECHTSFORMEN[region])}", f"{rng.choice(STRASSEN[region])} {rng.randint(1, 90)}", rng.choice(ORTE[region]), kern)
        namen["F1"] = ("ORG", firma[1])
    dritte = [_person(rng, f"D{i + 1}", sprache, selten=rng.random() < 0.3) for i in range(rng.randint(1, 3))]
    for p in [sb] + personen + dritte:
        namen[p.wer] = ("PERSON", p.voll)

    b.t(f"{rng.choice(BEHOERDEN).upper()}\n{rng.choice(['Dienst Cybercrime', 'Regionalpolizei', 'Kriminalabteilung', 'Posten Bahnhof'])}\n\n{titel}\n")
    b.t(f"Rapport-Nr.: R-2026-{rng.randint(1000, 99999):06d}\nDatum: {rng.randint(1, 28):02d}.{rng.randint(1, 12):02d}.2026\n")
    b.t(f"Betreff: {rng.choice(['Betrug (Phishing)', 'Betrügerischer Missbrauch einer Datenverarbeitungsanlage', 'Erpressung (Ransomware)', 'Anlagebetrug', 'Betrug auf Kleinanzeigenplattform'])}\n\n")
    _kopf(b, rng, marken, nr, aufbau, personen, firma[:4] if firma else None, sb)

    # --- Fliesstext
    absaetze: list[list] = []

    def tag() -> str:
        return f"{rng.randint(1, 28):02d}.{rng.randint(1, 12):02d}.2026"

    def satz(rahmen: str, schluessel: str, stuecke: list) -> list:
        vor, nach = rahmen.split("{" + schluessel + "}")
        fuellen = {"tag": tag(), "betrag": f"{rng.randint(1, 95)}'{rng.randint(0, 999):03d}.00"}
        for k, v in fuellen.items():
            vor, nach = vor.replace("{" + k + "}", v), nach.replace("{" + k + "}", v)
        return [vor] + stuecke + [nach]

    formen = FORMEN[:]
    rng.shuffle(formen)
    for i, form in enumerate(formen):       # jede Schreibweise mindestens einmal, reihum über die Personen im Kopf
        p = (personen + [sb])[i % (len(personen) + 1)] if i % 4 == 3 else personen[i % len(personen)]
        rahmen = rng.choice(RAHMEN[sprache])
        if form == "klein":
            rahmen = RAHMEN["de"][6] if sprache == "de" else rahmen
        absaetze.append(satz(rahmen, "p", nennung(p, form)))
    p1 = personen[0]
    weitere = [
        ["Wohnhaft ist die geschädigte Person an der ", (_strasse(p1, "kurz"), "ADRESSE", "P1.adr", "strasse kurz"), "."],
        ["Die Post geht an ", (f"{p1.strasse}, {p1.ort}", "ADRESSE", "P1.adr", "voll"), "."],
        ["Gemeldet ist sie in ", (p1.ort, "ADRESSE", "P1.adr", "plz ort"), "."],
        ["Telefonisch ist sie unter ", (_tel(p1, rng.choice(["plus", "null", "klammer", "eng", "punkt", "schraeg"])), "TEL", "P1.tel", "andere Schreibung"), " erreichbar."],
        ["Die Person (geb. ", (_datum(p1, rng.choice(["kurz", "punkt"])), "GEBDAT", "P1.geb", "mit Stichwort"), ") ist nicht vorbestraft."],
        ["Laut Ausweis geboren am ", (_datum(p1, "lang"), "GEBDAT", "P1.geb", "ausgeschrieben"), "."],
        ["Im Formular der Bank steht als Geburtstag der ", (_datum(p1, rng.choice(["iso", "zwei", "punkt"])), "GEBDAT", "P1.geb", "ohne Stichwort"), "."],
        ["Die Bestätigung ging an ", (p1.email, "EMAIL", "P1.mail", "im Text"), "."],
        ["Belastet wurde das Konto ", (_ibanf(p1, rng.choice(["eng", "gruppe"])), "KONTO", "P1.iban", "im Text"), "."],
        ["Die AHV-Nummer lautet ", (_ahv(p1, rng.choice(["punkt", "eng", "leer"])), "AHV", "P1.ahv", "im Text"), "."],
        ["Das Fahrzeug mit dem Kontrollschild ", (_kfz(p1, rng.choice(["leer", "eng", "strich", "gruppe"])), "KFZ", "P1.kfz", "im Text"), " stand vor dem Haus."],
        ["Vorgelegt wurde der Ausweis ", (p1.ausweis, "AUSWEIS", "P1.ausweis", "im Text"), "."],
    ]
    rng.shuffle(weitere)
    absaetze += weitere[:rng.randint(5, 9)]

    for d in dritte:        # Drittpersonen: in keinem Feld
        erste = rng.choice(["anrede_voll", "voll", "voll", "anrede", "umgekehrt", "anrede_kurz", "gross"])
        absaetze.append(satz(rng.choice(RAHMEN_DRITT[sprache]), "d", nennung(d, erste)))
        if rng.random() < 0.7:
            absaetze.append(satz(rng.choice(RAHMEN[sprache]), "p", nennung(d, rng.choice(["nachname", "anrede", "genitiv", "initial"]))))
        wurf = rng.random()
        if wurf < 0.25:
            absaetze.append(["Erreichbar unter ", (_tel(d, rng.choice(["national", "plus", "eng", "schraeg"])), "TEL", d.wer + ".tel", "Drittperson"), "."])
        elif wurf < 0.45:
            absaetze.append(["Wohnhaft an der ", (f"{d.strasse}, {d.ort}", "ADRESSE", d.wer + ".adr", "Drittperson"), "."])
        elif wurf < 0.55:
            absaetze.append(["Ihre Adresse lautet ", (d.email, "EMAIL", d.wer + ".mail", "Drittperson"), "."])
    if firma:
        absaetze.append(satz(rng.choice(RAHMEN_FIRMA[sprache]), "f", [(firma[1], "ORG", "F1", "voll")]))
        absaetze.append(satz(rng.choice(RAHMEN_FIRMA[sprache]), "f", [(firma[4], "ORG", "F1", "ohne Rechtsform")]))
        absaetze.append(["Sitz der Firma: ", (f"{firma[2]}, {firma[3]}", "ADRESSE", "F1.adr", "voll"), "."])
    for i in range(rng.randint(0, 2)):      # Firmen, die in keinem Feld stehen
        region = sprache if sprache in STRASSEN else "de"
        wer = f"G{i + 1}"
        if rng.random() < 0.65:
            kern = f"{rng.choice(NACH[region])} {rng.choice(FIRMEN_KERN)}"
            name = f"{kern} {rng.choice(RECHTSFORMEN[region])}"
            absaetze.append(satz(rng.choice(RAHMEN_FIRMA[sprache]), "f", [(name, "ORG", wer, "mit Rechtsform")]))
            if rng.random() < 0.5:
                absaetze.append(satz(rng.choice(RAHMEN_FIRMA[sprache]), "f", [(kern, "ORG", wer, "ohne Rechtsform")]))
        else:
            name = f"{rng.choice(GEWERBE[region])} {rng.choice(NACH[region])}"
            absaetze.append(satz(rng.choice(RAHMEN_FIRMA[sprache]), "f", [(name, "ORG", wer, "ohne Rechtsform, Gewerbe")]))
        namen[wer] = ("ORG", name)
    absaetze += _technik(rng)
    absaetze.append(["Der Rapport geht zur Kenntnis an die Staatsanwaltschaft. Herr Staatsanwalt wird um Weisung ersucht."])
    rng.shuffle(absaetze)

    b.t(f"{sachverhalt}\n")
    drittel = max(1, len(absaetze) // 3)
    for i, teile in enumerate(absaetze):
        if i == drittel:
            b.t(f"\n{technisch}\n")
        elif i == 2 * drittel:
            b.t(f"\n{weiteres}\n")
        b.t(f"{i + 1}. ").alle(teile).t("\n")
    b.t(f"\n{massnahmen}\nDie Bank wurde um Sperrung ersucht. Weitere Abklärungen folgen.\n\n")
    m = marken.nach_typ("PERSON", "name")
    if m:
        b.t(f"{m[(nr + 3) % len(m)].marke}: {rng.choice(['Wm ', 'Kpl ', ''])}")
        b.alle(nennung(sb, rng.choice(["voll", "initial", "nachname"])), im_feld=True).t("\n")
    return Dokument(nr, "".join(b.teile), b.gold, b.technik, namen, sprache, aufbau)


def pruefsatz(anzahl: int = ANZAHL, marken: ps.Marken | None = None, ab: int = 1) -> list[Dokument]:
    marken = marken or ps.feldmarken_lesen()
    return [rapport(nr, marken) for nr in range(ab, ab + anzahl)]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--anzahl", type=int, default=ANZAHL)
    p.add_argument("--zeigen", type=int, metavar="NR", help="ein Dokument mit seiner Lösung ausgeben")
    p.add_argument("--nach", metavar="ORDNER", help="alle Dokumente als Textdateien schreiben")
    p.add_argument("--feldmarken", metavar="DATEI", help="andere Feldmarken-Datei")
    a = p.parse_args()
    marken = ps.feldmarken_lesen(Path(a.feldmarken) if a.feldmarken else None)
    if a.zeigen:
        d = rapport(a.zeigen, marken)
        print(d.text)
        print("--- Lösung")
        for g in d.gold:
            print(f"  {g.typ:8} {g.wer:8} {'Feld' if g.im_feld else 'Text':5} {g.form:22} {d.text[g.start:g.ende]!r}")
        print("--- bleibt stehen")
        for start, ende, art in d.technik:
            print(f"  {art:22} {d.text[start:ende]}")
        return 0
    satz = pruefsatz(a.anzahl, marken)
    if a.nach:
        ordner = Path(a.nach)
        ordner.mkdir(parents=True, exist_ok=True)
        for d in satz:
            (ordner / f"rapport_{d.nr:03d}.txt").write_text(d.text, encoding="utf-8")
        print(f"{len(satz)} Dokumente geschrieben nach {ordner}")
    gold = [g for d in satz for g in d.gold]
    print(f"{len(satz)} Dokumente, {len(gold)} Stellen mit Personendaten, {sum(len(d.technik) for d in satz)} technische Indikatoren")
    for typ in ps.TYPEN:
        n = [g for g in gold if g.typ == typ]
        if n:
            print(f"  {typ:8} {len(n):5}   davon in einem Feld {sum(g.im_feld for g in n)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
