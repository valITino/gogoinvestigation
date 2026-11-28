"""Robin: Dark-Web-Suche über Tor, als eigener MCP-Server neben dem Gateway. Was die übrigen Teile über ihn wissen müssen,
steht an dieser einen Stelle. Nur Standardbibliothek: Auch der Sitzungs-Hook und die Oberfläche laden dieses Modul.

    BEREICHE            die vier Untersuchungsbereiche von Robin. Der Sachbearbeiter wählt einen mit der Freigabe darkweb
    text_aus()          die Antwort eines Robin-Werkzeugs als Text, so wie Robin sie schrieb
    einordnen()         was eine Antwort bedeutet: ausgeführt, nichts gefunden, nicht ausgeführt, Fehler
    eingeordnet()       ein Protokolleintrag, so wie er auszuwerten ist: Ältere Einträge werden aus der gesicherten Antwort eingeordnet
    lesen()             Treffer und gelesene Seiten aus einer Antwort, für Oberfläche, Datenblätter und Protokoll
    absage()            weshalb ein Aufruf in diesem Fall nicht zulässig ist. Leer, wenn nichts dagegen spricht
    aktive_massnahme()  ob ein Aufruf ein Ziel im offenen Netz berührt (robin_scrape mit allow_clearweb)
    verstoss()          dasselbe als Feststellung für das Protokoll, getrennt vom Rat an den Analysten
    host_aus()          der Host einer Adresse, wenn sie sich auf genau eine Art lesen lässt. Sonst None
    onion_host()        der Onion-Dienst hinter einer Adresse
    sperrliste_werte()  die Einträge der Sperrliste von Ahmia, wenn der Text eine solche Liste ist. Sonst None
    sperrliste_stand()  ob eine Onion-Adresse in diesem Fall gegen die Sperrliste von Ahmia geprüft wurde und was herauskam
    sperrliste_urteil() was eine einzelne protokollierte Prüfung ergab

Robin antwortet in Textform. Die erste Zeile nennt den Stand («status: ok», «status: tor_bootstrapping», «error: …»), was
von fremden Seiten stammt, steht zwischen Begrenzern. Die Formen sind am Abbild abgelesen, das plattform.ROBIN_ABBILD festlegt
(Robin 1.30.0, Stand bei Docker Hub vom 3.10.2026), mit Robins eigenem Servercode und gestelltem Netz (20.11.2026).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Callable

from .akte import freigabe_erteilt, jsonl_lesen

SERVER = "robin"
PRAEFIX = "mcp__robin__"
QUELLE = "Robin (Tor)"

# Die Untersuchungsbereiche (bei Robin: preset). Robin sucht nur in einem Bereich, den ein Mensch gewählt hat. An diesem
# Arbeitsplatz wählt ihn der Sachbearbeiter mit der Freigabe darkweb. Die Schlüssel sind die von Robin.
BEREICHE: dict[str, tuple[str, str]] = {
    "threat_intel": ("Allgemeine Lage", "Spuren, Akteure und Ansatzpunkte ohne festen Schwerpunkt"),
    "ransomware_malware": ("Ransomware und Schadsoftware", "Gruppen, Leak-Seiten, Schadsoftware-Familien, Infrastruktur"),
    "corporate_espionage": ("Datenabfluss bei Organisationen", "angebotene oder veröffentlichte Daten von Firmen und Behörden"),
    "personal_identity": ("Personen und Konten", "offengelegte Angaben zu Konten, Aliasnamen und E-Mail-Adressen der Täterseite"),
}
BEREICH_MIT_PERSONENBEZUG = "personal_identity"     # braucht zusätzlich die Freigabe personenbezug

# Was an diesem Arbeitsplatz nicht verwendet wird, mit dem Grund. Die Berechtigungen des Projekts verbieten beide Werkzeuge.
NICHT_VERWENDET = {
    "robin_investigate": "Es öffnet Seiten von sich aus, ohne die Prüfung gegen die Sperrliste, und gibt die gelesenen Seiten nicht "
                         "einzeln zurück: Sie lägen nicht als Belege in der Fallakte. Ein eigenes Sprachmodell hat Robin hier ohnehin nicht.",
    "robin_save_investigation": "Es legte eine zweite Kopie der Ergebnisse ausserhalb der Fallakte ab. Jede Antwort von Robin steht schon "
                                "als Beleg in der Fallakte.",
}
# Werkzeuge, die über Tor nach aussen gehen. Die übrigen (refine, filter, die Listen) arbeiten im Container.
NACH_AUSSEN = ("robin_search", "robin_scrape", "robin_investigate")

# Platzhalter stehen in eckigen Klammern: [PERSON_01]. Dokumente aus Werkzeugen im Haus schreiben sie manchmal ohne Klammern (PERSON_03),
# und die PII-Prüfung nimmt diese Form als Platzhalter an (tools/pii_pruefung.py). Bis zum 23.11.2026 erkannte die Regel für den Suchtext
# nur Klammern und Grossbuchstaben: «PERSON_03 leak» und «[person_01]» gingen an die Suchmaschinen. Ohne Klammern gelten hier nur die
# Typen, die dieser Arbeitsplatz vergibt (tools/_pseudo.py, TYPEN): Das breite Muster der PII-Prüfung träfe auch Suchbegriffe wie
# «LOCKBIT_30».
PLATZHALTER_TYPEN = ("PERSON", "ORG", "ADRESSE", "TEL", "EMAIL", "GEBDAT", "AHV", "KONTO", "KFZ", "AUSWEIS", "DOMAIN", "IP")
PLATZHALTER = re.compile(r"(?i:\[\s*[A-ZÄÖÜ][A-ZÄÖÜ_]*_\d+\s*\])|(?<![\w\[])(?:" + "|".join(PLATZHALTER_TYPEN) + r")_\d{1,3}(?![\w\]])")
ONION_HOST = re.compile(r"([a-z2-7]{16}|[a-z2-7]{56})\.onion")
# Eine Adresse in der strengen Form: höchstens http oder https, im Host-Teil nur Buchstaben, Ziffern, Punkt und Bindestrich, auf Wunsch
# ein Port, danach Pfad, Abfrage oder Anker aus sichtbaren ASCII-Zeichen ohne Rückstrich. Kein Benutzerteil («@» im Host-Teil).
_ADRESSE = re.compile(r"(?:https?://)?([a-z0-9.-]{1,253})(?::[0-9]{1,5})?(?:[/?#][!-\[\]-~]*)?")
# Ein Onion-Dienst im Namen eines Hosts im offenen Netz: Tor2Web-Dienste liefern die Seite <name>.onion unter <name>.onion.ly und ähnlich aus
_DIENST_IM_HOST = re.compile(r"(?:^|\.)([a-z2-7]{16}|[a-z2-7]{56})\.onion\.")
_STAND = re.compile(r"\A\s*(status|error)\s*:\s*([^\n]*)")
_ZAUN = re.compile(r'<<<ROBIN_UNTRUSTED_CONTENT source="([^"\n]*)">>>\n(?:UNTRUSTED DATA:[^\n]*\n)?(.*?)\n?<<<END_ROBIN_UNTRUSTED_CONTENT>>>', re.S)
_TREFFER = re.compile(r"^\s*(\d+)\.\s+\[([A-Za-z0-9_-]{1,40})\]\s*(.*)\n\s+(\S+)\s*$", re.M)
_SEITE = re.compile(r"^## (\S+)\nstatus: ([a-z_]+)(?: \(http (\d{3})\))?\n", re.M)
# Die Verweisliste am Schluss einer gelesenen Seite. Jede Zeile der Liste endet am Zeilenende oder am Schluss des Inhalts, nirgends
# sonst: So gibt es für eine Zeile genau eine Lesart. Bis zum 23.11.2026 war das Zeilenende freigestellt («\n?»). Stand die Überschrift
# mitten im Seitentext über einer Zeile aus lauter «- », probierte der Ausdruck jede Aufteilung dieser Zeile durch (28 Wiederholungen:
# 36 Sekunden, jede weitere das Doppelte). Der Sitzungs-Hook lief über sein Zeitlimit, und die Antwort wurde kein Beleg.
_VERWEISE = re.compile(r"\n\nOnion links on this page \((\d+)\)[^\n]*\n((?:- [^\n]*(?:\n|\Z))+)\s*\Z")
GEKUERZT = "...(truncated)"


# --------------------------------------------------------------------------- Antwort lesen

def text_aus(antwort: object) -> str:
    """Die Antwort eines Robin-Werkzeugs als Text. Claude Code reicht sie dem Hook verpackt weiter: als JSON-Text der Form
    {"result": "…"} (gesehen am 20.11.2026 mit Claude Code 2.1.329), sonst als Liste von Textblöcken. Beides wird ausgepackt.
    Lässt sich nichts auspacken, kommt die Antwort als JSON-Text zurück: Verloren geht nichts."""
    if isinstance(antwort, str):
        text = antwort
    elif isinstance(antwort, list):
        teile = [b.get("text") for b in antwort if isinstance(b, dict) and isinstance(b.get("text"), str)]
        text = "\n".join(teile) if teile else json.dumps(antwort, ensure_ascii=False)
    elif isinstance(antwort, dict):
        if isinstance(antwort.get("result"), str):
            return antwort["result"]
        if isinstance(antwort.get("content"), list):
            return text_aus(antwort["content"])
        return json.dumps(antwort, ensure_ascii=False)
    else:
        return "" if antwort is None else json.dumps(antwort, ensure_ascii=False)
    if text.lstrip().startswith("{"):
        try:
            innen = json.loads(text)
        except ValueError:
            return text
        if isinstance(innen, dict) and isinstance(innen.get("result"), str):
            return innen["result"]
    return text


_FEHLERSATZ = (
    ("not an onion host", "Eine verlangte Adresse ist keine Onion-Adresse. Es wurde nichts gelesen."),
    ("unknown preset", "Der genannte Untersuchungsbereich ist Robin unbekannt. Es wurde nichts gesucht."),
    ("no robin_search has run", "In dieser Sitzung wurde noch nicht gesucht. Es gab nichts zu tun."),
    ("robin_filter has not run", "Seiten wurden über Treffernummern verlangt, bevor Robins Filter gelaufen war. Es wurde nichts gelesen."),
    ("not among the results robin_filter kept", "Eine Treffernummer gehört nicht zu den Treffern, die Robins Filter behalten hat. Es wurde nichts gelesen."),
    ("came from an earlier robin_search", "Eine Treffernummer stammt aus einer früheren Suche und gilt nicht mehr. Es wurde nichts gelesen."),
    ("unknown result id", "Eine Treffernummer ist Robin unbekannt. Es wurde nichts gelesen."),
    ("over the per-call cap", "Die Antwort wäre grösser geworden, als ein Aufruf zurückgeben darf. Es wurde nichts gelesen."),
    ("larger than the", "Die Seiten waren grösser, als ein Aufruf zurückgeben darf. Robin gab nichts zurück."),
    ("no model available", "Robin hat an diesem Arbeitsplatz kein Sprachmodell. Dieser Weg läuft hier nicht."),
    ("nothing to scrape", "Der Aufruf nannte keine Seite. Es wurde nichts gelesen."),
    ("nothing to refine", "Der Aufruf nannte keinen Suchtext."),
    ("nothing to filter", "Der Aufruf nannte keinen Suchtext."),
)
_STANDSATZ = {
    "tor_bootstrapping": ("nicht_ausgefuehrt", "Tor war noch nicht bereit. Es wurde nichts gesucht und nichts gelesen."),
    "needs_domain": ("nicht_ausgefuehrt", "Der Untersuchungsbereich war nicht angegeben. Es wurde nichts gesucht."),
    "engines_unreachable": ("fehler", "Keine Suchmaschine hat geantwortet. Das heisst nicht «nichts gefunden»: Die Suche lief nicht."),
    "no_results": ("kein_treffer", "Die Suchmaschinen haben zu diesem Suchtext nichts geliefert."),
    "nothing_relevant": ("kein_treffer", "Kein Treffer passte zum Thema."),
    "nothing_readable": ("fehler", "Keine der Seiten liess sich lesen."),
    "failed": ("fehler", "Robin meldet einen Fehlschlag."),
}
_HINWEIS = {
    "unfiltered": "Robin hat hier kein eigenes Sprachmodell: Die Treffer sind ungefiltert, die Auswahl trifft der Analyst.",
    "refine_it_yourself": "Robin hat hier kein eigenes Sprachmodell: Der Suchtext wurde nicht verändert.",
}


def einordnen(werkzeug: str, text: str) -> dict:
    """Was die Antwort eines Robin-Werkzeugs bedeutet. `ergebnis` spricht dieselbe Sprache wie das Protokoll des Gateways:

        ok                  ausgeführt, es kam etwas zurück
        kein_treffer        ausgeführt, nichts gefunden
        fehler              versucht, aber gescheitert (keine Suchmaschine erreichbar, keine Seite lesbar)
        nicht_ausgefuehrt   es ging nichts hinaus (Tor nicht bereit, Untersuchungsbereich fehlte, Aufruf zurückgewiesen)

    Dazu `status` (Robins eigenes Wort), bei fehler und nicht_ausgefuehrt `fehler` (der Grund in einem Satz), sonst allenfalls
    `hinweis`, und was sich zählen lässt: treffer, maschinen, seiten_gelesen, seiten_verlangt, tor."""
    name = werkzeug.rsplit("__", 1)[-1]
    m = _STAND.match(text or "")
    if not m:
        return {"ergebnis": "ok", "status": "", "hinweis": "Robin hat in einer unbekannten Form geantwortet. Der Wortlaut steht in den Rohdaten."}
    if m.group(1) == "error":
        satz = next((deutsch for stueck, deutsch in _FEHLERSATZ if stueck in m.group(2)), "Robin hat den Aufruf zurückgewiesen. Der Wortlaut steht in den Rohdaten.")
        return {"ergebnis": "nicht_ausgefuehrt", "status": "error", "fehler": satz}
    status = (m.group(2).split() or [""])[0].lower()
    if status in _STANDSATZ:
        ergebnis, satz = _STANDSATZ[status]
        if status == "no_results" and name != "robin_search":
            satz = "Es lagen keine Treffer vor, mit denen sich arbeiten liess."
        return {"ergebnis": ergebnis, "status": status, "fehler": satz}
    aus: dict = {"ergebnis": "ok", "status": status}
    if status in _HINWEIS:
        aus["hinweis"] = _HINWEIS[status]
    if status != "ok":
        if status not in _HINWEIS:
            aus["hinweis"] = f"Robin meldet den Stand «{status}». Der Wortlaut steht in den Rohdaten."
        return aus
    kopf = text.split("<<<ROBIN_UNTRUSTED_CONTENT", 1)[0]
    if name == "robin_search":
        if (z := re.search(r"^(\d+) results? for", kopf, re.M)):
            aus["treffer"] = int(z.group(1))
        if (z := re.search(r"(\d+) of (\d+) engines answered", kopf)):
            aus["maschinen"] = f"{z.group(1)} von {z.group(2)}"
        if (z := re.search(r"(\d+) dropped as child sexual abuse material", kopf)):
            aus["hinweis"] = f"Robin hat {z.group(1)} Treffer verworfen, deren Titel oder Adresse Missbrauchsdarstellungen nennt."
    elif name == "robin_scrape":
        if (z := re.search(r"^(\d+) of (\d+) pages read", kopf, re.M)):
            gelesen, verlangt = int(z.group(1)), int(z.group(2))
            aus.update(seiten_gelesen=gelesen, seiten_verlangt=verlangt)
            if gelesen == 0:
                return {**aus, "ergebnis": "fehler", "fehler": f"Keine der {verlangt} Seiten liess sich lesen (gesperrt, Zeitüberschreitung oder Fehler der Seite)."}
            if gelesen < verlangt:
                aus["hinweis"] = f"{verlangt - gelesen} von {verlangt} Seiten liessen sich nicht lesen."
    elif name == "robin_filter":
        if (z := re.search(r"^(\d+) of (\d+) results are on topic", kopf, re.M)):
            aus["treffer"] = int(z.group(1))
    elif name == "robin_health":
        if (z := re.search(r"^tor:\s*(\w+)", kopf, re.M)):
            aus["tor"] = z.group(1) == "up"
            aus["hinweis"] = "Tor ist bereit." if aus["tor"] else "Tor ist nicht bereit: Es startet noch, oder der Rechner erreicht das Tor-Netz nicht."
        if (z := re.search(r"^engines:\s*(\d+) of (\d+) up", kopf, re.M)):
            aus["maschinen"] = f"{z.group(1)} von {z.group(2)}"
    return aus


def eingeordnet(e: dict, pfad: Path) -> dict:
    """Ein Eintrag aus extern.jsonl, so wie er auszuwerten ist. ``pfad`` ist der Ordner der Fallakte.

    Seit dem 20.11.2026 sagt ein Eintrag von Robin selbst, was die Antwort bedeutet (art, ergebnis, fehler, robin). Davor stand bei
    jeder Antwort «ok» und als Art «tor», auch wenn Robin nichts gesucht hatte oder nur im Container gearbeitet hatte. Für solche
    Einträge wird die gesicherte Antwort gelesen und eingeordnet wie heute. Die gespeicherte Zeile bleibt, wie sie ist: Mit ihr
    rechnet die Protokollkette. Zurück kommt eine Kopie mit den vier Feldern und dem Vermerk ``nachgelesen``.

    Wer Einträge auswertet (Ermittlungsprotokoll, Rapport, Oberfläche, fall_status), liest sie über akte.extern_lesen und bekommt
    sie so. Bis zum 23.11.2026 las nur die Zeile im Ermittlungsprotokoll die Antwort neu: Sie sagte «nicht ausgeführt», während
    Kacheln und Rapport denselben Eintrag als Abfrage mit Treffer zählten und der Rapport ihn als Beleg annahm.

    Unverändert zurück kommt, was nicht von Robin stammt, was schon in heutiger Form dasteht, und ein älterer Eintrag, dessen
    Rohdatei sich nicht lesen lässt: Über ihn lässt sich nicht mehr sagen, als dass eine Antwort gesichert wurde."""
    if ((e.get("anfrage") or {}).get("server") or "") != SERVER or "robin" in e:
        return e
    roh = (e.get("antwort") or {}).get("rohdaten") or ""
    try:
        inhalt = (pfad / roh).read_text(encoding="utf-8", errors="replace") if roh else ""
    except OSError:
        inhalt = ""
    if not inhalt:
        return e
    if roh.endswith(".json"):       # damals lag die Antwort so in der Akte, wie Claude Code sie verpackt
        try:
            inhalt = text_aus(json.loads(inhalt))
        except ValueError:
            pass
    name = str(e.get("werkzeug") or "")
    stand = einordnen(PRAEFIX + name, inhalt)
    eingabe = (e.get("anfrage") or {}).get("eingabe")
    aussen = name in NACH_AUSSEN or (name == "robin_health" and isinstance(eingabe, dict) and bool(eingabe.get("check_engines")))
    return {**e, "art": "tor" if aussen else "robin_lokal", "ergebnis": stand["ergebnis"], "fehler": stand.get("fehler"),
            "robin": {k: v for k, v in stand.items() if k not in ("ergebnis", "fehler")}, "nachgelesen": True}


def lesen(text: str) -> dict:
    """Zerlegt eine Antwort von Robin, für die Anzeige. Nichts wird gedeutet: Was von fremden Seiten stammt, bleibt Text.

        stand       die erste Zeile
        kopf        Robins eigene Zeilen vor dem ersten fremden Inhalt
        treffer     [{"nr", "id", "titel", "adresse"}]                             aus einer Suche oder aus Robins Filter
        seiten      [{"id", "stand", "http", "adresse", "text", "verweise", "gekuerzt"}]      aus robin_scrape
        anhang      Robins Arbeitsanweisungen am Schluss (für sein eigenes Vorgehen. An diesem Arbeitsplatz gilt der Ermittlungsstandard)"""
    text = text or ""
    erster = min((i for i in (text.find("<<<ROBIN_UNTRUSTED_CONTENT"), text.find("\n## ")) if i >= 0), default=len(text))
    kopf = [z for z in text[:erster].splitlines() if z.strip()]
    aus: dict = {"stand": kopf[0] if kopf else "", "kopf": kopf[1:], "treffer": [], "seiten": [], "anhang": ""}
    letzte = 0
    marken = list(_SEITE.finditer(text))
    for m in _ZAUN.finditer(text):
        quelle, inhalt = m.group(1), m.group(2)
        letzte = m.end()
        davor = [s for s in marken if s.end() <= m.start() + 1]
        seite = davor[-1] if davor and not text[davor[-1].end():m.start()].strip() else None
        if seite is not None:
            verweise: list[str] = []
            if (v := _VERWEISE.search(inhalt)):
                verweise = [z[2:].strip() for z in v.group(2).splitlines() if z.startswith("- ")]
                inhalt = inhalt[:v.start()]
            ok = seite.group(2) == "ok"
            aus["seiten"].append({"id": seite.group(1), "stand": seite.group(2), "http": int(seite.group(3)) if seite.group(3) else None,
                                  "adresse": quelle, "text": inhalt if ok else "", "verweise": verweise,
                                  "meldung": "" if ok else inhalt.removeprefix("detail:").strip(), "gekuerzt": inhalt.rstrip().endswith(GEKUERZT)})
        elif quelle == "dark web search engines":
            aus["treffer"] += [{"nr": int(t.group(1)), "id": t.group(2), "titel": t.group(3).strip(), "adresse": t.group(4)} for t in _TREFFER.finditer(inhalt)]
    aus["anhang"] = text[letzte:].strip() if letzte else ""
    return aus


# --------------------------------------------------------------------------- Sperrliste

def host_aus(adresse: object) -> str | None:
    """Der Host einer Adresse oder URL, kleingeschrieben, wenn sie sich auf genau eine Art lesen lässt. Sonst None.

    Die Regeln prüfen den Host, bevor Robin die Seite abruft. Beide müssen denselben Host meinen. Bis zum 23.11.2026 zerlegte die
    Regel nachsichtig (urlsplit): Bei «http://A.onion\\@B.onion/» prüfte sie B, während requests und urllib3 den Host am Rückstrich
    beenden und A öffnen. Und ein unsichtbares Zeichen im Wort «onion» machte aus der Adresse «offenes Netz», für das die Sperrliste
    nicht gilt, während Robin solche Zeichen entfernt und die Onion-Seite liest. Deshalb gilt nur die strenge Form (_ADRESSE), in
    der jedes Programm denselben Host liest: reines ASCII, kein Benutzerteil, kein Rückstrich, keine Leer- und Steuerzeichen.
    Alles andere wird abgelehnt, nicht gedeutet."""
    if not isinstance(adresse, str) or not adresse.isascii():
        return None
    m = _ADRESSE.fullmatch(adresse.strip(" \t\r\n").lower())
    host = m.group(1).removesuffix(".") if m else ""        # ein Punkt am Schluss ist die ausgeschriebene Form desselben Namens
    if not host or any(not teil or teil.startswith("-") or teil.endswith("-") for teil in host.split(".")):
        return None
    return host


def onion_host(adresse: object) -> str:
    """Der Onion-Dienst hinter einer Adresse oder URL, als «<name>.onion», kleingeschrieben. Vorangestellte Teile fallen weg:
    www.<name>.onion ist derselbe Dienst, und die Sperrliste kennt nur den Namen des Dienstes. Auch hinter einem Tor2Web-Dienst
    (<name>.onion.ly) steht der Onion-Dienst <name>.onion. Leer, wenn die Adresse nicht eindeutig zu lesen ist (host_aus) oder zu
    keinem Onion-Dienst führt. Ob der Name die Form einer Onion-Adresse hat, sagt onion_gueltig(): Robin selbst nimmt jeden Host
    auf .onion."""
    host = host_aus(adresse)
    if not host:
        return ""
    teile = host.split(".")
    if len(teile) >= 2 and teile[-1] == "onion":
        return f"{teile[-2]}.onion"
    m = _DIENST_IM_HOST.search(host)
    return f"{m.group(1)}.onion" if m else ""


def onion_gueltig(host: str) -> bool:
    """Hat der Host die Form einer Onion-Adresse (16 oder 56 Zeichen aus a–z und 2–7)? Nur solche lassen sich prüfen."""
    return bool(ONION_HOST.fullmatch(host or ""))


# Unter so vielen Einträgen ist eine Antwort von Ahmia nicht die Sperrliste, auch wenn jede Zeile ein MD5-Wert ist: Gesehen wurden
# 60'371 Einträge (16.11.2026) und 60'394 (20.11.2026). Die Grenze liegt bei einem Sechzigstel davon. Sie fängt den Rest einer
# abgebrochenen Übertragung und eine Antwort, die nur aus einer Prüfsumme besteht, und sie lässt der Liste Raum zu schrumpfen, ohne
# dass der Arbeitsplatz stehen bleibt. Eine zur Hälfte geladene Liste erkennt sie nicht. Sie gilt beim Laden (onion_sperrliste), auch
# aus dem Fall-Cache. Der Musterfall stellt eine Liste mit 40 erfundenen Einträgen und setzt die Grenze für seinen Lauf darauf herab.
SPERRLISTE_MINDESTENS = 1000
_MD5 = re.compile(r"[a-f0-9]{32}")


def sperrliste_werte(listentext: str | None, mindestens: int = 0) -> frozenset[str] | None:
    """Die Einträge der Sperrliste von Ahmia, oder None, wenn der Text keine solche Liste ist. Die Liste ist reiner Text, je Zeile
    ein MD5-Wert, sonst nichts (gesehen am 16.11.2026). Bis zum 23.11.2026 galt jeder Text als Liste, in dem irgendwo 32 Hex-Zeichen
    standen: Eine Wartungsseite mit dem Dateinamen main.<32 Hex-Zeichen>.css war eine «Liste» mit einem Eintrag, und jede Adresse
    des Falls war einen Tag lang «frei». `mindestens`: Mit weniger verschiedenen Einträgen ist es keine Liste."""
    zeilen = [z.strip().lower() for z in (listentext or "").removeprefix("\ufeff").splitlines()]
    werte = frozenset(z for z in zeilen if z)
    if not werte or len(werte) < mindestens or not all(_MD5.fullmatch(w) for w in werte):
        return None
    return werte


def in_liste(host: str, liste: frozenset[str]) -> bool:
    """Nennt die Liste diesen Host? Sie führt den MD5-Wert des Namens, mit oder ohne «http://» davor."""
    return any(hashlib.md5(v.encode()).hexdigest() in liste for v in (host, f"http://{host}", f"http://{host}/"))


def auf_sperrliste(host: str, listentext: str | None, mindestens: int = 0) -> bool | None:
    """Steht der Host auf der Sperrliste von Ahmia? None: Der Text ist keine solche Liste (sperrliste_werte)."""
    liste = sperrliste_werte(listentext, mindestens)
    return None if liste is None else in_liste(host, liste)


def sperrliste_urteil(pfad: Path, eintrag: dict) -> str | None:
    """Was eine protokollierte Prüfung mit onion_sperrliste ergab: «frei», «gesperrt» oder None (die Prüfung schlug fehl, oder
    die gesicherte Liste lässt sich nicht lesen oder ist keine Liste). Es zählt, was die Liste in den Rohdaten sagt. Die
    Untergrenze für ihren Umfang galt beim Laden: Ein Eintrag mit «ok» steht nur da, wenn die Antwort sie erfüllte."""
    if eintrag.get("werkzeug") != "onion_sperrliste" or eintrag.get("ergebnis") != "ok":
        return None
    roh = (eintrag.get("antwort") or {}).get("rohdaten")
    try:
        gesperrt = auf_sperrliste(str(eintrag.get("ziel") or ""), (pfad / roh).read_text(encoding="utf-8", errors="replace")) if roh else None
    except OSError:
        gesperrt = None
    return None if gesperrt is None else "gesperrt" if gesperrt else "frei"


def sperrliste_stand(pfad: Path, host: str, eintraege: list[dict] | None = None) -> tuple[str | None, str | None]:
    """Wurde dieser Onion-Dienst in diesem Fall gegen die Sperrliste geprüft? Gibt (stand, Beleg) zurück: «frei», «gesperrt» oder
    None (nie geprüft, oder die Prüfung schlug fehl), dazu die Nummer der jüngsten Prüfung. Es zählt, was im Abfrageprotokoll
    steht und was die dort gesicherte Liste sagt."""
    if eintraege is None:
        eintraege = jsonl_lesen(pfad / "protokoll" / "abfragen.jsonl")
    for e in reversed(eintraege):
        if e.get("ziel") != host:
            continue
        urteil = sperrliste_urteil(pfad, e)
        if urteil:
            return urteil, e.get("id")
    return None, None


# --------------------------------------------------------------------------- Zulässigkeit

def bereich(daten: dict) -> str:
    """Der Untersuchungsbereich, den der Sachbearbeiter mit der Freigabe darkweb gewählt hat. Leer, wenn keiner gewählt ist."""
    wert = ((daten.get("freigaben") or {}).get("darkweb") or {}).get("bereich") or ""
    return wert if wert in BEREICHE else ""


def suchangaben(daten: dict) -> dict | None:
    """Was robin_search in diesem Fall mitbekommen muss, oder None ohne Freigabe oder ohne Bereich."""
    b = bereich(daten)
    if not freigabe_erteilt(daten, "darkweb") or not b:
        return None
    return {"preset": b, "user_chose": True}


def aktive_massnahme(werkzeug: str, eingabe: object) -> bool:
    """Berührt dieser Aufruf ein Ziel im offenen Netz? Das tut robin_scrape mit allow_clearweb: Robin ruft die Seite dann über Tor
    auf, und ihr Betreiber sieht den Besuch. Für aktive Massnahmen ist die Freigabe «aktiv» nur die Voraussetzung: Der Sachbearbeiter
    stimmt jedem Aufruf einzeln zu, am Terminal wie in der Oberfläche (dort bis zum 23.11.2026 nicht: Die Freigabe genügte)."""
    return werkzeug.rsplit("__", 1)[-1] == "robin_scrape" and isinstance(eingabe, dict) and bool(eingabe.get("allow_clearweb"))


def verstoss(werkzeug: str, eingabe: object, daten: dict, pruefstand: Callable[[str], str | None] | None = None) -> tuple[str, str]:
    """Verletzt dieser Aufruf von Robin die Regeln des Falls? Gibt (Feststellung, Rat an den Analysten) zurück, beide leer, wenn
    nichts dagegen spricht. Die Feststellung steht für sich: Der Sitzungs-Hook schreibt sie zum Beleg, wenn ein Aufruf trotzdem
    lief (am Terminal entscheidet der Sachbearbeiter je Aufruf selbst, dort prüft sonst niemand die Regeln).
    `pruefstand(host)` sagt, was die Prüfung gegen die Sperrliste für einen Onion-Host ergab: «frei», «gesperrt» oder None."""
    name = werkzeug.rsplit("__", 1)[-1]
    e = eingabe if isinstance(eingabe, dict) else {}
    if not freigabe_erteilt(daten, "darkweb"):
        return ("Der Fall hat keine Freigabe «darkweb».",
                "Robin wird nicht ausgeführt. Die Freigabe erteilt der Sachbearbeiter (Oberfläche: «Bedienen»). Bis dahin nicht erneut "
                "versuchen, sondern als Lücke melden.")
    if name in NICHT_VERWENDET:
        return f"{name} wird an diesem Arbeitsplatz nicht verwendet.", NICHT_VERWENDET[name]
    if name == "robin_search":
        b = bereich(daten)
        if not b:
            return ("Für diesen Fall ist kein Untersuchungsbereich gewählt.",
                    "Der Sachbearbeiter wählt ihn mit der Freigabe «darkweb» (Oberfläche: «Bedienen». Terminal: tools/fall.py freigabe … "
                    "--bereich). Bis dahin nicht suchen, sondern als Lücke melden.")
        if b == BEREICH_MIT_PERSONENBEZUG and not freigabe_erteilt(daten, "personenbezug"):
            return f"Der Untersuchungsbereich «{BEREICHE[b][0]}» braucht zusätzlich die Freigabe «personenbezug». Sie ist nicht erteilt.", ""
        if e.get("preset") != b or e.get("user_chose") is not True:
            return (f"Die Suche nannte nicht den Untersuchungsbereich des Falls: «{BEREICHE[b][0]}» hat der Sachbearbeiter gewählt.",
                    f"robin_search braucht in diesem Fall preset=\"{b}\" und user_chose=true. Mit diesen Angaben noch einmal aufrufen.")
        if PLATZHALTER.search(str(e.get("query") or "")):
            return "Der Suchtext enthält einen Platzhalter.", "Platzhalter werden nie abgefragt."
    if name == "robin_scrape":
        if not isinstance(eingabe, dict):
            return "Die Eingabe des Aufrufs hat keine lesbare Form.", "robin_scrape braucht urls als Liste von Adressen."
        offenes_netz = aktive_massnahme(werkzeug, eingabe)
        if offenes_netz and not freigabe_erteilt(daten, "aktiv"):
            return ("Eine Seite im offenen Netz wurde über Robin verlangt. Das berührt das Ziel (der Aufruf kommt aus dem Tor-Netz) und "
                    "braucht zusätzlich die Freigabe «aktiv». Sie ist nicht erteilt.", "")
        if e.get("ids"):
            return ("Seiten wurden über Treffernummern verlangt (ids).",
                    "Seiten über ihre Adressen lesen (urls), nicht über Treffernummern: Nur so lässt sich jede Adresse der Prüfung gegen "
                    "die Sperrliste zuordnen.")
        urls = e.get("urls")
        # Was sich nicht prüfen lässt, ist nicht zulässig. Kam «urls» als Text (auch als JSON-Text einer Liste, so senden Sprachmodelle
        # Listenfelder gelegentlich), lief die Prüfung bis zum 23.11.2026 über die einzelnen Zeichen, fand keine Onion-Adresse und liess
        # den Aufruf zu. Ein Server auf dem MCP-SDK macht aus dem JSON-Text die Liste und liest die Seite.
        if urls is not None and not (isinstance(urls, list) and all(isinstance(u, str) for u in urls)):
            return ("Die Angabe urls ist keine Liste von Adressen.",
                    "robin_scrape mit urls als Liste aufrufen, jede Adresse ein Text für sich: Nur so lässt sich jede Adresse prüfen.")
        for adresse in urls or []:
            host = host_aus(adresse)
            if host is None:
                sichtbar = adresse.encode("ascii", "backslashreplace").decode("ascii")      # unsichtbare Zeichen werden sichtbar
                sichtbar = "".join(z if " " < z <= "~" else f"\\x{ord(z):02x}" for z in sichtbar)[:200]
                return (f"Die Adresse {sichtbar} ist nicht eindeutig zu lesen.",
                        "Sie wird nicht geöffnet. Zulässig ist nur die schlichte Form http://<name>.onion/pfad: ohne Benutzerteil («@»), "
                        "ohne Rückstrich, ohne Leer-, Sonder- und unsichtbare Zeichen. Stammt sie so von einer Seite oder aus einem "
                        "Treffer, unter Auffälligkeiten melden.")
            dienst = onion_host(adresse)
            if not host.endswith(".onion"):
                if not offenes_netz:
                    return (f"{host} ist keine Onion-Adresse.",
                            "Robin liest an diesem Arbeitsplatz Onion-Seiten. Für Seiten im offenen Netz gibt es die Werkzeuge des Gateways.")
                if not dienst:
                    continue            # eine Adresse im offenen Netz: Dafür gilt die Regel oben
            # Ab hier steht ein Onion-Dienst hinter der Adresse, auch hinter einem Tor2Web-Dienst im offenen Netz: Für ihn gilt die Sperrliste
            if not onion_gueltig(dienst):
                return (f"{dienst} hat nicht die Form einer Onion-Adresse (16 oder 56 Zeichen).",
                        "Die Adresse lässt sich nicht gegen die Sperrliste prüfen und wird nicht geöffnet. Schreibweise im Eingangsdokument "
                        "oder in den Treffern nachsehen.")
            stand = pruefstand(dienst) if pruefstand else None
            if stand is None:
                return f"Die Adresse {dienst} wurde in diesem Fall noch nicht mit onion_sperrliste geprüft.", "Erst prüfen, dann lesen."
            if stand == "gesperrt":
                return f"Die Adresse {dienst} steht auf der Sperrliste von Ahmia.", "Sie wird nicht geöffnet. Unter Auffälligkeiten melden."
    return "", ""


def absage(werkzeug: str, eingabe: object, daten: dict, pruefstand: Callable[[str], str | None] | None = None) -> str:
    """Weshalb dieser Aufruf von Robin in diesem Fall nicht zulässig ist, mit dem Rat an den Analysten. Leer, wenn nichts dagegen
    spricht. Die Oberfläche fragt das vor jedem Aufruf (dort entscheiden die Regeln, nicht ein Dialog. Nur eine aktive Massnahme
    legt sie dem Sachbearbeiter danach noch einzeln vor, siehe aktive_massnahme). Am Terminal entscheidet der Sachbearbeiter je
    Aufruf selbst. Dem Analysten sind dieselben Regeln aufgetragen."""
    return " ".join(teil for teil in verstoss(werkzeug, eingabe, daten, pruefstand) if teil)
