"""Was die Ermittlung tut, in Worten: für den Chat und für die Rückfragen der Oberfläche.

Claude Code nennt Werkzeuge bei ihrem technischen Namen und gibt ihre Eingabe als JSON aus. Wer eine Ermittlung führt,
braucht einen Satz: welche Quelle, was sie gefragt wird, zu welchem Ziel und wozu. Dieses Modul übersetzt. Der technische
Name bleibt daneben stehen, weil er im Protokoll steht.

Dazu liest es die Erlaubt- und die Rückfrage-Liste des Projekts (.claude/settings.json), soweit sie Werkzeuge beim Namen
nennen. So kann die Oberfläche sagen, warum Claude Code fragt: weil es eine aktive Massnahme ist, weil der Aufruf auf
keiner Liste steht, oder weil Claude Code die Erlaubt-Liste nicht anwendet (es vertraut dem Projektordner noch nicht).

Bibliothek ohne Bedienung, ohne Netz, ohne Schreiben. Nur Standardbibliothek.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

from gateway.akte import PROJEKT

GATEWAY = "mcp__osint__"
ROBIN = "mcp__robin__"
FRAGE_WERKZEUG = "AskUserQuestion"

# Werkzeug des Gateways -> (Quelle, was gefragt wird). Ein Selbsttest hält die Liste mit dem Gateway in Deckung.
GATEWAY_WORT: dict[str, tuple[str, str]] = {
    "fall_status": ("Fallakte", "Stand, Freigaben und Pflichtquellen lesen"),
    "shodan_host": ("Shodan", "offene Dienste, Zertifikate und Betreiber einer IP"),
    "shodan_internetdb": ("Shodan InternetDB", "Schnellübersicht einer IP (Ports, bekannte Schwachstellen)"),
    "shodan_dns": ("Shodan", "Subdomains und DNS-Einträge einer Domain"),
    "shodan_suche": ("Shodan", "Suche über alle Hosts (gleiches Zertifikat, Banner)"),
    "spur_kontext": ("Spur", "VPN, Proxy, Tor oder Privatanschluss"),
    "abuseipdb_pruefen": ("AbuseIPDB", "Missbrauchsmeldungen zu einer IP (Übersicht)"),
    "abuseipdb_meldungen": ("AbuseIPDB", "einzelne Missbrauchsmeldungen zu einer IP"),
    "virustotal_ip": ("VirusTotal", "Einschätzung einer IP"),
    "virustotal_domain": ("VirusTotal", "Einschätzung einer Domain, Registrar und Erstelldatum"),
    "virustotal_datei": ("VirusTotal", "Ist dieser Datei-Hash als Schadsoftware bekannt"),
    "virustotal_url": ("VirusTotal", "vorhandene Analyse zu einer URL"),
    "virustotal_beziehungen": ("VirusTotal", "Verknüpfungen eines Indikators"),
    "ip_einordnung": ("IP-Einordnung", "Netz, Art des Anschlusses und Anonymisierung, aus mehreren Quellen"),
    "krypto_adresse_pruefen": ("Blockchain", "Kette und Format einer Adresse prüfen, ohne Abfrage"),
    "krypto_adresse": ("Blockchain", "Überblick über eine Adresse"),
    "krypto_transaktionen": ("Blockchain", "Zahlungen einer Adresse"),
    "krypto_transaktion": ("Blockchain", "eine Zahlung im Einzelnen"),
    "krypto_geldfluss": ("Blockchain", "Geldfluss über mehrere Stationen verfolgen"),
    "krypto_zuordnung": ("Blockchain", "Zuordnung einer Adresse (Börse, Sanktionsliste, bekannte Adresse)"),
    "krypto_kurs": ("Blockchain", "Kurs und Gegenwert an einem Stichtag"),
    "ransomware_opfer": ("ransomware.live", "Opferlisten der Leak-Seiten"),
    "ransomware_gruppe": ("ransomware.live", "Steckbrief einer Gruppe"),
    "ransomware_iocs": ("ransomware.live", "veröffentlichte Indikatoren einer Gruppe"),
    "ransomware_aktuell": ("ransomware.live", "zuletzt veröffentlichte Opfer"),
    "onion_sperrliste": ("Sperrliste", "Onion-Adresse vor dem Öffnen prüfen"),
    "telegram_kanal": ("Telegram", "neueste Beiträge eines öffentlichen Kanals"),
    "telegram_kanalinfo": ("Telegram", "Stammdaten eines öffentlichen Kanals"),
    "telegram_entitaet": ("Telegram", "öffentliche Angaben zu einem Konto, einer Gruppe oder einem Kanal"),
    "telegram_suche": ("Telegram", "Suche nach Konten, Gruppen und Kanälen"),
    "chan_katalog": ("4chan", "laufende Threads eines Boards"),
    "chan_thread": ("4chan", "einen Thread sichern und lesen"),
    "mastodon_instanz": ("Mastodon", "öffentliche Angaben zu einer Instanz"),
    "mastodon_konto": ("Mastodon", "öffentliche Konten zu einem Benutzernamen"),
    "urlscan_suche": ("urlscan.io", "vorhandene Scans suchen"),
    "urlscan_ergebnis": ("urlscan.io", "Ergebnis eines vorhandenen Scans lesen"),
    "urlscan_kontingent": ("urlscan.io", "Kontingent des eigenen Kontos lesen"),
    "urlscan_einreichen": ("urlscan.io", "URL zum Scan einreichen"),
    "urlquery_suche": ("urlquery", "vorhandene Sandbox-Berichte suchen"),
    "urlquery_bericht": ("urlquery", "einen Sandbox-Bericht lesen"),
    "urlquery_reputation": ("urlquery", "Kurzurteil zu einer URL"),
    "urlquery_einreichen": ("urlquery", "URL in der Sandbox aufrufen lassen"),
    "urlquery_status": ("urlquery", "Stand einer Einreichung"),
    "wayback_verlauf": ("Wayback Machine", "seit wann und wie oft eine Seite archiviert ist"),
    "wayback_abruf": ("Wayback Machine", "archivierten Stand einer Seite lesen"),
    "wayback_sichern": ("Wayback Machine", "Seite jetzt öffentlich archivieren lassen"),
    "webcheck_passiv": ("Web-Check", "DNS, Registrierung, Zertifikate und Sperrlisten, ohne das Ziel aufzurufen"),
    "webcheck_aktiv": ("Web-Check", "das Ziel direkt aufrufen und untersuchen"),
}
ROBIN_WORT = {"robin_health": "Bereitschaft von Tor und Suchmaschinen prüfen", "robin_search": "im Dark Web suchen", "robin_refine": "Suchbegriff verfeinern",
              "robin_filter": "Treffer filtern", "robin_scrape": "Onion-Seite lesen"}
# Was das Ziel bemerken kann oder öffentlich sichtbar wird. Die Rückfrage-Liste des Projekts verlangt dafür eine Zustimmung je Aufruf.
AKTIV = {"urlscan_einreichen": "urlscan.io ruft die Adresse von seinen Servern aus auf. Der Betreiber der Zielseite sieht einen Besuch.",
         "urlquery_einreichen": "urlquery ruft die Adresse in seiner Sandbox auf. Der Betreiber der Zielseite sieht einen Besuch.",
         "wayback_sichern": "Die Wayback Machine ruft die Seite ab und archiviert sie öffentlich und dauerhaft. Der Betreiber sieht einen Besuch.",
         "webcheck_aktiv": "Web-Check ruft das Ziel direkt auf. Der Betreiber sieht die Adresse eurer Web-Check-Instanz in seinen Logs."}
PERSONENBEZUG = ("telegram_entitaet", "telegram_suche", "mastodon_konto")
# Die Felder einer Eingabe, die das Ziel nennen, in der Reihenfolge ihres Gewichts
ZIELE = ("ip", "domain", "url", "hashwert", "adresse", "tx", "wert", "suchtext", "ziel", "gruppe", "kanal", "konto", "instanz", "query", "uuid", "board", "thread")
TEAM = {"hauptsitzung": "Ermittlungsleitung", "infrastruktur-analyst": "Infrastruktur", "malware-url-analyst": "Malware und URLs", "darkweb-analyst": "Dark Web",
        "socmint-analyst": "Kanäle und Foren", "blockchain-analyst": "Blockchain", "gegenpruefer": "Gegenprüfung", "rapportfuehrer": "Rapport"}
AUSSEN = {"WebFetch": "eine Webseite direkt abrufen", "WebSearch": "im Internet suchen"}
SCHREIBEND = ("Write", "Edit", "MultiEdit", "NotebookEdit")


def kurz(wert: object, n: int = 160) -> str:
    text = wert if isinstance(wert, str) else json.dumps(wert, ensure_ascii=False)
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n - 1] + "…"


def team(name: str) -> str:
    """Der Name eines Analysten, wie ihn ein Mensch liest."""
    return TEAM.get(name, name)


def datei(pfad: object) -> str:
    """Ein Pfad aus einer Eingabe, bezogen auf den Projektordner: So steht kein Benutzerordner im Chat."""
    text = str(pfad or "")
    try:
        return Path(text).resolve().relative_to(PROJEKT).as_posix() if Path(text).is_absolute() else text
    except (OSError, ValueError):
        return Path(text).name or text


def ziel(eingabe: object) -> str:
    return next((str(eingabe[k]) for k in ZIELE if eingabe.get(k) not in (None, "")), "") if isinstance(eingabe, dict) else ""


def schritt(werkzeug: str, eingabe: object) -> dict:
    """Ein Werkzeugaufruf in Worten.

    text      der Satz für den Chat, ohne den Namen dessen, der ihn tut
    technik   der Name des Werkzeugs, wie er im Protokoll steht (ohne Vorsatz des Servers)
    ziel      der Indikator oder die Suche
    zweck     wozu, laut der Eingabe (das Gateway verlangt ihn bei jeder Abfrage)
    art       quelle, robin, aussen, befehl, datei, lesen, frage, sonst
    """
    e = eingabe if isinstance(eingabe, dict) else {}
    zweck = kurz(e.get("zweck") or "", 300)
    if werkzeug.startswith(GATEWAY):
        name = werkzeug[len(GATEWAY):]
        quelle, was = GATEWAY_WORT.get(name, ("Gateway", name))
        z = ziel(e)
        return {"text": f"{quelle}: {was}" + (f" · {kurz(z, 200)}" if z else ""), "technik": name, "ziel": z, "zweck": zweck, "art": "quelle"}
    if werkzeug.startswith(ROBIN):
        name = werkzeug[len(ROBIN):]
        z = ziel(e)
        return {"text": f"Robin (Dark Web): {ROBIN_WORT.get(name, name)}" + (f" · {kurz(z, 200)}" if z else ""), "technik": name, "ziel": z, "zweck": zweck, "art": "robin"}
    if werkzeug in AUSSEN:
        z = str(e.get("url") or e.get("query") or "")
        return {"text": f"Am Gateway vorbei {AUSSEN[werkzeug]}" + (f" · {kurz(z, 200)}" if z else ""), "technik": werkzeug, "ziel": z, "zweck": "", "art": "aussen"}
    if werkzeug == "Bash":
        befehl = str(e.get("command") or "")
        return {"text": "Befehl ausführen: " + kurz(befehl, 220), "technik": werkzeug, "ziel": befehl, "zweck": kurz(e.get("description") or "", 300), "art": "befehl"}
    if werkzeug in SCHREIBEND:
        z = datei(e.get("file_path") or e.get("notebook_path"))
        return {"text": f"Datei {'schreiben' if werkzeug == 'Write' else 'ändern'}: {kurz(z, 200)}", "technik": werkzeug, "ziel": z, "zweck": "", "art": "datei"}
    if werkzeug == "Read":
        z = datei(e.get("file_path"))
        return {"text": "Datei lesen: " + kurz(z, 200), "technik": werkzeug, "ziel": z, "zweck": "", "art": "lesen"}
    if werkzeug in ("Grep", "Glob"):
        z = str(e.get("pattern") or "")
        ort = datei(e.get("path")) if e.get("path") else ""
        return {"text": ("In den Akten suchen: " if werkzeug == "Grep" else "Dateien suchen: ") + kurz(z, 160) + (f" (in {kurz(ort, 80)})" if ort else ""),
                "technik": werkzeug, "ziel": z, "zweck": "", "art": "lesen"}
    if werkzeug == "Skill":
        z = str(e.get("skill") or "")
        return {"text": "Anleitung laden: " + kurz(z, 120), "technik": werkzeug, "ziel": z, "zweck": "", "art": "lesen"}
    if werkzeug == "TodoWrite":
        return {"text": "Arbeitsplan nachführen", "technik": werkzeug, "ziel": "", "zweck": "", "art": "sonst"}
    if werkzeug == FRAGE_WERKZEUG:
        erste = next((str(f.get("question") or "") for f in e.get("questions") or [] if isinstance(f, dict)), "")
        return {"text": "Frage an dich: " + kurz(erste, 240), "technik": werkzeug, "ziel": "", "zweck": "", "art": "frage"}
    z = ziel(e) or str(e.get("description") or "")
    return {"text": werkzeug + (f" · {kurz(z, 200)}" if z else ""), "technik": werkzeug, "ziel": z, "zweck": zweck, "art": "sonst"}


# --------------------------------------------------------------------------- Listen des Projekts, soweit sie Werkzeuge beim Namen nennen

def regeln(projekt: Path = PROJEKT) -> dict[str, list[str]]:
    """Die Regeln aus .claude/settings.json, die ein Werkzeug beim Namen nennen (ohne Klammer): erlaubt, Rückfrage, verboten.
    Regeln mit Klammer (ein Befehl, ein Pfad) wertet nur Claude Code selbst aus: Ihr Abgleich ist seine Sache."""
    try:
        rechte = json.loads((projekt / ".claude" / "settings.json").read_text(encoding="utf-8")).get("permissions") or {}
    except (OSError, ValueError, AttributeError):
        rechte = {}
    return {art: [str(r) for r in rechte.get(art) or [] if isinstance(r, str) and "(" not in r] for art in ("allow", "ask", "deny")}


def _trifft(werkzeug: str, liste: list[str]) -> bool:
    return any(werkzeug == regel or fnmatch.fnmatchcase(werkzeug, regel) or werkzeug.startswith(regel + "__") for regel in liste)


def auf_erlaubt_liste(werkzeug: str, alle: dict[str, list[str]] | None = None) -> bool:
    """Steht das Werkzeug beim Namen auf der Erlaubt-Liste des Projekts, und auf keiner der beiden anderen? Dann hätte Claude Code
    nicht fragen müssen. Fragt es doch, wendet es die Liste nicht an."""
    alle = regeln() if alle is None else alle
    return _trifft(werkzeug, alle["allow"]) and not _trifft(werkzeug, alle["ask"]) and not _trifft(werkzeug, alle["deny"])


def auf_rueckfrage_liste(werkzeug: str, alle: dict[str, list[str]] | None = None) -> bool:
    alle = regeln() if alle is None else alle
    return _trifft(werkzeug, alle["ask"])


LISTE_RUHT = ("Claude Code wendet die Erlaubt-Liste des Projekts gerade nicht an und fragt deshalb bei jedem Werkzeug einzeln nach. "
              "Der übliche Grund: Es vertraut dem Projektordner noch nicht.")
BEHEBEN = ("Die Ermittlung anhalten (Knopf «Anhalten» im Chat).",
           "Im Terminal im Projektordner einmal «claude» starten und die Frage nach dem Ordner mit Ja bestätigen.",
           "Claude Code mit /exit beenden.",
           "Hier im Chat «Fortsetzen» wählen.")
OHNE_VERTRAUEN = LISTE_RUHT + " Beheben: " + " ".join(f"({n}) {s}" for n, s in enumerate(BEHEBEN, 1))


def zustimmung(werkzeug: str, eingabe: object, alle: dict[str, list[str]] | None = None) -> dict:
    """Eine Rückfrage von Claude Code in Worten: was es tun will, warum es fragt und was daraus folgt.

    art       aktiv (das Ziel kann es bemerken), aussen (am Gateway vorbei), erlaubt (steht auf der Erlaubt-Liste), befehl, datei, sonst
    satz      was getan werden soll
    grund     warum Claude Code fragt
    folge     was «Erlauben» bedeutet
    rat       eine Empfehlung, wo es eine gibt
    beheben   Schritte, mit denen die Frage künftig entfällt, wo es welche gibt
    """
    s = schritt(werkzeug, eingabe)
    name = s["technik"]
    aus = {"satz": s["text"], "technik": werkzeug, "ziel": s["ziel"], "zweck": s["zweck"], "rat": "", "merkbar": False}
    if werkzeug.startswith(GATEWAY) and name in AKTIV:
        return {**aus, "art": "aktiv", "grund": "Aktive Massnahme: " + AKTIV[name],
                "folge": "Erlauben gilt für diesen einen Aufruf. Das Gateway führt ihn nur aus, wenn der Fall die Freigabe «Aktive Massnahmen» hat."}
    if werkzeug in AUSSEN:
        return {**aus, "art": "aussen", "grund": "Dieser Abruf ginge nicht über das Gateway: Er stünde in keinem Protokoll, und seine Antwort wäre nicht gesichert.",
                "folge": "Erlauben gilt für diesen einen Aufruf.", "rat": "Empfehlung: ablehnen. Die Regeln des Arbeitsplatzes sehen Abfragen nur über das Gateway vor."}
    if auf_erlaubt_liste(werkzeug, alle):
        return {**aus, "art": "erlaubt", "merkbar": True, "grund": "Dieses Werkzeug steht auf der Erlaubt-Liste des Projekts. " + LISTE_RUHT, "beheben": list(BEHEBEN),
                "folge": "Erlauben gilt für diesen einen Aufruf. Mit «Erlauben und nicht mehr fragen» gilt es bis zum Ende dieser Ermittlung für alle Werkzeuge der Erlaubt-Liste."}
    if s["art"] == "befehl":
        return {**aus, "art": "befehl", "grund": "Dieser Befehl steht auf keiner Liste des Projekts, oder Claude Code wendet die Erlaubt-Liste nicht an.",
                "folge": "Erlauben gilt für diesen einen Befehl. Er läuft auf diesem Rechner, im Projektordner."}
    if s["art"] == "datei":
        return {**aus, "art": "datei", "grund": "Diese Datei steht auf keiner Liste des Projekts, oder Claude Code wendet die Erlaubt-Liste nicht an.",
                "folge": "Erlauben gilt für diese eine Änderung."}
    return {**aus, "art": "sonst", "grund": "Dieser Aufruf steht auf keiner Liste des Projekts.", "folge": "Erlauben gilt für diesen einen Aufruf."}


def fragen_lesen(eingabe: object) -> list[dict]:
    """Die Fragen aus einer Eingabe von AskUserQuestion, in fester Form. Leer, wenn die Eingabe keine lesbare Frage enthält.
    Jede Frage: {"frage", "kopf", "mehrere", "wahl": [{"name", "text"}]}. Die Frage selbst ist der Schlüssel der Antwort."""
    aus = []
    for f in (eingabe.get("questions") if isinstance(eingabe, dict) else None) or []:
        if not isinstance(f, dict) or not str(f.get("question") or "").strip():
            continue
        wahl = [{"name": str(o.get("label") or "").strip(), "text": str(o.get("description") or "").strip()} for o in f.get("options") or []
                if isinstance(o, dict) and str(o.get("label") or "").strip()]
        aus.append({"frage": str(f["question"]).strip(), "kopf": str(f.get("header") or "").strip(), "mehrere": bool(f.get("multiSelect")), "wahl": wahl})
    return aus[:8]
