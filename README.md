# gogoinvestigation

**Ein OSINT-Ermittlungsarbeitsplatz für Claude Code.** Ein pseudonymisierter Rapport geht hinein. Ein
Ermittler-Team aus KI-Agenten fragt Clearweb- und Dark-Web-Quellen ab, verknüpft die Ergebnisse und prüft sich
gegenseitig. Heraus kommen ein verständlicher Abschlussrapport mit Diagrammen und ein lückenloses Protokoll
darüber, wann was wo und wozu abgefragt wurde.

> *English summary:* A Claude Code workspace for CTI and law-enforcement OSINT. One MCP gateway wraps Shodan,
> VirusTotal, Spur, AbuseIPDB, urlquery, Wayback Machine, Web-Check, ransomware.live, Telegram, 4chan and
> Mastodon, logs every request in a hash-chained audit trail and stores every raw response. A team of
> subagents investigates, an independent agent cross-checks every finding against the raw data, and a
> generator refuses to build the final report unless each statement is backed by evidence. Documentation is
> in German.

![Abschlussrapport des Musterfalls](docs/bilder/abschlussrapport.png)

**Muster ansehen:** [Abschlussrapport (PDF, 12 Seiten)](muster/Abschlussrapport.pdf) ·
[Ermittlungsprotokoll (PDF, 7 Seiten)](muster/Ermittlungsprotokoll.pdf) ·
[was der Musterfall zeigt](muster/README.md). Der Fall ist frei erfunden.

## Inhalt

- [Was ihr bekommt](#was-ihr-bekommt)
- [Einrichten](#einrichten)
- [Schlüssel](#schlüssel)
- [Eine Ermittlung durchführen](#eine-ermittlung-durchführen)
- [Das Ermittler-Team](#das-ermittler-team)
- [Quellen](#quellen)
- [Schutzmechanismen](#schutzmechanismen)
- [Fehler beheben](#fehler-beheben)
- [Stand der Prüfung und Grenzen](#stand-der-prüfung-und-grenzen)
- [Erweitern](#erweitern)
- [Recht und Verantwortung](#recht-und-verantwortung)

## Was ihr bekommt

```mermaid
flowchart LR
    A["Rapport, Nachtrag<br/>(Klartext)"] -->|"eigenes LLM<br/>im Haus"| B["pseudonymisiert<br/>mit Platzhaltern"]
    B -->|"tools/fall.py<br/>PII-Prüfung"| C[("Fallakte")]
    C --> D["Claude Code<br/>/ermittlung"]
    D --> T["Ermittler-Team<br/>4 Analysten"]
    T --> G["OSINT-Gateway<br/>(MCP)"]
    T --> R["Robin<br/>(MCP, Tor)"]
    G --> Q["Shodan · VirusTotal · Spur · AbuseIPDB<br/>urlquery · Wayback · Web-Check<br/>ransomware.live · Telegram · 4chan · Mastodon"]
    R --> O["Onion-Suchmaschinen"]
    G -->|"jede Abfrage"| P[("Protokoll + Rohdaten<br/>hash-verkettet")]
    R -->|"Sitzungs-Hook"| P
    T --> F["Rapportführer<br/>befunde.json"]
    F --> X["Gegenprüfer<br/>prüft gegen Rohdaten"]
    X --> E["Abschlussrapport<br/>Ermittlungsprotokoll"]
    P --> E
    E -->|"im Haus<br/>zurückführen"| Z["Rapport mit<br/>echten Angaben"]
```

| Baustein | Aufgabe |
|---|---|
| **OSINT-Gateway** (`gateway/`) | Ein MCP-Server mit 36 Werkzeugen für alle Quellen. Protokolliert jede Abfrage, legt jede Antwort unverändert ab, hält Schlüssel aus Protokoll und Modell heraus, drosselt und cacht. |
| **Ermittler-Team** (`.claude/agents/`) | Sechs Subagenten: vier Analysten, ein unabhängiger Gegenprüfer, ein Rapportführer. |
| **Skills** (`.claude/skills/`) | Die Methodik: Ablauf der Ermittlung, Indikatoren ziehen, Ermittlungsstandard, Rapport, Protokoll. |
| **Wächter und Sitzungsprotokoll** (`.claude/hooks/`) | Sperren, was Agenten nicht dürfen, und halten fest, wer was getan hat. |
| **Werkzeuge** (`tools/`) | Einrichten, Fall anlegen, PII-Prüfung, Rapport und Protokoll erzeugen, Kette prüfen, Einrichtung prüfen. |
| **Musterfall** (`faelle/MUSTER-2026-001/`, `muster/`) | Ein erfundener Fall, komplett durchgespielt. Zeigt, was am Ende in der Fallakte liegt. Rapport und Protokoll als PDF unter [`muster/`](muster/). |

Die Ergebnisse einer Ermittlung:

- `Abschlussrapport.html`: Zusammenfassung, Indikatoren, Befunde mit «Einfach erklärt», Beziehungsgraf, Zeitachse,
  Lücken, Empfehlungen, Glossar. Eine Datei, ohne Abhängigkeiten, aus dem Browser als PDF druckbar.
- `Ermittlungsprotokoll.html` und `.csv`: jede Abfrage mit Zeit, Quelle, Ziel, Zweck, Ergebnis, Prüfsumme, Rohdatei und Agent.
- `indikatoren.csv`: die Indikatorliste zum Weitergeben.
- Beide Dokumente als PDF im Format A4: `python3 tools/pdf.py <Fall-ID>`.

![Beziehungsgraf](docs/bilder/beziehungsgraf.png)

## Einrichten

Ein Befehl prüft die Voraussetzungen, installiert, was fehlt, und richtet den Arbeitsplatz ein. Er fragt
nichts und lässt sich beliebig oft wiederholen.

```bash
git clone https://github.com/valITino/gogoinvestigation.git
cd gogoinvestigation
./setup.sh              # Linux, macOS, WSL
```

```powershell
.\setup.cmd             # Windows: PowerShell oder Eingabeaufforderung
```

**Voraussetzungen und was die Einrichtung damit tut**

| Was | Wozu | Nötig? | Wenn es fehlt |
|---|---|---|---|
| Python 3.10 oder neuer | Gateway, Werkzeuge, Hooks | ja | wird installiert: über die Paketverwaltung des Systems (apt, dnf, yum, pacman, zypper, apk, Homebrew), unter Windows über winget |
| `venv` und `pip` | eigene Python-Umgebung `.venv` im Projektordner | ja | wird installiert (Debian, Ubuntu, Kali: Paket `python3-venv`) |
| [Claude Code](https://code.claude.com/docs) ab 2.1.295 | die Agenten | ja | wird mit dem Installer von Anthropic installiert |
| Git for Windows, nur unter Windows | Git Bash. Darin führt Claude Code Wächter und Protokoll aus. | ja | wird über winget installiert |
| `pdftotext` (Poppler) | Rapporte als PDF aufnehmen | nein, `.txt` `.md` `.docx` gehen ohne | wird installiert |
| Docker | Web-Check und Robin (Dark Web) | nein, beides bleibt sonst aus | wird gemeldet. Debian, Ubuntu, Kali: `./setup.sh --docker-installieren` holt es nach |
| Chrome, Chromium, Edge oder Brave | Rapport und Protokoll als PDF erzeugen | nein, sonst im Browser als PDF drucken | wird gemeldet |
| Konto für Claude Code | Anmeldung, Zugang zu Fable 5.2 | ja | bleibt bei euch |

Systempakete brauchen unter Linux root. Läuft die Einrichtung nicht als root, fragt `sudo` einmal nach dem
Passwort. Alles andere landet im Projektordner oder im eigenen Benutzerkonto. Unter Windows kommt die
Einrichtung in der Regel ohne Administratorrechte aus. Fehlt Git for Windows, kann dessen Installation danach fragen.

**Die sechs Schritte**

1. Voraussetzungen prüfen und Fehlendes installieren.
2. `.venv` anlegen und die Pakete installieren.
3. `.env` aus `.env.example` anlegen, nur für das eigene Konto lesbar. Eine vorhandene `.env` bleibt.
4. Web-Check per Docker auf `127.0.0.1:3000` starten und das Robin-Abbild laden, falls Docker läuft.
5. Claude Code: MCP-Server freischalten und das Modell der Ermittlungsphase setzen (`.claude/settings.local.json`),
   Anmeldung prüfen.
6. Musterfall bauen und die Einrichtung mit 20 Selbsttests prüfen.

Am Ende steht, was neu eingerichtet wurde, was bereit ist und was für euch bleibt. Die Meldungen der
Installationsprogramme liegen im Ordner `osint-setup` des temporären Verzeichnisses (`/tmp/osint-setup`, unter
Windows `%TEMP%\osint-setup`).

**Optionen**

| Option | Wirkung |
|---|---|
| `--nur-pruefen` | zeigt, was vorhanden ist und was fehlt. Verändert nichts. |
| `--nichts-installieren` | installiert nichts am System, richtet nur das Projekt ein |
| `--ermittlungsmodell mythos` | stellt die Ermittlungsphase auf Claude Mythos 5.2, siehe [Modelle je Phase](#modelle-je-phase) |
| `--env-von DATEI` | übernimmt Schlüssel und Einstellungen aus einer vorbereiteten Datei nach `.env` |
| `--docker-installieren` | installiert Docker aus den Paketquellen mit (Debian, Ubuntu, Kali) |
| `--ohne-docker`, `--ohne-robin` | lässt Web-Check und Robin aus, oder nur Robin |
| `--hilfe` | alle Optionen |

**Mehrere Arbeitsplätze.** Eine ausgefüllte Kopie von `.env.example` an einem geschützten Ort ablegen, auf
Wunsch mit `OSINT_ERMITTLUNGSMODELL=mythos`. Dann genügt je Laptop ein Befehl:

```powershell
.\setup.cmd --env-von \\server\freigabe\osint.env
```

**Was von Hand bleibt** und sich bewusst nicht automatisieren lässt:

- Schlüssel bei den Anbietern besorgen, siehe [Schlüssel](#schlüssel).
- Bei Claude Code anmelden: `claude` starten, die Anmeldung läuft über den Browser.
- Beim ersten Start von `claude` im Projektordner den Vertrauensdialog bestätigen. Erst dann gelten Wächter,
  Protokoll und MCP-Server.

**Kontrolle**

```bash
python3 tools/pruefen.py          # Umgebung, Konfiguration, Modelle, Quellen, Selbsttests
python3 tools/pruefen.py --live   # zusätzlich eine harmlose Testabfrage je eingerichteter Quelle
claude mcp list                   # zeigt "osint … Connected", sobald der Ordner als vertrauenswürdig bestätigt ist
```

### Windows

Zwei Wege führen zum selben Arbeitsplatz. Nicht mischen: Je System braucht es einen eigenen Klon, denn die
Python-Umgebungen von Linux und Windows vertragen sich nicht im selben Ordner. Die Einrichtung erkennt das und
bricht mit einem Hinweis ab.

| Weg | So | Docker |
|---|---|---|
| **WSL** | Repository in WSL klonen, dort `./setup.sh`. Es gilt alles, was für Linux gilt. | freie Docker Engine: `./setup.sh --docker-installieren` |
| **Windows direkt** | `.\setup.cmd` in PowerShell oder der Eingabeaufforderung | Docker Desktop, von Hand |

Für Windows direkt gilt:

- **Der Interpreter heisst `python`**, nicht `python3`. Sonst sind alle Befehle dieser Anleitung gleich:
  `python tools\fall.py neu 2026-0412 …`.
- **`setup.cmd` startet `setup.ps1`** mit `-ExecutionPolicy Bypass` für genau diesen einen Lauf. Die Richtlinie
  des Rechners bleibt, wie sie ist. Sperrt eine Gruppenrichtlinie PowerShell-Skripte ganz, leistet
  `py tools\einrichten.py` dasselbe, sobald Python installiert ist.
- **Nach der Einrichtung ein neues Terminal öffnen.** Die Einrichtung setzt für euer Benutzerkonto die
  Umgebungsvariable `OSINT_PYTHON`. Über sie startet Claude Code das Gateway, weil es unter Windows kein
  `python3` gibt. Ein schon offenes Fenster kennt die Variable noch nicht.
- **Freigaben in PowerShell oder der Eingabeaufforderung erteilen**, nicht im Fenster von Git Bash. Dort
  erkennt Python kein Terminal und lehnt die Bestätigung ab.
- **Docker Desktop installiert die Einrichtung nicht.** Laut Docker brauchen grössere Unternehmen und Behörden
  dafür ein bezahltes Abonnement ([Bedingungen](https://docs.docker.com/desktop/setup/install/windows-install/)).
  Ohne Docker bleiben nur Web-Check und Robin aus.
- **Befehle laufen in Git Bash.** Das Projekt schaltet das PowerShell-Werkzeug von Claude Code ab
  (`CLAUDE_CODE_USE_POWERSHELL_TOOL=0`), damit Wächter und Berechtigungen an einer Stelle greifen. Der Wächter
  prüft PowerShell-Befehle trotzdem wie Bash, falls das Werkzeug doch aktiv ist.

## Schlüssel

Alle Schlüssel stehen in `.env`. Jede Quelle ist für sich optional: Was keinen Schlüssel hat, bleibt aus, der
Rest läuft. Sechs Quellen brauchen gar keinen.

| Quelle | Variable in `.env` | Woher | Hinweis |
|---|---|---|---|
| Shodan | `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | DNS-Abfragen und Trefferlisten der Suche verbrauchen Query-Credits. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Bedingungen des öffentlichen Schlüssels prüfen. Die Drossel ist auf ihn eingestellt (`VT_INTERVALL=15.5`), mit Premium auf `0` setzen. |
| Spur | `SPUR_TOKEN` | Spur-App, Settings → API ([Doku](https://docs.spur.us/context-api)) | Kommerzieller Dienst. |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) | |
| urlquery | `URLQUERY_API_KEY` | Konto auf [urlquery.net](https://urlquery.net) | |
| ransomware.live | `RANSOMWARE_LIVE_API_KEY` | [my.ransomware.live](https://my.ransomware.live) | API PRO. Die schlüssellose API v2 ist laut Anbieter nur für private Nutzung, darum hier nur mit `RANSOMWARE_LIVE_V2=1`. |
| Telegram über RapidAPI | `RAPIDAPI_KEY` | [rapidapi.com](https://rapidapi.com), APIs «Telegram Channel» und «Telegram Scraper API» abonnieren | Nur für Kanal-Stammdaten und Kontoabfragen. Drittanbieter unbekannter Herkunft, vor dem Einsatz prüfen. |
| Shodan InternetDB, Wayback Machine, Ahmia-Sperrliste, Telegram-Kanalvorschau, 4chan, Mastodon | keine | | Laufen sofort. |
| Web-Check | keine | eigene Instanz, die Einrichtung startet sie | Adresse in `WEBCHECK_URL`. |
| Robin (Dark Web) | keine | Docker-Abbild, die Einrichtung lädt es | Tor läuft im Container. Eigener Fork: `ROBIN_IMAGE` setzen. |

Weitere Einstellungen in `.env`: `OSINT_PROXY` (alle Abfragen über einen Proxy leiten, damit sie nicht auf eure
Adresse zurückführen), `OSINT_ZEITZONE`, `OSINT_USER_AGENT`, `OSINT_ERMITTLUNGSMODELL`.

Die Schlüssel liest nur das Gateway. Claude Code darf `.env` nicht lesen, und im Protokoll erscheinen
Schlüssel als `***`.

## Eine Ermittlung durchführen

**1. Pseudonymisieren, im Haus.** Euer eigenes LLM ersetzt Personendaten durch nummerierte Platzhalter:
`[PERSON_01]`, `[ORG_01]`, `[ADRESSE_01]`, `[TEL_01]`. Nummeriert, nicht alle «Hans Muster», sonst geht verloren,
wer wer ist. Technische Indikatoren (IPs, Domains, Hashes, Adressen der Täterseite) bleiben stehen, denn nach
ihnen wird gesucht. Eine fertige Anweisung für euer LLM und die Regeln, was bleibt und was geht, stehen in
[docs/PSEUDONYMISIERUNG.md](docs/PSEUDONYMISIERUNG.md).

**2. Ermitteln.** Ein Befehl in Claude Code:

```
claude
/ermittlung 2026-0412 ~/eingang/rapport_pseudonymisiert.docx
```

Das legt den Fall an, schickt das Dokument durch die PII-Prüfung, zieht die Indikatoren, setzt das Team ein,
lässt gegenprüfen und erzeugt Rapport und Protokoll. Rückfragen gibt es nur, wo ein Mensch entscheiden muss.

Wer den Fall lieber selbst anlegt:

```bash
python3 tools/fall.py neu 2026-0412 --titel "Phishing Kundenportal" --kuerzel ABC --rapport rapport.docx
```

**3. Freigaben erteilen, falls nötig.** Drei Dinge sind standardmässig aus und werden pro Fall am Terminal freigegeben:

```bash
python3 tools/fall.py freigabe 2026-0412 darkweb       --durch "Kürzel/Funktion" --vermerk "Grundlage"
python3 tools/fall.py freigabe 2026-0412 aktiv         --durch "…" --vermerk "…"
python3 tools/fall.py freigabe 2026-0412 personenbezug --durch "…" --vermerk "…"
```

| Freigabe | Schaltet frei |
|---|---|
| `darkweb` | Suche und Lektüre von Onion-Seiten über Robin. |
| `aktiv` | Massnahmen, die das Ziel bemerken kann: URL bei urlquery einreichen, Seite in der Wayback Machine sichern, aktive Web-Check-Prüfungen. Jede einzelne verlangt zusätzlich eine Bestätigung in der Sitzung. |
| `personenbezug` | Kontoabfragen: Mastodon-Konto, Telegram-Benutzer und -Suche. |

Der Befehl verlangt eine Bestätigung am Terminal. Ein Agent kann sich keine Freigabe selbst erteilen.

**4. Ergebnis ansehen.** `faelle/2026-0412/rapport/Abschlussrapport.html` im Browser öffnen. Als PDF:

```bash
python3 tools/pdf.py 2026-0412
```

**5. Zurückführen, im Haus.** Die Platzhalter im fertigen Rapport ersetzt ihr ausserhalb von Claude Code:

```bash
python3 tools/reidentifizieren.py 2026-0412 --zuordnung /sicher/zuordnung.csv --ausgabe /sicher/ablage/
```

Weitere Befehle:

```bash
python3 tools/fall.py liste                    # alle Fälle
python3 tools/fall.py status 2026-0412         # Stand und Freigaben
python3 tools/fall.py aufnehmen 2026-0412 nachtrag.docx
python3 tools/rapport.py 2026-0412             # Rapport neu erzeugen (--entwurf, --nur-pruefen)
python3 tools/protokoll.py 2026-0412           # Protokoll neu erzeugen
python3 tools/pdf.py 2026-0412                 # beide Dokumente als PDF (A4)
python3 tools/audit_pruefen.py 2026-0412       # Protokollkette prüfen
python3 tools/musterfall.py                    # Musterfall neu bauen
```

In Claude Code: `/ermittlung <Fall-ID> [Dokument]`, `/abschlussrapport <Fall-ID>`, `/protokoll <Fall-ID>`.

## Das Ermittler-Team

| Agent | Fragt | Werkzeuge |
|---|---|---|
| `infrastruktur-analyst` | Wem gehört die IP? Rechenzentrum, VPN oder Privatanschluss? Was läuft darauf, was lag sonst dort? | Shodan, Spur, AbuseIPDB, VirusTotal, Web-Check passiv, Wayback |
| `malware-url-analyst` | Ist die Datei bekannt? Was tat die Seite beim Aufruf? Seit wann gibt es sie? | VirusTotal, urlquery, Wayback, Web-Check passiv |
| `darkweb-analyst` | Ist die Gruppe bekannt? Passt die Leak-Seite? Taucht der Fall in Breach-Feeds oder im Dark Web auf? | ransomware.live, Ahmia-Sperrliste, Telegram, Robin |
| `socmint-analyst` | Was wird in Foren und Kanälen zum Fall gesagt? Was zeigen Konten der Täterseite? | 4chan, Telegram, Mastodon |
| `gegenpruefer` | Steht das, was im Rapport stehen soll, wirklich in den Rohdaten? | nur Lesen. Kennt den Ermittlungsverlauf nicht. |
| `rapportfuehrer` | Verdichtet die Meldungen zu `befunde.json`, arbeitet die Gegenprüfung ein, erzeugt Rapport und Protokoll. | Lesen, Schreiben, `tools/` |

Die Hauptsitzung leitet: Sie zieht die Indikatoren, verteilt sie, entscheidet über Pivots (höchstens zwei Runden)
und ist die einzige, die aktive Massnahmen ausführt.

### Modelle je Phase

Zwei Modelle teilen sich die Arbeit: eines ermittelt, Claude Fable 5.2 schliesst ab.

| Phase | Wer | Modell | Wo festgelegt |
|---|---|---|---|
| **Ermittlung** | Hauptsitzung (Leitung, Indikatoren, Pivots, aktive Massnahmen) und die vier Analysten | das Modell der Sitzung. Standard `claude-fable-5-2`, umstellbar auf `claude-mythos-5-2` | `.claude/settings.json`, lokal übersteuert in `.claude/settings.local.json`. Die Analysten haben `model: inherit`. |
| **Abschluss** | `gegenpruefer`, `rapportfuehrer`, `/abschlussrapport`, `/protokoll` | fest `claude-fable-5-2` | `model:` in den Agenten- und Skill-Dateien |

Wer Zugang zu Claude Mythos 5.2 hat, stellt die Ermittlungsphase mit einem Befehl um:

```bash
./setup.sh --ermittlungsmodell mythos      # zurück: --ermittlungsmodell fable
```

Mythos 5.2 ist dasselbe Modell wie Fable 5.2, ohne dessen zusätzliche Schutzmassnahmen für Cybersicherheit und
Biologie, und steht nur Organisationen offen, die Anthropic verifiziert hat
([Modellseite](https://platform.claude.com/docs/en/models/mythos-5-2/overview)). Fehlt der Zugang, meldet
Claude Code das beim Start. Dann zurückstellen. Statt `mythos` oder `fable` nimmt die Option auch jede Modell-ID.

Was «Abschluss auf Fable 5.2» heisst: Die Texte des Rapports (Zusammenfassung, Befunde, «Einfach erklärt»,
Lücken, Empfehlungen) und die Daten für Beziehungsgraf und Zeitachse schreibt der Rapportführer in
`befunde.json`. Die Grafiken selbst zeichnet `tools/rapport.py` daraus als Programm, ohne Modell. Bei gleichen
Befunden fallen sie deshalb immer gleich aus.

Die geltende Zuteilung zeigt `python3 tools/pruefen.py` unter «Konfiguration». Ein Selbsttest schlägt an, wenn ein
Agent des Abschlusses nicht auf Fable 5.2 steht. Die Hauptsitzung gibt beim Start eines Subagenten kein Modell
mit, sonst würde sie diese Zuteilung übersteuern (so steht es im Skill `ermittlung`).

Skills und Subagenten ergänzen sich: Ein **Subagent** ist eine Rolle mit eigenem Kontext und eigenen Werkzeugen.
Ein **Skill** ist Wissen, wie etwas zu tun ist. Der Skill `ermittlungsstandard` wird in jeden Analysten vorgeladen
und regelt Zweckangabe, Sicherheitsstufen, Quellenbewertung und das Format der Rückmeldung.

## Quellen

So sind die gewünschten Werkzeuge eingebunden. Details und Endpunkte: [docs/QUELLEN.md](docs/QUELLEN.md).

| Quelle | Einbindung | Art |
|---|---|---|
| Shodan | Gateway: `shodan_host`, `shodan_internetdb`, `shodan_dns`, `shodan_suche` | passiv |
| VirusTotal | Gateway: `virustotal_ip`, `_domain`, `_datei`, `_url`, `_beziehungen`. Nur Abfragen, nie Uploads. | passiv |
| Spur | Gateway: `spur_kontext` | passiv |
| AbuseIPDB | Gateway: `abuseipdb_pruefen`, `abuseipdb_meldungen` | passiv |
| web-check | Eigene Instanz per Docker. Gateway: `webcheck_passiv` (13 Prüfungen), `webcheck_aktiv` (27 Prüfungen) | passiv und aktiv |
| Robin | Eigener MCP-Server des Projekts, läuft als Container mit Tor. Wächter verlangt Freigabe `darkweb`, Hook sichert jede Antwort als Beleg `X-…`. | Tor |
| Darkus | Menügesteuert, deshalb nicht agentenfähig. Seine Suchmaschinen deckt Robin ab. Die Prüfung gegen die Ahmia-Sperrliste ist als `onion_sperrliste` nachgebaut und Pflicht vor jedem Öffnen einer Onion-Seite. | passiv |
| ransomware.live | Gateway: `ransomware_opfer`, `_gruppe`, `_iocs`, `_aktuell` | passiv |
| urlquery | Gateway: `urlquery_suche`, `_bericht`, `_reputation`, `_status` und `urlquery_einreichen` | passiv, Einreichen aktiv |
| Wayback Machine | Gateway: `wayback_verlauf`, `wayback_abruf` und `wayback_sichern` | passiv, Sichern aktiv |
| Telegram Breach Monitor | Die Seite verweist auf den Kanal `breachdetect`. Gateway: `telegram_kanal` liest dessen öffentliche Web-Vorschau. | passiv |
| TeleGramSint | Menügesteuert. Drei seiner Abfragen sind nachgebaut: `telegram_kanalinfo`, `telegram_entitaet`, `telegram_suche`. Die Suche nach Telefonnummern ist bewusst weggelassen. | passiv, teils Personenbezug |
| OSINT-Chan | Nachgebaut über die offizielle Lese-API: `chan_katalog`, `chan_thread`. Stichworte werden lokal gefiltert. | passiv |
| Masto | Nachgebaut: `mastodon_instanz`, `mastodon_konto` | passiv, Konto mit Personenbezug |

**Passiv** heisst: Die Datenbank eines Dritten wird befragt, das Ziel merkt nichts. Der Anbieter sieht aber
den Indikator. **Aktiv** heisst: Das Ziel wird aufgerufen und kann das bemerken.

Warum ein eigenes Gateway statt je eines fertigen MCP-Servers pro Dienst: eine Stelle für Protokoll, Rohdaten,
Drossel und Cache, ein überschaubarer Code statt eines Dutzends fremder Server mit euren Schlüsseln, und kurze
Antworten, die den Kontext der Agenten schonen. Die vollständige Antwort liegt immer in den Rohdaten.

## Schutzmechanismen

Technisch erzwungen, nicht nur dem Modell aufgetragen:

| Schutz | Wie | Wo |
|---|---|---|
| Keine übersehenen Personendaten | PII-Prüfung vor der Aufnahme (AHV-Nummer, IBAN, Telefon, Geburtsdatum, Kontrollschild, Kreditkarte). Sperrfunde verhindern die Aufnahme. | `tools/pii_pruefung.py` |
| Agenten lesen nur geprüfte Dokumente | Wächter vergleicht den Hash jeder Datei im Eingang mit dem Register der PII-Prüfung. | `.claude/hooks/waechter.py` |
| Keine Abfrage ohne Fall und Zweck | Das Gateway weist sie ab. | `gateway/kern.py` |
| Aktiv, Dark Web, Personenbezug nur mit Freigabe | Gateway und Wächter prüfen `fall.json`. Abgelehnte Versuche stehen im Protokoll. | `gateway/kern.py`, Wächter |
| Keine Selbstfreigabe | `fall.py freigabe` verlangt ein Terminal. Wächter und Berechtigungen sperren den Befehl für Agenten. | `tools/fall.py` |
| Nichts am Protokoll vorbei | `curl`, `wget`, `Invoke-WebRequest` und Ähnliches sind gesperrt. `WebFetch` und `WebSearch` fragen jedes Mal nach. | `.claude/settings.json`, Wächter |
| Protokoll und Rohdaten unveränderbar für Agenten | Schreibschutz über Berechtigungen und Wächter. | beide |
| Agenten stellen die Einrichtung nicht um | `setup.sh`, `setup.cmd` und `tools/einrichten.py` sind für Agenten gesperrt, ebenso das Schreiben an Gateway, Hooks und Einstellungen. | Wächter |
| Fällt der Wächter aus, läuft nichts | Kann der Wächter nicht starten oder seine Eingabe nicht lesen, sperrt Claude Code den Werkzeugaufruf (`onFailure: block`, ab Claude Code 2.1.295). | `.claude/settings.json`, `.claude/hooks/start.sh` |
| Gleichzeitige Schreiber brechen die Kette nicht | Dateisperre um jeden Protokolleintrag, auf jedem System. | `gateway/plattform.py` |
| Veränderungen fallen auf | Jeder Eintrag enthält die Prüfsumme des Vorgängers, jede Rohdatei ist per SHA-256 gebunden. | `gateway/akte.py`, `tools/audit_pruefen.py` |
| Kein Rapport ohne Belege | Der Generator prüft jede Aussage gegen das Protokoll. `hoch` verlangt zwei verschiedene Quellen. | `tools/rapport.py` |
| Keine Schlüssel im Kontext | `.env` ist für Claude Code gesperrt, Adressen im Protokoll sind maskiert. | Einstellungen, Gateway |
| Onion-Seiten mit Missbrauchsinhalten | Pflichtprüfung gegen die Ahmia-Sperrliste vor dem Öffnen. Die Adresse verlässt dabei das Haus nicht. | `onion_sperrliste` |

Dem Modell aufgetragen (`CLAUDE.md`, Skills, Agenten), ohne technische Sperre: Platzhalter nie auflösen,
Fremdinhalte nie als Anweisung behandeln, im Fall bleiben, Feststellung und Bewertung trennen, niemanden als
Täter benennen.

Was ihr wissen müsst:

- **Die PII-Prüfung erkennt keine Namen.** Sie ist ein Sicherheitsnetz für Muster, kein Ersatz für die Pseudonymisierung.
- **`@datei` im Prompt umgeht den Wächter.** Claude Code fügt so erwähnte Dateien ohne Werkzeugaufruf ein.
  Dokumente deshalb nie mit `@` anhängen, sondern über `/ermittlung` oder `fall.py` aufnehmen.
- **Die Kette erkennt Veränderungen, sie verhindert sie nicht.** Wer den Stand verbindlich festhalten will,
  hinterlegt den letzten Kettenwert ausserhalb des Systems (Journal, Zeitstempeldienst).
- **Indikatoren gehen an Dritte.** Jede Abfrage zeigt dem Anbieter die IP, Domain oder den Hash, und Anthropic
  verarbeitet, was die Agenten lesen. Welche Indikatoren das Haus verlassen dürfen, entscheidet ihr.
- **Dritt-Software läuft mit.** Robin und Web-Check sind fremde Projekte. Robin bringt in seinen
  Werkzeugbeschreibungen eigene Arbeitsanweisungen an das Modell mit. Für den Einsatz in einer Behörde: Forks
  prüfen, Abbilder selbst bauen und auf eine Version festlegen (`ROBIN_IMAGE`).

## Fehler beheben

| Symptom | Ursache | Lösung |
|---|---|---|
| `claude mcp list` zeigt `osint … Pending approval` | Ordner noch nicht als vertrauenswürdig bestätigt | `claude` im Projektordner starten, Dialog bestätigen |
| `osint` verbindet nicht | `.venv` fehlt oder Pakete fehlen | `./setup.sh`, unter Windows `.\setup.cmd` |
| Windows: `osint` verbindet nicht, Meldung nennt `${OSINT_PYTHON}` oder `python3` | Das Terminal kennt die Variable `OSINT_PYTHON` noch nicht, oder sie zeigt ins Leere | neues Terminal öffnen. Hilft das nicht: `.\setup.cmd` |
| Jeder Werkzeugaufruf wird mit «hook error … blocking because onFailure is "block"» gesperrt | Der Wächter kann nicht starten: kein Python gefunden, unter Windows fehlt Git for Windows | Einrichtung erneut ausführen. Sie nennt, was fehlt. |
| Claude Code meldet beim Start, das Modell sei nicht verfügbar | Ermittlungsphase steht auf Mythos 5.2, das Konto hat keinen Zugang | `./setup.sh --ermittlungsmodell fable` |
| `fall.py freigabe` meldet «trifft ein Mensch am Terminal», obwohl ihr am Terminal sitzt | Fenster von Git Bash unter Windows | in PowerShell oder der Eingabeaufforderung ausführen |
| `.\setup.ps1` meldet «Ausführung von Skripts ist deaktiviert» | Ausführungsrichtlinie von PowerShell | `.\setup.cmd` verwenden |
| Einrichtung meldet «Dieser Ordner wurde unter … eingerichtet» | derselbe Ordner unter WSL und unter Windows benutzt | je System ein eigener Klon |
| Werkzeug meldet «Schlüssel … fehlt in .env» | Quelle nicht eingerichtet | Schlüssel eintragen, Claude Code neu starten |
| «verweigert den Zugriff (HTTP 401/403)» | Schlüssel falsch, abgelaufen oder Abo deckt den Endpunkt nicht | Schlüssel prüfen, `python3 tools/pruefen.py --live` |
| «Kontingent oder Ratenlimit erreicht (HTTP 429)» | Tages- oder Minutenlimit der Quelle | Später weiter. Der Rapport nennt die Lücke. |
| «Keine Verbindung zu Web-Check» | Container läuft nicht | `docker compose up -d webcheck` |
| VirusTotal-Abfragen dauern lange | Drossel für den öffentlichen Schlüssel | Mit Premium `VT_INTERVALL=0` in `.env` |
| «Nicht ausgeführt: … braucht der Fall die Freigabe» | Freigabe fehlt | `python3 tools/fall.py freigabe …` am Terminal |
| «… ist nicht durch die PII-Prüfung freigegeben» | Datei von Hand in den Eingang kopiert oder nachträglich geändert | `python3 tools/fall.py aufnehmen <Fall-ID> <Datei>` |
| Dokument wird nicht aufgenommen (Sperrfunde) | Personendaten übersehen, oder Fehlalarm | Nachpseudonymisieren. Bei Fehlalarm am Terminal: `--trotzdem "Begründung" --durch "Kürzel"` |
| `rapport.py` meldet Mängel | Aussage ohne Beleg, `hoch` mit nur einer Quelle, Gegenprüfung offen | An der Sache beheben. Zwischenstand mit `--entwurf`. |
| Robin erscheint nicht | Docker fehlte bei der Einrichtung | Docker starten, Einrichtung erneut ausführen |
| «Protokoll … ABWEICHUNGEN» | Protokoll oder Rohdatei wurde verändert | Nicht reparieren. Vorfall klären. |

Meldungen der Einrichtung: `/tmp/osint-setup/` (unter Windows `%TEMP%\osint-setup\`), je Schritt eine Datei:
`pakete.log`, `venv.log`, `pip.log`, `claude.log`, `docker.log`, `muster.log`. Was fehlt, ohne etwas zu ändern:
`./setup.sh --nur-pruefen`.

## Stand der Prüfung und Grenzen

Geprüft auf Linux (Ubuntu 24.04, Python 3.13, Claude Code 2.1.323):

- 20 Selbsttests ohne Netz (`python3 tools/selbsttest.py`): Gateway über echtes MCP-stdio, Protokollkette samt
  Manipulationserkennung, Cache, Freigaben, Wächter für Bash und PowerShell, Hook-Starter, Sitzungs-Hook,
  Dateisperre und gleichzeitige Hooks, PII-Prüfung, Prüfregeln des Rapports, Zuteilung der Modelle,
  Übereinstimmung der Agenten mit den Werkzeugen. Zwei Gegenproben: Ohne Dateisperre scheitert der Sperrtest,
  ein absichtlich falscher Wert in den Einstellungen wird von `claude doctor` beanstandet.
- Die Einrichtung in einem frischen Klon: erster Lauf, zweiter Lauf ohne Neuinstallation, Modellwechsel hin und
  zurück, Übernahme von Schlüsseln aus einer Datei, und die Fehlerbilder «Claude Code fehlt», «nur ein altes
  Python», «Ordner unter dem anderen System eingerichtet», «unbekannte Option». Der Klon bleibt danach unverändert
  (`git status` leer), der Musterfall fällt also Byte für Byte gleich aus.
- Der Musterfall läuft durch dieselben Gateway-Werkzeuge wie eine echte Ermittlung, mit vorgefertigten Antworten.
- Claude Code liest `.mcp.json`, verbindet sich mit dem Gateway (`claude mcp list`), übernimmt den Interpreter
  aus der Umgebungsvariablen `OSINT_PYTHON` und beanstandet die Einstellungen nicht (`claude doctor`).

Bei jeder Änderung prüft GitHub Actions die Einrichtung samt Selbsttests auf Linux, macOS und Windows
(Windows PowerShell 5.1 und PowerShell 7), siehe [`.github/workflows/pruefung.yml`](.github/workflows/pruefung.yml).

Nicht geprüft:

- **Die Quellen selbst.** Beim Bau standen weder Schlüssel noch Netzzugang zu den Diensten zur Verfügung. Die
  Endpunkte folgen den Dokumentationen und offiziellen Clients (siehe [docs/QUELLEN.md](docs/QUELLEN.md)).
  `python3 tools/pruefen.py --live` prüft jede eingerichtete Quelle mit einem harmlosen Testwert. Am unsichersten
  sind die Pfade der ransomware.live API PRO und das Auslesen der Telegram-Vorschau.
- **Eine vollständige Ermittlung in einer echten Claude-Code-Sitzung** mit Subagenten, Skills und Hooks im
  Zusammenspiel, und damit auch: ob die Sitzung auf Mythos 5.2 läuft und der Abschluss auf Fable 5.2 wechselt.
  Die Modell-ID `claude-mythos-5-2` und die Felder `model` für Sitzung, Subagenten und Skills stammen aus den
  Dokumentationen von Anthropic. Die Hooks sind einzeln mit den dokumentierten Ereignisdaten getestet.
- **Die Installation fehlender Systempakete** über dnf, yum, pacman, zypper, apk und winget sowie
  `--docker-installieren`. Geprüft ist, welche Befehle die Einrichtung je Paketverwaltung absetzt, nicht deren
  Ausführung auf den jeweiligen Systemen.
- **Robin und Web-Check im Betrieb.** Docker lief beim Bau nicht.

Grenzen:

- Fable 5.2 hat zusätzliche Schutzmassnahmen im Bereich Cybersicherheit. Der Arbeitsplatz verlangt vom Modell
  Abfragen und deren Auswertung, keine Analyse oder Entwicklung von Schadcode.
- Abfragen mit Klarnamen (etwa die geschädigte Firma auf Leak-Seiten suchen) sind mit pseudonymisierten Dokumenten
  nicht möglich. Der Rapport weist sie als «im Haus nachzuholen» aus.
- Unter Windows direkt braucht es Git for Windows, und Docker heisst dort Docker Desktop. Wer beides nicht will,
  nimmt WSL.

## Erweitern

Eine neue Quelle in vier Schritten:

1. In `gateway/quellen_*.py` eine Funktion mit `@werkzeug` schreiben. Sie ruft `abfrage(...)` auf und gibt eine
   gekürzte Fassung der Antwort zurück. Protokoll, Rohdaten, Cache und Fehlerbehandlung kommen von `abfrage`.
2. Die Quelle in `gateway/quellen.py` eintragen (Name, Schlüsselvariable, Werkzeuge, Testabfrage).
3. Das Werkzeug dem passenden Agenten unter `tools:` geben und in `.claude/settings.json` erlauben.
4. `python3 tools/selbsttest.py`. Der Test schlägt an, wenn Agenten, Einstellungen und Gateway nicht zusammenpassen.

```python
@werkzeug
async def beispiel_abfrage(fall: Fall, zweck: Zweck, domain: str) -> dict:
    """Beispielquelle: was sie liefert und wann man sie braucht. Diese Zeilen liest der Agent."""
    domain = pruef_domain(domain)
    a = await abfrage(fall, zweck, werkzeug="beispiel_abfrage", quelle="Beispiel", ziel=domain, ziel_typ="domain",
                      url=f"https://api.beispiel.example/v1/domain/{domain}",
                      kopf={"Authorization": schluessel("BEISPIEL_API_KEY", "Beispiel")})
    return a.als_dict(nimm(a.daten, "registriert", "inhaber_land") if a.ergebnis == "ok" else None)
```

## Recht und Verantwortung

Das Projekt ist ein Werkzeug. Ob und wie ihr es einsetzen dürft, bestimmen euer Auftrag, eure Rechtsgrundlagen
und die Bedingungen der Anbieter. Vor dem Einsatz mit echten Fällen mit Rechtsdienst und Datenschutz klären:

- welche Indikatoren an Dritte und an Anthropic gehen dürfen,
- unter welchen Voraussetzungen aktive Massnahmen, Dark-Web-Recherche und Kontoabfragen zulässig sind,
- ob eure Abos die dienstliche Nutzung der Quellen decken,
- wie Protokolle und Rohdaten aufbewahrt und gelöscht werden.

Die Freigaben, das Protokoll und die Prüfregeln sind dafür gebaut, diese Entscheide festzuhalten und
durchzusetzen. Sie ersetzen sie nicht. Dieser Text ist keine Rechtsberatung.

## Lizenz und Mitmachen

Eine Lizenz ist noch nicht festgelegt. Ohne sie dürfen andere den Code rechtlich nicht weiterverwenden. Wer
das Projekt für die Gemeinschaft öffnen will, legt eine `LICENSE` ins Repository.

Die eingebundenen Projekte haben eigene Lizenzen: [Robin](https://github.com/apurvsinghgautam/robin),
[Web-Check](https://github.com/Lissy93/web-check), [Darkus](https://github.com/Lucksi/Darkus),
[TeleGramSint](https://github.com/OSINTCabal/TeleGramSint), [OSINT-Chan](https://github.com/OSINTCabal/OSINT-Chan),
[Masto](https://github.com/C3n7ral051nt4g3ncy/Masto). Aus ihnen wurde kein Code übernommen. Robin und Web-Check
laufen als unveränderte Container, die übrigen Funktionen sind gegen die jeweiligen öffentlichen Schnittstellen neu geschrieben.

Beiträge sind willkommen, besonders neue Quellen und Rückmeldungen aus `pruefen.py --live`. Bitte keine
Falldaten, Schlüssel oder echten Indikatoren in Issues und Pull Requests.
