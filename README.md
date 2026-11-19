# gogoinvestigation

**Ein OSINT-Ermittlungsarbeitsplatz für Claude Code.** Ein pseudonymisierter Rapport geht hinein. Ein
Ermittler-Team aus KI-Agenten fragt Clearweb- und Dark-Web-Quellen ab, verfolgt Zahlungen in Kryptowährungen,
verknüpft die Ergebnisse und prüft sich gegenseitig. Heraus kommen ein verständlicher Abschlussrapport mit Diagrammen und ein lückenloses Protokoll
darüber, wann was wo und wozu abgefragt wurde.

> [!WARNING]
> **Noch nicht an echten Fällen erprobt.** Geprüft ist mit dem Musterfall und mit erfundenen Dokumenten. Die
> Steuerung von Claude Code aus der Oberfläche ist mit dem echten Claude Code nicht geprüft. Den Wächter-Hook gibt
> es seit dem 17.11.2026 nicht mehr: Was Agenten dürfen, regeln die Berechtigungen von Claude Code, die Werkzeuge
> selbst und das Gateway. Was damit gilt und was nicht mehr: [Schutzmechanismen](#schutzmechanismen) und
> [Stand der Prüfung](#stand-der-prüfung-und-grenzen).

> *English summary:* A Claude Code workspace for CTI and law-enforcement OSINT. One MCP gateway wraps Shodan,
> VirusTotal, Spur, AbuseIPDB, urlquery, Wayback Machine, Web-Check, ransomware.live, Telegram, 4chan and
> Mastodon, traces cryptocurrency payments on Bitcoin, Ethereum and TRON (multi-hop money flow, sanctions and
> exchange attribution, fiat value on the day), logs every request in a hash-chained audit trail and stores
> every raw response. A team of
> subagents investigates, an independent agent cross-checks every finding against the raw data, and a
> generator refuses to build the final report unless each statement is backed by evidence. Documentation is
> in German.

![Abschlussrapport des Musterfalls](docs/bilder/abschlussrapport.png)

**Muster ansehen:** [Abschlussrapport (PDF, 21 Seiten)](muster/Abschlussrapport.pdf) ·
[Ermittlungsprotokoll (PDF, 28 Seiten)](muster/Ermittlungsprotokoll.pdf) ·
[Datenblätter (PDF, 94 Seiten)](muster/Datenblaetter.pdf) ·
[was der Musterfall zeigt](muster/README.md). Der Fall ist frei erfunden.

## Inhalt

- [Was ihr bekommt](#was-ihr-bekommt)
- [Einrichten](#einrichten)
- [Schlüssel](#schlüssel)
- [Eine Ermittlung durchführen](#eine-ermittlung-durchführen)
- [Oberfläche](#oberfläche)
- [Pseudonymisieren ohne LLM: der Rückfall](#pseudonymisieren-ohne-llm-der-rückfall)
- [Das Ermittler-Team](#das-ermittler-team)
- [Blockchain-Analyse](#blockchain-analyse)
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
    D --> T["Ermittler-Team<br/>5 Analysten"]
    T --> G["OSINT-Gateway<br/>(MCP)"]
    T --> R["Robin<br/>(MCP, Tor)"]
    G --> Q["Shodan · VirusTotal · Spur · AbuseIPDB<br/>urlquery · Wayback · Web-Check<br/>ransomware.live · Telegram · 4chan · Mastodon<br/>Bitcoin · Ethereum · TRON"]
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
| **OSINT-Gateway** (`gateway/`) | Ein MCP-Server mit 48 Werkzeugen für alle Quellen. Protokolliert jede Abfrage, legt jede Antwort unverändert ab, hält Schlüssel aus Protokoll und Modell heraus, drosselt und cacht. |
| **Ermittler-Team** (`.claude/agents/`) | Sieben Subagenten: fünf Analysten, ein unabhängiger Gegenprüfer, ein Rapportführer. |
| **Blockchain-Analyse** (`gateway/krypto_*.py`) | Adressen prüfen und einordnen, Geldflüsse über mehrere Stationen verfolgen, Gegenwerte am Tag der Zahlung. Bitcoin, Ethereum und Verwandte, TRON samt USDT und USDC. Mehr unter [Blockchain-Analyse](#blockchain-analyse). |
| **Skills** (`.claude/skills/`) | Die Methodik: Ablauf der Ermittlung, Indikatoren ziehen, Ermittlungsstandard, Rapport, Protokoll. |
| **Berechtigungen und Sitzungsprotokoll** (`.claude/settings.json`, `.claude/hooks/`) | Legen fest, was Agenten ohne Rückfrage dürfen und was nie, und halten fest, wer was getan hat und mit welchem Modell. |
| **Werkzeuge** (`tools/`) | Einrichten, Fall anlegen, PII-Prüfung, Rapport und Protokoll erzeugen, Kette prüfen, Einrichtung prüfen. |
| **Musterfall** (`faelle/MUSTER-2026-001/`, `muster/`) | Ein erfundener Fall, komplett durchgespielt. Zeigt, was am Ende in der Fallakte liegt. Rapport und Protokoll als PDF unter [`muster/`](muster/). |

Die Ergebnisse einer Ermittlung:

- `Abschlussrapport.html`: Zusammenfassung, Indikatoren, Befunde mit «Einfach erklärt», Beziehungsgraf, Geldfluss
  mit Flussbild, Zeitachse, Lücken, Empfehlungen, Glossar. Eine Datei, ohne Abhängigkeiten, aus dem Browser als PDF druckbar.
- `Ermittlungsprotokoll.html` und `.csv`: jede Abfrage mit Zeit, Quelle, Ziel, Zweck, Ergebnis, Prüfsumme, Rohdatei und Agent.
- `indikatoren.csv`: die Indikatorliste zum Weitergeben.
- Beide Dokumente als PDF im Format A4: `python3 tools/pdf.py <Fall-ID>`.

![Beziehungsgraf](docs/bilder/beziehungsgraf.png)

## Einrichten

Ein Befehl richtet den Arbeitsplatz ein. Im Terminal führt ein Assistent hindurch: Er fragt, was nur ihr wissen
könnt, zeigt eine Übersicht und verändert erst etwas, wenn ihr sie bestätigt. Danach läuft alles von selbst.
Der Befehl lässt sich beliebig oft wiederholen.

```bash
git clone https://github.com/valITino/gogoinvestigation.git
cd gogoinvestigation
./setup.sh              # Linux, macOS, WSL
```

```powershell
.\setup.cmd             # Windows: PowerShell oder Eingabeaufforderung
```

![Der Assistent fragt nach den Schlüsseln der Quellen](docs/bilder/einrichtung-schluessel.png)

**Der Assistent**

Bedient wird er mit den Pfeiltasten und Enter, angekreuzt wird mit der Leertaste, Esc bricht ab. Jede Frage hat
eine Vorgabe: Wer nur Enter drückt, bekommt eine lauffähige Einrichtung ohne Mythos, ohne Schlüssel und ohne Proxy.

| Frage | Worum es geht |
|---|---|
| Installieren | Erscheint nur, wenn etwas fehlt (Claude Code, `pdftotext`, ein Browser für die PDF-Fassung, unter Windows Git for Windows). Nennt, was auf welchem Weg installiert würde. |
| Modelle | Darf euer Konto Claude Mythos 5.2 nutzen? Mit Ja schaltet die Ermittlung von selbst darauf um, siehe [Modelle je Phase](#modelle-je-phase). |
| Schlüssel | Liste der Quellen mit ihrem Stand. Eine Quelle öffnen und den Schlüssel einfügen. Die Eingabe bleibt unsichtbar, gezeigt wird nur die Zahl der Zeichen. Mit Entf wird ein Schlüssel entfernt. «Aus einer Datei übernehmen» liest eine vorbereitete Kopie von `.env.example`. |
| Proxy | Sollen die Abfragen an die Quellen über einen Proxy laufen? Kein Proxy, Tor auf diesem Rechner oder eine eigene Adresse. Wer Tor wählt, bekommt es auch: Die Einrichtung installiert und startet es und wartet, bis es Verbindungen aufbaut. Wo sie das nicht kann, nimmt sie die Wahl nicht an. Robin (Dark Web) braucht diesen Proxy nicht, es bringt sein eigenes Tor mit. |
| Dienste | Web-Check und Robin über Docker. Fehlt Docker, bietet der Assistent unter Debian, Ubuntu und Kali die Installation an. Läuft es nur nicht, lässt sich nach dem Start erneut prüfen. |
| Anmeldung | Erscheint nur, wenn Claude Code noch nicht angemeldet ist. Auf Wunsch startet die Einrichtung am Ende die Anmeldung im Browser. |
| Testabfragen | Auf Wunsch geht am Ende je eingerichteter Quelle eine harmlose Abfrage hinaus. Das zeigt sofort, ob Schlüssel, Netz und Proxy stimmen. |
| Start | Auf Wunsch führt die Einrichtung am Ende bis in die Oberfläche: Sie startet Claude Code einmal im Projektordner, damit ihr dem Ordner vertraut (Ordner bestätigen, die Antwort gebt ihr selbst), und öffnet danach die Oberfläche. Ist der Ordner schon bestätigt, fragt sie nur noch nach der Oberfläche. Wer «Prüfen und auffrischen» wählt, bekommt dieselbe Frage am Schluss, sobald der Arbeitsplatz einsatzbereit ist. |

Am Schluss steht die Übersicht. Jede Zeile lässt sich öffnen und ändern. Erst «Einrichten» verändert etwas,
«Abbrechen» lässt alles, wie es war. Tasten, die vor einer Frage getippt wurden, zählen nicht, und die Übersicht
nimmt die erste halbe Sekunde keine Taste an: Ein doppelt gedrücktes Enter bestätigt nichts, was noch niemand
lesen konnte.

![Übersicht vor dem Einrichten](docs/bilder/einrichtung-uebersicht.png)

Schlüssel landen nur in der Datei `.env` auf eurem Rechner. Sie erscheinen weder auf dem Bildschirm noch in den
Meldungen der Einrichtung. Wer den Assistenten erst ansehen will: `./setup.sh --vorschau` stellt die Fragen,
zeigt die Übersicht und verändert nichts.

**Später etwas ändern.** Auf einem eingerichteten Arbeitsplatz bietet derselbe Befehl drei Wege an: «Prüfen und
auffrischen» (fragt nichts, die Einstellungen bleiben), «Einstellungen ändern» (führt direkt zur Übersicht) und
«Nur den Stand zeigen». So kommt ein neuer Schlüssel dazu, ein Proxy weg oder Mythos an.

**Ohne Rückfragen.** Ohne Terminal fragt die Einrichtung von selbst nichts, etwa in einem Skript, in einer
CI-Umgebung oder wenn die Ausgabe in eine Datei geht. Im Terminal erreicht das `--ohne-rueckfragen`. Dann
gelten die Optionen der Befehlszeile und die Werte aus `.env`, und Fehlendes wird ohne Nachfrage installiert. Steht
dort als Proxy Tor auf diesem Rechner (`OSINT_PROXY=socks5h://127.0.0.1:9050`), gehört Tor dazu.

**Wenn das Terminal nicht mitspielt.** `--schlicht` stellt dieselben Fragen als nummerierte Listen, ohne
Cursorsteuerung und ohne Laufanzeige. Das ist der Weg für Bildschirmleser und sehr alte Terminals. Farben
schaltet die Umgebungsvariable `NO_COLOR=1` ab. Keine Aussage hängt an der Farbe allein, jeder Zustand hat ein
Zeichen und ein Wort.

**Voraussetzungen und was die Einrichtung damit tut**

| Was | Wozu | Nötig? | Wenn es fehlt |
|---|---|---|---|
| Python 3.10 oder neuer | Gateway, Werkzeuge, Hooks | ja | wird installiert: über die Paketverwaltung des Systems (apt, dnf, yum, pacman, zypper, apk, Homebrew), unter Windows über winget. Im Terminal fragt das Startskript vorher. |
| `venv` und `pip` | eigene Python-Umgebung `.venv` im Projektordner | ja | wird installiert (Debian, Ubuntu, Kali: Paket `python3-venv`) |
| [Claude Code](https://code.claude.com/docs) ab 2.1.295 | die Agenten | ja | wird mit dem Installer von Anthropic installiert |
| Git for Windows, nur unter Windows | Git Bash. Darin führt Claude Code das Sitzungsprotokoll aus. | ja | wird über winget installiert |
| `pdftotext` (Poppler) | Rapporte als PDF aufnehmen | nein, `.txt` `.md` `.docx` gehen ohne | wird installiert |
| Docker | Web-Check und Robin (Dark Web) | nein, beides bleibt sonst aus | wird gemeldet. Debian, Ubuntu, Kali: `./setup.sh --docker-installieren` holt es nach |
| Chrome, Chromium, Edge oder Brave | Rapport und Protokoll als PDF erzeugen | nein, sonst im Browser als PDF drucken | WSL: Es druckt der Browser von Windows (Edge gehört zum System), installiert wird nichts. Linux: Chromium wird installiert, über die Paketverwaltung, unter Ubuntu als Snap. In beiden Fällen druckt die Einrichtung zur Probe eine kleine Seite und sagt, ob es geklappt hat. macOS: wird gemeldet. Windows: Edge gehört zum System. |
| Tor | Proxy für die Abfragen an die Quellen, nur wenn ihr «Tor auf diesem Rechner» wählt | nein | wird installiert und gestartet (Paket `tor`). Unter Windows direkt nicht: dort einen eigenen Proxy nennen oder WSL nehmen. |
| Konto für Claude Code | Anmeldung, Zugang zu Fable 5.2 | ja | bleibt bei euch |

«Wird installiert» heisst im Assistenten: nach eurem Ja auf die Frage «Installieren». Ohne Rückfragen
geschieht es von selbst, es sei denn, ihr gebt `--nichts-installieren` mit.

Systempakete brauchen unter Linux root. Läuft die Einrichtung nicht als root, fragt `sudo` einmal nach dem
Passwort. Alles andere landet im Projektordner oder im eigenen Benutzerkonto. Unter Windows kommt die
Einrichtung in der Regel ohne Administratorrechte aus. Fehlt Git for Windows, kann dessen Installation danach fragen.

**Die sechs Schritte** nach der Bestätigung

1. Voraussetzungen prüfen und Fehlendes installieren.
2. `.venv` anlegen und die Pakete installieren.
3. `.env` aus `.env.example` anlegen, nur für das eigene Konto lesbar, und eure Antworten eintragen.
   Eine vorhandene `.env` bleibt, geändert wird nur, was ihr geändert habt.
4. Web-Check per Docker auf `127.0.0.1:3000` starten und das Robin-Abbild laden, falls Docker läuft.
5. Claude Code: MCP-Server freischalten, Mythos freischalten, wenn ihr es erklärt habt
   (`.claude/settings.local.json`), Anmeldung prüfen.
6. Musterfall bauen und die Einrichtung mit 99 Selbsttests prüfen.

Auf Wunsch folgen die Anmeldung bei Claude Code und die Testabfragen. Während längerer Arbeiten läuft eine Zeile mit,
die sagt, was gerade geschieht. Am Ende steht, wo ihr steht: ob der Arbeitsplatz einsatzbereit ist, was neu
eingerichtet wurde und was offen bleibt.

Ist er einsatzbereit, fragt die Einrichtung einmal: «Soll die Oberfläche jetzt öffnen?» Mit Ja geht es von selbst
weiter. Vertraut Claude Code dem Projektordner noch nicht, startet es davor einmal und fragt danach: mit Ja bestätigen,
dann `/exit`. Danach öffnet die Oberfläche, und auf ihrer ersten Seite steht unter «So geht es», was dort zu tun ist:
Fall anlegen, ermitteln, Ergebnisse holen.

Wer Nein sagt oder ohne Terminal einrichtet, findet unter «So geht es weiter» höchstens zwei Schritte:

1. Ein neues Terminal öffnen, wenn es eines braucht. Der Grund steht dabei, etwa: Das Konto kam eben erst in die
   Gruppe `docker`.
2. Die Oberfläche starten: `python3 tools/oberflaeche.py`. Fehlt Claude Code noch das Ja zum Projektordner, fragt
   dieser Start einmal danach.

![Ergebnis der Einrichtung](docs/bilder/einrichtung-ergebnis.png)

Das Bild stammt aus einem Lauf vor dem 17.11.2026. Der Schluss ist seit dem 19.11.2026 kürzer: eine Frage statt einer
Liste von Schritten.

Die Prüfung erscheint hier als Kurzfassung, jeder Fehler steht einzeln da. Ausführlich zeigt sie
`python3 tools/pruefen.py`. Die Meldungen der Installationsprogramme liegen im Ordner `osint-setup` des
temporären Verzeichnisses (`/tmp/osint-setup`, unter Windows `%TEMP%\osint-setup`).

**Optionen**

Alles, was der Assistent fragt, lässt sich auch als Option mitgeben. Im Assistenten sind die Optionen die
Vorgaben der Fragen. Auf einem schon eingerichteten Arbeitsplatz fragt die Einrichtung nicht nach, wenn eine
Option etwas einstellt: `./setup.sh --mythos` schaltet Mythos frei und ist fertig.

| Option | Wirkung |
|---|---|
| `--ohne-rueckfragen` | fragt nichts. Kurz: `--ja` oder `-y` |
| `--vorschau` | stellt die Fragen und zeigt die Übersicht, verändert aber nichts |
| `--schlicht` | Fragen als nummerierte Listen, ohne Cursorsteuerung und ohne Laufanzeige |
| `--nur-pruefen` | zeigt, was vorhanden ist und was fehlt. Verändert nichts. |
| `--nichts-installieren` | installiert nichts am System, richtet nur das Projekt ein |
| `--mythos` | erklärt: Dieses Konto hat Claude Mythos 5.2. Die Ermittlung schaltet dann von selbst darauf um, siehe [Modelle je Phase](#modelle-je-phase). Zurücknehmen: `--ohne-mythos` |
| `--env-von DATEI` | übernimmt Schlüssel und Einstellungen aus einer vorbereiteten Datei nach `.env` |
| `--docker-installieren` | installiert Docker aus den Paketquellen mit (Debian, Ubuntu, Kali) |
| `--ohne-docker`, `--ohne-webcheck`, `--ohne-robin` | lässt Web-Check und Robin aus, oder nur eines von beiden |
| `--testen` | schickt am Ende je eingerichteter Quelle eine harmlose Testabfrage |
| `--hilfe` | alle Optionen |

**Mehrere Arbeitsplätze.** Eine ausgefüllte Kopie von `.env.example` an einem geschützten Ort ablegen, auf
Wunsch mit `OSINT_MYTHOS=ja`. Dann genügt je Laptop ein Befehl, und niemand muss etwas beantworten:

```powershell
.\setup.cmd --ohne-rueckfragen --env-von \\server\freigabe\osint.env
```

**Was von Hand bleibt** und sich bewusst nicht automatisieren lässt:

- Schlüssel bei den Anbietern besorgen, siehe [Schlüssel](#schlüssel). Eintragen kann sie der Assistent.
- Bei Claude Code anmelden. Der Assistent startet die Anmeldung auf Wunsch, durch den Browser geht ihr selbst.
  Sonst: `claude` starten und der Anmeldung folgen.
- Den Projektordner bestätigen. Claude Code fragt beim ersten Start in einem Ordner, ob es ihm vertrauen soll. Die
  Einrichtung startet Claude Code dafür auf Wunsch, und der Start der Oberfläche fragt danach, solange das Ja fehlt.
  Die Antwort gebt ihr selbst: Ja, dann `/exit`. Erst mit diesem Ja
  wendet Claude Code die Erlaubnisse des Projekts an (`.claude/settings.json`). Ohne sie fragt es bei jeder Abfrage
  einzeln nach. Ob der Ordner bestätigt ist, liest die Einrichtung aus der Datei von Claude Code ab (`~/.claude.json`)
  und zeigt es in der Zeile «Projektordner». Sie schreibt dort nie.

**Kontrolle**

```bash
python3 tools/pruefen.py          # Umgebung, Konfiguration, Modelle, Quellen, alle Selbsttests einzeln
python3 tools/pruefen.py --live   # zusätzlich eine harmlose Testabfrage je eingerichteter Quelle
claude mcp list                   # zeigt "osint … Connected", sobald der Ordner als vertrauenswürdig bestätigt ist
```

**Abschalten und einschalten**

```bash
python3 tools/dienste.py          # zeigt, was läuft: Oberfläche, Web-Check, Robin, Tor
python3 tools/dienste.py aus      # schaltet alles ab, auch eine Oberfläche in einem anderen Terminal
python3 tools/dienste.py ein      # schaltet Web-Check und Tor wieder ein
```

«Alles abschalten» hält eine laufende Ermittlung an, beendet die Oberfläche und stoppt Robin und Web-Check. Am Terminal
stoppt es auch Tor, wenn der Arbeitsplatz es als Proxy nutzt, und fragt dafür nach dem Passwort (sudo).
Gelöscht wird dabei nichts: Fallakten, Schlüssel und Einstellungen bleiben, und eine angehaltene Ermittlung lässt sich
fortsetzen. Docker selbst läuft weiter, es kann auch anderem dienen.

In der Oberfläche steht derselbe Knopf auf der Seite «Arbeitsplatz». Er lässt Tor laufen, denn ein Browser kann nicht
nach dem Passwort fragen. Die Oberfläche startet wieder mit `python3 tools/oberflaeche.py` und schaltet dabei einen
abgeschalteten Web-Check von selbst wieder ein. Abschalten und einschalten kann nur ein Mensch am Terminal oder im
bedienbaren Fenster: Ohne Terminal und aus Claude Code heraus zeigt das Werkzeug nur den Stand.

### Windows

Zwei Wege führen zum selben Arbeitsplatz. Nicht mischen: Je System braucht es einen eigenen Klon, denn die
Python-Umgebungen von Linux und Windows vertragen sich nicht im selben Ordner. Die Einrichtung erkennt das und
bricht mit einem Hinweis ab.

| Weg | So | Docker |
|---|---|---|
| **WSL** | Repository in WSL klonen (im Linux-Heimordner, nicht unter `/mnt/c`), dort `./setup.sh`. Es gilt alles, was für Linux gilt. Die Oberfläche öffnet den Browser von Windows. Öffnet sich keiner, steht die Adresse im Terminal. Sie lautet dort auf `localhost`: Unter diesem Namen reicht Windows die Anfrage an WSL weiter. | freie Docker Engine: `./setup.sh --docker-installieren` |
| **Windows direkt** | `.\setup.cmd` in PowerShell oder der Eingabeaufforderung | Docker Desktop, von Hand |

Für Windows direkt gilt:

- **Der Interpreter heisst `python`**, nicht `python3`. Sonst sind alle Befehle dieser Anleitung gleich:
  `python tools\fall.py neu 2026-0412 …`.
- **`setup.cmd` startet `setup.ps1`** mit `-ExecutionPolicy Bypass` für genau diesen einen Lauf. Die Richtlinie
  des Rechners bleibt, wie sie ist. Sperrt eine Gruppenrichtlinie PowerShell-Skripte ganz, leistet
  `py tools\einrichten.py` dasselbe, sobald Python installiert ist.
- **Der Assistent läuft in Windows Terminal, in PowerShell und in der Eingabeaufforderung.** Im alten
  Konsolenfenster erscheinen schlichtere Zeichen (`>` statt `›`, `ok` statt `✓`), weil dessen Schrift die
  anderen nicht kennt. Einen Schlüssel fügt ihr dort mit einem Rechtsklick ein, Strg+V kommt in diesem Fenster
  nicht immer an. In Git Bash startet die Einrichtung nicht.
- **Nach der Einrichtung ein neues Terminal öffnen.** Die Einrichtung setzt für euer Benutzerkonto die
  Umgebungsvariable `OSINT_PYTHON`. Über sie startet Claude Code das Gateway, weil es unter Windows kein
  `python3` gibt. Ein schon offenes Fenster kennt die Variable noch nicht.
- **Freigaben in PowerShell oder der Eingabeaufforderung erteilen**, nicht im Fenster von Git Bash. Dort
  erkennt Python kein Terminal und lehnt die Bestätigung ab.
- **Docker Desktop installiert die Einrichtung nicht.** Laut Docker brauchen grössere Unternehmen und Behörden
  dafür ein bezahltes Abonnement ([Bedingungen](https://docs.docker.com/desktop/setup/install/windows-install/)).
  Ohne Docker bleiben nur Web-Check und Robin aus.
- **Befehle laufen in Git Bash.** Das Projekt schaltet das PowerShell-Werkzeug von Claude Code ab
  (`CLAUDE_CODE_USE_POWERSHELL_TOOL=0`), damit die Berechtigungen an einer Stelle greifen. Die Verbote für
  Netzbefehle stehen trotzdem auch für PowerShell da, falls das Werkzeug doch aktiv ist.

## Schlüssel

Alle Schlüssel stehen in `.env`. Eintragen kann sie der Assistent der Einrichtung (`./setup.sh`, auf einem
eingerichteten Arbeitsplatz «Einstellungen ändern»), von Hand in der Datei geht es genauso. Jede Quelle ist für
sich optional: Was keinen Schlüssel hat, bleibt aus, der Rest läuft. Dreizehn Quellen brauchen gar keinen, eine
davon (Web-Check) braucht Docker. Die Blockchain-Analyse läuft für Bitcoin, Ethereum und TRON ohne Schlüssel.

| Quelle | Variable in `.env` | Woher | Hinweis |
|---|---|---|---|
| Shodan | `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io) | DNS-Abfragen und Trefferlisten der Suche verbrauchen Query-Credits. `shodan_dns` verlangt eine bezahlte Mitgliedschaft: Ein kostenloses Konto bekommt HTTP 403. |
| VirusTotal | `VIRUSTOTAL_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Bedingungen des öffentlichen Schlüssels prüfen. Die Drossel ist auf ihn eingestellt (`VT_INTERVALL=15.5`), mit Premium auf `0` setzen. |
| Spur | `SPUR_TOKEN` | Spur-App, Settings → API ([Doku](https://docs.spur.us/context-api)) | Kommerzieller Dienst. |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) | |
| proxycheck.io | `PROXYCHECK_API_KEY` | [proxycheck.io/dashboard](https://proxycheck.io/dashboard), kostenlos | Für `ip_einordnung`: VPN, Proxy, Tor, Betreiber des Dienstes, 60 Tage Historie. 1'000 Abfragen am Tag. |
| ipapi.is | `IPAPI_API_KEY` | [ipapi.is/app/signup](https://ipapi.is/app/signup), kostenlos | Zweite Stimme für `ip_einordnung`. Ohne Schlüssel liefert der Dienst die Merkmale für VPN, Proxy und Tor nicht (seit dem 1.9.2026), das Gateway fragt ihn dann nicht. |
| urlscan.io | `URLSCAN_API_KEY` | [urlscan.io/user/profile](https://urlscan.io/user/profile), kostenlos | Suche und Abruf vorhandener Scans. Kostenlos am 16.11.2026: 1'000 Suchen, 10'000 Abrufe und 50 private Scans am Tag, Suche über 365 Tage. |
| urlquery | `URLQUERY_API_KEY` | Konto auf [urlquery.net](https://urlquery.net) | |
| ransomware.live | `RANSOMWARE_LIVE_API_KEY` | [my.ransomware.live](https://my.ransomware.live) | API PRO. Die schlüssellose API v2 ist laut Anbieter nur für private Nutzung, darum hier nur mit `RANSOMWARE_LIVE_V2=1`. |
| Telegram über RapidAPI | `RAPIDAPI_KEY` | [rapidapi.com](https://rapidapi.com), APIs «Telegram Channel» und «Telegram Scraper API» abonnieren | Nur für Kanal-Stammdaten und Kontoabfragen. Drittanbieter unbekannter Herkunft, vor dem Einsatz prüfen. |
| Ethereum-Familie (Blockscout) | `BLOCKSCOUT_API_KEY` | [dev.blockscout.com](https://dev.blockscout.com), kostenlos | Ethereum läuft auch ohne, dann gedrosselt. Mit dem kostenlosen Schlüssel kommen Arbitrum und Gnosis verlässlich dazu. Für Polygon und Base verlangt Blockscout ein bezahltes Paket (gesehen am 16.11.2026). Blockscout stellt den Zugang ohne Schlüssel nach eigener Angabe ein: Der Schlüssel ist der Weg, den der Anbieter für Programme vorsieht. |
| TRON (TronGrid) | `TRONGRID_API_KEY` | [trongrid.io](https://www.trongrid.io), kostenlos | TRON läuft auch ohne, dann stark gedrosselt. Für Geldflüsse über viele Stationen lohnt sich der Schlüssel. |
| Etherscan | `ETHERSCAN_API_KEY` | [etherscan.io/apidashboard](https://etherscan.io/apidashboard), kostenlos | Weitere Ketten (Polygon, Arbitrum) und die Gegenprüfung von Ethereum-Transaktionen. Gnosis, Base, BNB Smart Chain und Optimism verlangen dort ein bezahltes Abo (Gnosis und Base so gesehen am 16.11.2026). |
| Tronscan | `TRONSCAN_API_KEY` | [Anleitung von Tronscan](https://docs.tronscan.org/getting-started/api-keys), kostenlos | Namen von Börsen und Diensten für TRON-Adressen. Ohne ihn endet eine Verfolgung auf TRON bei «Sammeladresse, Dienst unbekannt». |
| Chainabuse | `CHAINABUSE_API_KEY` | Profil auf [chainabuse.com](https://www.chainabuse.com) | Betrugsmeldungen Geschädigter. Das kostenlose Kontingent ist sehr klein, gefragt wird nur auf ausdrücklichen Wunsch. |
| Iknaio GraphSense | `IKNAIO_API_KEY` | [ikna.io](https://www.ikna.io), Zugang für Behörden auf Anfrage | Etiketten und Cluster für Bitcoin, Ethereum, TRON. |
| Shodan InternetDB, RIPEstat, Wayback Machine, Ahmia-Sperrliste, Telegram-Kanalvorschau, 4chan, Mastodon | keine | | Laufen sofort. |
| Bitcoin (mempool.space), Krypto-Zuordnung (OFAC, TRM Labs, Ransomwhere, WalletExplorer), Krypto-Kurse (DefiLlama, EZB) | keine | | Laufen sofort. |
| Etikettenliste (GraphSense TagPacks) | keine | liegt im Repo | Lokal, fester Stand mit Prüfsumme. Die elf Massenlisten (rund 12 MB) holt einmal `python3 tools/listen.py laden`. |
| Web-Check | keine | eigene Instanz, die Einrichtung startet sie | Adresse in `WEBCHECK_URL`. |
| Robin (Dark Web) | keine | Docker-Abbild, die Einrichtung lädt es | Tor läuft im Container: Auf dem Rechner braucht es weder Tor noch SOCKS5. Der Container muss das Tor-Netz erreichen, siehe [Hinweise je Quelle](docs/QUELLEN.md#hinweise-je-quelle). Eigener Fork: `ROBIN_IMAGE` setzen. |

Weitere Einstellungen in `.env`: `OSINT_PROXY` (alle Abfragen über einen Proxy leiten, damit sie nicht auf eure
Adresse zurückführen), `OSINT_ZEITZONE`, `OSINT_USER_AGENT`, `OSINT_MYTHOS`, `OSINT_RIPESTAT_APP`, `OSINT_LISTEN`, und für eigene Instanzen der
Block-Explorer `KRYPTO_BITCOIN_API`, `KRYPTO_ETHEREUM_API` (je Kette), `KRYPTO_TRON_API`.

**Proxy.** Mit `OSINT_PROXY` geht jede Abfrage des Gateways über den Proxy, keine an ihm vorbei. Antwortet er nicht,
kommt deshalb keine einzige durch. Das System sagt es dann an jeder Stelle mit denselben Worten: Die Einrichtung und
`tools/pruefen.py` melden «nicht einsatzbereit» und lassen die Testabfragen aus, `fall_status` meldet es der
Ermittlung, die daraufhin anhält, und jede Fehlermeldung des Gateways nennt den Proxy als Ursache. Für Tor auf diesem
Rechner prüfen Einrichtung und Prüfung zusätzlich, ob Tor Verbindungen ins Netz aufbaut: Sie öffnen über Tor eine
Verbindung zu `check.torproject.org` und schliessen sie wieder, ohne etwas zu senden. Über Tor können Quellen
langsamer antworten oder Anfragen abweisen, und Quellen mit Schlüssel erkennen euer Konto in jedem Fall.

Die Schlüssel liest nur das Gateway. Claude Code darf `.env` nicht lesen, und im Protokoll erscheinen
Schlüssel als `***`.

## Eine Ermittlung durchführen

**1. Pseudonymisieren, im Haus.** Euer eigenes LLM ersetzt Personendaten durch nummerierte Platzhalter:
`[PERSON_01]`, `[ORG_01]`, `[ADRESSE_01]`, `[TEL_01]`. Nummeriert, nicht alle «Hans Muster», sonst geht verloren,
wer wer ist. Technische Indikatoren (IPs, Domains, Hashes, Adressen der Täterseite) bleiben stehen, denn nach
ihnen wird gesucht. Eine fertige Anweisung für euer LLM und die Regeln, was bleibt und was geht, stehen in
[docs/PSEUDONYMISIERUNG.md](docs/PSEUDONYMISIERUNG.md). Fällt das LLM aus, gibt es einen zweiten Weg, der den
Rechner nicht verlässt: [Pseudonymisieren ohne LLM](#pseudonymisieren-ohne-llm-der-rückfall).

**2. Ermitteln.** Am einfachsten in der [Oberfläche](#oberfläche):

```bash
python3 tools/oberflaeche.py          # Windows: python tools\oberflaeche.py
```

Der Browser öffnet sich von selbst. Dort:

1. **«Neuer Fall».** Rapport und Beilagen hineinziehen: einzeln, als Ordner oder als ZIP. Jede Datei wird gelesen und
   auf Personendaten geprüft. Hat die Pseudonymisierung im Haus etwas übersehen, bessert ihr es auf einem lokalen
   Bildschirm nach, ohne Sprachmodell. Dann Fall-ID und Titel eintragen und den Fall anlegen.
2. **«Ermittlung».** Vorgaben in den Chat schreiben, wenn es welche gibt, und starten. Wer will, wählt vorher
   Pflichtquellen an: Quellen, die in dieser Ermittlung gefragt werden müssen. Jeder Schritt erscheint im
   Verlauf. Nachrichten gehen jederzeit hinterher. Braucht Claude Code eine Zustimmung, erscheint ein Fenster.
3. **«Ergebnisse».** Rapport, Protokoll und Datenblätter ansehen, einzeln herunterladen oder alles als ein Archiv
   mitnehmen, samt Sitzungsprotokoll.

Oder am Terminal, mit einem Befehl in Claude Code:

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

**3. Freigaben erteilen, falls nötig.** Drei Dinge sind standardmässig aus und werden pro Fall freigegeben: in der
Oberfläche unter «Bedienen» oder am Terminal:

```bash
python3 tools/fall.py freigabe 2026-0412 darkweb       --durch "Kürzel/Funktion" --vermerk "Grundlage"
python3 tools/fall.py freigabe 2026-0412 aktiv         --durch "…" --vermerk "…"
python3 tools/fall.py freigabe 2026-0412 personenbezug --durch "…" --vermerk "…"
```

| Freigabe | Schaltet frei |
|---|---|
| `darkweb` | Suche und Lektüre von Onion-Seiten über Robin. |
| `aktiv` | Massnahmen, die das Ziel bemerken kann: URL bei urlquery oder urlscan.io einreichen, Seite in der Wayback Machine sichern, aktive Web-Check-Prüfungen. Jede einzelne verlangt zusätzlich eine Bestätigung in der Sitzung. Bei urlscan.io reicht das Gateway nur mit der Sichtbarkeit «private» ein. |
| `personenbezug` | Kontoabfragen: Mastodon-Konto, Telegram-Benutzer und -Suche. |

Der Befehl verlangt eine Bestätigung am Terminal. Ein Agent kann sich keine Freigabe selbst erteilen.

**Pflichtquellen vorgeben, falls gewünscht.** Ohne Vorgabe wählt das Team die Quellen selbst, nach den Indikatoren
und den Fragen des Auftrags. Wer sicher sein will, dass bestimmte Quellen gefragt werden, gibt sie vor: in der
Oberfläche unter «Ermittlung», vor dem Start, oder am Terminal:

```bash
python3 tools/fall.py quellen 2026-0412                                  # was sich vorgeben lässt, was vorgegeben ist, der Stand
python3 tools/fall.py quellen 2026-0412 --pflicht "Shodan, VirusTotal"   # oder --alle, oder --keine
```

- **Was eine Pflichtquelle heisst.** Sie wird für jeden Indikator aus den Eingangsdokumenten abgefragt, zu dem sie
  passt: Shodan für jede IP-Adresse, VirusTotal für IP-Adressen, Domains, URLs und Datei-Hashes, ein Block-Explorer für
  die Adressen seiner Kette. Suchquellen (4chan, Telegram, Robin) und Quellen für Gruppen und Konten werden mindestens
  einmal im Fall gefragt.
- **Ein Mindestmass, keine Beschränkung.** Weitere Quellen fragt das Team nach eigenem Ermessen. Pivots und die Seite
  der Geschädigten fallen nicht unter die Pflicht.
- **Nachprüfbar.** Ob eine Pflichtquelle gefragt wurde, liest das System aus dem Protokoll, nicht aus dem Bericht des
  Teams. Der Abschlussrapport weist die Pflichtquellen in Abschnitt 4 aus, und er lässt sich erst abschliessen, wenn
  zu jedem fälligen Indikator eine Abfrage im Protokoll steht. Ein Fehlschlag (Kontingent, Störung) gilt als gefragt
  und steht als Lücke da. Er wird nicht in Schleife wiederholt. Was das Gateway selbst abgelehnt hat, etwa weil eine
  Freigabe fehlt, hat die Quelle nie erreicht und gilt nicht als gefragt.
- **Keine Freigabe durch die Hintertür.** Vorgeben lässt sich nur, was eingerichtet ist. Robin verlangt dazu die
  Freigabe `darkweb`. Aktive Massnahmen und Kontoabfragen bleiben an ihre Freigabe gebunden.
- **Nur der Sachbearbeiter.** Vorgeben, ändern und aufheben verlangen ein Terminal oder die Oberfläche. Ein Agent
  kann die Vorgabe weder setzen noch aufheben.

**Eine Abklärung von Hand festhalten.** Nicht jede Quelle hat eine Schnittstelle. Schlagt ihr eine IP-Adresse
selbst nach, etwa in der Weboberfläche eines Dienstes oder per Auskunft eines Anbieters, gehört das Ergebnis in
die Akte wie jede Abfrage:

```bash
python3 tools/beleg.py erfassen 2026-0412      # fragt ab: Indikator, Quelle, Zeitpunkt, Wortlaut, wer
python3 tools/beleg.py zeigen 2026-0412
```

Der Beleg bekommt eine Nummer `X-…`, steht hash-verkettet im Protokoll und ist überall als «von Hand erfasst»
gekennzeichnet. Für eine IP-Adresse kann er den Wert setzen, ob sie der Ausgang eines Anonymisierungsdienstes
ist («ja» oder «kein Hinweis», ein «nein» gibt es nicht). Das Werkzeug läuft nur am Terminal oder aus der
Oberfläche, die Berechtigungen verbieten es für Agenten, und die PII-Prüfung liest den Wortlaut mit.

**4. Ergebnis ansehen.** In der Oberfläche unter «Ergebnisse», dort auch zum Herunterladen. Ohne Oberfläche:
`faelle/2026-0412/rapport/Abschlussrapport.html` im Browser öffnen. Als PDF:

```bash
python3 tools/pdf.py 2026-0412
```

Unter WSL druckt dafür der Browser von Windows (`msedge.exe`), wenn in WSL selbst keiner druckt. Rapport und PDF bleiben
im Projektordner. Nur das leere Wegwerf-Profil des Browsers liegt für die Dauer des Drucks im Ordner TEMP von Windows und
wird danach entfernt.

Alles an einem Ort, vom Rapport bis zur Rohdatei, zeigt die [Oberfläche](#oberfläche): `python3 tools/oberflaeche.py 2026-0412`.

**5. Zurückführen, im Haus.** Die Platzhalter im fertigen Rapport ersetzt ihr ausserhalb von Claude Code: mit der
Zuordnung, die im Haus geführt wird. Was in der Oberfläche nachgebessert wurde, führt sie unter «Bedienen» selbst zurück.

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
python3 tools/oberflaeche.py 2026-0412         # Oberfläche: Akten, Ermittlung mit Chat und alle Ergebnisse des Falls im Browser
python3 tools/fall.py entfernen 2026-0412 <Datei> --durch "…" --grund "…"    # Dokument aus dem Eingang nehmen
python3 tools/fall.py loeschen 2026-0412 --durch "…"                         # Fall löschen, solange nichts abgefragt wurde
python3 tools/anhang.py 2026-0412              # Datenblätter aller Indikatoren als HTML und PDF
python3 tools/audit_pruefen.py 2026-0412       # Protokollkette prüfen
python3 tools/musterfall.py                    # Musterfall neu bauen
```

In Claude Code: `/ermittlung <Fall-ID> [Dokument]`, `/abschlussrapport <Fall-ID>`, `/protokoll <Fall-ID>`.

## Oberfläche

Alle Ergebnisse eines Falls an einem Ort: der Rapport zum Durchklicken, ein Datenblatt je Indikator, jeder Beleg
und jede Rohdatei. Die Ansichten **lesen** die Fallakte und schreiben nie. Wer die Oberfläche selbst am Terminal
startet, arbeitet darin vom ersten bis zum letzten Schritt: Akten hochladen, Fall anlegen, im Chat Vorgaben geben, der
Ermittlung zusehen, Ergebnisse herunterladen. Abschlussrapport und Ermittlungsprotokoll bleiben die Dokumente für die Akte.

```bash
python3 tools/oberflaeche.py                     # startet den Server und öffnet den Browser (Windows: python tools\oberflaeche.py)
python3 tools/oberflaeche.py MUSTER-2026-001     # öffnet gleich diesen Fall
```

Ein Befehl, auf Linux, macOS und Windows. Dahinter steht ein kleiner Server in Python, der nur die
Standardbibliothek braucht: kein Bauschritt, kein zusätzliches Paket, kein Internet. Beenden mit Strg+C, oder mit
«Alles abschalten» auf der Seite «Arbeitsplatz»: Sie zeigt, was läuft (Oberfläche, Ermittlung, Web-Check, Robin, Tor),
und hält mit einem Knopf alles an. Siehe [Abschalten und einschalten](#einrichten).

![Fallübersicht mit Kennzahlen, Schritten und Arbeitsspur](docs/bilder/oberflaeche-uebersicht.png)

Links die Navigation, oben der Kopf des Falls mit Freigaben und Schrittleiste, rechts die Arbeitsspur: das
Abfrageprotokoll, laufend nachgeführt, filterbar nach Abfragen, «kein Treffer», Fehlschlägen, Auswertungen und Freigaben.
Ist die Oberfläche bedienbar, steht darunter ein kleines Chat-Fenster zur Ermittlung.

**Fallübersicht.** Kennzahlen aus denselben Funktionen wie im Abschlussrapport, offene Punkte und die Abdeckung
Indikator × Quelle. «Kein Treffer», Fehlschlag und «nicht abgefragt» sind so sichtbar wie ein Treffer:

![Abdeckung: welche Quelle zu welchem Indikator gefragt wurde](docs/bilder/oberflaeche-abdeckung.png)

**Rapport.** Derselbe Inhalt, dieselbe Reihenfolge und derselbe Wortlaut wie der Abschlussrapport, weil er aus
demselben Generator kommt. Dazu: Befunde filtern (Sicherheit, Art, Indikator, Analyst), jeden Beleg bis zur
Rohdatei aufklappen, den Graf verschieben und vergrössern, die Zeitachse einengen, die Stationen im Geldfluss anklicken.

![Rapport: Befunde mit Filter](docs/bilder/oberflaeche-rapport.png)

![Rapport: Beziehungsgraf zum Verschieben und Vergrössern](docs/bilder/oberflaeche-graf.png)

**Datenblatt je Indikator.** Alles, was irgendeine Quelle geliefert hat, in festen Abschnitten je Art des
Indikators. Jede Angabe nennt Quelle, Abfragezeit, Beleg und Stelle in der Rohdatei. Hat keine Quelle etwas
geliefert, steht «keine Angabe» und wer gefragt wurde. Nennen zwei Quellen Verschiedenes, steht «Widerspruch» dabei.

![Datenblatt einer Domain, mit einem Widerspruch zwischen zwei Quellen](docs/bilder/oberflaeche-datenblatt.png)

**Beleg und Rohdatei.** Je Abfrage der Protokolleintrag und die Antwort der Quelle, geordnet von einem
Darsteller: benannte Felder in festen Abschnitten, alles Übrige unter «Weitere Angaben der Quelle». Keine Angabe
geht verloren. Die Rohdatei steht daneben, mit Prüfsumme und der Auskunft, ob sie noch zur Protokollkette passt.

![Beleg: die Antwort von Shodan, geordnet vom Darsteller](docs/bilder/oberflaeche-beleg.png)

![Rohdatei mit Prüfsumme und Kettenprüfung](docs/bilder/oberflaeche-rohdatei.png)

**Suche und Ergebnisse.** Die Suche geht über den ganzen Fall, samt Rohdaten. Unter «Ergebnisse» stehen
Abschlussrapport, Ermittlungsprotokoll und Datenblätter, als HTML und PDF, mit dem Vermerk, ob sie noch zum Stand
der Daten passen, und alles zusammen als Archiv. Jede Tabelle lässt sich sortieren, filtern und als CSV ausgeben, jede
Ansicht hat eine feste Adresse und lässt sich drucken. Die Oberfläche folgt der hellen oder dunklen Einstellung des Systems:

![Datenblatt einer Wallet-Adresse in der dunklen Darstellung](docs/bilder/oberflaeche-dunkel.png)

**Bedienen ohne Terminal.** Startet der Sachbearbeiter die Oberfläche selbst an einem Terminal, lässt sie sich aus dem
Browserfenster bedienen, das sich dabei öffnet. Der Ablauf:

![Neuer Fall: Akten hineinziehen, jede Datei geprüft, mit Auswahl](docs/bilder/oberflaeche-neu.png)

- **Akten hineinziehen.** Unter «Neuer Fall»: einzelne Dateien, ein ganzer Ordner oder ein ZIP. Gelesen werden Text,
  Word, PDF, OpenDocument, Excel, PowerPoint, RTF, E-Mail (.eml, die Anhänge werden eigene Dokumente), CSV und JSON.
  Jede Datei geht sofort durch die PII-Prüfung: bereit, Personendaten oder nicht lesbar. Bilder, Ton und alte Formate
  lassen sich nicht prüfen und bleiben bei euch.
- **Auswählen und ordnen.** Jede Zeile hat einen Haken, dazu «alle auswählen» und die Umschalttaste für einen Bereich.
  Für die Auswahl: nochmals pseudonymisieren, als Rapport oder Beilage ordnen, entfernen, in den Akten-Eingang eines
  anderen Falls verschieben.
- **Nochmals pseudonymisieren.** Hat die Pseudonymisierung im Haus etwas übersehen, zeigt ein lokaler Bildschirm das
  Dokument mit markierten Fundstellen: annehmen, verwerfen, ergänzen, übernehmen. Das geschieht auf eurem Rechner,
  ohne Sprachmodell. Platzhalter, die schon im Dokument stehen, bleiben. Neue zählen dahinter weiter.

![Der lokale Bildschirm der Pseudonymisierung, mit erfundenen Angaben](docs/bilder/oberflaeche-klartext.png)

- **Fall anlegen.** Fall-ID und Titel. In den Fall kommt von jedem Dokument die Textfassung, nie das Original, unter
  einem neutralen Namen (`rapport-01.txt`, `beilage-01.txt`). Welche Datei wie heisst, hält die Ablage ausserhalb des
  Projekts fest.
- **Ermitteln mit Chat.** Unter «Ermittlung»: Vorgaben eintragen, wenn es welche gibt, und starten. Die Oberfläche
  steuert Claude Code mit `/ermittlung <Fall-ID>`. Der Verlauf zeigt jeden Schritt: welcher Analyst, welche Abfrage,
  welcher Beleg, welches Ergebnis. Eine Nachricht an die Ermittlung wartet auf das Ende des laufenden Auftrags oder
  unterbricht ihn. Anhalten und fortsetzen geht jederzeit. Derselbe Chat steht in den übrigen Ansichten klein am Rand.

![Ermittlung: der Chat mit Vorgaben, Schritten und wartenden Nachrichten](docs/bilder/oberflaeche-ermittlung.png)

- **Pflichtquellen.** Über dem Chat, eingeklappt: anwählen, welche Quellen die Ermittlung abfragen muss. Leer lassen,
  einzeln anwählen oder «Alle auswählen». Was nicht eingerichtet ist, ist gesperrt und nennt den Grund. Der Start der
  Ermittlung übernimmt die Auswahl. Die Kopfzeile zeigt den Stand («8 von 11 erfüllt, 3 offen»). Aufgeklappt steht je
  Quelle, für welche Indikatoren sie gefragt wurde, mit Beleg, und was noch offen ist. Derselbe Stand steht in der
  Fallübersicht und im Abschlussrapport.

![Pflichtquellen: Auswahl in drei Gruppen und der Stand laut Protokoll, am Musterfall](docs/bilder/oberflaeche-pflichtquellen.png)

- **Rückfragen.** Braucht Claude Code eine Zustimmung, etwa für eine einzelne aktive Massnahme, erscheint ein Fenster,
  in jeder Ansicht: erlauben oder ablehnen. «Erst nachsehen» lässt die Ermittlung warten.

![Rückfrage: Claude Code braucht eine Zustimmung, das Fenster nennt Werkzeug und Eingabe](docs/bilder/oberflaeche-rueckfrage.png)

- **Ergebnisse.** Rapport, Protokoll und Datenblätter ansehen, als HTML und PDF einzeln herunterladen oder alles als
  ein Archiv mitnehmen: mit Sitzungsprotokoll und Verlauf, auf Wunsch die ganze Fallakte mit Rohdaten. Jedes Archiv
  nennt in `INHALT.txt` die Prüfsumme jeder Datei.

![Ergebnisse: Unterlagen mit Stand, einzeln oder als Archiv](docs/bilder/oberflaeche-ergebnisse.png)

- **Akten eines Falls.** Weitere Dokumente nachziehen, und was im Eingang liegt: auswählen, entfernen (mit «Durch» und
  «Grund»), in einen anderen Fall verschieben, von Hand Kopiertes nachträglich prüfen.

![Akten eines Falls: Dokumente im Eingang auswählen, entfernen, verschieben](docs/bilder/oberflaeche-akten.png)

- **Bedienen.** Freigaben, Abklärung von Hand, Dokumente einzeln erzeugen, Zurückführen, einen Fall löschen, solange
  nichts abgefragt wurde. Per Klick oder Formular, über die bestehenden Werkzeuge. Jeder Schritt steht im
  Sitzungsprotokoll, mit Zeit und dem Vermerk «über die Oberfläche».

![Bedienen: Freigaben, Abklärung von Hand, Dokumente](docs/bilder/oberflaeche-bedienen.png)

![Zurückführen: der Rapport mit echten Angaben, nur auf diesem Bildschirm (erfundene Angaben)](docs/bilder/oberflaeche-zurueck.png)

Die Sitzung von Claude Code läuft im Projektordner und ohne Schalter, die Einstellungen, Hooks oder MCP-Server
abschalten. Berechtigungen und Protokoll-Hooks gelten wie am Terminal, die Modelle bleiben, wie das Projekt sie
festlegt. Ob der Weg an eurem Arbeitsplatz trägt (Ausgabe und Hooks, Fortsetzen, Verbote, Rückfrage), zeigt eine Probe
mit dem echten Claude Code in vier kurzen Sitzungen: `python3 tools/oberflaeche.py --sitzungsprobe`.

**Abrechnung: Abo oder API.** Eine Sitzung aus der Oberfläche rechnet über denselben Zugang ab wie `claude` am Terminal
desselben Benutzers. Einen eigenen API-Schlüssel braucht dieser Weg nicht. Stand: Dokumentation von Claude Code
(code.claude.com/docs, Seiten «Authentication», «Manage costs effectively» und «Run Claude Code programmatically»,
gelesen am 16.11.2026).

- **Mit einem Abo angemeldet** (`/login` mit Pro, Max, Ultra, Team oder Enterprise): Die Ermittlung zählt gegen das
  Kontingent des Abos, wie am Terminal. Sie verbraucht deutlich mehr als ein Gespräch, weil mehrere Analysten
  nebeneinander arbeiten.
- **Mit einem Console-Konto angemeldet oder `ANTHROPIC_API_KEY` gesetzt:** Abrechnung über die API, nach Verbrauch. Ist
  die Variable gesetzt, nimmt Claude Code im Skriptbetrieb immer den Schlüssel, auch wenn ein Abo angemeldet ist.
- Die Ansicht «Ermittlung» sagt vor dem Start, über welchen Zugang abgerechnet wird, soweit es an der Umgebung abzulesen
  ist. Sie nennt nur den Namen der Variablen. Einen `apiKeyHelper` in den Einstellungen des Benutzers sieht sie nicht.
- **Nicht gewählt: das Agent SDK für Python.** Seine Dokumentation verweist für die Anmeldung auf API-Schlüssel, also
  Abrechnung nach Verbrauch, und es wäre eine neue Pflicht-Abhängigkeit. Es startet dieselbe Kommandozeile.

Zwei Dinge sind offen. Erstens die Bedingungen: Die Dokumentation zum Agent SDK hält fest, dass Dritte in ihren Produkten
ohne Zustimmung von Anthropic keine Anmeldung mit claude.ai anbieten dürfen. Die Oberfläche bietet keine Anmeldung an,
sie startet das installierte Claude Code des Sachbearbeiters mit dessen eigener Anmeldung. Ob ein Abo den Betrieb in
einer Dienststelle deckt, ist damit nicht gesagt. Die Bedingungen der Abos selbst sind nicht gelesen. Zweitens kündigt
die Dokumentation an, dass der Skriptbetrieb künftig von sich aus ohne die Einstellungen des Projekts startet (`--bare`
als Vorgabe) und dann nur noch mit API-Schlüssel läuft. Die Oberfläche merkt das am Start der Sitzung und beendet sie,
statt ohne Berechtigungen und Protokoll zu arbeiten.

**Anhang für die Akte.** Die Datenblätter gibt es auch ohne laufende Oberfläche, als ein Dokument:

```bash
python3 tools/anhang.py 2026-0412                # rapport/Datenblaetter.html und rapport/Datenblaetter.pdf
```

Das HTML steht für sich allein: keine Skripte, keine Verweise nach aussen, Bilder aus den Rohdaten eingebettet.
Muster: [Datenblätter des Musterfalls (PDF)](muster/Datenblaetter.pdf).

**Schutz.**

- Der Server hört nur auf 127.0.0.1 und weist Anfragen mit fremdem Host-Kopf oder fremder Herkunft ab.
- Lesen geht mit GET und HEAD. Ändern geht nur mit dem Geheimnis, das beim Start entsteht: Es liegt nur im Speicher des
  Servers und im Browserfenster des Sachbearbeiters, in keiner Datei und nicht in der Umgebung der Sitzungen, die der
  Server startet. Ohne Terminal oder aus Claude Code heraus gestartet, läuft die Oberfläche «nur lesen». Ein Agent kann
  sich so keine Freigabe erteilen, keinen Beleg von Hand erfassen und seine eigene Rückfrage nicht beantworten.
- Die Oberfläche schreibt nie selbst in Protokoll, Rohdaten, Eingang oder `fall.json`. Sie ruft die bestehenden
  Werkzeuge auf. Die eine Datei, die sie selbst in einem Fall ablegt, ist der Verlauf des Chats im Arbeitsstand.
- In einen Fall kommt nur, was die PII-Prüfung besteht, und immer die Textfassung, nie das Original. Auch was der
  Sachbearbeiter in den Chat schreibt, geht durch die PII-Prüfung, bevor es das Sprachmodell erreicht.
- Klartext bearbeitet nur der lokale Server, nie eine Claude-Sitzung. Hochgeladene Dateien liegen im Speicher,
  Zuordnungstabelle und zurückgeführter Rapport ausserhalb des Projektordners, nichts davon steht in einem Protokoll.
  Echte Angaben können drei Bildschirme zeigen (Akten-Eingang mit den Namen der Dateien, Pseudonymisierung,
  Zurückführen), alle als «lokal, Klartext» gekennzeichnet und nur gegen das Geheimnis zu haben.
- Was aus einer Quelle stammt, erscheint als Text und wird nie als HTML ausgeführt. Rohdateien liefert er als Text oder Bild.
- Bilder kommen nur aus den Rohdaten des gezeigten Falls. Eine Content-Security-Policy verbietet alles von aussen.
- Adressen aus dem Fall (URLs, Domains, Onion-Adressen) sind nie anklickbar. Platzhalter bleiben Platzhalter.

**Grenzen.** Zum Lesen hat die Oberfläche keine Anmeldung. Sie gehört auf den Arbeitsplatz des Sachbearbeiters, nicht auf
einen geteilten Server. Die Steuerung von Claude Code ist nur gegen ein Programm geprüft, das Claude Code spielt: Mit dem
echten Claude Code ist noch keine Ermittlung aus der Oberfläche gelaufen, und auch der Chat ist nur so geprüft. Der
Akten-Eingang lebt im Speicher: Was hochgeladen, aber nicht aufgenommen ist, ist nach dem Beenden der Oberfläche weg.
Bilder, Ton, gescannte PDF und die alten Office-Formate liest er nicht, sie bleiben bei euch. Die PII-Prüfung erkennt
Muster, keine Namen: Ein Name, der in einem Dokument oder im Chat stehen bleibt, erreicht das Sprachmodell. Rohdateien
über 3 MB zeigt die Oberfläche nur im Anfang und durchsucht sie nicht. Für Werkzeuge, zu denen keine
echte Antwort vorlag (aktive Massnahmen, Kontoabfragen, Spur, Telegram über RapidAPI, Shodan-DNS, Wayback Machine,
Robin), ist nicht geprüft, ob der Darsteller zur echten Antwort passt. Passt er nicht, stehen die Angaben unter «Weitere Angaben».

Alle Einzelheiten, die Abschnitte je Art des Indikators, die Regeln der Darstellung und die Tabelle der
Darsteller: [docs/OBERFLAECHE.md](docs/OBERFLAECHE.md).

## Pseudonymisieren ohne LLM: der Rückfall

Fällt euer LLM im Haus aus, pseudonymisiert `tools/pseudonymisieren.py` ein Dokument auf dem eigenen Rechner:
ohne Sprachmodell, ohne Netz, nur mit der Standardbibliothek von Python. Das Werkzeug schlägt vor, ein Mensch
entscheidet. Es läuft nur an einem Terminal und nicht aus Claude Code heraus, denn was es zeigt, ist Klartext.

```bash
python3 tools/pseudonymisieren.py /sicher/rapport.docx \
    --zuordnung /sicher/2026-0412_zuordnung.csv --ausgabe /sicher/pseudonymisiert/
```

Dokument, Zuordnungstabelle und Ausgabeordner liegen ausserhalb des Projektordners. Gibt es die Zuordnungstabelle
schon, wird sie fortgeschrieben: Wer im Rapport `[PERSON_01]` war, bleibt es im Nachtrag. Das Ergebnis ist eine
Textdatei mit Platzhaltern und die Tabelle im Format von `tools/reidentifizieren.py`.

> **Stand: nicht abgeschlossen.** Die Feldmarken in `tools/feldmarken.txt` sind vorläufig mit üblichen Marken
> gefüllt, die Vornamenliste in `tools/vornamen.txt` ist vorläufig von Hand zusammengestellt. Die Messwerte unten
> gelten für genau diese beiden Dateien und für erfundene Rapporte. Mit der Liste eurer Feldmarken wird neu
> gemessen, erst dann ist das Werkzeug für den Betrieb beurteilt.

**So arbeitet es.** Sieben Schichten, in dieser Reihenfolge:

| Schicht | Was sie tut | Ersetzt von selbst? |
|---|---|---|
| 0 Schutz | Markiert technische Indikatoren: IP-Adressen, Domains, URLs, Hashes, Wallet-Adressen, Transaktions-IDs, Onion-Adressen, Dateinamen. Keine spätere Schicht ersetzt sie. | nein, sie schützt |
| 1 Feldmarken | Liest die Werte hinter den Marken aus `tools/feldmarken.txt` («Name:», «Geb.-Datum», «Name/Vorname»): auf derselben Zeile, auf der nächsten, in Tabellen, mit oder ohne Doppelpunkt. | ja |
| 2 Fortpflanzung | Sucht jede geerntete oder bestätigte Angabe im ganzen Dokument, in allen Schreibweisen: «Muster, Hans», «H. Muster», «MUSTER Hans», Genitiv, Zeilenumbruch, Silbentrennung, «Mueller» für «Müller», Telefonnummern und Daten in jeder Schreibung. | ja |
| 3 Muster | AHV-Nummer, IBAN (mit Prüfziffer), Telefonnummer, Geburtsdatum mit Stichwort, Kontrollschild, Kreditkarte, E-Mail-Adresse, Strassenadresse. Dieselben Muster wie in der PII-Prüfung. | ja |
| 4 Namensliste | Was der Sachbearbeiter zum Fall mitgibt (`--namen`). | ja |
| 5 Kandidaten | Mögliche Namen und Firmen im Fliesstext: nach Anreden und Titeln (deutsch, französisch, italienisch), nach einem Vornamen aus der Liste, vor einer Rechtsform («AG», «Sàrl»). | **nie**, sie legt vor |
| 6 Bestätigung | Der Mensch nimmt jede Fundstelle an, verwirft sie, ändert den Typ oder ergänzt, was fehlt. Erst danach wird geschrieben. | |

Bei E-Mail-Adressen kann das Werkzeug nicht wissen, ob sie der Täterseite gehören (dann bleiben sie stehen) oder
den Geschädigten (dann werden sie ersetzt). Es fragt. Am Ende läuft die PII-Prüfung über das Ergebnis, und bei der
Aufnahme in einen Fall prüft `tools/fall.py` noch einmal. Ablauf, Format der Feldmarken und alle Grenzen stehen in
[docs/PSEUDONYMISIERUNG.md](docs/PSEUDONYMISIERUNG.md#rückfall-ohne-llm-toolspseudonymisierenpy).

**Messung.** `python3 tools/pseudo_messen.py` erzeugt 240 erfundene Schweizer Polizeirapporte mit bekannter Lösung
(`tools/pseudo_pruefsatz.py`) und zählt, was stehen bleibt. Massstab ist zuerst die Durchrutschquote: der Anteil
der Stellen mit Personendaten, die im Ergebnis noch lesbar sind. Eine Stelle gilt nur als ersetzt, wenn jeder
Buchstabe und jede Ziffer ersetzt ist. Die Tabellen schreibt das Werkzeug selbst (`--readme`), die CI prüft, dass
sie zum Stand des Codes passen (`--pruefen`).

<!-- pseudo-messung:anfang -->
Prüfsatz: 240 synthetische Rapporte, 10395 Stellen mit Personendaten, 1875 technische Indikatoren. Feldmarken: 132 (vorläufige Liste). Vornamenliste: 820 Namen (vorläufige Liste). Von 1050 Personen im Prüfsatz tragen 166 einen Vornamen, der nicht in der Liste steht.

**Angaben, die in einem Feld stehen (alle ihre Stellen, auch die im Fliesstext)**: Stellen, die stehen bleiben

| Typ | Stellen | nach Schicht 1 | nach 2 | nach 3 (ohne Zutun) | mit 5 (Kandidaten bestätigt) | mit 4 (alle Namen eingegeben) |
|---|---:|---:|---:|---:|---:|---:|
| Person | 4657 | 3600 (77.3 %) | 0 | 0 | 0 | 0 |
| Organisation | 327 | 218 (66.7 %) | 0 | 0 | 0 | 0 |
| Adresse | 1045 | 365 (34.9 %) | 0 | 0 | 0 | 0 |
| Telefonnummer | 487 | 139 (28.5 %) | 0 | 0 | 0 | 0 |
| E-Mail-Adresse | 483 | 146 (30.2 %) | 0 | 0 | 0 | 0 |
| Geburtsdatum | 747 | 399 (53.4 %) | 0 | 0 | 0 | 0 |
| AHV-Nummer | 283 | 89 (31.4 %) | 0 | 0 | 0 | 0 |
| Bankverbindung | 332 | 102 (30.7 %) | 0 | 0 | 0 | 0 |
| Kontrollschild | 166 | 44 (26.5 %) | 0 | 0 | 0 | 0 |
| Ausweisnummer | 191 | 57 (29.8 %) | 0 | 0 | 0 | 0 |
| **Alle** | 8718 | 5159 (59.2 %) | 0 | 0 | 0 | 0 |

**Angaben, die nur im Fliesstext stehen (Drittpersonen, weitere Firmen)**: Stellen, die stehen bleiben

| Typ | Stellen | nach Schicht 1 | nach 2 | nach 3 (ohne Zutun) | mit 5 (Kandidaten bestätigt) | mit 4 (alle Namen eingegeben) |
|---|---:|---:|---:|---:|---:|---:|
| Person | 771 | 771 (100.0 %) | 759 (98.4 %) | 759 (98.4 %) | 103 (13.4 %) | 1 (0.1 %) |
| Organisation | 329 | 329 (100.0 %) | 329 (100.0 %) | 329 (100.0 %) | 20 (6.1 %) | 0 |
| Adresse | 124 | 39 (31.5 %) | 39 (31.5 %) | 0 | 0 | 0 |
| Telefonnummer | 121 | 121 (100.0 %) | 121 (100.0 %) | 0 | 0 | 0 |
| E-Mail-Adresse | 43 | 43 (100.0 %) | 43 (100.0 %) | 0 | 0 | 0 |
| AHV-Nummer | 64 | 64 (100.0 %) | 64 (100.0 %) | 0 | 0 | 0 |
| Bankverbindung | 43 | 43 (100.0 %) | 43 (100.0 %) | 0 | 0 | 0 |
| Kontrollschild | 98 | 98 (100.0 %) | 98 (100.0 %) | 0 | 0 | 0 |
| Ausweisnummer | 84 | 84 (100.0 %) | 84 (100.0 %) | 84 (100.0 %) | 84 (100.0 %) | 84 (100.0 %) |
| **Alle** | 1677 | 1592 (94.9 %) | 1580 (94.2 %) | 1172 (69.9 %) | 207 (12.3 %) | 85 (5.1 %) |

**Fehlalarme und technische Indikatoren**

| Was | Zahl |
|---|---:|
| Ersetzungen ohne Zutun insgesamt | 9268 |
| davon keine Personendaten (Fehlalarm) | 26 (0.3 %) |
| … als Kontrollschild | 26 |
| Technische Indikatoren im Prüfsatz | 1875 |
| davon verändert, ohne Zutun | 0 |
| davon verändert, nach Bestätigung und Namensliste | 0 |
| Rückfragen «Täterseite oder Geschädigte?» zu E-Mail-Adressen | 184 |
| E-Mail-Adressen der Täterseite im Prüfsatz | 142 |
| davon ersetzt, wenn niemand die Rückfrage beantwortet | 142 |
| Kandidaten, die Schicht 5 vorlegt | 1021 |
| davon richtig (Personendaten) | 785 (76.9 %) |

**Gegenprobe: Das Dokument trägt Marken, die nicht in der Liste stehen.** Dieselben Dokumente, aber das Werkzeug kennt nur jede zweite Marke (66 von 132). Von 8718 Stellen der Angaben, die in einem Feld stehen, bleiben ohne Zutun 3137 (36.0 %) stehen.

**Kontrolle an 240 weiteren Rapporten (Nummern 241 bis 480), die bei der Entwicklung nie angesehen wurden.** Stellen, die stehen bleiben:

| Angaben | Stellen | nach 3 (ohne Zutun) | mit 5 (Kandidaten bestätigt) | mit 4 (alle Namen eingegeben) |
|---|---:|---:|---:|---:|
| in einem Feld | 8527 | 3 (< 0.1 %) | 1 (< 0.1 %) | 1 (< 0.1 %) |
| nur im Fliesstext | 1775 | 1252 (70.5 %) | 203 (11.4 %) | 90 (5.1 %) |

Technische Indikatoren in der Kontrolle: 1834, davon verändert: 0.

<!-- pseudo-messung:ende -->

Was die Zahlen sagen, und was nicht:

- **Was in einem Feld steht, findet das Werkzeug fast vollständig**, auch an allen anderen Stellen des Dokuments.
  Das gilt nur, solange die Marke in der Liste steht. Die Gegenprobe zeigt, wie viel sonst stehen bleibt. Darum
  ist die Liste eurer Feldmarken die wichtigste Zutat.
- **Wer nur im Fliesstext vorkommt, wird von keiner Schicht von selbst ersetzt.** Das ist Absicht: Ein Name im
  Fliesstext lässt sich ohne Sprachverständnis nicht von einem gewöhnlichen Wort unterscheiden, und ein falsch
  ersetztes Wort zerstört den Rapport. Schicht 5 legt diese Stellen vor. Bestätigt der Mensch alles Richtige,
  bleibt der Rest der Spalte «mit 5» stehen: Namen ohne Anrede, deren Vorname nicht in der Liste steht, Firmen
  ohne Rechtsform, Ausweisnummern ohne Feld.
- **Für diesen Rest ist ein lokales Sprachmodell die naheliegende nächste Schicht** (GLiNER, Flair). Es ist nicht
  eingebaut. Die Schnittstelle dafür steht: `erkennen(text, erkenner=[funktion])` in `tools/_pseudo.py` nimmt eine
  Funktion, die einen Text liest und Kandidaten liefert (Beginn, Ende, Typ, Grund). Auch sie legt nur vor. Die
  Messung beziffert, was sie höchstens beitragen kann: die Spalte «mit 5» der zweiten Tabelle. An den Schichten 0
  bis 3 ändert ein Modell nichts, sie sind genauer und nachvollziehbar.
- **Die Zahlen sind eine Obergrenze dessen, was das Werkzeug kann, keine Zusage für echte Rapporte.** Prüfsatz
  und Erkennung stammen vom selben Verfasser, und die Erkennung wurde an den Rapporten 1 bis 240 nachgebessert.
  Die Kontrolle an 240 weiteren Rapporten zeigt, dass die Werte nicht an den einzelnen Dokumenten hängen. Sie
  zeigt nicht, wie eure Rapporte aufgebaut sind. Die Spalten «mit 5» und «mit 4» setzen einen Menschen voraus,
  der nichts übersieht.
- **Fehlalarme**: Als Kontrollschild ersetzt das Werkzeug auch «ZH 2024» (Kanton und Jahr). Die PII-Prüfung sperrt
  an derselben Stelle, das Verhalten ist also dasselbe. In der Bestätigung lässt sich die Stelle verwerfen.

**Grenzen.** Kein Werkzeug findet alles, das Ergebnis wird gelesen. Scans ohne Text gehen nicht (zuerst OCR im
Haus). Aus `.docx` und `.pdf` entsteht eine Textdatei, die Gestaltung geht verloren. Der blosse Wohnort ohne
Postleitzahl bleibt stehen. «Herr Muster» und «Frau Muster» kann das Werkzeug nicht auseinanderhalten: Gibt es
zwei Personen mit demselben Nachnamen, meldet es die Stelle als mehrdeutig.

**Zwei Wege, die verworfen sind.** *Claude liest den Klartext selbst und pseudonymisiert ihn:* Dann sind die
Personendaten bereits an Anthropic übermittelt, bevor ein Platzhalter steht. *Ein Inkognito-Chat:* Er ändert, was
aufbewahrt wird, nicht, dass der Text das Haus verlässt.

**Die Vornamenliste.** Vorgesehen ist die Vornamenstatistik des Bundesamtes für Statistik («Vornamen der
Bevölkerung nach Jahrgang», BFS-Nummer su-d-01.04.00.11). Auf der Seite des Datensatzes steht als Nutzungsbedingung
«OPEN-BY: Freie Nutzung. Quellenangabe ist Pflicht.» (gesehen am 16.11.2026). Die Datei liess sich aus der
Entwicklungsumgebung nicht abrufen, im Repository liegt deshalb eine von Hand zusammengestellte Liste. Wer die
Tabellen des BFS heruntergeladen hat, baut die Liste mit `python3 tools/vornamen.py bauen <Dateien> --stand 2025`
und misst neu.

## Das Ermittler-Team

| Agent | Fragt | Werkzeuge |
|---|---|---|
| `infrastruktur-analyst` | Wem gehört die IP? Rechenzentrum, VPN oder Privatanschluss? Was läuft darauf, was lag sonst dort? | Shodan, Spur, AbuseIPDB, VirusTotal, Web-Check passiv, Wayback |
| `malware-url-analyst` | Ist die Datei bekannt? Was tat die Seite beim Aufruf? Seit wann gibt es sie? | VirusTotal, urlquery, Wayback, Web-Check passiv |
| `darkweb-analyst` | Ist die Gruppe bekannt? Passt die Leak-Seite? Taucht der Fall in Breach-Feeds oder im Dark Web auf? | ransomware.live, Ahmia-Sperrliste, Telegram, Robin |
| `socmint-analyst` | Was wird in Foren und Kanälen zum Fall gesagt? Was zeigen Konten der Täterseite? | 4chan, Telegram, Mastodon |
| `blockchain-analyst` | Stimmt die Zahlung? Wohin ging das Geld? Bei welcher Börse lässt sich ansetzen, wo liegt noch Guthaben? | Bitcoin, Ethereum und Verwandte, TRON: Explorer, Sanktionslisten, Etiketten, Kurse |
| `gegenpruefer` | Steht das, was im Rapport stehen soll, wirklich in den Rohdaten? | nur Lesen. Kennt den Ermittlungsverlauf nicht. |
| `rapportfuehrer` | Verdichtet die Meldungen zu `befunde.json`, arbeitet die Gegenprüfung ein, erzeugt Rapport und Protokoll. | Lesen, Schreiben, `tools/` |

Die Hauptsitzung leitet: Sie zieht die Indikatoren, verteilt sie, entscheidet über Pivots (höchstens zwei Runden)
und ist die einzige, die aktive Massnahmen ausführt.

### Modelle je Phase

Zwei Modelle teilen sich die Arbeit. Die Zuteilung steht fest in den Dateien des Projekts und ist für alle gleich:

| Phase | Wer | Verlangt |
|---|---|---|
| **Ermittlung** | `/ermittlung` (Leitung, Indikatoren, Pivots, aktive Massnahmen) und die fünf Analysten | `claude-mythos-5-2` |
| **Abschluss** | `gegenpruefer`, `rapportfuehrer` (Befunde, Rapport, Übergabe), `/abschlussrapport`, `/protokoll` | `claude-fable-5-2` |
| alles andere | die Sitzung vor und nach der Ermittlung, etwa Rückfragen zum Rapport | `claude-fable-5-2` |

Ob die Ermittlung tatsächlich auf Mythos läuft, hängt an einer einzigen Angabe.

**Ohne Angabe läuft alles auf Fable 5.2.** Das Projekt lässt in `.claude/settings.json` nur dieses Modell zu
(`availableModels`). Verlangt ein Skill oder Agent ein Modell ausserhalb der Liste, übergeht Claude Code den
Wunsch und nimmt das Modell der Sitzung. So funktioniert das Repository für alle, ohne dass jemand etwas ändert.

**Wer Mythos 5.2 hat, erklärt das einmal:**

```bash
./setup.sh --mythos          # Windows: .\setup.cmd --mythos        zurücknehmen: --ohne-mythos
```

oder mit `OSINT_MYTHOS=ja` in `.env`. Die Einrichtung trägt Mythos in die lokale Liste ein
(`.claude/settings.local.json`, nicht eingecheckt), und Claude Code fügt beide Listen zusammen. Von da an gilt
bei jeder Ermittlung, ohne Umstellen von Hand:

1. `/ermittlung` schaltet die Sitzung auf Mythos 5.2. Die Analysten laufen auf Mythos 5.2.
2. Gegenprüfung, Befunde, Rapport, Protokoll und Übergabe laufen auf Fable 5.2.
3. Mit eurer nächsten Eingabe ist die Sitzung wieder auf Fable 5.2.

Mythos 5.2 ist dasselbe Modell wie Fable 5.2, ohne dessen zusätzliche Schutzmassnahmen für Cybersicherheit und
Biologie, und steht nur Organisationen offen, die Anthropic verifiziert hat
([Modellseite](https://platform.claude.com/docs/en/models/mythos-5-2/overview)). Ob euer Konto es nutzen darf,
zeigt `python3 tools/pruefen.py --live` mit einem kurzen Testaufruf je Modell. Ist Mythos freigeschaltet, das Konto
aber ohne Zugang, bricht `/ermittlung` gleich beim Start mit der Meldung von Claude Code ab. Dann `--ohne-mythos`.

Gut zu wissen:

- **Die Umschaltung von `/ermittlung` gilt bis zu eurer nächsten Eingabe.** Beantwortet ihr mitten in der
  Ermittlung eine Rückfrage, leitet danach wieder Fable 5.2. Die Analysten laufen weiter auf Mythos.
- **Ohne Mythos meldet Claude Code beim Start jedes Analysten**, dass statt des verlangten Modells das der Sitzung
  läuft. Das ist der Normalfall und kein Fehler.
- **Die Liste gilt für den ganzen Projektordner.** Mit `/model` lässt sich hier nur wählen, was zugelassen ist.
  Wer weitere Modelle will, ergänzt `availableModels` in den eigenen Einstellungen (`~/.claude/settings.json`).
  Legt eure Organisation die Liste zentral fest (verwaltete Einstellungen), gilt allein deren Liste.
- **Grafiken zeichnet kein Modell.** Die Texte des Rapports und die Daten für Beziehungsgraf und Zeitachse schreibt
  der Rapportführer in `befunde.json`. Die Grafiken zeichnet `tools/rapport.py` daraus als Programm. Bei gleichen
  Befunden fallen sie deshalb immer gleich aus.

**Nachsehen, was tatsächlich lief.** Das Sitzungsprotokoll hält fest, welches Modell die Hauptsitzung und jeder
Subagent benutzt hat, gelesen aus den Transkripten von Claude Code. Das Ermittlungsprotokoll zeigt es unter
«Sitzungsverlauf» als Zeile «Eingesetzte Sprachmodelle», ebenso jeden Wechsel mit `/model`. Während der Arbeit
zeigt `/tasks` das Modell jedes laufenden Subagenten.

Die geltende Zuteilung zeigt `python3 tools/pruefen.py` unter «Konfiguration». Selbsttests schlagen an, wenn ein
Agent des Abschlusses nicht auf Fable 5.2 steht oder das Projekt Mythos von sich aus zuliesse. Wie Claude Code
Modelle ausserhalb der Liste behandelt, steht in dessen Dokumentation:
[Modelle einschränken](https://code.claude.com/docs/en/model-config),
[Modell eines Subagenten](https://code.claude.com/docs/en/sub-agents).

Skills und Subagenten ergänzen sich: Ein **Subagent** ist eine Rolle mit eigenem Kontext und eigenen Werkzeugen.
Ein **Skill** ist Wissen, wie etwas zu tun ist. Der Skill `ermittlungsstandard` wird in jeden Analysten vorgeladen
und regelt Zweckangabe, Sicherheitsstufen, Quellenbewertung und das Format der Rückmeldung.

## Blockchain-Analyse

Für Fälle, in denen Geld in Kryptowährungen floss: Online-Anlagebetrug, Lösegeld, Zahlungen an Betrüger. Eine
Blockchain ist ein öffentliches Kassenbuch. Jede Zahlung steht für immer darin, aber ohne Namen. Namen kennt nur,
wer Kunden hat: Börsen und Zahlungsdienste. Die Analyse folgt deshalb dem Geld bis zu der Stelle, an der es bei
einem solchen Dienst ankommt, und nennt, was die fallführende Stelle dort verlangen kann.

![Geldfluss im Abschlussrapport des Musterfalls](docs/bilder/geldfluss.png)

| Frage | Werkzeug |
|---|---|
| Ist die Adresse richtig abgeschrieben? Welche Kette ist es? | `krypto_adresse_pruefen` prüft Format und Prüfsumme, ohne etwas abzufragen. Ein vertauschtes Zeichen fällt auf, bevor eine falsche Adresse in einen Rapport gerät. |
| Was liegt auf der Adresse, was lief darüber, wer hat sie zuerst finanziert? | `krypto_adresse` |
| Welche Zahlungen gingen ein und aus, mit wem? | `krypto_transaktionen`. Köderzahlungen über null und Token mit dem Namen einer bekannten Währung, aber fremdem Vertrag, sind gekennzeichnet. |
| Stimmt die Zahlung des Geschädigten? Betrag, Zeit, Empfänger, Gegenwert in Franken am Tag der Zahlung | `krypto_transaktion`, auf Wunsch mit Gegenprüfung bei einer zweiten Quelle |
| Wohin ging das Geld? | `krypto_geldfluss` folgt einer Zahlung über mehrere Stationen |
| Wem lässt sich eine Adresse zuordnen? | `krypto_zuordnung`: Sanktionslisten, bekannte Lösegeld-Adressen, Etiketten von Börsen, gesperrte Adressen |
| Was war ein Betrag am Stichtag wert? | `krypto_kurs` in CHF, EUR und USD |

**Was abgedeckt ist**

| Kette | Ohne Schlüssel | Mit Schlüssel |
|---|---|---|
| Bitcoin | mempool.space, bei Störung Blockstream. Zuordnung über OFAC, TRM Labs, Ransomwhere, WalletExplorer. | Iknaio: Etiketten und Cluster |
| Ethereum, Optimism | Blockscout: ETH, USDT, USDC und jeder andere Token, Etiketten von Börsen und Brücken. Einzelne Abfragen sind ohne Schlüssel gedrosselt, siehe Grenzen. | Blockscout: Tageskontingent statt Drossel. Etherscan: Gegenprüfung von Transaktionen |
| Arbitrum, Gnosis | Blockscout, sofern es den Anschluss zulässt. Aus Rechenzentren weist es diese Ketten oft ab. | Blockscout mit kostenlosem Schlüssel. Etherscan: Arbitrum kostenlos, Gnosis nur mit bezahltem Abo |
| Polygon, Base | wie oben | Blockscout nur mit bezahltem Paket. Etherscan: Polygon kostenlos, Base nur mit bezahltem Abo. Mit beiden kostenlosen Schlüsseln ist Base also nur über die öffentliche Instanz erreichbar, sofern sie den Anschluss zulässt. |
| BNB Smart Chain | nicht abfragbar | Etherscan mit bezahltem Abo |
| TRON | TronGrid: TRX, USDT, USDC und jeder andere Token, Sperrliste von Tether. Gedrosselt. | TronGrid: ohne Drossel. Tronscan: Namen von Börsen und Diensten |
| Monero, Litecoin, Bitcoin Cash, Dogecoin, Solana | werden erkannt und als nicht abfragbar gemeldet. Monero lässt sich grundsätzlich nicht verfolgen. | |

**So folgt das Werkzeug dem Geld.** Ausgangspunkt ist eine Zahlung (die Transaktions-ID aus dem Rapport) oder eine
Adresse (dann alles, was sie verlassen hat). Von dort geht es Station um Station weiter, bis das Geld an einem
dieser Enden ankommt:

| Ende | Bedeutung |
|---|---|
| Bei einem Dienst | Die Adresse gehört laut Etikett einer Börse, einem Zahlungsdienst oder einem Verwahrer. Dort ist ein Editionsbegehren möglich. Massgebend ist die Kategorie, die die Quelle vergibt. Ein Name allein genügt nicht: Namen tragen auch Adressen von Tätern und von Sanktionierten. |
| Sammelbewegung | Muster eines Dienstes, der Kundengelder zusammenlegt. Der Name ist nicht bekannt. |
| Liegt unbewegt | Der Betrag wurde seit dem Eingang nicht weitergeleitet. Bei USDT und USDC kann der Emittent ihn sperren. |
| Mischdienst | Adresse eines Mischdienstes laut Etikett, oder Transaktion mit dessen Muster. Dahinter ist keine belastbare Zuordnung möglich. |
| Programm auf der Kette | Tauschbörse oder Brücke. Was dort geschah, zeigen die genutzten Quellen nicht. |
| Nicht weiterverfolgt | Grenze des Laufs: Tiefe, Kleinbetrag, Abfragebudget, oder die Quelle hat nicht geantwortet. Das Ergebnis nennt, wo es weitergeht. |

Die Summe aller Enden ist der Startbetrag. Was nicht aufgeht, steht als «Verbleib unklar» da.

Bitcoin kennt keine Kontostände, sondern einzelne Zahlungsausgänge, die genau einmal ausgegeben werden. Welcher
Ausgang wohin ging, ist eine Tatsache der Kette. Legt eine Transaktion mehrere Eingänge zusammen, teilt das
Werkzeug den verfolgten Betrag im Verhältnis der Ausgänge auf. Ethereum und TRON führen Kontostände. Dort ordnet
es einen Eingang den zeitlich nächsten Abgängen derselben Währung zu. Beides sind anerkannte, aber nicht die
einzig möglichen Verfahren. Deshalb gilt im Rapport: **Eine einzelne Zahlung ist eine Feststellung. Was über
mehrere Stationen zugeordnet ist, ist eine Bewertung**, höchstens mit Sicherheit «mittel», und das Verfahren steht
dabei.

**Was am Ende im Rapport steht.** Das Flussbild oben, die Tabelle der Stationen und Enden, und Ansatzpunkte in
dieser Art:

- Editionsbegehren an die Börse: Welchem Kundenkonto ist die Einzahlungsadresse zugeordnet, auf der der Betrag
  ankam? Mit Adresse, Betrag und Transaktion.
- Sperrersuchen an den Emittenten, solange USDT oder USDC auf einer Adresse liegen.
- Editionsbegehren an die Börse, von der die Täteradresse ihr erstes Geld für Gebühren bekam. Das ist in der
  Regel eine Auszahlung aus einem Kundenkonto.

Ein Ansatzpunkt nennt die Stelle, die den Kunden kennt. Eine Person benennt der Rapport nie.

**Etiketten ohne Abfrage.** Neben den Abfragequellen schlägt das Gateway jede Adresse in einer lokalen Liste nach,
den [GraphSense TagPacks](https://github.com/graphsense/graphsense-tagpacks) (MIT-Lizenz): rund 31'700 Einträge im
Repo, dazu auf Wunsch elf Massenlisten mit rund 481'000 Adressen (`python3 tools/listen.py laden`). Dabei geht
nichts hinaus. Stand, Datum und Prüfsumme der Liste stehen im Ergebnis und im Protokoll, und das Gateway liest die
Liste nur, wenn ihre Prüfsumme zum Verzeichnis `gateway/listen/tagpacks.json` passt. Als «Dienst» gilt eine Adresse
nur, wenn die Liste sie als Börse, Zahlungsdienst oder Verwahrer einstuft. Ein Name allein macht keinen Dienst, und
eine Adresse mit dem Vermerk eines Missbrauchs ist nie einer. Sagen Liste und Abfragequelle Verschiedenes, stehen
beide Angaben da. Ein neuer Stand der Liste ist ein bewusster Schritt (`tools/listen.py bauen`, per Pull Request).

**Grenzen, die ihr kennen solltet**

- Etiketten sind Angaben Dritter und können alt oder falsch sein. Für TRON gibt es ohne Tronscan-Schlüssel keine
  Namen: Die Verfolgung erkennt dann die Sammeladresse eines Dienstes, weiss aber nicht, welcher es ist.
- Kommerzielle Analysewerkzeuge kennen ein Vielfaches an Adressen und verfolgen auch durch Tauschbörsen und
  Brücken hindurch. Dieses Werkzeug endet dort und sagt es. Es ersetzt sie nicht, es zeigt, wo sich ihr Einsatz
  oder ein Editionsbegehren lohnt.
- Das Abfragebudget gilt für die Verfolgung selbst. Die Zuordnung der Stationen (Sanktionslisten, Etiketten) und
  der Kurs am Stichtag kommen danach dazu, auch wenn das Budget aufgebraucht ist: Ein Lauf mit Budget 10 kann so auf
  rund 18 Abfragen kommen. Das Ergebnis nennt beide Zahlen.
- Ein Lauf hat ein Abfragebudget (Standard 80 Abfragen, vier Stationen tief). Reicht es nicht, nennt das Ergebnis
  die Stelle, an der sich die Verfolgung fortsetzen lässt.
- Auf Ethereum fehlen in den Listen Eingänge, die ein Programm ausgelöst hat (interne Transaktionen).
- Bei ETH und TRX stehen Zahlungen in der Liste einer Adresse zwischen Aufrufen von Programmen, die keinen Betrag
  bewegen. Auf TRON ist jede USDT-Zahlung ein solcher Aufruf. Das Werkzeug liest deshalb je Station bis zu 600
  Einträge auf TRON und 200 auf der Ethereum-Familie. Hat eine Adresse seit dem Eingang mehr, endet die
  Verfolgung dort als Sammelbewegung.
- Zahlt eine Station Kleinbeträge (unter 2 % des Startbetrags) an viele Adressen, stehen die zwölf grössten
  Empfänger einzeln im Ergebnis und der Rest als Summe. Sonst verbrauchte eine Adresse, die an Hunderte zahlt,
  alle 60 Stationen eines Laufs.
- Blockscout drosselt ohne Schlüssel die Abfragen in der Listenform von Etherscan stark. In der Prüfung liess der
  Dienst zehn davon zu, dann wies er rund 40 Minuten lang ab (HTTP 429). Das Werkzeug liest Zahlungen deshalb über
  die REST-Schnittstelle des Dienstes, die nicht so eng begrenzt ist. Die Listenform braucht es noch in zwei
  Fällen: für die ältesten Zahlungen einer Adresse mit über 200 Einträgen (Erstfinanzierung, Start ab einer
  Adresse), und als zweiten Versuch, wenn die REST-Schnittstelle bei einer sehr grossen Adresse nicht antwortet.
  Weist eine Quelle ab, wartet das Werkzeug einmal, so lange sie es verlangt, und fragt dann nicht weiter: Die
  offenen Stationen stehen unter «Nicht weiterverfolgt», jede mit der Stelle, an der es weitergeht. Mit dem
  kostenlosen `BLOCKSCOUT_API_KEY` gilt laut Anbieter ein Tageskontingent statt der Drossel (100'000 Credits,
  20 bis 30 je Abfrage, also mehrere tausend Abfragen).
- TRM Labs erlaubt ohne Schlüssel 100 Anfragen am Tag je Internetanschluss. Ein Geldfluss auf Bitcoin braucht
  davon in der Regel eine, auf Ethereum und TRON eine je Stufe, bei vielen Stationen mehr. Ist das Kontingent
  erschöpft, steht TRM im Ergebnis als «nicht geprüft». Die Sanktionsliste von OFAC lädt das Gateway selbst, sie
  ist davon nicht betroffen.
- Der Betreiber eines Explorers sieht, für welche Adressen ihr euch interessiert. Wer das vermeiden will, leitet
  über `OSINT_PROXY` oder trägt eigene Instanzen ein (`KRYPTO_BITCOIN_API` und weitere, siehe `.env.example`).
- Jede Abfrage eines Laufs steht einzeln im Ermittlungsprotokoll, das errechnete Ergebnis als «Auswertung» mit
  Verweis auf diese Abfragen. Ein Geldfluss füllt das Protokoll deshalb mit einigen Dutzend Zeilen.

**Ausprobieren.** Der [Musterfall](muster/README.md) enthält eine Lösegeldzahlung in einer erfundenen Kette.
Gegen die echten Dienste, mit Adressen, die seit Jahren öffentlich bekannt sind:

```bash
python3 tools/krypto_live.py --ausfuehrlich
```

## Quellen

So sind die gewünschten Werkzeuge eingebunden. Details und Endpunkte: [docs/QUELLEN.md](docs/QUELLEN.md).

| Quelle | Einbindung | Art |
|---|---|---|
| Shodan | Gateway: `shodan_host`, `shodan_internetdb`, `shodan_dns`, `shodan_suche` | passiv |
| VirusTotal | Gateway: `virustotal_ip`, `_domain`, `_datei`, `_url`, `_beziehungen`. Nur Abfragen, nie Uploads. | passiv |
| Spur | Gateway: `spur_kontext` | passiv |
| AbuseIPDB | Gateway: `abuseipdb_pruefen`, `abuseipdb_meldungen` | passiv |
| Einordnung einer IP: proxycheck.io, ipapi.is, RIPEstat, dazu AbuseIPDB und Spur | Gateway: `ip_einordnung`. Netz und Inhaber (mit Tatzeit: wer das Netz damals ankündigte und hielt), Art des Anschlusses je Quelle, und ob die Adresse der Ausgang eines Anonymisierungsdienstes ist: «ja», «kein Hinweis» oder «nicht geprüft». Der Rapport verlangt den Wert für jede IP. | passiv |
| urlscan.io | Gateway: `urlscan_suche`, `urlscan_ergebnis` (mit Seitentext und Bildschirmfoto), `urlscan_kontingent` und `urlscan_einreichen` | passiv, Einreichen aktiv und nur «private» |
| web-check | Eigene Instanz per Docker. Gateway: `webcheck_passiv` (13 Prüfungen), `webcheck_aktiv` (27 Prüfungen) | passiv und aktiv |
| Robin | Eigener MCP-Server des Projekts, läuft als Container mit Tor. Jeder Aufruf braucht die Zustimmung des Sachbearbeiters. Die Oberfläche lehnt ihn ohne Freigabe `darkweb` von selbst ab. Der Hook sichert jede Antwort als Beleg `X-…`. | Tor |
| Darkus | Menügesteuert, deshalb nicht agentenfähig. Seine Suchmaschinen deckt Robin ab. Die Prüfung gegen die Ahmia-Sperrliste ist als `onion_sperrliste` nachgebaut und Pflicht vor jedem Öffnen einer Onion-Seite. | passiv |
| ransomware.live | Gateway: `ransomware_opfer`, `_gruppe`, `_iocs`, `_aktuell` | passiv |
| urlquery | Gateway: `urlquery_suche`, `_bericht`, `_reputation`, `_status` und `urlquery_einreichen` | passiv, Einreichen aktiv und nur «private» |
| Wayback Machine | Gateway: `wayback_verlauf`, `wayback_abruf` und `wayback_sichern` | passiv, Sichern aktiv |
| Telegram Breach Monitor | Die Seite verweist auf den Kanal `breachdetect`. Gateway: `telegram_kanal` liest die öffentliche Web-Vorschau eines Kanals. Für `breachdetect` zeigte Telegram am 16.11.2026 keine Vorschau mehr, das Werkzeug meldet das. | passiv |
| TeleGramSint | Menügesteuert. Drei seiner Abfragen sind nachgebaut: `telegram_kanalinfo`, `telegram_entitaet`, `telegram_suche`. Die Suche nach Telefonnummern ist bewusst weggelassen. | passiv, teils Personenbezug |
| OSINT-Chan | Nachgebaut über die offizielle Lese-API: `chan_katalog`, `chan_thread`. Stichworte werden lokal gefiltert. | passiv |
| Masto | Nachgebaut: `mastodon_instanz`, `mastodon_konto` | passiv, Konto mit Personenbezug |
| Blockchain: mempool.space, Blockstream, Blockscout, Etherscan, TronGrid | Gateway: `krypto_adresse_pruefen`, `krypto_adresse`, `krypto_transaktionen`, `krypto_transaktion`, `krypto_geldfluss` | passiv |
| Zuordnung: OFAC, TRM Labs, Ransomwhere, WalletExplorer, Blockscout, Tronscan, Chainabuse, Iknaio | Gateway: `krypto_zuordnung`, und eingebaut in die übrigen Krypto-Werkzeuge | passiv |
| Etikettenliste: GraphSense TagPacks | Lokale Liste im Repo (`gateway/listen`), fester Stand mit Prüfsumme. `krypto_zuordnung` und die übrigen Krypto-Werkzeuge schlagen darin nach, ohne dass eine Adresse den Rechner verlässt. Verwaltung: `python3 tools/listen.py` | lokal |
| Kurse: DefiLlama, Europäische Zentralbank | Gateway: `krypto_kurs`, und eingebaut in die übrigen Krypto-Werkzeuge | passiv |

**Passiv** heisst: Die Datenbank eines Dritten wird befragt, das Ziel merkt nichts. Der Anbieter sieht aber
den Indikator. **Aktiv** heisst: Das Ziel wird aufgerufen und kann das bemerken.

Warum ein eigenes Gateway statt je eines fertigen MCP-Servers pro Dienst: eine Stelle für Protokoll, Rohdaten,
Drossel und Cache, ein überschaubarer Code statt eines Dutzends fremder Server mit euren Schlüsseln, und kurze
Antworten, die den Kontext der Agenten schonen. Die vollständige Antwort liegt immer in den Rohdaten.

## Schutzmechanismen

Technisch erzwungen, nicht nur dem Modell aufgetragen:

| Schutz | Wie | Wo |
|---|---|---|
| Keine übersehenen Personendaten | PII-Prüfung vor der Aufnahme (AHV-Nummer, IBAN, Telefon, Geburtsdatum, Kontrollschild, Kreditkarte). Sperrfunde verhindern die Aufnahme. Dieselbe Prüfung liest in der Oberfläche jede hochgeladene Datei und jede Eingabe im Chat, bevor sie das Sprachmodell erreicht. Sie erkennt Muster, keine Namen. | `tools/pii_pruefung.py`, `tools/ui/bedienung.py`, `tools/ui/sitzung.py` |
| In den Fall kommt die Textfassung, nie das Original | Der Akten-Eingang der Oberfläche liest jede Datei im Speicher und nimmt nur ihren Text auf, unter einem neutralen Namen. Verfasser, eingebettete Bilder und Änderungsverlauf eines Originals bleiben draussen. Was sich nicht lesen lässt (Bilder, Ton, alte Formate), geht nicht in den Fall. | `tools/ui/bedienung.py`, `tools/pii_pruefung.py` |
| Geprüft ist nur, was die PII-Prüfung aufgenommen hat | `fall_status` nennt den Agenten nur Dokumente, deren Prüfsumme im Register der PII-Prüfung steht. Von Hand Kopiertes und nachträglich Verändertes meldet es als ungeprüft, ohne den Namen zu nennen. Die Oberfläche warnt im Kopf des Falls. Dass ein Agent ein solches Dokument liest, verhindert seit dem Wegfall des Wächters keine Sperre mehr. | `gateway/akte.py` (`eingang_stand`), `gateway/server.py` |
| Keine Abfrage ohne Fall und Zweck | Das Gateway weist sie ab. | `gateway/kern.py` |
| Aktiv und Personenbezug nur mit Freigabe | Das Gateway prüft `fall.json`. Abgelehnte Versuche stehen im Protokoll. Aktive Werkzeuge fragen zudem jedes Mal nach. | `gateway/kern.py`, `.claude/settings.json` |
| Dark Web nur mit Zustimmung | Jeder Aufruf von Robin fragt nach (Regel «ask»). Die Oberfläche lehnt ihn ohne Freigabe `darkweb` von selbst ab und lässt ihn mit Freigabe zu. Am Terminal entscheidet der Mensch je Aufruf: Dort prüft niemand mehr die Freigabe. | `.claude/settings.json`, `tools/ui/sitzung.py` |
| Pflichtquellen gibt nur der Sachbearbeiter vor | Vorgeben, ändern und aufheben verlangen ein Terminal oder das Geheimnis der Oberfläche. Die Berechtigungen verbieten den Befehl für Agenten. Ob eine Pflichtquelle gefragt wurde, liest der Rapport aus dem Protokoll: Nie gefragt ist ein Mangel und verhindert ihn. Eine Pflichtquelle ersetzt keine Freigabe. | `tools/fall.py`, `gateway/pflichtquellen.py`, `tools/rapport.py`, `.claude/settings.json` |
| Keine Selbstfreigabe | `fall.py freigabe` und das Übersteuern der PII-Prüfung verlangen ein Terminal. Die Berechtigungen verbieten den Befehl für Agenten. Der Aufruf der Funktion dahinter aus einem Shell-Befehl steht auf keiner Erlaubt-Liste: Claude Code fragt dafür den Menschen. | `tools/fall.py`, `.claude/settings.json` |
| Nichts am Protokoll vorbei | `curl`, `wget`, `Invoke-WebRequest` und Ähnliches sind verboten. `WebFetch` und `WebSearch` fragen jedes Mal nach, ebenso jeder Shell-Befehl, der nicht auf der Erlaubt-Liste steht. | `.claude/settings.json` |
| Keine öffentliche Einreichung | Eine URL geht bei urlscan.io und urlquery nur als «private» hinaus. Die Werkzeuge haben keinen Parameter dafür, und eine Schranke im Kern hält jede andere Einreichung auf, egal welches Werkzeug sie schickt. | `gateway/kern.py` (`schranke`) |
| Kein selbst geschriebener Beleg | Abklärungen von Hand erfasst nur der Sachbearbeiter, am Terminal oder in der Oberfläche. Das Werkzeug verlangt ein Terminal, die Berechtigungen verbieten den Befehl für Agenten. | `tools/beleg.py`, `.claude/settings.json` |
| Klartext bleibt beim Sachbearbeiter | `tools/pseudonymisieren.py` und `tools/reidentifizieren.py` laufen nur an einem Terminal und nicht aus Claude Code heraus. Die Berechtigungen verbieten beide Befehle für Agenten. Dokument, Zuordnungstabelle und Ausgabe müssen ausserhalb des Projektordners liegen. Das Pseudonymisieren sperrt sich selbst jede Netzverbindung. | `.claude/settings.json`, `tools/pseudonymisieren.py` |
| Etiketten nur aus der geprüften Liste | Das Gateway liest die lokale Etikettenliste nur, wenn ihre Prüfsumme zum Verzeichnis passt. Sonst gilt sie als «nicht geprüft». | `gateway/krypto_listen.py` |
| Protokoll und Rohdaten für die Schreibwerkzeuge gesperrt | Die Berechtigungen verbieten `Edit` und `Write` auf `fall.json`, Protokoll, Rohdaten und Eingang. Ein Shell-Befehl, der dort schreibt, steht auf keiner Erlaubt-Liste: Claude Code fragt dafür den Menschen. Veränderungen zeigt die Kette. | `.claude/settings.json` |
| Die Oberfläche ändert nur für den Sachbearbeiter | Ändernde Anfragen brauchen das Geheimnis des Starts (nur im Speicher des Servers und im Browserfenster). Ohne Terminal oder aus Claude Code gestartet, läuft sie «nur lesen». Eine hochgeladene Datei liest der Server erst ein, wenn das Geheimnis stimmt. Sie ruft die bestehenden Werkzeuge auf und schreibt nie selbst in Protokoll, Rohdaten, Eingang oder `fall.json`. Die Ablage mit Klartext und Zuordnungstabellen liegt ausserhalb des Projekts. Die Vorgabe `OSINT-Ablage` im Benutzerordner sperren die Berechtigungen für Agenten. | `tools/ui/bedienung.py`, `tools/oberflaeche.py`, `.claude/settings.json` |
| Die Oberfläche führt nichts Fremdes aus | Der Server hört nur auf 127.0.0.1 und weist fremde Host-Köpfe ab. Inhalte aus Quellen erscheinen als Text, Rohdateien als Text oder Bild, eine Content-Security-Policy verbietet alles von aussen. Adressen aus dem Fall sind nie anklickbar. | `tools/ui/server.py`, `tools/ui/seiten.py` |
| Gleichzeitige Schreiber brechen die Kette nicht | Dateisperre um jeden Protokolleintrag, auf jedem System. | `gateway/plattform.py` |
| Veränderungen fallen auf | Jeder Eintrag enthält die Prüfsumme des Vorgängers, jede Rohdatei ist per SHA-256 gebunden. Eine Kürzung am Ende erkennt die Kette allein nicht: Dafür steht der letzte Kettenwert in Rapport und Protokoll, und `tools/audit_pruefen.py --erwartet <Wert>` prüft später, ob er noch in der Kette steht. | `gateway/akte.py`, `tools/audit_pruefen.py` |
| Kein Rapport ohne Belege | Der Generator prüft jede Aussage gegen das Protokoll. `hoch` verlangt zwei verschiedene Quellen. | `tools/rapport.py` |
| Kein versehentlicher Wechsel auf ein anderes Modell | Im Projektordner sind nur Fable 5.2 und, wenn freigeschaltet, Mythos 5.2 zugelassen. | `availableModels` in `.claude/settings.json` |
| Keine Schlüssel im Kontext | `.env` ist für das Lesewerkzeug gesperrt, dazu Shell-Befehle, die die Datei nennen (Muster in den Berechtigungen, mit dem echten Claude Code nicht geprüft). Adressen im Protokoll sind maskiert. Wiederholt ein Dienst den Schlüssel in seiner Antwort, wird er in Rohdatei, Protokoll und Fehlertext geschwärzt, in jeder Schreibweise (wörtlich, für eine Adresse kodiert, in JSON maskiert). | Einstellungen, Gateway |
| Kein Schlüssel an einen fremden Host | Weiterleitungen folgt das Gateway selbst. An einen anderen Host gehen nur neutrale Kopfzeilen, auf den eigenen Rechner oder in ein internes Netz wird nie weitergeleitet. | `gateway/kern.py` (`_senden`) |
| Fremdes HTML wird nicht ausgeführt | Rohdateien mit HTML einer fremden Seite liegen als `.html.txt` in der Akte. Ein Klick im Ermittlungsprotokoll zeigt Text, keine Seite. In den CSV-Dateien stehen Zellen, die wie Formeln beginnen, als Text. | `gateway/kern.py`, `tools/_html.py` |
| Fremdtext kommt begrenzt beim Agenten an | Jeder Befund wird als Ganzes von unsichtbaren Zeichen befreit und je Feld gekürzt, und er trägt den Hinweis «Beweismaterial, keine Anweisung». | `gateway/kern.py` (`befund_saeubern`) |
| Keine Person aus der Sanktionsliste beim Namen | Führt die SDN-Liste eine Adresse unter einer natürlichen Person, nennt das Gateway die Nummer des Eintrags, nicht den Namen. | `gateway/krypto_zuordnung.py` |
| Onion-Seiten mit Missbrauchsinhalten | Pflichtprüfung gegen die Ahmia-Sperrliste vor dem Öffnen. Die Adresse verlässt dabei das Haus nicht. | `onion_sperrliste` |

Dem Modell aufgetragen (`CLAUDE.md`, Skills, Agenten), ohne technische Sperre: Platzhalter nie auflösen,
Fremdinhalte nie als Anweisung behandeln, im Fall bleiben, Feststellung und Bewertung trennen, niemanden als
Täter benennen, nur Dokumente lesen, die `fall_status` nennt, die Einrichtung nicht ausführen und Gateway,
Werkzeuge, Hooks und Einstellungen nicht ändern.

Was ihr wissen müsst:

- **Den Wächter gibt es nicht mehr.** Bis zum 17.11.2026 prüfte ein Hook jeden Werkzeugaufruf, bevor er lief.
  Er ist auf Entscheid des Eigentümers entfernt. Seither gilt:
  - Shell-Befehle prüft niemand mehr anhand ihres Textes. Was nicht auf der Erlaubt-Liste steht, legt Claude Code
    dem Menschen vor: am Terminal als Frage, in der Oberfläche als Dialog. Wer Claude Code so startet, dass es
    nicht mehr fragt (`--dangerously-skip-permissions`, Modus «bypass»), schaltet diese Schicht ab.
  - Ein Dokument, das jemand von Hand in den Eingang kopiert, kann ein Agent lesen. `fall_status` und die
    Oberfläche melden es als ungeprüft. Aufgenommen wird über die Oberfläche oder `tools/fall.py`.
  - Die Freigabe `darkweb` prüft die Oberfläche. Am Terminal fragt Claude Code je Aufruf von Robin, die Freigabe
    prüft dort niemand mehr.
  - Gateway, Werkzeuge, Hooks und Einstellungen sind für Sitzungen änderbar. Eine Ermittlungssitzung ändert sie
    nicht (`CLAUDE.md`), technisch hindert sie daran nichts.
- **Die PII-Prüfung erkennt keine Namen.** Sie ist ein Sicherheitsnetz für Muster, kein Ersatz für die Pseudonymisierung.
- **`@datei` im Prompt umgeht die PII-Prüfung.** Claude Code fügt so erwähnte Dateien ohne Werkzeugaufruf ein.
  Dokumente deshalb nie mit `@` anhängen, sondern über die Oberfläche oder `fall.py` aufnehmen.
- **Die Kette erkennt Veränderungen, sie verhindert sie nicht.** Wer den Stand verbindlich festhalten will,
  hinterlegt den letzten Kettenwert ausserhalb des Systems (Journal, Zeitstempeldienst).
- **Indikatoren gehen an Dritte.** Jede Abfrage zeigt dem Anbieter die IP, Domain oder den Hash, und Anthropic
  verarbeitet, was die Agenten lesen. Welche Indikatoren das Haus verlassen dürfen, entscheidet ihr.
- **Dritt-Software läuft mit.** Robin und Web-Check sind fremde Projekte. Robin bringt in seinen
  Werkzeugbeschreibungen eigene Arbeitsanweisungen an das Modell mit. Für den Einsatz in einer Behörde: Forks
  prüfen, Abbilder selbst bauen und auf eine Version festlegen (`ROBIN_IMAGE`).
- **Mit Robin verbindet sich der Rechner zu Beginn jeder Sitzung mit dem Tor-Netz,** auch ohne Freigabe `darkweb`:
  Claude Code startet den Container, und Tor läuft darin sofort an. Gesucht und gelesen wird erst mit Freigabe.
  Wer das an einem Arbeitsplatz nicht will, richtet ihn ohne Robin ein (`--ohne-robin`).

## Fehler beheben

| Symptom | Ursache | Lösung |
|---|---|---|
| `claude mcp list` zeigt `osint … Pending approval` | Ordner noch nicht als vertrauenswürdig bestätigt | `claude` im Projektordner starten, Dialog bestätigen |
| `osint` verbindet nicht | `.venv` fehlt oder Pakete fehlen | `./setup.sh`, unter Windows `.\setup.cmd` |
| Windows: `osint` verbindet nicht, Meldung nennt `${OSINT_PYTHON}` oder `python3` | Das Terminal kennt die Variable `OSINT_PYTHON` noch nicht, oder sie zeigt ins Leere | neues Terminal öffnen. Hilft das nicht: `.\setup.cmd` |
| `/ermittlung` bricht sofort ab, Claude Code meldet, das Modell sei nicht verfügbar | Mythos 5.2 ist freigeschaltet, das Konto hat aber keinen Zugang | `./setup.sh --ohne-mythos`. Vorab prüfen: `python3 tools/pruefen.py --live` |
| Claude Code meldet beim Start eines Analysten, er laufe auf einem anderen Modell als verlangt | Mythos 5.2 ist nicht freigeschaltet | nichts, das ist der Normalfall. Wer Mythos hat: `./setup.sh --mythos` |
| `/model` lehnt ein Modell ab | Das Projekt lässt nur Fable 5.2 zu, und Mythos 5.2, wenn freigeschaltet | gewollt. Weitere Modelle: `availableModels` in `~/.claude/settings.json` ergänzen |
| `fall.py freigabe` meldet «trifft ein Mensch am Terminal», obwohl ihr am Terminal sitzt | Fenster von Git Bash unter Windows | in PowerShell oder der Eingabeaufforderung ausführen |
| `.\setup.ps1` meldet «Ausführung von Skripts ist deaktiviert» | Ausführungsrichtlinie von PowerShell | `.\setup.cmd` verwenden |
| Die Einrichtung fragt nichts, obwohl ihr am Terminal sitzt | Sie erkennt kein Terminal: Ausgabe umgeleitet (`\| tee`, `> datei`), Umgebungsvariable `CI` gesetzt, oder der Arbeitsplatz ist eingerichtet und der Aufruf enthält eine Option, die etwas einstellt | ohne Umleitung und ohne Option starten: `./setup.sh` |
| Im Assistenten wirken die Pfeiltasten nicht, oder es erscheinen Zeichen wie `←[2K` | Das Terminal versteht die Steuerzeichen nicht | `./setup.sh --schlicht` stellt dieselben Fragen als nummerierte Listen |
| Strg+V fügt im Assistenten nichts ein (altes Konsolenfenster unter Windows) | Dieses Fenster reicht Strg+V nicht als Text weiter | Rechtsklick fügt ein. Oder Windows Terminal verwenden. |
| Ein Schlüssel wird mit «enthält keine Leerzeichen» oder «zu kurz» abgewiesen | Beim Kopieren ist etwas mitgekommen oder verloren gegangen | noch einmal kopieren, nur den Schlüssel selbst. Notfalls direkt in `.env` eintragen. |
| Am Ende steht «Eingerichtet» statt «Einsatzbereit» | Nicht jede Testabfrage kam durch | Die Zeilen mit ✗ nennen den Grund: Schlüssel, Netz oder Proxy. Danach `python3 tools/pruefen.py --live` |
| Einrichtung oder `pruefen.py` meldet «Proxy … antwortet nicht», die Testabfragen werden ausgelassen | In `.env` steht ein Proxy, hinter dem nichts läuft, etwa Tor, das nicht gestartet ist | `./setup.sh` und «Prüfen und auffrischen»: Ist Tor gewählt, installiert und startet die Einrichtung es. Oder «Einstellungen ändern», «Proxy», «Kein Proxy» |
| «Tor läuft, baut aber noch keine Verbindungen auf» | Tor ist eben gestartet (bis zwei Minuten), oder das Netz lässt Tor nicht zu | kurz warten, dann `python3 tools/pruefen.py --live`. Bleibt es dabei: ohne Proxy oder mit einem eigenen arbeiten |
| WSL: `docker ps` meldet nach der Einrichtung auch im neuen Fenster «permission denied» | Das Konto kam eben erst in die Gruppe `docker`, und sie gilt erst ab der nächsten Anmeldung. Unter WSL ist das nicht in jedem Fall schon das nächste Fenster | in PowerShell `wsl --shutdown` ausführen, WSL neu öffnen |
| WSL: Beim Start der Oberfläche öffnet sich kein Browser | WSL hat keinen eigenen Browser, und der von Windows liess sich nicht starten | die Adresse aus dem Terminal im Browser von Windows öffnen. Sie steht da, sobald die Oberfläche läuft |
| «Browser für PDF: … die Probe ergab kein PDF» | Der Browser startet ohne Fenster nicht, oder er darf im Projektordner nicht schreiben (ein Snap darf nur in den Benutzerordner) | Projekt im Benutzerordner ablegen oder einen anderen Browser in `OSINT_BROWSER` nennen. Sonst den Rapport im Browser öffnen und als PDF drucken |
| «Browser für PDF: chromium ist installiert, in diesem WSL-Fenster aber nicht zu sehen» (oder «noch nicht zu sehen») | Der Snap ist installiert und für das System eingehängt, dieses Fenster sieht seinen Inhalt aber nicht. Gesehen am 18.11.2026 unter Ubuntu 26.04 in WSL. Bekannt ist das von WSL-Fenstern, die unter Windows «Als Administrator» gestartet wurden (ein Fehler von WSL, microsoft/WSL#9097). Erkennt die Einrichtung ein solches Fenster, steht es in der Zeile. Auf dem Rechner, auf dem es zuerst auffiel, lag es nicht daran: Der Snap blieb auch im gewöhnlichen neuen Fenster unsichtbar (19.11.2026). Die Zeile erscheint unter WSL deshalb nur noch, wenn auch der Browser von Windows nicht druckt | Der Schritt steht am Schluss: Fenster schliessen, WSL gewöhnlich öffnen (nicht «Als Administrator ausführen»), `./setup.sh` erneut. Meldet die Zeile dort dasselbe: in PowerShell `wsl --shutdown` ausführen, WSL neu öffnen, `./setup.sh` erneut. Hilft auch das nicht, bleibt es beim Drucken im Browser von Windows |
| «Browser für PDF: … Auch der Browser von Windows (msedge.exe) druckt von hier nicht» | Unter WSL druckt sonst der Browser von Windows. Hier geht es nicht: Programme von Windows lassen sich aus WSL nicht starten, oder der Browser erreicht den Projektordner nicht. Der Grund steht hinter dem Doppelpunkt | Den Rapport im Browser von Windows öffnen und als PDF drucken. Oder einen Browser in WSL nennen, der druckt: `OSINT_BROWSER` |
| «Browser für PDF: chromium ist als Snap installiert, startet aber nicht» | Der Snap ist installiert, sein Inhalt aber auch für das System nicht eingehängt | Versuch: WSL neu starten (in PowerShell `wsl --shutdown`, dann WSL neu öffnen) und `./setup.sh` erneut. Die Zeile zeigt dann, ob er druckt. Bis dahin den Rapport im Browser von Windows öffnen und als PDF drucken |
| Vor einer Installation steht «Die Paketverwaltung ist gerade belegt», oder danach «Tor liess sich noch nicht installieren, die Paketverwaltung war belegt» | Ein anderer Vorgang hält die Paketverwaltung besetzt. Kurz nach dem Start sind das meist die automatischen Aktualisierungen des Systems (`unattended-upgr`). Gesehen am 18.11.2026 unter Ubuntu 26.04 in WSL | Die Einrichtung wartet von selbst, höchstens zehn Minuten. Reicht das nicht: in ein paar Minuten `./setup.sh` erneut ausführen. Für Tor geht es auch ohne: «Einstellungen ändern», «Proxy», «Kein Proxy» |
| «Tor liess sich nicht installieren» oder «Chromium liess sich nicht installieren» | Die Paketverwaltung hat die Installation abgelehnt | Der Grund steht eingerückt unter der Zeile («Die Paketverwaltung meldet: …»), vollständig in `/tmp/osint-setup/pakete.log`. Beheben, dann `./setup.sh` erneut. Für Tor geht es auch ohne: «Einstellungen ändern», «Proxy», «Kein Proxy» |
| Die Einrichtung fragt ein zweites Mal nach dem Passwort (sudo) | sudo merkt sich das Passwort nur eine Weile, meist 15 Minuten. Eine lange Installation davor hat die Frist aufgebraucht | Passwort noch einmal eingeben. Die Zeile davor sagt, wofür es gebraucht wird |
| «Docker läuft, Zugriff vorerst über sudo» | Das Konto steht in der Gruppe `docker`, aber die Anmeldung dieses Terminals ist älter. Robin erreicht Docker so nicht | Der Schritt steht am Schluss: Fenster schliessen und neu öffnen. Unter WSL mit `docker ps` prüfen, sonst in PowerShell `wsl --shutdown` |
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
| `rapport.py` meldet «Pflichtquelle …: nicht abgefragt für …» oder «… im Fall nie abgefragt» | Eine vorgegebene Quelle wurde für einen passenden Indikator nie gefragt, eine Suchquelle im ganzen Fall nie | Die Ermittlung fortsetzen: Sie holt die Abfrage nach. Fehlt dafür eine Freigabe oder ein Schlüssel: erteilen, einrichten oder die Quelle aus der Vorgabe nehmen (`python3 tools/fall.py quellen <Fall-ID>`, oder in der Oberfläche) |
| Robin meldet `tor_bootstrapping` | Tor startet noch (bis zwei Minuten nach Beginn der Sitzung), oder das Netz lässt Tor nicht zu | Kurz warten und noch einmal fragen. Bleibt es dabei: Der Container muss das Tor-Netz direkt erreichen, siehe `docs/QUELLEN.md` |
| «Protokoll … ABWEICHUNGEN» | Protokoll oder Rohdatei wurde verändert | Nicht reparieren. Vorfall klären. |

Meldungen der Einrichtung: `/tmp/osint-setup/` (unter Windows `%TEMP%\osint-setup\`), je Schritt eine Datei:
`pakete.log`, `venv.log`, `pip.log`, `claude.log`, `docker.log`, `muster.log`, `pruefung.log`. Was fehlt, ohne
etwas zu ändern: `./setup.sh --nur-pruefen`.

## Stand der Prüfung und Grenzen

**Bei jeder Änderung geprüft** durch GitHub Actions ([`.github/workflows/pruefung.yml`](.github/workflows/pruefung.yml)),
zuletzt auf Ubuntu 26.04, macOS 26 und Windows Server 2025, dort je einmal mit Windows PowerShell 5.1 und mit
PowerShell 7:

- Die Einrichtung ohne Rückfragen in einem frischen Klon, unter Windows über `setup.ps1` und über `setup.cmd`.
  Dabei installiert sie Claude Code selbst, unter Linux und macOS auch `pdftotext`.
- 99 Selbsttests ohne Netz (`python3 tools/selbsttest.py`): Gateway über echtes MCP-stdio, Protokollkette samt
  Manipulationserkennung, Cache, Freigaben, Berechtigungen, Hook-Starter (unter Windows in
  Git Bash), Sitzungs-Hook samt Aufzeichnung der Modelle, Dateisperre und gleichzeitige Hooks, PII-Prüfung,
  Prüfregeln des Rapports, Zuteilung und Freischaltung der Modelle, Übereinstimmung der Agenten mit den
  Werkzeugen, die Oberfläche der Einrichtung und der Weg der Antworten des Assistenten bis in `.env`. Unter Linux
  laufen sie ein zweites Mal so, als wäre der Rechner ein WSL: Ein echtes WSL gibt es in der CI nicht.
- Acht davon gelten den Quellen aus dem November 2026: die Einordnung einer IP (drei Werte, uneinige Quellen,
  Tatzeit im Fenster der Historie, Residential Proxy, frühere Zuteilung, nie eine Kontaktperson im Ergebnis), die
  Regel im Rapport (jede IP trägt den Wert aus der Fallakte, Empfehlungen bekommen den Vorbehalt), der Beleg von
  Hand, urlscan.io (Suche, Seitentext als Text, Bildschirmfoto als Datei, und: ohne «private» verlässt keine
  Einreichung das Gateway) und die Etikettenliste (Prüfsumme, Einstufung, veränderte Liste gilt als nicht geprüft).
- Vierzehn gelten der lokalen Pseudonymisierung (`tools/pseudonymisieren.py`), Stand 16.11.2026: jede Schicht
  für sich (technische Indikatoren bleiben zeichengenau stehen, Feldmarken in zwölf Lagen, eine andere
  Feldmarken-Liste ohne Änderung am Code, Fortpflanzung in allen Schreibweisen, die Muster der PII-Prüfung,
  Namensliste und Kandidaten, Entscheide und Zuordnungstabelle über zwei Dokumente), der Dialog mit gespielten
  Eingaben, ein Lauf im Pseudo-Terminal von Dokument bis Zuordnungstabelle (nur Linux und macOS), kein Start ohne
  Terminal und aus Claude Code heraus, kein Zusatzpaket und kein Netz, die Verbote in den Einstellungen, der Prüfsatz
  (über 200 Rapporte, immer gleich, jede Feldmarke kommt vor, nichts darin kann echt sein) und Schwellen der
  Messung an 45 Rapporten. Ein eigener Schritt der CI prüft, dass die Tabellen im README zum Stand des Codes
  passen (`python3 tools/pseudo_messen.py --pruefen`). Nicht geprüft: echte Rapporte, die Liste eurer
  Feldmarken, die Tabellen des BFS und der Dialog in einer Windows-Konsole.
- Zwei gelten den Pflichtquellen (`gateway/pflichtquellen.py`), Stand 17.11.2026: die Regeln an erfundenen
  Indikatoren und Protokolleinträgen (fällig ist nur, was aus den Eingangsdokumenten stammt und abgefragt werden darf;
  «kein Treffer» und ein Fehlschlag gelten als gefragt, eine vom Gateway abgelehnte Abfrage nicht; hinter einer
  Auswertung zählen die Abfragen ihrer Grundlage;
  eine Bitcoin-Adresse passt nur zu Bitcoin; Monero ergibt keine Pflicht; Robin zählt erst, wenn es gesucht hat),
  vorgeben nur für eingerichtete Quellen und für Robin nur mit Freigabe, kein Vorgeben ohne Terminal, `fall_status`
  nennt den Agenten die offenen Paare, und am Musterfall: Der Rapport meldet drei Mängel, solange drei Abfragen
  fehlen, und keinen, wenn alles gefragt ist. In der Oberfläche: Speichern nur mit Geheimnis und nicht, während die
  Ermittlung arbeitet. Der Musterfall selbst hat keine Vorgabe und bleibt Byte für Byte gleich.
  Dazu eine Gegenprobe mit echten Einträgen (17.11.2026): Am Protokoll der Testabfragen (Fall `SELBSTTEST`, 1149
  Einträge, nur öffentlich bekannte Indikatoren) erkennt die Auswertung die Abfragen von 25 der 29 Quellen, eine davon
  als Fehlschlag (Wayback Machine, von der Prüfumgebung aus nicht erreichbar). Zu Spur, RapidAPI Telegram und Iknaio
  gibt es ohne Schlüssel keine Einträge, zu Robin auch nicht: Robin ist nie gelaufen. Die Auswertung brauchte dafür
  rund 0,15 Sekunden (96 Indikatoren, alle 29 Quellen vorgegeben).
  **Nicht geprüft:** ob das Team in einer echten Ermittlung die Pflichtquellen abarbeitet. Das hängt an der Steuerung
  mit dem echten Claude Code, die nicht geprüft ist. Geprüft ist, dass der Rapport es merkt, wenn es das nicht tut.
- Vier gelten der Einrichtung bis zum Start, Stand 17.11.2026. Anlass war die Einrichtung des Eigentümers unter
  Ubuntu 26.04 in WSL am selben Tag: Als Proxy war «Tor auf diesem Rechner» gewählt, Tor aber nicht installiert, und
  21 von 25 Testabfragen scheiterten, ohne dass die Meldung die Ursache nannte. Geprüft ist jetzt, mit Attrappen für
  Paketverwaltung, Dienste und Programme: Der Assistent bietet Tor nur an, wenn es am Ende läuft. Die Einrichtung
  installiert und startet es und wartet, bis es Verbindungen aufbaut (gegen einen nachgebauten SOCKS-Server: Gefragt
  wird mit dem Namen des Ziels, dieser Rechner fragt kein DNS). Ein Proxy, der nicht antwortet, heisst in der Meldung
  des Gateways, in `fall_status` und in `pruefen.py` beim Namen, sein Passwort erscheint nirgends, und am Proxy vorbei
  geht keine Abfrage. Fehlt ein Browser für PDF, installiert die Einrichtung Chromium (unter Ubuntu als Snap) und
  druckt zur Probe eine kleine Seite. Der Abschluss nennt jeden Schritt in der Reihenfolge, in der er zu tun ist.
  Claude Code und die Oberfläche startet die Einrichtung nur auf Wunsch, und nicht, wenn das Konto eben erst in die
  Gruppe `docker` kam. Ob Claude Code dem Projektordner schon vertraut, liest sie ab und schreibt es nie selbst. Unter
  WSL öffnet die Oberfläche den Browser von Windows und zeigt die Adresse in jedem Fall, dort mit `localhost`.
  Die Probe für den Browser lief hier auch echt: Mit `chrome-headless-shell` entstand das PDF in unter einer Sekunde.
  Der `google-chrome` der Prüfumgebung antwortete ohne Fenster nie (Zeitlimit 45, 20 und 12 Sekunden): Die Probe
  sagte das, beendete ihn samt seinen Kindprozessen, und danach lief kein Prozess des Browsers mehr und kein Profil
  blieb liegen.
  Am 17.11.2026 an den Paketen selbst nachgesehen (Ubuntu 24.04, heruntergeladen und gelesen, nicht installiert): Das
  Paket `tor` (0.4.9.11) bringt den Dienst `tor.service` und das Startskript `/etc/init.d/tor` mit, startet sich nach
  der Installation selbst und hört in der Vorgabe auf Port 9050. Ein Paket `chromium` gibt es dort nicht:
  `chromium-browser` verweist nur auf den Snap und setzt `snapd` voraus. Deshalb der Weg über Snap.
  Aus den Dokumentationen, gelesen am 17.11.2026: Claude Code wendet die Erlaubnisse eines Projekts erst an, wenn der
  Mensch dem Ordner vertraut, und hält das in `~/.claude.json` fest (Claude Code, «Project allow rules and workspace
  trust»). Aus einem Browser von Windows erreicht man einen Server in WSL unter `localhost` (Microsoft, «Accessing
  network applications with WSL»).
  **Nicht geprüft:** die echte Installation von Tor und von Chromium (Paket und Snap), der Start von Tor als Dienst
  mit und ohne systemd, ob der Snap unter WSL ohne Fenster druckt, das Öffnen des Browsers von Windows aus WSL, ab
  wann die Gruppe `docker` unter WSL gilt, der Start von Claude Code aus der Einrichtung, und ob Claude Code das
  Vertrauen auf einem echten Arbeitsplatz so ablegt, wie es die Dokumentation sagt. Die Prüfumgebung hat weder WSL noch systemd noch Snap: Das alles liess sich
  nur mit Attrappen nachstellen. Bei jedem dieser Punkte sagt die Einrichtung selbst, was sie gesehen hat (Zeilen
  «Tor (Proxy)», «Browser für PDF», «Projektordner»).
- Einer gilt dem, was der erste echte Lauf unter WSL gezeigt hat (18.11.2026, Ubuntu 26.04 in WSL, Einrichtung des
  Eigentümers mit «Prüfen und auffrischen»). Der Lauf ging durch und endete mit «nicht einsatzbereit». Vier Dinge
  daraus sind behoben:
  Ein Selbsttest scheiterte (94 von 95). Er las den Port der Oberfläche mit `127.0.0.1` aus ihrer Ausgabe, unter WSL
  steht dort `localhost`. Hier nachgestellt, indem die ganze Suite mit gesetztem `WSL_DISTRO_NAME` lief: vorher 94 von
  95 mit derselben Meldung, nachher alle. Dieser zweite Lauf gehört seither zur CI (Linux).
  Chromium liess sich als Snap installieren, startete aber nicht (snap meldete, der Inhalt des installierten Snaps
  fehle unter `/snap`). Die Probe sagte das, die Liste «Neu eingerichtet» nannte Chromium trotzdem. Jetzt gilt Chromium
  erst als eingerichtet, wenn es gedruckt hat. Die Nachschau auf jenem Rechner am selben Tag zeigte, was los war: Für
  das System war der Snap eingehängt (die Einheit `snap-chromium-….mount` meldete «active (mounted)»), im offenen
  WSL-Fenster zeigte `mount` aber keinen einzigen Snap, und der Ordner des Snaps war dort leer. Die Einrichtung erkennt
  diese Lage jetzt selbst, nennt sie in einfachen Worten und setzt Chromium zu dem, was erst im neuen Fenster gilt.
  `tools/pruefen.py` meldet einen solchen Browser nicht mehr als vorhanden. Bekannt ist genau diese Meldung von
  WSL-Fenstern, die unter Windows «Als Administrator» gestartet wurden: So berichtet es microsoft/WSL#9097, dort zuletzt
  bestätigt in einem Kommentar vom Januar 2026 (gelesen am 18.11.2026). Der Schritt sagt deshalb, das neue Fenster
  gewöhnlich zu öffnen. Ob das Fenster als Administrator läuft, fragt die Einrichtung unter WSL das Windows-Programm
  `whoami` (Verbindlichkeitsstufe `S-1-16-12288`). Trifft es zu, nennt die Zeile das als Grund.
  Tor liess sich nicht installieren, und der Grund stand nur in einer Protokolldatei. Dort stand: «Could not get lock
  /var/lib/dpkg/lock-frontend. It is held by process … (unattended-upgr)». Das System spielte gerade automatische
  Aktualisierungen ein. Jetzt wartet `apt-get` bis zu zehn Minuten auf die Sperre, und die Einrichtung sagt vorher,
  dass und worauf sie wartet. Reicht das nicht, nennt sie die belegte Paketverwaltung als Grund und rät, es in ein paar
  Minuten noch einmal zu versuchen. Bei jedem anderen Fehlschlag steht die Meldung der Paketverwaltung eingerückt unter
  der Zeile. Fragt sudo ein zweites Mal nach dem Passwort, sagt die Einrichtung vorher wofür.
  Die Zeile «Projektordner» versprach einen Schritt am Schluss, der bei «nicht einsatzbereit» fehlte, und «Docker
  läuft, Zugriff vorerst über sudo» blieb ohne Schritt. Beides steht jetzt in der Liste am Schluss, im selben Wortlaut
  wie unter «So geht es weiter».
  Richtig gemeldet hat der Lauf: den Projektordner als «noch nicht bestätigt», den Proxy, der nicht antwortet, als
  Ursache, und die Passwortfrage mit ihrem Zweck.
  Die belegte Paketverwaltung ist in der Prüfumgebung echt nachgestellt (18.11.2026, Ubuntu 24.04, apt 2.8.3, als
  root): Ein Skript namens `unattended-upgrade` hielt die Sperre `/var/lib/dpkg/lock-frontend`, und die
  Installationsroutine der Einrichtung lief dagegen. Sie kündigte das Warten an und nannte den Vorgang beim Namen. Bei
  8 Sekunden Sperre kam apt nach 9 Sekunden durch. War die Wartezeit kürzer als die Sperre (5 gegen 25 Sekunden),
  nannte die Einrichtung die belegte Paketverwaltung als Grund, und darunter standen zwei Zeilen von apt statt einer je
  Sekunde. Installiert wurde nichts: Gefragt war ein Paket, das schon da ist. Dabei gesehen: Ob die Sperre gehalten
  wird, steht in `/proc/locks`. Der Name eines Prozesses sagt es nicht, denn auch ein Skript namens
  `unattended-upgrade-shutdown` heisst in der Prozessliste `unattended-upgr`. Und die Zeilen «Waiting for cache lock»
  schreibt apt auch, wenn es danach weiterkommt: Als Grund zählt deshalb nur die Fehlerzeile.
  **Nicht geprüft:** die Meldung zur belegten Paketverwaltung auf einem echten WSL (beim zweiten Lauf war sie frei). Wie
  lange die automatischen Aktualisierungen die Paketverwaltung belegen: Dauern sie länger als zehn Minuten, braucht es
  einen zweiten Lauf. Weiterhin offen: das Öffnen des Browsers von Windows aus WSL und der Start von Claude Code aus
  der Einrichtung.
- Einer gilt dem, was der zweite echte Lauf unter WSL gezeigt hat (19.11.2026, derselbe Rechner, Stand nach dem
  vorigen Punkt). **Gesehen:** Die Einrichtung endete mit «Einsatzbereit mit 25 von 28 Quellen», alle 96 Selbsttests
  bestanden dort. Tor liess sich installieren, startete und baute Verbindungen auf. Docker war im neuen Fenster ohne
  sudo erreichbar, die Gruppe `docker` galt also. Die Abfrage von `whoami` aus WSL ging, und sie zeigte: Das Fenster
  lief nicht als Administrator (`S-1-16-8192`). Trotzdem sah es keinen einzigen Snap, während systemd den Snap von
  Chromium als eingehängt führte. Die bekannte Ursache trifft dort also nicht zu, und der Schritt «neues Fenster»
  half nicht: Die Einrichtung hätte im Kreis geführt.
  **Geändert:** Unter WSL druckt jetzt der Browser von Windows, wenn in WSL selbst keiner druckt. Edge gehört zu
  Windows, installiert wird dafür nichts. `tools/pdf.py` gibt ihm Dokument und Ziel unter dem Namen, unter dem Windows
  das Dateisystem von WSL zeigt (`\\wsl.localhost\…`, übersetzt mit `wslpath`). Rapport und PDF bleiben im
  Projektordner. Sein leeres Wegwerf-Profil liegt für die Dauer des Drucks im Ordner TEMP von Windows und wird danach
  entfernt. Ein Snap ohne sichtbaren Inhalt steht in der Reihenfolge der Versuche zuletzt. Die Einrichtung prüft den
  Browser von Windows mit derselben Probe wie jeden anderen und nennt ihn nur dann, wenn er wirklich gedruckt hat.
  **Nachgestellt** in der Prüfumgebung (19.11.2026): Stellvertreter für `wslpath`, `cmd.exe` und `msedge.exe`, die die
  Schreibweise von Windows verlangen und dahinter einen echten Browser drucken lassen. `tools/pdf.py` druckte so die
  Probe und beide Dokumente des Musterfalls, aus einem Ordner mit Leerzeichen im Namen. Im nachgebauten TEMP blieb kein
  Profil liegen, auch nicht nach einem Browser, der nie antwortete.
  **Nicht geprüft:** der ganze Weg auf einem echten WSL. Offen ist damit, ob Edge das Dokument über `\\wsl.localhost`
  liest und das PDF dorthin schreibt, ob es sich aus WSL ohne Fenster starten lässt und sich danach beendet, und ob ein
  Edge, der nicht antwortet, sich über PowerShell beenden lässt. Unter Windows selbst druckt Edge mit denselben
  Schaltern in der CI. Warum das Fenster den Snap nicht sieht, ist weiterhin nicht geklärt.
- Der Schluss der Einrichtung ist seit dem 19.11.2026 kürzer. Anlass war die Rückmeldung des Eigentümers nach dem
  zweiten echten Lauf: Sechs Schritte unter «So geht es weiter» waren zu viel. Geprüft ist jetzt, mit Attrappen für
  Tastatur, Claude Code und den Start der Oberfläche: Ist der Arbeitsplatz einsatzbereit und sitzt ein Mensch am
  Terminal, stellt die Einrichtung eine Frage und macht den Rest selbst (Claude Code für das Ja zum Projektordner,
  dann die Oberfläche). Sie fragt nicht, wenn der Assistent schon gefragt hat, ohne Terminal, mit
  `--ohne-rueckfragen`, in der CI, und wenn erst ein neues Terminal gilt, was die Oberfläche braucht. Im Terminal
  bleiben höchstens zwei Schritte. Der Start der Oberfläche fragt selbst nach dem Ja zum Projektordner, solange es
  fehlt, und behauptet nichts, wenn der Mensch Claude Code ohne Ja verlässt. Die drei Schritte in der Oberfläche
  stehen auf ihrer ersten Seite. Das alles steckt in zwei bestehenden Selbsttests, die dafür erweitert wurden.
  **Nicht geprüft:** der neue Schluss an einem echten Terminal, mit dem echten Claude Code und einem echten Browser.
- «Alles abschalten» gibt es seit dem 19.11.2026: als Befehl (`tools/dienste.py`) und als Knopf auf der Seite
  «Arbeitsplatz». Zwei Selbsttests gelten dem. Der eine prüft mit Stellvertretern für Docker und den Dienst Tor, was
  gestoppt wird und was nicht: Robin und Web-Check immer, Tor nur am Terminal und nur, wenn der Arbeitsplatz es als
  Proxy nutzt, Docker selbst nie, und kein Befehl löscht etwas. Er startet dazu eine echte Oberfläche, findet sie von
  aussen und bittet sie ums Ende. Der andere prüft den Knopf: Er verlangt das Geheimnis, hält laufende Ermittlungen an,
  vermerkt das im Sitzungsprotokoll und beendet die Oberfläche.
  **Gesehen** in der Prüfumgebung (19.11.2026, Linux, echter Docker mit dem Container von Web-Check): Eine laufende
  Oberfläche wurde über ihren Merker gefunden, gebeten und endete in weniger als einer Sekunde von selbst
  (Rückgabewert 0). Der Container wurde gestoppt (0,3 Sekunden), beim zweiten Mal hiess es «war schon aus», der Start
  der Oberfläche schaltete ihn wieder ein. Im Browser (Chromium): Wer die Rückfrage abbricht, schaltet nichts ab. Nach dem Ja stand
  der Container still, das Fenster zeigte «Abgeschaltet», der Server antwortete nicht mehr, und das Fenster fragte
  danach nichts mehr ab. Lief dabei eine Ermittlung (gespielt von dem Programm, das in den Tests für Claude Code
  steht), wurde sie angehalten, und im Sitzungsprotokoll stand «Ermittlung angehalten» mit dem Grund.
  Hart beendet wird nur ein Prozess, der sich auf dem Port seines Merkers eben noch als diese Oberfläche ausgewiesen
  hat (Prozess und Projekt). So trifft der Befehl nie einen fremden Prozess, dessen Nummer in einem alten Merker steht.
  Die Merker liegen in einem Ordner, der nur dem eigenen Konto gehört. Das Beenden geht über eine Bitte, die die
  Oberfläche selbst liest. So soll sie auch unter Windows sauber enden, wo es das Signal dafür nicht gibt: Ein
  Selbsttest prüft das mit einer echten Oberfläche, in der CI auch unter Windows und macOS.
  **Nicht geprüft:** der Befehl an einem echten Terminal (er verlangt einen Menschen: Aufgerufen wurden die Funktionen
  dahinter). Tor an einem echten System abschalten und starten. Robin mit seinem echten Abbild: Gestoppt wurde ein
  Container, der dafür stand. Docker Desktop unter Windows und macOS.
- Was nur ein Mensch tun darf (Freigabe, Beleg von Hand, Pseudonymisieren, Zurückführen, die bedienbare Oberfläche),
  verlangt ein echtes Terminal für Ein- und Ausgabe (`plattform.terminal`). Unter Windows genügt die übliche Abfrage
  dafür nicht: Python hält dort auch das Gerät NUL für ein Terminal, und `tools/reidentifizieren.py` lief bis zum
  17.11.2026 mit umgeleiteter Eingabe weiter (gesehen in der CI). Ein Selbsttest prüft auf allen Systemen die
  Abweisung mit NUL und unter Windows die Gegenprobe in einer eigenen Konsole.
- Elf gelten der Oberfläche (`tools/oberflaeche.py`, `tools/ui/`, `tools/anhang.py`), Stand 16.11.2026: Für jedes Werkzeug
  liegt eine Rohantwort als Vorlage im Repo, und keine ihrer Angaben geht verloren (105 Vorlagen, 4431 Angaben, jede
  zugeordnet oder unter «Weitere Angaben»). Jeder gezeigte Wert steht an der genannten Stelle der Rohdatei, in den
  Vorlagen, in jedem Datenblatt des Musterfalls und im Anhang. Zahlen ohne Rundung, Zeiten mit Original, Einheiten,
  gekürzt nur in der Anzeige. Feste Abschnitte je Art des Indikators, Widerspruch und «keine Angabe». «Kein Treffer»,
  Fehlschlag, Ablehnung und Fall-Cache mit der ursprünglichen Abfragezeit. Ein Fall voller Markup (Skripte, Ereignis-
  Attribute, `javascript:`-Adressen in Werten, Schlüsseln, Zielen und Befunden): In keiner Ansicht entsteht daraus ein
  ausführbares Element, ein Verweis nach aussen oder ein fremdes Bild. Der Server: über 600 Adressen zweier Fälle
  antworten, fremder Host-Kopf und fremde Herkunft werden abgewiesen, es gibt nur GET und HEAD, Pfade aus den
  Rohdaten hinaus enden bei 404, und die Fallakten sind nach dem Lauf Byte für Byte unverändert. Kennzahlen und
  Wortlaut entsprechen dem Abschlussrapport des Musterfalls. Dazu ein Durchgang im Browser (Chromium, ohne Fenster,
  16.11.2026) am Musterfall: 206 Ansichten geöffnet, 219 Tabellen sortierbar, Filter, CSV, Graf, Geldfluss, Zeitachse,
  Arbeitsspur, Tastatur, Druckansicht und dunkle Darstellung bedient, kein Fehler in der Konsole, keine Anfrage nach
  aussen. Die CI startet die Oberfläche auf Linux, macOS und Windows (`python3 tools/oberflaeche.py --selbstpruefung`).
  Nicht geprüft: Firefox und Safari, ein Bildschirmleser, Fälle mit mehr als rund tausend Protokolleinträgen
  (gemessen an einem Fall mit 1058 Einträgen: jede Ansicht unter einer Sekunde), und die Darsteller der Werkzeuge,
  zu denen keine echte Antwort vorlag (siehe [docs/OBERFLAECHE.md](docs/OBERFLAECHE.md)).
- Acht gelten der Bedienung der Oberfläche (`tools/ui/bedienung.py`, `tools/ui/sitzung.py`, `tools/ui/paket.py`), Stand
  17.11.2026, seit dem 19.11.2026 mit «Alles abschalten»: Jede der 26 ändernden Aktionen antwortet ohne Geheimnis, mit falschem Geheimnis und mit dem Startcode an
  seiner Stelle mit 403 und ändert nichts. Eine Datei liest der Server erst ein, wenn das Geheimnis stimmt. Der
  Startcode gilt einmal. Das Geheimnis steht in keiner Datei des Projekts und in keiner Umgebung. Ohne Terminal oder aus
  Claude Code gestartet, gibt es kein POST. Der Akten-Eingang mit erfundenen Dokumenten: einzelne Dateien, ein Ordner,
  ein ZIP mit einem ZIP darin, ein ZIP mit Passwort, eine E-Mail mit Anhängen, Word, ein Bild, gleicher Inhalt zweimal,
  eine leere Datei, ein Name, der aus dem Ordner hinausführen will. In den Fall kommt nur die Textfassung dessen, was
  die PII-Prüfung besteht, unter neutralen Namen. Der Verfasser aus den Eigenschaften eines Word-Dokuments steht danach
  nirgends im Projekt. Ohne Auswahl entfernt «entfernen» nichts. Entfernen, Verschieben (auch bei gleichem Namen im
  Zielfall), nachträgliches Prüfen von Hand Kopiertem, Löschen eines Falls ohne Abfragen. Nochmals pseudonymisieren:
  Nach dem Übernehmen steht kein Name und keine AHV-Nummer des Dokuments in Fallakte oder Protokoll, Platzhalter von
  anderer Hand bleiben, neue zählen dahinter weiter, die Zuordnungstabelle liegt ausserhalb des Projekts, und eine
  Tabelle, die ausserhalb der Oberfläche geändert wurde, wird nicht überschrieben. Freigabe und Beleg von Hand über die
  bestehenden Werkzeuge. Die Ermittlung gegen ein Programm, das Claude Code spielt: Die Sitzung startet im Projektordner
  mit `/ermittlung` und den Vorgaben aus dem Chat, ohne einen Schalter, der Einstellungen, Hooks, MCP-Server oder das
  Modell umstellt. Das Geheimnis steht weder in ihrer Umgebung noch in ihren Argumenten. Der gespielte Agent versucht,
  sich über die Oberfläche eine Freigabe zu erteilen, einen Beleg zu erfassen und seine Rückfrage selbst zu
  beantworten, und bekommt fünfmal 403. Jeder Schritt steht im Verlauf, mit Analyst, Beleg und Ergebnis. Eine Vorgabe
  oder Nachricht mit einer Telefonnummer geht nicht hinaus. Eine Nachricht setzt eine ruhende Sitzung fort, wartet auf
  das Ende eines laufenden Auftrags, lässt sich zurücknehmen oder unterbricht ihn. Rückfrage erlauben, ablehnen und
  unbeantwortet lassen, zwei Rückfragen nacheinander, anhalten und fortsetzen. Meldet das gespielte Claude Code beim
  Start kein Gateway, beendet die Oberfläche die Sitzung. Das Archiv: jede Datei mit der Prüfsumme aus `INHALT.txt`, im
  Auszug des Sitzungsprotokolls nur die Zeilen des Falls, kein Klartext, und die Fallakten sind danach Byte für Byte
  unverändert. Die Formate: Aus Word, OpenDocument, Excel, PowerPoint, RTF und E-Mail entsteht der erwartete Text.
  Dazu ein Durchgang im Browser (Chromium, ohne Fenster, 17.11.2026) mit erfundenen Akten durch den ganzen Ablauf, 81
  Prüfpunkte: Ordner wählen, ZIP, Datei ablegen, alle auswählen, Bereich mit der Umschalttaste, Filter, entfernen,
  umbenennen, verschieben, zwei Dokumente nacheinander pseudonymisieren, Fall anlegen, Vorgaben, Rückfrage als Fenster,
  Nachricht warten lassen und zurücknehmen, unterbrechen, anhalten, fortsetzen, Unterlagen erzeugen, Archive und
  einzelne Dateien herunterladen, zurückführen, dazu die Pflichtquellen (alle auswählen, keine, einzeln, der Start
  übernimmt die Auswahl, Robin erst mit Freigabe, Stand am Musterfall, aufheben). Kein Fehler in der Konsole, keine
  Anfrage nach aussen.
  **Nicht geprüft: die Steuerung mit dem echten Claude Code.** Die Form seiner JSON-Ausgabe und der Weg der Rückfrage
  (`--permission-prompt-tool`) folgen der Dokumentation (gelesen am 16.11.2026) und der Hilfe von Claude Code 2.1.326,
  gesehen sind sie nicht. Aus der Entwicklungssitzung liess sich kein zweites Claude Code starten, ohne deren
  Anmeldung und Umgebung mitzunehmen. Nachholen am eigenen Arbeitsplatz: `python3 tools/oberflaeche.py --sitzungsprobe`.
  Ebenfalls nicht geprüft: eine ganze Ermittlung aus der Oberfläche; ob Vorgaben nach der Fall-ID beim Skill ankommen
  und ob eine Nachricht mit `--resume` die Sitzung so fortsetzt, wie die Dokumentation es beschreibt; ob die
  Erlaubt-Regeln für die Arbeitsdateien eines Falls (`Edit(./faelle/*/arbeitsstand/**)` und zwei weitere) im echten
  Claude Code greifen; die Bedienung unter Windows und macOS; Firefox und Safari, vor allem das Hineinziehen ganzer
  Ordner; PDF im Akten-Eingang (der Leser dahinter ist derselbe wie am Terminal und dort geprüft); grosse Dateien nahe
  der Grenze von 60 MB; und eine Testabfrage aus der Oberfläche gegen eine echte Quelle.

- Elf dieser Selbsttests gelten der Blockchain-Analyse. Sie laufen gegen eine erfundene Kette
  (`tools/_kryptowelt.py`), die in den Formen der echten Dienste antwortet: Prüfsummen und Abschreibfehler,
  Geldfluss auf Bitcoin, Ethereum und TRON (die Enden ergeben zusammen auf die kleinste Einheit genau den
  Startbetrag), Börse, Sammeladresse, Mischdienst und gesperrtes Guthaben, eine Zahlung, die in der Liste hinter
  200 Aufrufen ohne Betrag steht, ein Programm, das im selben Zug annimmt und weiterzahlt, eine sanktionierte
  Adresse mit Namen, die kein Dienst ist, Kleinbeträge an viele Adressen, eine Quelle, die drosselt, Blockscout
  mit Schlüssel (der Schlüssel steht nie im Protokoll), Ausfall einer Quelle samt Ausweichquelle, Gegenprüfung bei
  zweiter Quelle, Kurs am Stichtag, die Fortsetzungsdatei der Sanktionsliste und das Flussbild im Rapport.
- Der Assistent in einem echten Terminal. Unter Linux und macOS fährt ihn ein Selbsttest in einem
  Pseudo-Terminal, unter Windows in einer eigenen, unsichtbaren Konsole, deren Bildschirm er ausliest und in
  deren Eingabepuffer er Tasten legt. Geprüft ist jeweils: Pfeiltasten und Enter kommen an, die Steuerzeichen
  für Farbe und Cursor wirken, ein eingegebener Schlüssel steht nie auf dem Bildschirm, die Vorschau verändert
  nichts, und das Terminal ist danach wieder im alten Zustand.
- Die ausführliche Prüfung `tools/pruefen.py`.
- Zwei weitere Läufe: Mythos freischalten und wieder zurücknehmen.
- Der Klon ist danach unverändert (`git status` leer). Der Musterfall fällt also auf allen drei Systemen Byte für
  Byte gleich aus.
- `claude doctor` beanstandet die Einstellungen nicht.

**Gegen die echten Dienste geprüft**, in einem eigenen Lauf
([`.github/workflows/blockchain-live.yml`](.github/workflows/blockchain-live.yml), `python3 tools/krypto_live.py`),
zuletzt am 13.11.2026, ohne Schlüssel und mit Adressen, die seit Jahren öffentlich bekannt sind:

- Bitcoin über mempool.space: Stand einer WannaCry-Adresse (250 Transaktionen), die erste Bitcoin-Zahlung von
  2009 samt Gegenprüfung bei Blockstream, und ein Geldfluss ab der WannaCry-Adresse. Er führte über mehrere
  Stationen zu Adressen, die WalletExplorer zwei Börsen zuordnet.
- Ethereum über Blockscout: eine Transaktion mit einer Zahlung von 1 Mio. USDC, eine sanktionierte Adresse (von
  OFAC, TRM Labs und Blockscout übereinstimmend gemeldet, Erstfinanzierung von einer Börse), ihre Abgänge in
  USDC, eine Börsen-Adresse. Der Geldfluss der USDC-Zahlung endete bei einem Programm mit über 200 Abgängen. Ein
  Geldfluss in ETH ab der sanktionierten Adresse führte über mehrere Stationen zu einer Adresse, die Blockscout
  als Tornado Cash führt: Ende «Mischdienst laut Etikett». Dazu Optimism.
- TRON über TronGrid: Adresse, Eingänge in USDT, eine Transaktion ohne Angabe der Kette, deren Geldfluss, ein
  Geldfluss in TRX ab einer Adresse mit mehreren hundert ausgehenden Transaktionen, und die Sperrliste von Tether.
- Sanktionsliste von OFAC (1064 Krypto-Adressen erkannt, samt Fortsetzungsdatei), TRM Labs, Ransomwhere,
  WalletExplorer.
- Kurse von DefiLlama und Referenzkurse der EZB, auch für einen Samstag.
- Die eingebaute Liste von 15 Token-Verträgen (USDT, USDC, DAI, WETH auf sieben Ketten): Kürzel und
  Dezimalstellen stimmen mit DefiLlama überein.

Dieser Lauf wiederholt sich jede Woche und bei Änderungen am Gateway. Ändert ein Dienst seine Schnittstelle,
fällt es dort auf und nicht erst in einem Fall. Hinterlegt ihr `BLOCKSCOUT_API_KEY` oder `TRONGRID_API_KEY` als
Secrets des Repositorys, nimmt der Lauf den Zugang mit Schlüssel.

Diese Läufe haben Fehler gezeigt, die an der erfundenen Kette nicht auffielen. Sie sind behoben und seither als
Selbsttest abgesichert: Blockscout vergibt Namen auch an sanktionierte Adressen und an Adressen von Tätern (sie
galten als «Dienst»), TRM Labs weist Anfragen über 1 KB ab, Blockscout drosselt die Listenform von Etherscan
nach zehn Abfragen, und seine REST-Liste antwortet bei sehr grossen Adressen nicht.

**Mit Schlüsseln geprüft**, am 16.11.2026 von einem Arbeitsplatz mit kostenlosen Schlüsseln, alles über das
Gateway (Fallakte `SELBSTTEST`): `python3 tools/pruefen.py --live`, `python3 tools/krypto_live.py`, dazu jedes
Werkzeug einzeln. Je Werkzeug wurde die gekürzte Antwort Feld für Feld mit der Rohdatei verglichen. Den Stand je
Endpunkt führt [docs/QUELLEN.md](docs/QUELLEN.md).

- Shodan (`shodan_host`, Zählen in `shodan_suche`), Shodan InternetDB, VirusTotal (alle fünf Werkzeuge), AbuseIPDB
  (beide), urlquery (Suche, Bericht und Reputation), ransomware.live API PRO (alle sechs Pfade), Ahmia-Sperrliste (60'371
  Einträge, jeder ein MD5-Wert), Telegram-Vorschau, 4chan (Katalog und Thread), Mastodon-Instanz.
- Blockchain mit Schlüssel, 22 von 22 Prüfungen: Blockscout für Ethereum, Optimism, Arbitrum und Gnosis, TronGrid,
  Etherscan (Gegenprüfung einer Ethereum-Transaktion, Polygon, Arbitrum), Tronscan (Etikett einer Börsen-Adresse,
  Risikohinweise), Chainabuse.
- Web-Check auf einem GitHub-Runner (Workflow [«Web-Check live»](.github/workflows/webcheck-live.yml),
  `python3 tools/webcheck_live.py`): Zwölf der 13 passiven Prüfungen lieferten für example.com ein Ergebnis, der
  dreizehnten (`shodan`) fehlt in der Instanz der Schlüssel. Der Lauf wiederholt sich jede Woche und bei Änderungen.
  Hinter dem HTTPS-Proxy der Prüfumgebung erreichte der Container die befragten Dienste nicht: Dort sind die
  Fehlerbilder gesehen, und dass das Gateway sie als «nicht geprüft» meldet.
- Ein Durchlauf von Anfang bis Ende mit einem synthetischen Rapport: Fall anlegen samt PII-Prüfung, 48 Abfragen,
  `befunde.json`, Gegenprüfung durch den Agenten `gegenpruefer` in einer echten Claude-Code-Sitzung (ein Befund
  bestätigt, fünf eingeschränkt, keiner widerlegt), Rapport, Protokoll, Kettenprüfung. Die Abfragen liefen über
  die Funktionen des Gateways, nicht über `/ermittlung`: Der MCP-Server war in der Prüfsitzung nicht verbunden.
- Die Protokollkette unter Last: 970 Einträge im Fall `SELBSTTEST`, geschrieben von mehreren Prozessen
  gleichzeitig, Kette und Rohdaten unverändert.

- Die neuen Quellen, am 16.11.2026: `ip_einordnung` mit proxycheck.io, ipapi.is und RIPEstat an 8.8.8.8, 1.1.1.1
  und einem öffentlich gelisteten Tor-Ausgang, mit und ohne Tatzeit. Gesehen sind alle drei Werte, «Quellen
  uneinig», die Historie von proxycheck.io (Parameter `days` und `history`), die Routing-Geschichte und die
  früheren Fassungen eines Registereintrags bei RIPEstat. urlscan.io: fünf Suchen (Domain, URL, IP, AS, SHA-256
  der EICAR-Testdatei), ein Ergebnis samt Seitentext und Bildschirmfoto eines öffentlichen Scans von example.com,
  das Kontingent. Eingereicht wurde nichts. Etikettenliste: alle 87 Dateien des Standes geladen, die Tabelle
  gebaut, die elf Massenlisten über `tools/listen.py laden` geholt und gegen die Prüfsummen geprüft, bekannte
  Adressen nachgeschlagen (eine WannaCry-Adresse, ein Vertrag von Tornado Cash, Reserve-Adressen zweier Börsen).

- Nachprüfung am 17.11.2026: je eine Testabfrage an 21 Quellen, dieselben Abfragen wie bei `tools/pruefen.py --live`.
  Alle 21 Werkzeuge antworteten. Nicht wiederholt: RIPEstat und Chainabuse (Obergrenze der Prüfung), Wayback Machine
  (am 16.11.2026 nicht erreichbar). Einzelheiten und ein dabei behobener Fehlertext zu Blockscout stehen in
  [docs/SCHLUSSBERICHT-2026-11.md](docs/SCHLUSSBERICHT-2026-11.md), Abschnitt 2.

- Eine Durchsicht von Code und Repo samt unabhängiger Gegenprüfung in einer Kopie ohne Netz (16.11.2026). Was sie
  gefunden hat, was behoben ist und was als Vorschlag offen bleibt, steht in
  [docs/REVIEW-2026-11.md](docs/REVIEW-2026-11.md). Den Wächter, den die Durchsicht mitgeprüft hat, gibt es seit
  dem 17.11.2026 nicht mehr.

Auch diese Prüfung hat Fehler gezeigt, die an erfundenen Antworten nicht auffielen. Sie sind behoben und als
Selbsttest abgesichert, gegen Vorlagen in der Form der echten Antworten (`tools/_vorlagen.py`): Das Gateway
schrieb Adressen samt Schlüssel in sein Log, Web-Check meldet Fehlschläge mit HTTP 200 (sie galten als Treffer),
ransomware.live nannte als Zahl der Opfer die Länge der gekürzten Liste und reichte die E-Mail-Adresse des
eigenen Kontos an den Agenten weiter, urlquery suchte im Volltext und fand Berichte ohne Bezug zum Ziel, der
kostenlose Blockscout-Schlüssel deckt Polygon und Base nicht, und der Sitzungs-Hook legte Antworten fremder
MCP-Server als Belege in die Fallakte.

**Zusätzlich von Hand geprüft** (Linux, Claude Code 2.1.323):

- Claude Code verbindet sich mit dem Gateway (`claude mcp list`) und startet es mit dem Interpreter aus der
  Umgebungsvariablen `OSINT_PYTHON`.
- Die Fehlerbilder der Einrichtung: Claude Code fehlt, Installer nicht erreichbar, nur ein altes Python,
  Ordner unter dem anderen System eingerichtet, unbekannte Option, Übernahme von Schlüsseln aus einer Datei.
- `claude doctor` nimmt die Einstellungen in beiden Zuständen an, mit und ohne freigeschaltetes Mythos.
- Gegenproben: Ohne Dateisperre scheitert der Sperrtest. Absichtlich falsche Werte in den Einstellungen
  (`onFailure`, `availableModels`) beanstandet `claude doctor`. Zeigt die verdeckte Eingabe den Schlüssel im
  Klartext, schlagen drei Selbsttests an. Legt die Vorschau eine Datei an, schlägt der Test im Terminal an.
- Der Assistent von Anfang bis Ende in einem Pseudo-Terminal: der erste Lauf mit echter Einrichtung, danach
  «Einstellungen ändern» (Schlüssel eintragen, in einem Stück einfügen, entfernen, aus einer Datei übernehmen,
  Proxy setzen und zurücknehmen), Abbruch mit Esc und mit Strg+C, vorab getippte Tasten und doppeltes Enter vor
  der Übersicht, schmale und niedrige Fenster bis 44 × 12 Zeichen, der schlichte Modus. Die Bilder im Abschnitt [Einrichten](#einrichten) stammen aus einem solchen Lauf.
- Der Musterfall läuft durch dieselben Gateway-Werkzeuge wie eine echte Ermittlung, mit vorgefertigten Antworten.

**Nicht geprüft:**

- **Quellen, für die in der Prüfung kein Schlüssel vorlag:** Spur, Iknaio und RapidAPI (Telegram). Sie sind nach
  den Dokumentationen der Anbieter gebaut und nie gegen den echten Dienst gelaufen.
- **Die Muster in den Berechtigungen mit dem echten Claude Code.** Ob die Verbote für Shell-Befehle
  (`Bash(*.env)` und weitere) und für die Ablage so greifen, wie sie gemeint sind, zeigt erst die Probe am
  Arbeitsplatz: `python3 tools/oberflaeche.py --sitzungsprobe`. Geprüft ist, dass sie in den Einstellungen stehen.
- **Residential Proxies an echten Adressen.** Ob `ip_einordnung` einen Privatanschluss erkennt, über den ein
  Residential Proxy läuft, ist nicht gemessen: Es gab keine Adresse, von der das feststand, und Adressen von
  Privatanschlüssen wurden nicht abgefragt. Geprüft ist an Vorlagen, dass ein solcher Eintrag richtig gelesen
  wird. proxycheck.io und ipapi.is sagen selbst, dass sie solche Adressen nur teilweise kennen. Ohne Spur ist
  die Erkennung schwächer, siehe Grenzen.
- **Spur innerhalb von `ip_einordnung`** (kein Token), das Objekt `vpn` in der Antwort von ipapi.is (keine der
  geprüften Adressen trug es) und ein bei proxycheck.io gelöschter Eintrag ohne heutige Erkennung. Diese Formen
  stehen nach der Dokumentation der Anbieter in den Vorlagen.
- **`urlscan_einreichen`.** Die Einreichung ist eine aktive Massnahme. Ihre Antwort steht nach der Dokumentation
  in den Vorlagen. Geprüft ist ohne Netz, dass sie nur mit Freigabe, nach Suche und Kontingent und nur mit
  «private» hinausgeht. Wie urlscan.io einen Scan meldet, der noch läuft (HTTP 404), ist nicht gesehen.
- **`tools/beleg.py` am Terminal.** Geprüft sind die Funktion dahinter, die Ablehnung ohne Terminal und das Verbot
  in den Einstellungen. Der Dialog selbst ist nicht in einem Terminal durchgespielt.
- **Die Wayback Machine.** Aus der Prüfumgebung vom 16.11.2026 kam keine Verbindung zu `web.archive.org` zustande.
  Geprüft ist an Vorlagen, wie das Werkzeug «keine Aufnahme» und einen Verlauf liest.
- **Was die kostenlosen Schlüssel nicht decken:** `shodan_dns` (Shodan verlangt eine Mitgliedschaft), die
  Trefferliste von `shodan_suche` (kostet Query-Credits), Base und BNB Smart Chain (bei Blockscout und Etherscan
  nur mit bezahltem Paket). Polygon lief nur über Etherscan, Gnosis nur über Blockscout.
- **Alle aktiven Werkzeuge und alle Kontoabfragen:** `urlquery_einreichen` samt `urlquery_status`,
  `wayback_sichern`, `webcheck_aktiv`, `mastodon_konto`, `telegram_entitaet`, `telegram_suche`.
- **Ein Geldfluss, der bei einem von Tronscan benannten Dienst endet.** Das Etikett einer Börsen-Adresse liest das
  Gateway richtig. In den geprüften Geldflüssen auf TRON endete aber kein Betrag bei einer benannten Adresse.
- **Ob Blockscout Polygon, Arbitrum, Gnosis und Base ohne Schlüssel von einem Arbeitsplatz aus beantwortet.** Aus
  den Rechenzentren der Prüfungen wies der Dienst diese Ketten mit HTTP 403 ab.
- **Die Faustregeln der Geldfluss-Verfolgung an vielen echten Fällen.** Ab acht Absenderadressen gilt eine
  Bitcoin-Transaktion als Sammelbewegung eines Dienstes, ab fünf gleich hohen Ausgängen als Mischdienst, eine
  Adresse mit über 200 Abgängen seit dem Eingang als Sammeladresse. Gesehen sind sie an der erfundenen Kette und an
  den echten Läufen oben. Wo sie falsch liegen, nennt das Ergebnis den Grund des Endes, und die Verfolgung
  lässt sich von dort fortsetzen.
- **Eine vollständige Ermittlung in einer echten Claude-Code-Sitzung** mit Subagenten, Skills und Hooks im
  Zusammenspiel, auf keinem System. Die Hooks sind einzeln mit den dokumentierten Ereignisdaten getestet. Gesehen
  ist in einer echten Sitzung der Agent `gegenpruefer`. Die Analysten und `/ermittlung` sind es nicht.
- **Die Umschaltung der Modelle in einer Sitzung.** Dass Claude Code den Wunsch nach Mythos übergeht, solange es
  nicht zugelassen ist, und umschaltet, sobald es das ist, steht so in der Dokumentation von Anthropic (Links
  unter [Modelle je Phase](#modelle-je-phase)). Gesehen ist es hier nicht: In der Bauumgebung liess sich aus
  Claude Code heraus kein zweites Claude Code mit einem Modell starten. Geprüft ist, was die Dateien verlangen
  und was die Einrichtung einträgt. Den Zugang eures Kontos prüft `python3 tools/pruefen.py --live`. Nach der
  ersten echten Ermittlung zeigt das Ermittlungsprotokoll, welches Modell welchen Teil gemacht hat. Diese
  Aufzeichnung ist ihrerseits nur an nachgestellten Transkripten getestet.
- **Windows auf einem Arbeitsplatzrechner.** Die Prüfung läuft auf Windows Server 2025, nicht auf Windows 10
  oder 11. Python, Git for Windows und Poppler waren dort schon vorhanden, ihre Installation über winget kam
  also nicht zum Zug. Dass Claude Code unter Windows `OSINT_PYTHON` übernimmt und die Hooks über Git Bash
  startet, ist aus den Bausteinen geschlossen (Linux-Lauf, Hook-Starter in Git Bash), nicht in einer Sitzung gesehen.
- **Der Assistent in Windows Terminal und auf Windows 10 oder 11.** Geprüft ist er im klassischen
  Konsolenfenster von Windows Server 2025, und dort mit Tasten, die der Test in den Eingabepuffer legt. Ob das
  Einfügen aus der Zwischenablage einen Schlüssel auf jedem Rechner als Text liefert, ist damit nicht gesehen.
  Für den Fall, dass etwas klemmt, gibt es `--schlicht` und den Eintrag von Hand in `.env`.
- **Die Anmeldung aus der Einrichtung heraus.** Der Assistent ruft dafür `claude auth login` auf. Den Befehl
  und seine Schalter gibt es (Claude Code 2.1.323). Der Ablauf im Browser liess sich in der Bauumgebung nicht
  durchspielen. Misslingt er, meldet die Einrichtung das und nennt den Weg von Hand.
- **Die Rückfragen ausserhalb des Assistenten:** die Frage der Startskripte vor der Installation von Python
  (auf den Prüfrechnern war Python vorhanden) und die Passwortfrage von `sudo` (die Prüfrechner brauchen keins).
  Die Skripte sind statisch geprüft (shellcheck, PowerShell-Parser).
- **Die Installation fehlender Systempakete** über dnf, yum, pacman, zypper und apk sowie die Installation von
  Docker, ob über `--docker-installieren` oder über die Frage «Dienste».
  Geprüft ist, welche Befehle die Einrichtung je Paketverwaltung absetzt. Ausgeführt wurden apt und Homebrew.
- **Robin im Betrieb.** Robin ist nie gelaufen. Was es vom Rechner und vom Netz braucht, steht in
  `docs/QUELLEN.md` nach den Unterlagen des Projekts (gelesen am 17.11.2026), nicht nach eigener Beobachtung.
- **Web-Check mit einem bösartigen Ziel.** Die Prüfungen liefen gegen example.com. Wie `threats`, `block-lists` und
  `breaches` bei einem Treffer antworten, ist nicht gesehen.

**Grenzen:**

- Die Einordnung einer IP sagt, was die Quellen wissen, nicht, was ist. «Kein Hinweis» ist kein «nein». Ohne Spur
  ist die Erkennung von Residential Proxies schwächer: proxycheck.io und ipapi.is führen vor allem Rechenzentren,
  VPN-Dienste und offene Proxys. An echten Proxy-Adressen ist die Erkennung nicht gemessen. Der Rapport setzt
  deshalb zu jeder Empfehlung an einen Zugangsanbieter den Vorbehalt, dass der Anschluss einem Unbeteiligten
  gehören kann.
- Die Auskunft zu einer IP gilt für den Abfragezeitpunkt. proxycheck.io reicht 60 Tage zurück, die Register nur
  für Netze der RIPE-Datenbank. Liegt die Tat weiter zurück, sagt das Ergebnis, dass es nur den heutigen Stand kennt.
- Die Etikettenliste gibt den Stand ihres Datums wieder (Dateien von 2019 bis 2023, Stand des Repos 5.11.2026).
  Eine Adresse kann seither den Besitzer gewechselt haben.

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
   Braucht ein Werkzeug mehrere Abfragen für ein Ergebnis, nimmt es einen `Vorgang` (siehe `gateway/kern.py` und
   als Beispiel `gateway/quellen_krypto.py`): Jede Abfrage steht einzeln im Protokoll, das errechnete Ergebnis
   als Auswertung mit Verweis darauf.
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

- welche Indikatoren an Dritte und an Anthropic gehen dürfen (auch Wallet-Adressen: Der Betreiber eines
  Block-Explorers sieht, wonach ihr sucht),
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
Die Blockchain-Analyse fragt öffentliche Dienste ab (mempool.space, Blockstream, Blockscout, TronGrid, OFAC,
TRM Labs, Ransomwhere, WalletExplorer, DefiLlama, EZB). Deren Nutzungsbedingungen gelten auch für euch.

Beiträge sind willkommen, besonders neue Quellen und Rückmeldungen aus `pruefen.py --live`. Bitte keine
Falldaten, Schlüssel oder echten Indikatoren in Issues und Pull Requests. Wie eine Quelle dazukommt und was vor
einem Pull Request läuft, steht in [CONTRIBUTING.md](CONTRIBUTING.md). Schwachstellen bitte vertraulich melden:
[SECURITY.md](SECURITY.md).

Die Etikettenliste unter `gateway/listen/` ist aus den GraphSense TagPacks abgeleitet (MIT-Lizenz, Text in
[`gateway/listen/LIZENZ-TagPacks.txt`](gateway/listen/LIZENZ-TagPacks.txt)).
