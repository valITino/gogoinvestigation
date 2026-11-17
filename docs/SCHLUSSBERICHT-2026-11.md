# Schlussbericht zum Auftrag «prüfen, erweitern und überarbeiten»

Stand 16.11.2026. Der Bericht fasst die sechs Pakete zusammen. Einzelheiten stehen in den Pull Requests und in den
Dokumenten, auf die er verweist. «Geprüft» heisst: an diesem Tag gesehen. Was nicht prüfbar war, steht mit Grund da.

> **Nachtrag vom 17.11.2026.** Mit Paket G ist der Wächter auf Entscheid des Eigentümers entfernt, und die Oberfläche
> hat ein Chat-Fenster, einen Akten-Eingang für mehrere Dateien und eine Seite «Ergebnisse» bekommen. Was unten zum
> Wächter und zur Aufbauphase steht, beschreibt den Stand vom 16.11.2026. Der heutige Stand: README, «Schutzmechanismen»
> und «Stand der Prüfung und Grenzen».

## 1. Stand

| Paket | Pull Request | Stand | Selbsttests |
|---|---|---|---:|
| A: Prüfung mit echten Schlüsseln | [PR 5](https://github.com/valITino/gogoinvestigation/pull/5) | offen, CI grün | 45 |
| B: neue Quellen | [PR 6](https://github.com/valITino/gogoinvestigation/pull/6) | offen, CI grün | 53 |
| C: Review von Code und Repo | [PR 7](https://github.com/valITino/gogoinvestigation/pull/7) | offen, CI grün | 57 |
| D: lokale Pseudonymisierung | [PR 8](https://github.com/valITino/gogoinvestigation/pull/8) | offen, CI grün. **Nicht abgeschlossen:** wartet auf die Liste der Feldmarken | 71 |
| E: Oberfläche Teil 1, nur lesen | [PR 9](https://github.com/valITino/gogoinvestigation/pull/9) | offen, CI grün | 82 |
| F: Oberfläche Teil 2, Bedienung | [PR 10](https://github.com/valITino/gogoinvestigation/pull/10) | offen. **Nicht geprüft:** die Steuerung mit dem echten Claude Code | 88 |
| G: Chat, Akten-Eingang, Ergebnisse, ohne Wächter (Nachtrag vom 17.11.2026) | [PR 11](https://github.com/valITino/gogoinvestigation/pull/11) | offen. **Nicht geprüft:** die Steuerung mit dem echten Claude Code, auch für den Chat | 89 |

Jeder Pull Request baut auf dem vorigen auf. Reihenfolge beim Mergen: A, B, C, D, E, F, G. Gemergt ist nichts.

**Was bei dir liegt, bevor echte Fälle laufen:**

1. Die Probe mit dem echten Claude Code: `python3 tools/oberflaeche.py --sitzungsprobe` (Paket F).
2. Die Liste eurer Feldmarken in `tools/feldmarken.txt`, danach `python3 tools/pseudo_messen.py --readme` (Paket D).
3. Den Shodan-Schlüssel ersetzen. Er stand in der Prüfsitzung einmal in einer Ausgabe (über das Logging, das Paket A abgestellt hat).
4. Der Schlüssel für RapidAPI fehlt noch. Telegram über RapidAPI ist deshalb nicht geprüft.
5. Die Entscheide in Abschnitt 8. Der wichtigste: die Aufbauphase beenden, bevor ein echter Fall auf den Arbeitsplatz kommt.

## 2. Quellen: was geprüft ist

Alle Abfragen liefen am 16.11.2026 über das Gateway, mit dem Fall `SELBSTTEST`, nur passiv und nur mit öffentlich
bekannten, unpersönlichen Indikatoren. Das Protokoll dieses Falls hat 1058 Einträge (10:10 bis 13:09 UTC). Es liegt in
der Prüfumgebung und nicht im Repo. Die Belege unten nennen den ersten Eintrag je Quelle. Die Zahl in Klammern ist die
Zahl der Abfragen im Protokoll.

| Quelle | Geprüft | Dabei gefunden und behoben | Nicht geprüft, mit Grund | Beleg |
|---|---|---|---|---|
| Shodan | `shodan_host`, `shodan_suche` (Zählen) (4) | Der Schlüssel stand im Log des MCP-Servers. Der Fehlertext nennt neu die Meldung der Quelle. | `shodan_dns`: HTTP 403, verlangt eine Mitgliedschaft. Trefferliste: kostet Credits. | P-0001, Ablehnung P-0127 |
| Shodan InternetDB | ja (1) | | | P-0002 |
| VirusTotal | IP, Domain, Datei, URL, Beziehungen (6) | Bei Beziehungen fehlte die Gesamtzahl. | Andere Beziehungen als `resolutions`, manche verlangen ein Premium-Abo. | P-0003 |
| Spur | | | Kein Schlüssel. | |
| AbuseIPDB | `abuseipdb_pruefen`, `_meldungen`, Stimme in `ip_einordnung` (7) | | | P-0004 |
| proxycheck.io (neu) | drei Adressen, mit und ohne Historie (11) | Die echte Antwort weicht von der Dokumentation ab. Das Gateway liest die echte Form. | Ein gelöschter Eintrag ohne heutige Erkennung. Residential Proxies an echten Adressen. | P-0971 |
| ipapi.is (neu) | dieselben drei Adressen, mit Schlüssel und einmal ohne (8) | | Das Objekt `vpn`: keine der Adressen trug es. | P-0986 |
| RIPEstat (neu) | alle sechs Aufrufe, Netze bei RIPE, ARIN und APNIC (36) | | | P-0977 |
| urlquery | Suche, Reputation, Bericht (6) | Die Suche lief im Volltext. Der Bericht las Felder, die es nicht gibt. Einreichen nahm `public` an, jetzt nur «private». | `urlquery_status`, `_einreichen`: aktive Massnahme. | P-0005, HTTP 400 auf eine erfundene Kennung P-0946 |
| urlscan.io (neu) | fünf Suchen, ein Ergebnis mit Seitentext und Bildschirmfoto, Kontingent (9) | | `urlscan_einreichen`: aktive Massnahme. Ein Scan mit Urteil «bösartig», ein laufender Scan. | P-1031 |
| Wayback Machine | | «Nichts da» stand im Protokoll als Treffer (an der Vorlage behoben). | Die Verbindung zu `web.archive.org` brach jedes Mal ab (kein 403, kein 407). | Fehlschlag P-0006 |
| Web-Check | 12 von 13 passiven Prüfungen auf einem GitHub-Runner. Lokal 32 Abfragen: 21 mit Ergebnis, 3 «kein Treffer», 8 Fehlschläge, als solche gemeldet. | Eine gescheiterte Prüfung (HTTP 200 mit `error`) galt als Treffer. | `webcheck_aktiv`: aktive Massnahme. Prüfung `shodan`: Der Instanz fehlt der Schlüssel. | P-0511 bis P-0828 |
| ransomware.live | alle sechs Pfade der API PRO (7) | Als Zahl der Opfer stand die Länge der gekürzten Liste da. Der Steckbrief las falsche Felder. Die E-Mail-Adresse des eigenen Kontos ging an den Agenten und in die Rohdatei. | API v2: laut Anbieter nur für private Nutzung. | P-0007 |
| Ahmia | Sperrliste geladen, 60'371 Zeilen (2) | | Ein Treffer: Dafür bräuchte es eine gesperrte Adresse. | P-0008 |
| Telegram, Web-Vorschau | Kanal `telegram` (2) | «Keine Web-Vorschau» stand als Treffer. | | P-0009 |
| RapidAPI Telegram | | | Kein Schlüssel. Zwei der drei Werkzeuge sind Kontoabfragen. | |
| 4chan | Katalog und Thread (3) | | | P-0010 |
| Mastodon | `mastodon_instanz` (2) | | Rückfall auf die ältere Schnittstelle. `mastodon_konto`: Kontoabfrage. | P-0011 |
| Bitcoin: mempool.space, Blockstream | Adresse, Transaktionen, Verbleib (60 und 2) | Wechselgeld an die eigene Adresse zählte als Eingang. Fehlte der Betrag eines Mit-Eingangs, wurde zu viel verteilt. | | P-0012, P-0094 |
| Blockscout | Ethereum, Optimism, Arbitrum, Gnosis, mit Schlüssel (217, davon 9 Fehlschläge) | HTTP 402 für Polygon und Base hiess «Schlüssel falsch». Jetzt stimmt die Meldung, und das Gateway weicht aus. | Polygon und Base über diesen Zugang: nur mit bezahltem Paket. | P-0022, P-0056 |
| Etherscan | Gegenprüfung auf Ethereum, Polygon, Arbitrum (31) | Die Live-Prüfung bestand, obwohl die andere Quelle geantwortet hatte. | Gnosis und Base: im kostenlosen Paket abgelehnt. BNB Smart Chain, Optimism. | P-0057, Ablehnung P-0459 |
| TronGrid | Konto, Zahlungen, Transaktion (155) | | | P-0030 |
| Tronscan | Etiketten, Risikohinweise (54) | Jeder Name machte die Adresse zum «Dienst». Jetzt nur, wenn der Name sie als Wallet eines Dienstes ausweist. | Ein Geldfluss, der bei einem benannten Dienst endet: kam nicht vor. | P-0040 |
| OFAC, TRM Labs, Ransomwhere, WalletExplorer | Zuordnung (88, 88, 8, 23) | Natürliche Personen aus der Sanktionsliste werden nicht mehr beim Namen genannt. | | P-0016, P-0019, P-0018, P-0020 |
| Chainabuse | eine Abfrage | Bei Anmeldung nach «Basic» blieb ein wiederholter Schlüssel stehen. | Mehr Abfragen: Kontingent geschont. | P-0079 |
| Iknaio GraphSense | | | Kein Schlüssel. | |
| DefiLlama, EZB | Kurse (65 und 59) | | | P-0014, P-0015 |
| GraphSense TagPacks (neu, lokal) | Bau aus 87 Dateien, Massenlisten samt Prüfsummen, Nachschlagen | | | Einträge der Art «lokal» |
| Robin (Dark Web) | | Der Sitzungs-Hook legte Antworten fremder MCP-Server als Beleg ab. | Nicht ausgeführt: kein Dark Web in dieser Prüfung. | |

Nicht ausgeführt wurden alle aktiven Massnahmen und alle Kontoabfragen zu Personen. Ihre Antwortformen folgen der
Dokumentation der Anbieter.

**Hosts, die aus der Prüfumgebung nicht erreichbar waren:** `web.archive.org` (Verbindung brach ab),
`dam-api.bfs.admin.ch` (Abruf von der Berechtigungsprüfung der Sitzung abgelehnt), `opendata.swiss` und
`ckan.opendata.swiss` (HTTP 403). Nichts davon wurde wiederholt oder umgangen.

**Nachprüfung am 17.11.2026 (07:17 UTC).** Je eine harmlose Testabfrage an 21 Quellen, dieselben Abfragen wie bei
`tools/pruefen.py --live`: Shodan, Shodan InternetDB, VirusTotal, AbuseIPDB, proxycheck.io, ipapi.is, urlquery,
urlscan.io (Kontingent), ransomware.live, Ahmia, Telegram (Web-Vorschau), 4chan, Mastodon, Bitcoin, Ethereum
(Blockscout), TRON (TronGrid), Krypto-Zuordnung, GraphSense TagPacks, Krypto-Kurse, Etherscan, Tronscan. Alle 21
Werkzeuge antworteten. Im Protokoll stehen dafür 91 Einträge (P-1059 bis P-1149): 88 mit Ergebnis, einer «kein
Treffer», zwei Fehlschläge. Beide Fehlschläge betreffen Blockscout für Polygon (HTTP 402 am Zugang mit Schlüssel,
HTTP 403 an der öffentlichen Instanz). Etherscan sprang wie vorgesehen ein. Dabei gefunden und behoben: Für die
Abweisung an der öffentlichen Instanz nannte das Protokoll den Schlüssel als Grund, obwohl die Anfrage ohne ihn
hinausging (P-0923, P-1126). Nicht wiederholt: RIPEstat und Chainabuse (Obergrenze der Prüfung), Wayback Machine (am
16.11.2026 nicht erreichbar). Nicht bereit: Spur, RapidAPI Telegram und Iknaio GraphSense (kein Schlüssel), Web-Check
(keine Instanz in der Prüfumgebung). Robin: weiterhin nie gelaufen. Was es vom Netz braucht, steht neu in
`docs/QUELLEN.md`.

## 3. Die neuen Quellen

| Quelle | Was sie liefert | Bedingungen, gelesen am 16.11.2026 | Wo die Lücke bleibt |
|---|---|---|---|
| proxycheck.io | Erkennung von VPN, Proxy und Tor, Art des Netzes, Historie für 60 Tage | Fassung vom 12.7.2026: Das ganze Ergebnis darf nicht wörtlich weitergegeben werden, ein kostenloses Konto je Kunde. Betreiber und Sitz nennt der Dienst nicht. Behörden sind nicht eigens geregelt. | Kein Feld für Residential Proxies. Historie nur 60 Tage. Im Rapport nie alleinige Grundlage. |
| ipapi.is | VPN, Proxy, Tor, Rechenzentrum, Netz, Meldestelle | Fassung vom 3.10.2026: Nutzung intern, öffentliche Stellen sind als Kunden genannt, abgefragte Adressen speichert der Dienst laut Vereinbarung nicht. Betreiber ist ein Einzelunternehmer in Berlin. | Erkennt Residential und mobile Proxys laut eigener Dokumentation meist nicht. Nur der Stand von heute. |
| RIPEstat | Netz, AS, Inhaber, Meldestelle. Mit Tatzeit: wer das Netz damals ankündigte und wem es zugeteilt war | RIPE NCC, Amsterdam. Kein Schlüssel. Erbeten sind ein Name der Anwendung und ab rund 1'000 Anfragen am Tag eine Anmeldung. Nennung bei Veröffentlichungen. | Die frühere Zuteilung kennt der Dienst nur für Netze der RIPE-Datenbank. Über VPN oder Proxy sagt er nichts. |
| urlscan.io | Vorhandene Scans zu Domain, URL, IP, AS und Hash: Ergebnis, Seitentext, Bildschirmfoto | urlscan GmbH, Deutschland. Fassung vom 22.7.2020: «persönlich, nicht kommerziell». Die Hilfeseite nennt Untersuchungen in Ordnung. | Kostenlos nur Scans der letzten 365 Tage. Einreichen ist nicht geprüft. Ob die Bedingungen eine Behörde decken, ist offen. |
| GraphSense TagPacks | Lokale Etikettenliste: 31'718 Einträge im Repo, 481'322 als Massenlisten zum Nachladen | MIT-Lizenz, fester Stand vom 5.11.2026 | 15 Dateien sind bewusst ausgelassen. Nur Bitcoin, Ethereum, TRON. Der Stand altert, bis ihn jemand neu festlegt. |
| Spur, als Stimme in `ip_einordnung` | wäre die Stimme für Residential Proxies | Der kostenlose Zugang schliesst Strafverfolgung aus. | Kein Token, nicht geprüft. |
| Beleg von Hand (`tools/beleg.py`) | Eine Abklärung von Hand als Beleg `X-…`, hash-verkettet | | Der Dialog an einem echten Terminal ist nicht geprüft. |

Die Lücke im Ganzen: Keine der kostenlosen Quellen erkennt Residential Proxies zuverlässig. Deshalb gibt es den Wert
«kein Hinweis» und kein «nein», und der Rapport setzt bei jeder Empfehlung zu einer IP den passenden Vorbehalt.

## 4. Review

Die ganze Tabelle mit Datei, Zeile, Befund und Stand steht in [`REVIEW-2026-11.md`](REVIEW-2026-11.md). Sie hat 44 Befunde.

| Schwere | Befunde | behoben | entschärft | Vorschlag, nicht umgesetzt | Hinweis |
|---|---:|---:|---:|---:|---:|
| hoch | 8 | 7 | | 1 | |
| mittel | 22 | 19 | 2 | 1 | |
| tief | 14 | 10 | | 2 | 2 |

Nach Bereich: Schutzmechanismen 4, Schlüssel 7, Fremdinhalte 6, Gateway 6, Blockchain 7, Rapport und Protokoll 4,
IP-Einordnung 1, Einrichtung und Repo 7, Doku gegen Code 2.

Die acht Befunde der Schwere «hoch»:

| Befund | Stand |
|---|---|
| Der Schalter `AUFBAUPHASE` steht in der Datei, die er schützt, und auf `main`. Jeder Klon ist damit im Aufbau. | Vorschlag: ein Entwicklungsmodus. Entschieden am 17.11.2026: Der Wächter fällt ganz weg. |
| Die Schlüsseldatei war nur für das Lesewerkzeug gesperrt. Ein Shell-Befehl kam daran vorbei. | behoben |
| Das Gateway folgte Weiterleitungen mit allen Kopfzeilen. Ein anderer Host bekam so den Schlüssel. | behoben |
| Wiederholte ein Dienst den Schlüssel in anderer Schreibweise, stand er in Rohdatei, Protokoll und Fehlertext. | behoben |
| Bei Anmeldung nach «Basic» kannte das Gateway nur die verpackte Form des Schlüssels. | behoben |
| Rohdateien mit fremdem HTML waren im Ermittlungsprotokoll anklickbar und öffneten die Seite der Gegenseite. | behoben: `.html.txt` |
| Eine fremde Gegenstelle konnte das Gateway auf eine interne Adresse weiterleiten. | behoben, soweit an der Adresse erkennbar |
| `urlquery_einreichen` nahm `public` an. Eine URL aus einem Fall wäre für alle sichtbar gewesen. | behoben: nur noch «private», Schranke im Kern |

**Nicht geprüft im Review:** die gezielte Suche nach Umgehungen des Wächters. Der dafür gestartete Prüf-Agent wurde von
den Schutzmassnahmen des Modells angehalten, und ich habe die Suche nicht von Hand wiederholt.

## 5. Pseudonymisierung: Messwerte

Lauf vom 16.11.2026, an 240 erfundenen Rapporten und mit der **vorläufigen** Liste der Feldmarken. Massstab ist der
Anteil der Stellen mit Personendaten, die im Ergebnis stehen bleiben.

| | Stellen | nach Schicht 1 | nach 2 | nach 3, ohne Zutun | mit 5, Kandidaten bestätigt | mit 4, alle Namen eingegeben |
|---|---:|---:|---:|---:|---:|---:|
| Angaben, die in einem Feld stehen | 8718 | 5159 (59.2 %) | 0 | 0 | 0 | 0 |
| Angaben nur im Fliesstext | 1677 | 1592 (94.9 %) | 1580 (94.2 %) | 1172 (69.9 %) | 207 (12.3 %) | 85 (5.1 %) |
| davon Personen | 771 | 771 | 759 (98.4 %) | 759 (98.4 %) | 103 (13.4 %) | 1 (0.1 %) |
| davon Organisationen | 329 | 329 | 329 (100 %) | 329 (100 %) | 20 (6.1 %) | 0 |
| davon Ausweisnummern | 84 | 84 | 84 (100 %) | 84 (100 %) | 84 (100 %) | 84 (100 %) |

- Technische Indikatoren: 1875 im Prüfsatz, 0 verändert.
- Fehlalarme ohne Zutun: 26 von 9268 Ersetzungen (0.3 %), alle als Kontrollschild («ZH 2024»).
- Kandidaten der Schicht 5: 1021 vorgelegt, 785 richtig (76.9 %).
- Gegenprobe: Kennt das Werkzeug nur jede zweite Feldmarke, bleiben 3137 von 8718 Feld-Stellen stehen (36.0 %).
- Kontrolle an 240 weiteren Rapporten, die bei der Entwicklung nie angesehen wurden: Feld-Angaben 3 von 8527,
  Fliesstext 1252 von 1775 (70.5 %) ohne Zutun und 203 (11.4 %) mit bestätigten Kandidaten.

Was das heisst: Was in einem Feld steht, wird ersetzt. Wer nur im Fliesstext steht, wird von keiner Schicht von selbst
ersetzt und braucht den Menschen. Die Zahlen sind eine Obergrenze, keine Zusage für echte Rapporte: Prüfsatz und
Erkennung stammen vom selben Verfasser, und echte Rapporte wurden nicht verwendet.

## 6. Oberfläche: die Darsteller

Die ganze Tabelle je Werkzeug steht in [`OBERFLAECHE.md`](OBERFLAECHE.md) und im Pull Request 9. Ein Selbsttest hält
sie aktuell. Zusammengefasst: 67 Zeilen (Werkzeuge, bei Sammelwerkzeugen je Quelle), 105 Vorlagen, 4431 Angaben. Jede
Angabe ist einem benannten Feld zugeordnet oder steht unter «Weitere Angaben der Quelle». Keine geht verloren.

| Herkunft der Vorlage | Zeilen | Welche |
|---|---:|---|
| echte Antwort | 42 | alle übrigen |
| Form der echten Antwort, Inhalt erfunden | 9 | `abklaerung_von_hand`, `krypto_adresse_pruefen`, `onion_sperrliste`, `ransomware_aktuell`, `_gruppe`, `_iocs`, `_opfer`, `telegram_kanal`, `webcheck_passiv` |
| erfunden nach Dokumentation | 16 | `spur_kontext` und Spur in `ip_einordnung`, `shodan_dns`, `mastodon_konto`, `telegram_kanalinfo`, `_entitaet`, `_suche`, `urlquery_einreichen`, `_status`, `urlscan_einreichen`, `wayback_verlauf`, `_abruf`, `_sichern`, `webcheck_aktiv`, `robin_search`, `robin_scrape` |

Für die 16 Zeilen der letzten Gruppe ist nicht geprüft, ob der Darsteller zur echten Antwort passt. Passt er nicht,
stehen die Angaben unter «Weitere Angaben» und gehen nicht verloren. Ohne eigenen Darsteller, also nur mit dem
allgemeinen: die Einzelabfragen bei Etherscan, TronGrid und Tronscan und die Einzelabrufe bei urlscan.io.

## 7. Oberfläche: was läuft und was ungeprüft ist

**Läuft und ist geprüft** (Selbsttests und Durchgang im Browser, Chromium ohne Fenster, 16.11.2026):

- Lesen: Fallübersicht, Rapport mit Filtern, Graf, Zeitachse und Geldfluss, Datenblatt je Indikator, Beleg und
  Rohdatei, Suche, Dokumente, Arbeitsspur. 206 Ansichten des Musterfalls geöffnet, 219 Tabellen sortierbar, 0 Fehler in
  der Konsole, 0 Anfragen nach aussen.
- Jeder gezeigte Wert steht an der genannten Stelle der Rohdatei. Fremdinhalte erscheinen als Text.
- Anhang mit allen Datenblättern als HTML und PDF (94 Seiten für den Musterfall).
- Bedienen, gegen ein Programm, das Claude Code spielt: neuer Fall auf beiden Wegen, Freigaben, Rückfrage als Dialog,
  Beleg von Hand, Dokumente erzeugen, Kette prüfen, Zurückführen, Testknöpfe der Quellen.
- Schutz: Ändern nur mit dem Geheimnis des Starts, «nur lesen» ohne Terminal oder aus Claude Code, Klartext und
  Zuordnungstabelle ausserhalb des Projekts, der Wächter sperrt Bedienschicht und Ablage für Agenten.

**Nicht geprüft:**

- Die Steuerung mit dem echten Claude Code: die Form seiner Ausgabe, der Weg der Rückfrage, die Sperren in einer so
  gestarteten Sitzung. Den Probelauf hat die Sicherheitsprüfung der Entwicklungssitzung abgelehnt.
- Eine ganze Ermittlung aus der Oberfläche.
- Ein echter Arbeitsplatz unter Windows oder macOS (nur die CI), das automatische Öffnen des Browsers, Firefox und
  Safari, ein Bildschirmleser.
- Word- und PDF-Dokumente im Klartext-Weg, eine Testabfrage aus der Oberfläche gegen eine echte Quelle.
- Fälle mit mehr als rund 1000 Protokolleinträgen.

**Abrechnung:** Die Steuerung läuft über die Kommandozeile von Claude Code und damit über die Anmeldung des
Sachbearbeiters. Mit einem Abo zählt die Ermittlung gegen dessen Kontingent. Ist `ANTHROPIC_API_KEY` gesetzt, rechnet
Claude Code über die API ab. Die Seite «Bedienen» sagt vor dem Start, welcher Fall vorliegt.

## 8. Entscheide, die dir gehören

Jeweils mit Empfehlung. Die Begründung steht im genannten Pull Request.

**Vor dem Einsatz mit echten Fällen**

| Frage | Empfehlung | Wo |
|---|---|---|
| Aufbauphase beenden | Entschieden am 17.11.2026: Der Wächter fällt ganz weg, und mit ihm die Aufbauphase. Was das heisst, steht im README unter «Schutzmechanismen». | PR 7 |
| Probe mit dem echten Claude Code | Vor dem Mergen von Paket F laufen lassen. | PR 10 |
| Suche nach Umgehungen des Wächters | Ein Mensch oder ein Konto mit Freigabe für Sicherheitsprüfungen holt sie nach. | PR 7 |
| Liste der Feldmarken | Eintragen und neu messen. Erst dann ist Paket D abgeschlossen. | PR 8 |
| Shodan-Schlüssel | Ersetzen. | PR 5 |

**Bedingungen der Anbieter**

| Frage | Empfehlung | Wo |
|---|---|---|
| Spur, kostenloser Zugang | Nicht für Ermittlungen nutzen: Der Anbieter schliesst Strafverfolgung aus. | PR 6 |
| urlscan.io und urlquery: Die Bedingungen beider Dienste sprechen von persönlicher, nicht kommerzieller Nutzung | Beim Anbieter nachfragen oder ein bezahltes Konto nehmen, bevor echte Fälle laufen. | PR 6, `QUELLEN.md` |
| proxycheck.io nennt weder Firma noch Sitz | Als zweite Stimme behalten, nie als alleinige Grundlage. | PR 6 |
| eth-labels | Nicht einbauen: Die Daten stammen aus Etherscan, dessen Bedingungen das untersagen. | PR 6 |
| Echte Antworten als Vorlagen im Repo | Wird das Repo öffentlich: die Bedingungen von VirusTotal, Shodan, AbuseIPDB, urlquery und urlscan.io dazu lesen. Sonst durch erfundene Werte in gleicher Form ersetzen. | PR 9 |
| Vornamenliste des BFS im Repo | Einbauen, mit Quelle, Ausgabe und Datum im Kopf. Im Zweifel beim BFS nachfragen. | PR 8 |
| Abo oder API für die Bedienung | Für eine Dienststelle ein Team- oder Enterprise-Abo oder die API, dazu eine kurze Nachfrage bei Anthropic. | PR 10 |

**Schutz und Nachvollziehbarkeit**

| Frage | Empfehlung | Wo |
|---|---|---|
| Rohdateien von ransomware.live: die E-Mail-Adresse des eigenen Kontos steht als `***` | So lassen. Es ist eine bewusste Abweichung von «Rohdaten unverändert», der Protokolleintrag vermerkt sie. | PR 5 |
| Zählt ein Beleg von Hand für «hoch»? | Nur, wenn er eine andere Quelle nennt als die Abfragen. | PR 7 |
| Mischdienst schlägt Dienst, wenn Liste und Abfragequelle sich widersprechen | So lassen. Es ist die vorsichtigere Lesart. | PR 6 |
| Verschärfte Telefon-Erkennung in der PII-Prüfung | Behalten. | PR 8 |
| «ZH 2024» gilt als Kontrollschild | So lassen: lieber einmal zu viel ersetzen. | PR 8 |
| Freigaben per Klick in der Oberfläche | So verlangt es der Auftrag. Grundsatz 6 in `CLAUDE.md` ist dafür geändert, bitte ansehen. | PR 10 |
| Ablage für Klartext und Zuordnungstabellen | Ein verschlüsseltes Laufwerk, und `OSINT_ABLAGE` dauerhaft setzen. | PR 10 |
| Oberfläche ohne Anmeldung zum Lesen | So lassen und nur am Arbeitsplatz des Sachbearbeiters starten. | PR 9 |
| Grenze des Geheimnisses der Bedienung | Annehmen: Ein Programm mit den Rechten des Benutzers hält es nicht auf. | PR 10 |
| Künftige Vorgabe von Claude Code für den Skriptbetrieb | Abwarten. Die Oberfläche bricht ab, statt ohne Wächter zu arbeiten. | PR 10 |

**Repo**

| Frage | Empfehlung | Wo |
|---|---|---|
| Lizenz | EUPL-1.2 oder Apache-2.0. Heute gibt es keine `LICENSE`. | PR 7 |
| Sperrdatei für Abhängigkeiten mit Prüfsummen | Ja. Sie ändert den Weg für Aktualisierungen. | PR 7 |
| Massenlisten der Etiketten (rund 12 MB) | Nicht ins Repo. Wer sie will, lädt sie mit einem Befehl. | PR 6 |
| Bilder und `muster/Datenblaetter.pdf` (rund 2,5 MB, ändert sich bei jeder Änderung am Stil) | Bilder behalten. Das PDF nur, wenn du es als Muster zeigen willst. | PR 9 |
| Gewollter Widerspruch im Musterfall (Registrar) | Behalten, er zeigt die Markierung im Datenblatt. | PR 9 |
| Berechtigung für `tools/anhang.py` | Wie `tools/rapport.py` erlauben. Die Oberfläche bleibt beim Sachbearbeiter. | PR 9 |
| Alte Branches | Löschen, was in `main` aufgegangen ist. | PR 7 |
| Lokales Sprachmodell für die Pseudonymisierung | Erst entscheiden, wenn mit euren Feldmarken gemessen ist. | PR 8 |
| Dieser Bericht im Repo | Er steht in einem eigenen Commit und lässt sich weglassen. | PR 10 |
