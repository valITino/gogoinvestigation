# Die Oberfläche

Die Oberfläche zeigt alle Ergebnisse eines Falls an einem Ort: den Rapport, jedes Datenblatt, jeden Beleg und jede
Rohdatei. Abschlussrapport und Ermittlungsprotokoll bleiben die Dokumente für die Akte. Die Oberfläche ersetzt sie
nicht, sie macht sie durchsuchbar und nachprüfbar.

Sie hat zwei Teile. Die **Ansichten** lesen die Fallakte und schreiben nie. Die **Bedienung** lässt den Sachbearbeiter
ohne Terminal arbeiten: Akten hochladen, Fall anlegen, im Chat Vorgaben geben und der Ermittlung zusehen, freigeben,
Ergebnisse herunterladen. Sie ändert die Fallakte nicht selbst, sondern ruft die bestehenden Werkzeuge auf, und nur für
den, der die Oberfläche am Terminal gestartet hat.

Stand: 17.11.2026.

## Start

```bash
python3 tools/oberflaeche.py                     # Linux, macOS
python tools\oberflaeche.py                      # Windows
python3 tools/oberflaeche.py MUSTER-2026-001     # öffnet gleich diesen Fall
python3 tools/oberflaeche.py --port 9000         # anderer Port (Vorgabe 8765, sonst der nächste freie)
python3 tools/oberflaeche.py --ohne-browser      # nur den Server starten, die Adresse steht im Terminal
python3 tools/oberflaeche.py --selbstpruefung    # kurz starten, Hauptseiten abrufen, wieder beenden
```

Der Befehl startet einen kleinen Server in Python und öffnet den Browser. Der Server braucht nur die
Standardbibliothek, keine Bauschritte und kein Internet. Beendet wird er mit Strg+C im Terminal.

## Aufbau

| Bereich | Inhalt |
|---|---|
| Links: Navigation | Fälle, «Neuer Fall», der geöffnete Fall (Fallübersicht, Akten, Ermittlung, Rapport, Indikatoren, Rohdaten, Suche, Ergebnisse, Bedienen), Quellen. «Neuer Fall», «Ermittlung» und «Bedienen» erscheinen nur, wenn die Oberfläche bedienbar ist. Darunter der Schalter Hell / Dunkel. |
| Oben: Kopf des Falls | Fall-ID, Titel, Freigaben (erteilt oder nicht, durch wen, wann) und die Schrittleiste. |
| Schrittleiste | Fall angelegt, Indikatoren, Plan, Abfragen, Gegenprüfung, Rapport. Jeder Schritt sagt, woran die Oberfläche ihn erkennt (zum Beispiel «12 von 13 Befunden gegengeprüft»). Fehlt ein Schritt in der Akte, steht «nicht abgelegt». |
| Mitte | Die Ansichten, siehe unten. |
| Rechts: Arbeitsspur | Das Abfrageprotokoll, laufend nachgeführt (alle drei Sekunden). Filter: Abfragen, «kein Treffer», Fehlschläge, Auswertungen, Freigaben. Darunter Zahl der Einträge und Stand der Protokollkette. |
| Rechts unten: Chat | Nur bedienbar: der Chat mit der Ermittlung, klein und einklappbar. In der Ansicht «Ermittlung» steht er gross in der Mitte. |
| Über allem: Rückfrage | Nur bedienbar: Braucht Claude Code eine Zustimmung, erscheint ein Fenster, in jeder Ansicht. |

Jede Ansicht hat eine feste Adresse. Sie lässt sich als Lesezeichen ablegen und weitergeben, solange die Oberfläche
auf demselben Rechner läuft:

| Adresse | Ansicht |
|---|---|
| `#/` | Liste der Fälle |
| `#/fall/<Fall-ID>` | Fallübersicht |
| `#/fall/<Fall-ID>/rapport` und `…/rapport/B-03` | Rapport, auf Wunsch an einem Befund |
| `#/fall/<Fall-ID>/indikatoren` | Liste der Indikatoren |
| `#/fall/<Fall-ID>/indikator/I-03` | Datenblatt eines Indikators |
| `#/fall/<Fall-ID>/beleg/P-0007` | Ein Beleg: Protokolleintrag und Antwort der Quelle, geordnet |
| `#/fall/<Fall-ID>/roh/P-0007` | Die Rohdatei zu einem Beleg |
| `#/fall/<Fall-ID>/rohdaten` | Alle Rohdateien |
| `#/fall/<Fall-ID>/suche/<Suchtext>` | Suche über den ganzen Fall |
| `#/fall/<Fall-ID>/ergebnisse` und `…/dokument/Abschlussrapport` | Ergebnisse: Unterlagen ansehen und herunterladen |
| `#/fall/<Fall-ID>/akten` | Was im Eingang des Falls liegt. Bedienbar: dazu der Akten-Eingang für weitere Dokumente |
| `#/neu`, `#/fall/<Fall-ID>/ermittlung`, `…/bedienen`, `…/zurueck` | Bedienung, siehe dort |
| `#/quellen` | Verzeichnis der Quellen und Begriffe |

Jede Tabelle lässt sich sortieren (Klick auf die Spaltenüberschrift), filtern (Feld über der Tabelle) und als CSV
ausgeben. Jede Ansicht lässt sich drucken: Navigation, Arbeitsspur und Bedienelemente fallen im Druck weg.
Die Oberfläche ist mit der Tastatur bedienbar und folgt der hellen oder dunklen Einstellung des Systems.

## Ansichten

### 1. Fallübersicht

Kennzahlen (Indikatoren, Abfragen, Quellen, Befunde, Antworten aus dem Fall-Cache, aktive Massnahmen), der Stand der
Schritte, die offenen Punkte und die Abdeckung: eine Tabelle Indikator × Quelle. Jede Zelle zeigt einen von sieben
Zuständen, als Zeichen und als Wort:

| Zustand | Bedeutung |
|---|---|
| Treffer | Die Quelle hat etwas geliefert. |
| kein Treffer | Die Quelle wurde gefragt und kennt den Indikator nicht. Das ist ein Ergebnis. |
| Fehlschlag | Die Abfrage ist gescheitert. Die Quelle wurde also nicht geprüft. |
| abgelehnt | Die Abfrage wurde nicht ausgeführt, zum Beispiel weil eine Freigabe fehlt. |
| nicht abgefragt | Die Quelle passt zum Indikator, wurde aber nicht gefragt. |
| Quelle nicht eingerichtet | Der Schlüssel der Quelle fehlt an diesem Arbeitsplatz. |
| passt nicht | Die Quelle sagt zu dieser Art von Indikator nichts. |

Ein Klick auf eine Zelle führt zum Beleg, auch bei «kein Treffer» und Fehlschlag.

Die Kennzahlen kommen aus denselben Funktionen wie im Abschlussrapport und im Ermittlungsprotokoll
(`tools/rapport.py`, `kennzahlen`, und `tools/protokoll.py`, `kennzahlen`). Die Oberfläche rechnet nichts ein zweites Mal.

### 2. Rapport

Derselbe Inhalt, dieselbe Reihenfolge und derselbe Wortlaut wie der Abschlussrapport: Die Oberfläche ruft denselben
Generator mit derselben `befunde.json` auf. Dazu kommt:

- Jeder Beleg ist ein Verweis auf den Protokolleintrag und von dort auf die Rohdatei.
- Die Befunde lassen sich filtern: nach Sicherheitsstufe, nach Indikator, nach Analyst.
- Der Beziehungsgraf lässt sich verschieben und vergrössern. Ein Knoten führt zum Datenblatt, Knoten lassen sich nach Art ausblenden.
- Die Zeitachse lässt sich auf einen Zeitraum einengen.
- Im Geldfluss führt jede Station zu ihren Einzelheiten.
- Über dem Rapport steht, ob der gespeicherte Abschlussrapport der Akte noch zum Stand der Daten passt.

### 3. Datenblatt je Indikator

Alles, was irgendeine Quelle zu diesem Indikator geliefert hat, in festen Abschnitten. Die Reihenfolge ist je Art
des Indikators immer dieselbe:

| Art | Abschnitte in dieser Reihenfolge |
|---|---|
| IP-Adresse | Einordnung · Netz und Inhaber · Standort · Dienste und Ports · Zertifikate · Domains auf der Adresse · Ruf und Meldungen · Geschichte · Verwandte Indikatoren |
| Domain | Registrierung · DNS · Zertifikate · Hosting · Inhalt der Seite · Ruf und Sperrlisten · Geschichte · Verwandte Indikatoren |
| URL | Inhalt der Seite · Hosting · Zertifikate · Ruf und Sperrlisten · Geschichte · Verwandte Indikatoren |
| Datei-Hash | Datei · Erkennung · Geschichte · Verwandte Indikatoren |
| Wallet-Adresse | Prüfung der Adresse · Guthaben und Bewegungen · Zuordnung · Geldfluss · Geschichte · Verwandte Indikatoren |
| Transaktion | Transaktion · Geldfluss · Zuordnung · Geschichte |
| Gruppe | Profil · Leak-Seiten und Werkzeuge · Opfer · Indikatoren der Gruppe · Geschichte |
| Onion-Adresse | Sperrliste · Inhalt · Geschichte |
| Konto | Stammdaten · Geschichte |
| E-Mail-Adresse | Domain der Adresse · Ruf und Sperrlisten · Geschichte |
| Sonstiges | Angaben der Quellen |

Danach folgen bei jedem Indikator «Befragte Quellen», «Befunde, die den Indikator nennen» und, wenn vorhanden,
«Beziehungen laut Team».

Jede Angabe trägt vier Dinge: die Quelle, die Abfragezeit, den Beleg und die Stelle in der Rohdatei
(zum Beispiel `/data/attributes/country`). Mit dem Beleg und der Stelle lässt sich jeder Wert in der Rohdatei nachschlagen.

- **Keine Angabe.** Hat keine Quelle zu einem Abschnitt etwas geliefert, steht «keine Angabe», und dahinter, welche
  Quellen gefragt wurden, mit Ergebnis und Beleg.
- **Widerspruch.** Nennen zwei Quellen für dasselbe Feld Verschiedenes, steht «Widerspruch» dabei. Verglichen werden
  einzelne Werte: Zahlen als Zahl (AS64500 und 64500 sind dasselbe), Zeiten als Zeitpunkt, Texte ohne Gross- und
  Kleinschreibung und ohne Satzzeichen. Steckt der eine Text ganz im andern («Beispiel Hosting AG» und
  «BEISPIEL-HOSTING - Beispiel Hosting AG, NL»), gilt das als Übereinstimmung. Nicht verglichen werden Listen (jede
  Quelle sieht einen Ausschnitt) und die Beobachtungszeiten im Abschnitt «Geschichte» (jede Quelle hat ihre eigenen).
  Die Oberfläche markiert den Widerspruch. Sie entscheidet nicht, wer recht hat.
- **Bewertung des Teams.** Die Einstufung des Indikators (bösartig, verdächtig, unauffällig) ist als Bewertung des
  Teams gekennzeichnet. Alles darunter sind Angaben der Quellen.

### 4. Rohdaten

Je Abfrage der Protokolleintrag, die Rohdatei, ihre Grösse, ihre Prüfsumme und die Auskunft, ob sie noch zur
Protokollkette passt. JSON steht als Baum zum Aufklappen da, HTML und DOM als Text, Bilder als Bild, CSV als Tabelle.
Eine Rohdatei, die nach der Abfrage verändert wurde, ist rot markiert: in der Ansicht, in der Fallübersicht und in der Arbeitsspur.

### 5. Suche

Sucht im ganzen Fall: Indikatoren, Befunde, Protokoll (Quelle, Werkzeug, Ziel, Zweck, Fehlermeldung) und den Inhalt
der Rohdateien. Gross- und Kleinschreibung spielen keine Rolle.

### 6. Ergebnisse

Abschlussrapport, Ermittlungsprotokoll und Datenblätter: ansehen, als HTML und PDF herunterladen, dazu
`indikatoren.csv`, `Ermittlungsprotokoll.csv` und `befunde.json`. Bei jedem Dokument steht, ob es dem Stand der Daten
entspricht oder älter ist und warum («seit der Erzeugung kamen 3 Protokolleinträge dazu», «befunde.json wurde seit der
Erzeugung geändert»). Alles zusammen gibt es als Archiv, siehe «Ergebnisse und Archiv» unter «Bedienung». Die frühere
Ansicht «Dokumente» gibt es unter ihrer Adresse weiter.

### 7. Akten

Was im Eingang des Falls liegt: jedes Dokument mit dem Stand der PII-Prüfung (geprüft, übersteuert, nicht geprüft) und
der Grösse. Im Modus «nur lesen» ist das alles. Bedienbar steht darüber der Akten-Eingang, siehe «Bedienung».

## Darsteller: Wie aus einer Rohantwort eine Ansicht wird

Jedes Werkzeug des Gateways hat einen Darsteller (`tools/ui/darsteller.py`). Er ordnet die Rohantwort festen
Abschnitten und benannten Feldern zu. Ein Darsteller ist eine Beschreibung, kein Programm: Er nennt je Feld den
Namen, den Ort in der Antwort (`data.attributes.country`), die Art (Text, Zahl, Zeit, Grösse, ja/nein, Liste) und,
wo nötig, die Einheit und eine Erklärung in einfachen Worten.

Was ein Darsteller nicht kennt, geht nicht verloren. Es steht unter **«Weitere Angaben der Quelle»** als Baum zum
Aufklappen, mit denselben Angaben zur Stelle. Für ein Werkzeug ohne eigenen Darsteller steht die ganze Antwort dort
(allgemeiner Darsteller). Ändert eine Quelle die Form ihrer Antwort, wandern die betroffenen Angaben also unter
«Weitere Angaben», statt zu verschwinden.

### Regeln der Darstellung

Diese Regeln prüfen die Selbsttests (`python3 tools/selbsttest.py`):

1. **Vollständig.** Für jedes Werkzeug liegt eine Rohantwort als Vorlage im Repo (`tools/ui/vorlagen/`). Ein
   Selbsttest zählt je Vorlage die Angaben der Rohantwort und prüft, dass jede in der Ansicht erscheint: zugeordnet
   oder unter «Weitere Angaben».
2. **Genau.** Ein Selbsttest prüft für jeden gezeigten Wert, dass er dem Wert an der genannten Stelle der Rohdatei entspricht.
3. **Gekürzt wird nur die Anzeige.** Lange Werte stehen eingeklappt da, der ganze Wert ist einen Klick entfernt. Bei
   sehr langen Werten (über 4000 Zeichen) zeigt die Oberfläche den Anfang, nennt die Länge und verweist auf die Rohdatei.
4. **Zahlen ohne Rundung.** Eine Zahl steht so da, wie die Quelle sie liefert. Ganze Zahlen ab fünf Stellen bekommen
   das Tausenderzeichen (12'345), sonst ändert sich nichts.
5. **Zeiten in der Zeitzone des Arbeitsplatzes**, der Wert der Quelle steht als «Original» daneben.
6. **Einheiten stehen dabei** (Bytes, Satoshi, «von 100»).
7. **«Kein Treffer», Fehlschläge und nicht Geprüftes** sind so sichtbar wie Treffer: als Zeichen und als Wort, in der
   Abdeckung, im Datenblatt und in der Arbeitsspur.
8. **Fall-Cache.** Kam eine Antwort aus der Fallakte statt von der Quelle, steht das dabei, mit Beleg und Zeit der
   ursprünglichen Abfrage. Im Datenblatt stehen solche Werte nicht doppelt.
9. **Feststellung, Bewertung und Hypothese** sehen verschieden aus und sind beim Namen genannt.
10. **Einheitliche Begriffe**, mit Erklärung in einfachen Worten (Fragezeichen neben dem Feld, Liste unter «Quellen»).

### Die Darsteller und ihre Vorlagen

Die Tabelle nennt je Werkzeug, ob es einen eigenen Darsteller hat, wie viele Angaben die Vorlage enthält, wie viele
davon einem benannten Feld zugeordnet sind und wie viele unter «Weitere Angaben» stehen. Letzte Spalte: woher die Vorlage stammt.

- **Echte Antwort:** Antwort der Quelle auf einen öffentlich bekannten Testwert (8.8.8.8, 1.1.1.1, example.com, der Hash
  der EICAR-Testdatei, ein öffentlich gelisteter Tor-Ausgang, bekannte Adressen aus der Blockchain), abgefragt über das
  Gateway. Listen sind auf zwei Einträge gekürzt. E-Mail-Adressen, Telefonnummern, Namen von Kontaktpersonen und
  Regelautoren sowie freie Texte Dritter sind ersetzt. Bei Antworten über Seiten Dritter (urlquery, Suche bei
  urlscan.io) sind auch Hostnamen, IP-Adressen und Kennungen ersetzt. Die Form ist unverändert.
- **Inhalt erfunden, Form der echten Antwort:** Die Form stammt aus einer echten Antwort, die in der Prüfung gesehen
  wurde, der Inhalt ist erfunden. So bei ransomware.live (echte Antworten nennen Opfer beim Namen), bei den passiven
  Prüfungen von Web-Check, beim Kanal auf Telegram und bei der Sperrliste von Ahmia.
- **Erfunden nach Dokumentation:** Für diese Werkzeuge lag keine echte Antwort vor. Die Vorlage folgt der Dokumentation
  der Quelle. Das betrifft die aktiven Massnahmen (nie ausgelöst), die Abfragen mit Personenbezug, die Werkzeuge ohne
  Schlüssel (Spur, Telegram über RapidAPI, Shodan-DNS), die Wayback Machine (am Prüftag nicht erreichbar) und Robin
  (Dark Web). **Ob diese Darsteller zur echten Antwort passen, ist nicht geprüft.** Passen sie nicht, stehen die
  Angaben unter «Weitere Angaben».

`fall_status` hat keine Vorlage: Es fragt keine Quelle ab und hinterlässt keinen Protokolleintrag.

<!-- darsteller:anfang -->
| Werkzeug | Eigener Darsteller | Angaben in der Vorlage | zugeordnet | unter «Weitere Angaben» | Vorlage |
|---|---|---:|---:|---:|---|
| `abklaerung_von_hand` | ja | 13 | 13 | 0 | Inhalt erfunden, Form der echten Antwort |
| `abuseipdb_meldungen` | ja | 19 | 17 | 2 | echte Antwort |
| `abuseipdb_pruefen` | ja | 28 | 28 | 0 | echte Antwort |
| `chan_katalog` | ja | 133 | 49 | 84 | echte Antwort |
| `chan_thread` | ja | 36 | 17 | 19 | echte Antwort |
| `ip_abruf (AbuseIPDB)` | ja | 14 | 14 | 0 | echte Antwort |
| `ip_abruf (RIPEstat)` | ja | 42 | 9 | 33 | echte Antwort |
| `ip_abruf (Spur)` | ja | 20 | 13 | 7 | erfunden nach Dokumentation |
| `ip_abruf (ipapi.is)` | ja | 52 | 26 | 26 | echte Antwort |
| `ip_abruf (proxycheck.io)` | ja | 59 | 37 | 22 | echte Antwort |
| `ip_einordnung` | ja | 138 | 49 | 89 | echte Antwort |
| `krypto_abruf (Blockscout)` | ja | 20 | 12 | 8 | echte Antwort |
| `krypto_abruf (Blockstream)` | ja | 28 | 13 | 15 | echte Antwort |
| `krypto_abruf (Chainabuse)` | ja | 23 | 23 | 0 | echte Antwort |
| `krypto_abruf (DefiLlama)` | ja | 15 | 15 | 0 | echte Antwort |
| `krypto_abruf (Etherscan)` | nein (allgemeiner) | 26 | 0 | 26 | echte Antwort |
| `krypto_abruf (Ransomwhere)` | ja | 30 | 18 | 12 | echte Antwort |
| `krypto_abruf (TRM Labs)` | ja | 4 | 4 | 0 | echte Antwort |
| `krypto_abruf (TronGrid)` | nein (allgemeiner) | 34 | 0 | 34 | echte Antwort |
| `krypto_abruf (Tronscan)` | nein (allgemeiner) | 141 | 0 | 141 | echte Antwort |
| `krypto_abruf (WalletExplorer)` | ja | 4 | 4 | 0 | echte Antwort |
| `krypto_abruf (mempool.space)` | ja | 29 | 13 | 16 | echte Antwort |
| `krypto_adresse` | ja | 37 | 32 | 5 | echte Antwort |
| `krypto_adresse_pruefen` | ja | 12 | 9 | 3 | Inhalt erfunden, Form der echten Antwort |
| `krypto_geldfluss` | ja | 158 | 76 | 82 | echte Antwort |
| `krypto_kurs` | ja | 22 | 15 | 7 | echte Antwort |
| `krypto_transaktion` | ja | 36 | 30 | 6 | echte Antwort |
| `krypto_transaktionen` | ja | 49 | 40 | 9 | echte Antwort |
| `krypto_zuordnung` | ja | 29 | 22 | 7 | echte Antwort |
| `mastodon_instanz` | ja | 140 | 13 | 127 | echte Antwort |
| `mastodon_konto` | ja | 15 | 13 | 2 | erfunden nach Dokumentation |
| `onion_sperrliste` | ja | Text | – | – | Inhalt erfunden, Form der echten Antwort |
| `ransomware_aktuell` | ja | 59 | 32 | 27 | Inhalt erfunden, Form der echten Antwort |
| `ransomware_gruppe` | ja | 285 | 243 | 42 | Inhalt erfunden, Form der echten Antwort |
| `ransomware_iocs` | ja | 8 | 6 | 2 | Inhalt erfunden, Form der echten Antwort |
| `ransomware_opfer` | ja | 64 | 37 | 27 | Inhalt erfunden, Form der echten Antwort |
| `robin_scrape` | ja | 3 | 3 | 0 | erfunden nach Dokumentation |
| `robin_search` | ja | 8 | 8 | 0 | erfunden nach Dokumentation |
| `shodan_dns` | ja | 13 | 13 | 0 | erfunden nach Dokumentation |
| `shodan_host` | ja | 86 | 22 | 64 | echte Antwort |
| `shodan_internetdb` | ja | 8 | 8 | 0 | echte Antwort |
| `shodan_suche` | ja | 14 | 13 | 1 | echte Antwort |
| `spur_kontext` | ja | 20 | 13 | 7 | erfunden nach Dokumentation |
| `telegram_entitaet` | ja | 7 | 7 | 0 | erfunden nach Dokumentation |
| `telegram_kanal` | ja | Text | – | – | Inhalt erfunden, Form der echten Antwort |
| `telegram_kanalinfo` | ja | 6 | 6 | 0 | erfunden nach Dokumentation |
| `telegram_suche` | ja | 8 | 8 | 0 | erfunden nach Dokumentation |
| `urlquery_bericht` | ja | 428 | 51 | 377 | echte Antwort |
| `urlquery_einreichen` | ja | 5 | 5 | 0 | erfunden nach Dokumentation |
| `urlquery_reputation` | ja | 3 | 3 | 0 | echte Antwort |
| `urlquery_status` | ja | 4 | 4 | 0 | erfunden nach Dokumentation |
| `urlquery_suche` | ja | 188 | 23 | 165 | echte Antwort |
| `urlscan_abruf (urlscan.io)` | nein (allgemeiner) | 506 | 0 | 506 | echte Antwort |
| `urlscan_einreichen` | ja | 10 | 6 | 4 | erfunden nach Dokumentation |
| `urlscan_ergebnis` | ja | 77 | 56 | 21 | echte Antwort |
| `urlscan_kontingent` | ja | 50 | 47 | 3 | echte Antwort |
| `urlscan_suche` | ja | 83 | 28 | 55 | echte Antwort |
| `virustotal_beziehungen` | ja | 38 | 14 | 24 | echte Antwort |
| `virustotal_datei` | ja | 156 | 56 | 100 | echte Antwort |
| `virustotal_domain` | ja | 222 | 55 | 167 | echte Antwort |
| `virustotal_ip` | ja | 278 | 42 | 236 | echte Antwort |
| `virustotal_url` | ja | 74 | 46 | 28 | echte Antwort |
| `wayback_abruf` | ja | Text | – | – | erfunden nach Dokumentation |
| `wayback_sichern` | ja | 4 | 4 | 0 | erfunden nach Dokumentation |
| `wayback_verlauf` | ja | 18 | 18 | 0 | erfunden nach Dokumentation |
| `webcheck_aktiv` | ja | 163 | 132 | 31 | erfunden nach Dokumentation (27 Prüfungen) |
| `webcheck_passiv` | ja | 129 | 96 | 33 | Inhalt erfunden, Form der echten Antwort (13 Prüfungen) |
<!-- darsteller:ende -->

Die Tabelle je einzelner Vorlage (auch je Prüfung von Web-Check) gibt `python3 tools/ui/pruefstand.py` aus.
Woher jede Vorlage stammt, steht in `tools/ui/vorlagen/verzeichnis.json`.

### Einen Darsteller ergänzen

1. In `tools/ui/darsteller.py` die Beschreibung eintragen: Abschnitte (`A`), Felder (`F`), Tabellen (`T`).
2. Feldern, die ins Datenblatt gehören, einen Schlüssel geben (`s="netz.as"`). Der Teil vor dem Punkt bestimmt den Abschnitt (`tools/ui/blaetter.py`).
3. Eine Rohantwort als Vorlage unter `tools/ui/vorlagen/` ablegen und in `verzeichnis.json` eintragen: ohne Angaben zu Personen, mit Herkunft.
4. `python3 tools/ui/pruefstand.py --kurz` ausführen und die Tabelle oben ersetzen. `python3 tools/selbsttest.py` prüft Vollständigkeit und Genauigkeit.

## Schutz

| Schutz | Wie er umgesetzt ist |
|---|---|
| Nur dieser Rechner | Der Server hört nur auf 127.0.0.1. Anfragen mit fremdem Host-Kopf weist er ab (Schutz davor, dass eine fremde Website den Browser auf die Oberfläche lenkt), ebenso Anfragen fremder Herkunft. |
| Ansichten lesen nur | Lesen geht mit GET und HEAD. In der Datenschicht und in den Ansichten gibt es keinen Aufruf, der eine Datei anlegt, ändert oder löscht. Ein Selbsttest vergleicht die Fallakten vor und nach dem Abruf aller Adressen. Ändern geht nur über die Bedienung, siehe dort. |
| Fremdinhalte sind Text | Alles, was aus einer Quelle stammt, wird als Text ausgegeben und nie als HTML ausgeführt: Werte, Schlüssel, Ziele, Zweck, Fehlermeldungen, Seitentexte. Rohdateien liefert der Server als `text/plain` oder als Bild, nie als HTML. |
| Bilder nur aus den Rohdaten | Ein Bild erscheint nur, wenn es als Datei in den Rohdaten des gezeigten Falls liegt. Eine fremde Bildadresse in einer Antwort ergibt Text, kein Bild. |
| Nichts von aussen | Eine Content-Security-Policy erlaubt Skripte, Stile, Bilder und Abrufe nur vom eigenen Server. Es gibt eine Skriptdatei (`app.js`), keine Bibliothek, keine Schrift und kein Bild von aussen. Die Oberfläche läuft ohne Internet. |
| Adressen aus dem Fall | URLs, Domains und Onion-Adressen aus dem Fall stehen als Text da und sind nie anklickbar. Verweise führen nur in die Oberfläche selbst. |
| Gespeicherte Dokumente | Der Abschlussrapport der Akte läuft in einem Rahmen ohne Skripte (Sandbox). |
| Platzhalter | `[PERSON_01]` und die übrigen Platzhalter bleiben, wie sie sind. Die Oberfläche löst nichts auf und kennt keine Zuordnungstabelle. |
| CSV | Beginnt eine Zelle mit `=`, `+`, `-` oder `@`, setzt die Ausgabe ein Hochkomma davor, damit eine Tabellenkalkulation sie nicht als Formel liest. |

Zum Lesen hat die Oberfläche keine Anmeldung. Wer am Rechner angemeldet ist und den Port erreicht, sieht die Fälle. Sie
gehört deshalb auf den Arbeitsplatz des Sachbearbeiters und nicht auf einen Server, den mehrere Personen teilen.

## Bedienung

Mit der Bedienung arbeitet der Sachbearbeiter ohne Terminal: Akten hineinziehen, wo nötig nochmals pseudonymisieren,
Fall anlegen, Vorgaben geben, der Ermittlung zusehen, Rückfragen beantworten, Ergebnisse ansehen und herunterladen.
Ein Terminal braucht es nur noch für den Start.

### Wann die Oberfläche bedienbar ist

```bash
python3 tools/oberflaeche.py                  # am Terminal gestartet: bedienbar aus dem Fenster, das sich öffnet
python3 tools/oberflaeche.py --nur-lesen      # nur ansehen
python3 tools/oberflaeche.py --ablage /sicher/osint   # Ablage für Klartext und Zuordnungstabellen (Vorgabe: OSINT_ABLAGE, sonst OSINT-Ablage im Benutzerordner)
```

Beim Start entsteht ein **Geheimnis**. Es liegt nur im Speicher des Servers und im Browserfenster, das sich beim Start
öffnet. Der Server gibt dem Fenster dafür einen Startcode in der Adresse mit. Das Fenster tauscht ihn sofort gegen das
Geheimnis, danach gilt der Code nicht mehr und steht nicht mehr in der Adresse. Ohne das Geheimnis ändert keine Anfrage
etwas. Es steht in keiner Datei des Projekts und nicht in der Umgebung der Sitzungen, die der Server startet.

Die Oberfläche läuft im Modus **«nur lesen»**, wenn sie ohne Terminal gestartet wird, aus Claude Code heraus oder mit
`--nur-lesen`. Dann gibt es kein POST, und die Seiten zeigen keine Formulare. Ein Agent, der die Oberfläche selbst
startet, bekommt so kein Geheimnis in die Hand. Ein zweites Browserfenster kann lesen, aber nicht bedienen: Es sieht
weder den Akten-Eingang noch den Chat.

### Der Ablauf

| Schritt | Wo | Was geschieht |
|---|---|---|
| 1. Akten hineinziehen | «Neuer Fall» | Dateien, ein Ordner oder ein ZIP. Jede Datei wird sofort gelesen und auf Personendaten geprüft. In einen Fall kommt noch nichts. |
| 2. Nachbessern | lokaler Bildschirm | Was die erste Pseudonymisierung übersehen hat, wird ersetzt: auf dem eigenen Rechner, ohne Sprachmodell. |
| 3. Fall anlegen | «Neuer Fall» | Fall-ID und Titel. In den Fall kommt die Textfassung dessen, was die PII-Prüfung besteht. |
| 4. Ermitteln | «Ermittlung» | Pflichtquellen anwählen, wenn gewünscht. Vorgaben in den Chat, starten, zusehen. Nachrichten jederzeit, Rückfragen als Fenster. |
| 5. Ergebnisse holen | «Ergebnisse» | Ansehen, einzeln herunterladen oder alles als ein Archiv, samt Sitzungsprotokoll. |
| 6. Zurückführen | «Bedienen» | Der Rapport mit echten Angaben, lokal, mit der Zuordnungstabelle. |

### Akten-Eingang

Der Akten-Eingang nimmt den Rapport und seine Beilagen auf, bevor es einen Fall gibt («Neuer Fall»), und weitere
Dokumente zu einem bestehenden Fall («Akten»). Hineinziehen lassen sich einzelne Dateien, mehrere auf einmal, ein ganzer
Ordner mit Unterordnern oder ein ZIP. Die Knöpfe «Dateien wählen» und «Ordner wählen» tun dasselbe.

Was hochgeladen ist, liegt im Speicher der Oberfläche und nirgends sonst, bis es in einen Fall aufgenommen oder entfernt
wird. Wird die Oberfläche beendet, ist der Akten-Eingang leer.

| Format | Wie es gelesen wird |
|---|---|
| Text: `.txt`, `.md`, `.csv`, `.json`, `.xml`, `.html`, `.log` und ähnliche | als Text (UTF-8, UTF-16 mit Kennung) |
| Word `.docx`, OpenDocument `.odt` `.ods` `.odp`, Excel `.xlsx`, PowerPoint `.pptx`, `.rtf` | der Text des Dokuments, ohne Zusatzpakete. Aus Tabellen wird je Blatt eine Tabelle mit Tabulatoren, aus Folien je Folie ein Abschnitt samt Notizen. |
| PDF | mit `pdftotext` (die Einrichtung installiert es). Ein gescanntes PDF ohne Text gilt als nicht lesbar. |
| E-Mail `.eml` | Kopfzeilen (Von, An, Kopie, Datum, Betreff, Message-ID), Namen der Anhänge und der Text. Jeder Anhang wird ein eigenes Dokument. |
| ZIP | wird entpackt, auch ein ZIP im ZIP (zwei Ebenen). Was Betriebssysteme hineinlegen (`__MACOSX`, `.DS_Store`), zählt nicht. Einträge mit Passwort bleiben draussen und werden genannt. |
| Bilder, Ton, Video, `.doc`, `.xls`, `.ppt`, `.msg`, andere Archive | **nicht lesbar.** Die Seite sagt, warum, und was stattdessen geht (zum Beispiel «als .docx oder .pdf speichern»). |

Je Datei zeigt die Tabelle den Namen, den Ordner, aus dem sie kam, die Grösse und das Ergebnis der PII-Prüfung:

- **bereit:** Die Prüfung findet nichts. Die Seite nennt die Zahl der Platzhalter. Namen erkennt die Prüfung nicht von
  selbst, deshalb lohnt der Blick auf den lokalen Bildschirm auch bei Dokumenten, die als bereit gelten.
- **Personendaten:** Die Prüfung findet eine Telefonnummer, eine AHV-Nummer, eine IBAN, ein Geburtsdatum, ein
  Kontrollschild oder eine Kreditkartennummer. Der Bericht zeigt die Fundstellen maskiert. Die Datei geht so nicht in
  einen Fall. E-Mail-Adressen und Strassenadressen meldet die Prüfung als Hinweis: Sie sperren nicht, weil sie auch zur
  Täterseite gehören können. Die Zeile trägt dann die Marke «Hinweis». Gehört die Adresse zur geschädigten Seite, wird
  sie auf dem lokalen Bildschirm ersetzt.
- **nicht lesbar:** Was sich nicht lesen lässt, lässt sich nicht prüfen. Die Datei geht nicht in den Fall und nicht an
  das Sprachmodell. Sie bleibt beim Sachbearbeiter. Im Sitzungsprotokoll steht, wie viele Dateien welcher Art nicht
  übergeben wurden, ohne ihre Namen.

**Auswählen.** Jede Zeile hat einen Haken, die Kopfzeile einen für alle. «Alle» meint, was nach dem Filter der Tabelle
zu sehen ist. Mit gedrückter Umschalttaste wählt ein Klick den ganzen Bereich seit dem letzten Haken. Für die Auswahl
gibt es: «Nochmals pseudonymisieren», «Als Rapport», «Als Beilage», «Entfernen» und «Verschieben» in den Akten-Eingang
eines anderen Falls. Ohne Auswahl sind diese Knöpfe aus. Eine einzelne Datei lässt sich umbenennen, die Endung bleibt.

**In den Fall aufnehmen.** Aufgenommen wird, was gewählt und bereit ist. Ist nichts gewählt: alles, was bereit ist. Beim
Knopf steht jeweils, wie viele Dateien das sind. Was Personendaten enthält oder nicht lesbar ist, bleibt im Akten-Eingang
liegen und wird genannt.

- **In den Fall kommt die Textfassung, nie das Original.** In einem Original können Angaben stecken, die niemand sieht:
  der Verfasser in den Eigenschaften, eingebettete Bilder, der Änderungsverlauf.
- **Neutrale Dateinamen** sind die Vorgabe: `rapport-01.txt`, `beilage-01.txt`, `beilage-02.csv`. Ein Dateiname nennt
  leicht eine Person, und er steht in jedem Protokoll. Welche hochgeladene Datei unter welchem Namen im Fall liegt, hält
  die Ablage ausserhalb des Projekts fest (`<Ablage>/<Fall-ID>/dateinamen.csv`). Wer die Namen behalten will, nimmt den
  Haken weg: Dann prüft die Oberfläche jeden Namen wie ein Dokument.
- Die Aufnahme läuft über `tools/fall.py`, das jede Datei selbst noch einmal prüft und im Register des Eingangs einträgt.
- Ein Dokument überschreibt nie ein anderes. Gibt es den Namen im Fall schon, bekommt das neue eine Nummer.

**Was im Fall liegt.** Unter «Akten» steht auch der Eingang des Falls. Gewählte Dokumente lassen sich entfernen (mit
«Durch» und «Grund», das Register hält es fest) oder in einen anderen Fall verschieben (dort mit PII-Prüfung
aufgenommen, hier entfernt). Liegt dort schon ein Dokument gleichen Namens, kommt das verschobene unter der nächsten
freien Nummer an. Ein Dokument, das jemand von Hand in den Eingang kopiert hat, erscheint als «nicht geprüft»: Es lässt
sich nachträglich prüfen oder entfernen. Von seinem Namen bleibt nach dem Entfernen nichts im Register, nur die Prüfsumme.

Grenzen des Akten-Eingangs: 60 MB je Datei, 600 MB und 2000 Dateien je Eingang.

### Nochmals pseudonymisieren

Die Akten kommen pseudonymisiert aus dem Haus. Hat die erste Pseudonymisierung etwas übersehen, bessert der
Sachbearbeiter hier nach: Dateien anhaken und «Nochmals pseudonymisieren», oder der Knopf in der Zeile. Mehrere gewählte
Dokumente kommen nacheinander («Dokument 2 von 5»).

Der Bildschirm zeigt den Text mit markierten Fundstellen: was ersetzt wird, was noch offen ist (Kandidaten), was stehen
bleibt. Technische Indikatoren sind eigens gekennzeichnet und bleiben immer stehen. Annehmen, verwerfen, ergänzen: Jede
Eingabe rechnet neu, damit sich eine Angabe im ganzen Dokument fortpflanzt. Dahinter steht dieselbe Bibliothek wie hinter
`tools/pseudonymisieren.py`, ohne Sprachmodell und ohne Netz.

- **Platzhalter von anderer Hand bleiben.** Steht im Dokument schon `[PERSON_08]`, bleibt das so. Neue Platzhalter
  zählen hinter der höchsten Nummer weiter, die im Akten-Eingang und in den Dokumenten des Falls vorkommt: Eine Nummer
  meint nie zwei Angaben.
- **Gleiche Angabe, gleicher Platzhalter**, über alle Dokumente desselben Akten-Eingangs und, bei einem bestehenden Fall,
  über dessen Zuordnungstabelle.
- **«Übernehmen»** schickt das Ergebnis durch die PII-Prüfung. Besteht es, ersetzt es die Datei im Akten-Eingang, und der
  Klartext verlässt den Speicher. Besteht es nicht, bleibt alles, wie es war, und die Seite zeigt die Stellen maskiert.
- **«Abbrechen»** lässt die Datei, wie sie war.
- Die Zuordnungstabelle entsteht in der Ablage ausserhalb des Projekts, sobald die Akten in den Fall aufgenommen sind
  (`<Ablage>/<Fall-ID>/zuordnung.csv`). Sie enthält, was hier ersetzt wurde. Platzhalter von anderer Hand kennt sie
  nicht: Für sie gilt die Zuordnung, die im Haus geführt wird.

### Ermittlung und Chat

Die Ansicht «Ermittlung» zeigt den Stand der Sitzung von Claude Code, den Chat und darunter, welcher Analyst woran
arbeitet. In allen anderen Ansichten eines Falls steht derselbe Chat klein am rechten Rand, unter der Arbeitsspur. Er
lässt sich einklappen.

- **Vorgaben.** Vor dem Start nimmt das Feld Vorgaben auf: ein Schwerpunkt, eine Eingrenzung, ein Hinweis. Sie gehen
  mit dem Auftrag `/ermittlung <Fall-ID>` an Claude Code. Der Skill berücksichtigt sie im Plan. Vorgaben ersetzen keine
  Freigabe.
- **Jeder Schritt im Verlauf.** Antworten der Ermittlung, jeder Auftrag an einen Analysten, jeder Werkzeugaufruf mit
  Ziel, Beleg (`P-0007`, anklickbar) und Ergebnis (Treffer, kein Treffer, Fehlschlag), jede Rückfrage mit ihrem
  Entscheid. «Jeden Schritt zeigen» blendet die Einzelschritte aus, wenn nur die Nachrichten interessieren.
- **Nachrichten.** Arbeitet die Sitzung nicht, setzt eine Nachricht sie fort. Arbeitet sie, wartet die Nachricht auf das
  Ende des laufenden Auftrags und lässt sich bis dahin zurücknehmen, oder sie unterbricht ihn («Jetzt unterbrechen und
  senden»). Strg+Eingabe sendet.
- **Anhalten, fortsetzen, neu starten.** Anhalten beendet den laufenden Schritt. Fortsetzen nimmt dieselbe Sitzung
  wieder auf, auch nach einem Neustart der Oberfläche: Sie findet die letzte Sitzung zum Fall im Sitzungsprotokoll.
- **Was hier steht, liest das Sprachmodell.** Jede Eingabe geht durch dieselbe PII-Prüfung wie ein Dokument. Findet sie
  etwas, geht nichts hinaus, und die Meldung zeigt die Stelle maskiert.
- **Am Ende.** Hat die Ermittlung Befunde und einen Rapport hinterlassen, erzeugt die Oberfläche Ermittlungsprotokoll,
  PDF und Datenblätter und bietet «Ergebnisse ansehen» an.

Jede Nachricht, jede Vorgabe und die Antwort der Ermittlung am Ende eines Auftrags stehen im Sitzungsprotokoll. Den
ganzen Verlauf legt die Oberfläche zusätzlich als Textdatei im Arbeitsstand des Falls ab
(`arbeitsstand/verlauf-oberflaeche-<Zeit>.txt`). Die Datei ist eine Lesehilfe, kein Beleg: Belegt ist, was im
Sitzungsprotokoll und in der Protokollkette steht.

### Pflichtquellen

Über dem Chat steht, eingeklappt, die Auswahl der Pflichtquellen: Quellen, die in dieser Ermittlung gefragt werden
müssen. Sie ist freiwillig. Ohne Vorgabe wählt das Team die Quellen selbst.

- **Anwählen.** Jede Quelle des Verzeichnisses ist ein Kasten, in drei Gruppen: mit Schlüssel, ohne Schlüssel, Dark
  Web. Leer lassen, einzeln anwählen, «Alle auswählen» oder «Keine». Neben jedem Namen steht, wofür die Quelle fällig
  wird (IP-Adressen, Domains, Wallets, «einmal im Fall»).
- **Was gesperrt ist.** Eine Quelle, deren Schlüssel fehlt, Web-Check ohne laufende Instanz und Robin, solange es an
  diesem Arbeitsplatz nicht eingeschaltet ist oder dem Fall die Freigabe «Dark Web» fehlt. Der Grund steht dabei. Eine
  Pflichtquelle ersetzt keine Freigabe.
- **Speichern.** «Pflichtquellen speichern», oder einfach starten: «Ermittlung starten» übernimmt eine Auswahl, die
  noch nicht gespeichert ist. Scheitert das Speichern, startet die Ermittlung nicht. Die Vorgabe steht in `fall.json`
  (`pflichtquellen`, mit Zeit und `"weg": "Oberfläche"`), im Sitzungsprotokoll und im ersten Eintrag des Verlaufs.
- **Was eine Pflichtquelle bewirkt.** Die Ermittlung liest die Vorgabe mit `fall_status`, samt der Liste dessen, was
  noch offen ist. Jede Pflichtquelle wird für jeden Indikator aus den Eingangsdokumenten abgefragt, zu dem sie passt,
  Suchquellen und Quellen für Gruppen und Konten mindestens einmal im Fall. Weitere Quellen bleiben dem Team überlassen.
- **Der Stand.** Die Kopfzeile der Auswahl zeigt ihn in einer Zeile («8 von 11 erfüllt, 3 offen»). Aufgeklappt steht
  je Quelle: erfüllt, offen, Fehlschlag, entfällt (kein passender Indikator im Fall) oder noch nicht fällig (die
  Indikatoren stehen noch nicht fest), mit den offenen Indikatoren und den Belegen. Gelesen wird das aus dem Protokoll.
  Dieselbe Tabelle steht in der Fallübersicht, auch im Modus «nur lesen».
- **Während die Ermittlung arbeitet**, ruht die Auswahl. Ändern lässt sie sich, sobald die Ermittlung angehalten
  oder beendet ist. Der Rapport prüft am Ende die Vorgabe, die dann im Fall steht.
- **Am Ende.** `tools/rapport.py` prüft die Vorgabe am Protokoll. Was nie gefragt wurde, ist ein Mangel und steht
  unter den offenen Punkten. Ein Fehlschlag gilt als gefragt und gehört unter die Lücken. Der Abschlussrapport weist
  die Pflichtquellen in Abschnitt 4 aus.

Wofür eine Quelle fällig wird, steht an einer Stelle im Code (`gateway/quellen.py`, `VORGABEN`). Die Regel ist enger
als die Abdeckung der Fallübersicht: Dort steht, wozu eine Quelle etwas sagen kann. Hier steht, wofür sie gefragt
werden muss. Am Terminal zeigt `python3 tools/fall.py quellen <Fall-ID>` dieselbe Liste und den Stand.

### Rückfragen

Braucht ein Werkzeugaufruf eine Zustimmung, erscheint ein Fenster über der Ansicht, in jeder Ansicht und auch, wenn
gerade ein anderer Fall offen ist. Es nennt den Fall, das Werkzeug und die Eingabe im Wortlaut. Der Titel des
Browser-Reiters zeigt die Rückfrage an.

- **Erlauben** gilt für diesen einen Aufruf. **Ablehnen** auch. Ohne Antwort innert 30 Minuten gilt die Frage als abgelehnt.
- **«Erst nachsehen»** blendet das Fenster aus und lässt einen Balken stehen. Die Ermittlung wartet.
- Mehrere Rückfragen (Hauptsitzung und Analysten) kommen nacheinander, in der Reihenfolge ihres Eingangs.
- Eine Rückfrage stellt Claude Code für jeden Aufruf, den die Einstellungen des Projekts weder erlauben noch verbieten.
  Erlaubt sind die passiven Abfragen, die Werkzeuge für Fall, Rapport und Protokoll und das Schreiben der Arbeitsdateien
  eines Falls (`arbeitsstand/`, `befunde.json`, `rapport/`). Aktive Massnahmen, die Websuche und alles Übrige fragen nach.
- Über Aufrufe von Robin (Dark Web) entscheidet die Freigabe «darkweb» des Falls, ohne Fenster.

### Ergebnisse und Archiv

Die Ansicht «Ergebnisse» sammelt, was die Ermittlung hinterlassen hat:

- **Ansehen:** Rapport, Indikatoren, Rohdaten, Fallübersicht und Suche, je mit einem Satz, was dort zu finden ist.
- **Unterlagen:** Abschlussrapport, Ermittlungsprotokoll und Datenblätter, je mit Stand, zum Ansehen und als HTML und
  PDF zum Herunterladen. Dazu die Indikatorliste und das Protokoll als CSV und die Befunde als JSON. «Alle Unterlagen neu
  erzeugen» ruft die Werkzeuge des Projekts auf.
- **Alles mitnehmen:** drei Archive (ZIP).

| Archiv | Inhalt |
|---|---|
| Unterlagen und Sitzungsprotokoll | Rapport, Protokoll und Datenblätter (HTML und PDF), CSV, Befunde. Dazu je Sitzung die Zeilen des Sitzungsprotokolls, die diesen Fall betreffen, und der Verlauf aus dem Chat. |
| Nur die Unterlagen | wie oben, ohne Sitzungsprotokoll |
| Die ganze Fallakte | alles oben, dazu `fall.json`, die Dokumente des Eingangs, die Protokollkette, der Arbeitsstand und alle Rohdaten |

Jedes Archiv enthält `INHALT.txt`: jede Datei mit Grösse und SHA-256, der Stand der Protokollkette und, was fehlt oder
älter ist als die Daten. Das Archiv entsteht im Speicher und liest die Fallakte nur. Es enthält die pseudonymisierte
Akte, keinen Klartext.

### Weitere Funktionen

| Funktion | Was geschieht | Womit |
|---|---|---|
| **Freigaben** | Aktive Massnahmen, Dark Web und Kontoabfragen per Klick, mit «Durch» und «Grundlage». | `tools/fall.py` (Funktion `freigabe_setzen`) |
| **Pflichtquellen** | In der Ansicht «Ermittlung»: Quellen, die die Ermittlung abfragen muss. Siehe oben. | `tools/fall.py` (Funktion `pflichtquellen_setzen`) |
| **Abklärung von Hand** | Formular für Indikator, Quelle, Zeit und Wortlaut. Der Eintrag geht in die Kette und ist als «von Hand erfasst» gekennzeichnet. | `tools/beleg.py` |
| **Dokumente** | Abschlussrapport, Ermittlungsprotokoll, Datenblätter und PDF einzeln neu erzeugen, Kette prüfen. Die Seite zeigt die Ausgabe des Werkzeugs. | `tools/rapport.py`, `protokoll.py`, `anhang.py`, `pdf.py`, `audit_pruefen.py` |
| **Zurückführen** | Der fertige Rapport mit echten Angaben, lokal, mit der Zuordnungstabelle. | `tools/reidentifizieren.py` |
| **Fall löschen** | Nur, solange nichts abgefragt wurde: keine Protokolleinträge, keine Rohdaten, keine Befunde. Nie der Musterfall. Für eine falsche Fall-ID. | `tools/fall.py` (Funktion `loeschen`) |
| **Quellen** | Welche bereit sind und welche fehlen, eine Testabfrage je Quelle, das Kontingent von urlscan.io, Stand der lokalen Listen. Von Schlüsseln nur der Name der Variablen. | wie `tools/pruefen.py --live` |

Jeder dieser Schritte steht im Sitzungsprotokoll des Falls (`protokoll/sitzungen/`), mit Zeit und dem Vermerk
«Oberfläche», und erscheint im Ermittlungsprotokoll unter «Sitzungsverlauf». Eine Freigabe trägt den Vermerk zusätzlich
in `fall.json` (`"weg": "Oberfläche"`).

### Der Weg des Klartexts

Klartext bearbeitet nur der lokale Server, nie eine Claude-Sitzung.

1. Eine hochgeladene Datei geht vom Browser an den Server, als Rohinhalt und nur mit dem Geheimnis. Sie liegt dort im
   Speicher: das Original und seine Textfassung. Für das Auslesen eines PDF, das `pdftotext` nicht aus dem Speicher
   liest, liegt es kurz in einem Ordner ausserhalb des Projekts, der danach verschwindet.
2. Auf dem Bildschirm «Pseudonymisieren» entscheidet der Sachbearbeiter. Mit «Übernehmen» ersetzt das Ergebnis die
   Datei im Akten-Eingang, und das Original verlässt den Speicher.
3. Erst das Ergebnis geht über `tools/fall.py` in den Fall. Für die Übergabe liegt die Textfassung kurz in einem Ordner
   ausserhalb des Projekts.
4. Die Zuordnungstabelle und die Liste der Dateinamen gehen in die Ablage ausserhalb des Projektordners
   (`<Ablage>/<Fall-ID>/`, nur für den Benutzer lesbar). Sie stehen in keinem Protokoll. Die Vorgabe `OSINT-Ablage`
   sperren die Berechtigungen für Agenten. Steht in der Ablage schon eine Tabelle, bleibt jedes ihrer Paare erhalten.
   Passt sie nicht zu dem, was hier ersetzt wurde (jemand hat sie ausserhalb der Oberfläche geändert), entsteht eine
   eigene Datei daneben: Überschrieben wird nichts.
5. Zurückführen schreibt den Rapport mit echten Angaben ebenfalls in die Ablage und zeigt ihn nur auf dem Bildschirm
   «Zurückführen».

Echte Angaben kann die Oberfläche auf drei Bildschirmen zeigen: im Akten-Eingang (die Namen hochgeladener Dateien, nie
ihren Inhalt), auf dem Bildschirm der Pseudonymisierung und beim Zurückführen. Alle drei tragen das Band
**«lokal, Klartext»**, und ihren Inhalt gibt der Server nur gegen das Geheimnis heraus. Überall sonst stehen Platzhalter.

### Claude Code steuern

Die Oberfläche startet die Kommandozeile von Claude Code im Skriptbetrieb, mit fortlaufender JSON-Ausgabe:

```
claude -p "/ermittlung <Fall-ID>" --output-format stream-json --verbose
       --permission-prompt-tool mcp__oberflaeche__rueckfrage --mcp-config <Datei ausserhalb des Projekts>
```

- **Im Projektordner, ohne abschaltende Schalter.** Die Sitzung läuft im Projektordner. Die Oberfläche setzt keinen
  Schalter, der Einstellungen, Hooks oder MCP-Server des Projekts abschaltet (`--bare`, `--safe-mode`, `--restricted`,
  `--setting-sources`, `--strict-mcp-config`, `--dangerously-skip-permissions`). Berechtigungen, `.mcp.json`
  und die Protokoll-Hooks gelten also wie am Terminal.
- **Abbruch ohne Einstellungen des Projekts.** Claude Code meldet beim Start, welche MCP-Server es geladen hat. Fehlt
  darunter das Gateway des Projekts (`osint`), sind die Einstellungen des Projekts nicht geladen, und Berechtigungen
  und Protokoll gälten nicht. Die Oberfläche beendet die Sitzung dann sofort und sagt es.
- **Modelle.** Kein Schalter für das Modell. Es bleibt, wie das Projekt es festlegt.
- **Vorgaben und Nachrichten.** Vorgaben folgen der Fall-ID im ersten Auftrag als eigener Absatz. Eine Nachricht geht
  als neuer Auftrag an dieselbe Sitzung (`--resume <Sitzung>`). Unterbricht sie einen laufenden Auftrag, beendet die
  Oberfläche zuerst den Prozess und setzt die Sitzung dann mit der Nachricht fort.
- **Rückfragen.** Braucht ein Aufruf eine Zustimmung, ruft Claude Code das Werkzeug `rueckfrage` eines kleinen
  MCP-Servers auf (`tools/ui/rueckfrage.py`). Der gibt die Frage an die Oberfläche weiter, und sie erscheint im Browser
  als Fenster. Die Karte, mit der sich der MCP-Server bei der Oberfläche ausweist, taugt nur zum Fragen: Erlauben kann
  nur das Browserfenster mit dem Geheimnis. Die Antwort geht als ein Textblock mit JSON zurück, wie die Dokumentation
  es verlangt.
- **Anhalten und fortsetzen.** Anhalten beendet den Prozess. Claude Code bricht dabei den laufenden Schritt ab. Was bis
  dahin abgefragt wurde, steht im Protokoll. Fortsetzen nimmt dieselbe Sitzung wieder auf (`--resume`) und gibt ihr
  den Auftrag weiterzumachen.
- **Wer woran arbeitet** liest die Oberfläche aus der JSON-Ausgabe: je Analyst der letzte Werkzeugaufruf und die Zahl
  der Schritte. Beleg und Ergebnis einer Abfrage liest sie aus der Antwort des Werkzeugs.

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

**Die Probe am eigenen Arbeitsplatz.** Ob der Weg mit dem echten Claude Code trägt, zeigt ein Befehl:

```bash
python3 tools/oberflaeche.py --sitzungsprobe          # am Terminal, verbraucht etwas Kontingent
```

Er startet vier kurze Sitzungen auf demselben Weg wie «Ermittlung starten» und ändert nichts am Fall:

1. **Ablauf.** Claude Code ruft einmal `fall_status` auf. Geprüft wird: Meldet es Sitzung und Modell, ist das Gateway
   geladen, kommt die Antwort an, läuft der Aufruf ohne Rückfrage, und hat der Protokoll-Hook mitgeschrieben.
2. **Fortsetzen.** Dieselbe Sitzung wird wieder aufgenommen, wie es eine Nachricht aus dem Chat tut.
3. **Verbote.** Claude Code soll zwei gesperrte Befehle versuchen (sich eine Freigabe erteilen, die Schlüsseldatei
   lesen). Erwartet wird: beide abgelehnt, `fall.json` unverändert.
4. **Rückfrage.** Claude Code soll ein Werkzeug aufrufen, das eine Zustimmung verlangt. Die Probe lehnt jede Rückfrage ab.

Die Probe nennt dazu, über welchen Zugang abgerechnet wird und welche MCP-Server Claude Code geladen hat.

### Schutz der Bedienung

| Schutz | Wie er umgesetzt ist |
|---|---|
| Ändern nur mit Geheimnis | Jede ändernde Anfrage ist ein POST und trägt das Geheimnis in einer Kopfzeile: Angaben als JSON, eine Datei als Rohinhalt. Ohne es antwortet der Server mit 403 und ändert nichts. Eine Datei liest er erst ein, wenn das Geheimnis stimmt. Host-Kopf und Herkunft prüft er wie beim Lesen. |
| Kein Geheimnis für Agenten | Der Startcode gilt einmal. Das Geheimnis steht in keiner Datei und in keiner Umgebung. Aus Claude Code oder ohne Terminal gestartet, läuft die Oberfläche «nur lesen». Ein Agent kann sich so über die Oberfläche keine Freigabe erteilen, keinen Beleg erfassen und seine eigene Rückfrage nicht beantworten. |
| Die Kette bleibt die eine Wahrheit | Die Oberfläche schreibt nie selbst in Protokoll, Rohdaten, Eingang oder `fall.json`. Sie ruft die bestehenden Werkzeuge auf. Das Sitzungsprotokoll schreibt der Hook, der es immer schreibt. Die eine Datei, die sie selbst in einem Fall ablegt, ist der Verlauf des Chats im Arbeitsstand. |
| Der Chat geht durch die PII-Prüfung | Vorgaben und Nachrichten prüft die Oberfläche wie ein Dokument, bevor sie an Claude Code gehen. Titel, Auftrag und Kürzel eines Falls ebenso. |
| Werkzeuge schützen sich selbst | Freigabe, Beleg von Hand, Entfernen, Löschen, Pseudonymisieren und Zurückführen verlangen am Terminal eine Eingabe von Hand. Die Berechtigungen des Projekts verbieten die Befehle für Agenten. Die Funktionen dahinter ruft die Oberfläche erst auf, wenn die Anfrage das Geheimnis trägt. |
| Die Ablage ist für Agenten gesperrt | Die Berechtigungen verbieten Lesen und Schreiben in der Vorgabe-Ablage (`~/OSINT-Ablage`). Eine eigene Ablage (`--ablage`, `OSINT_ABLAGE`) kennen die Berechtigungen nicht: Wer sie nimmt, trägt den Ordner selbst als Verbot in `.claude/settings.local.json` ein. |
| Klartext bleibt draussen | Siehe «Der Weg des Klartexts». Ablage und Zwischendateien liegen ausserhalb des Projektordners. Eine Ablage im Projektordner lehnt die Oberfläche ab. |

**Grenzen dieses Schutzes.** Einen Wächter, der jeden Werkzeugaufruf vorab prüft, gibt es seit dem 17.11.2026 nicht
mehr. Ein Agent, der die Funktionen hinter der Oberfläche aus einem Shell-Befehl aufruft (zum Beispiel
`freigabe_setzen`), braucht dafür kein Geheimnis. Ein solcher Befehl steht aber auf keiner Erlaubt-Liste: Claude Code
legt ihn dem Menschen vor, in einer Sitzung aus der Oberfläche als Fenster mit dem Befehl im Wortlaut. Wer ihn erlaubt,
hat entschieden. Wer Claude Code so einstellt, dass es nicht mehr fragt, hat diese Schicht abgeschaltet.
Ein Programm mit den Rechten des Benutzers, das gezielt den Speicher des Servers ausliest oder den
Startcode in der halben Sekunde zwischen Start und Browserfenster aus der Prozessliste fischt, hält er nicht auf. Der
zweite Fall fiele auf: Das Browserfenster des Sachbearbeiters könnte dann nicht bedienen und sagt es.
Die PII-Prüfung erkennt Muster (Telefonnummern, AHV-, Konto- und Kartennummern, Geburtsdaten, Kontrollschilder), keine Namen. Ein
Name, der in einem hochgeladenen Dokument oder im Chat stehen bleibt, geht an das Sprachmodell. Dagegen hilft nur der
Blick des Sachbearbeiters auf dem lokalen Bildschirm.

## Anhang für die Akte

```bash
python3 tools/anhang.py <Fall-ID>                # rapport/Datenblaetter.html und rapport/Datenblaetter.pdf
python3 tools/anhang.py <Fall-ID> --ohne-pdf     # nur das HTML
```

Das Werkzeug schreibt alle Datenblätter eines Falls in ein Dokument, ohne dass die Oberfläche läuft. Das HTML steht
für sich allein: keine Skripte, keine Verweise nach aussen, Bilder aus den Rohdaten sind eingebettet, jeder Wert
steht ausgeschrieben da. Das PDF erzeugt derselbe Weg wie `tools/pdf.py` (ein installierter Chrome, Chromium, Edge
oder Brave, ohne Fenster). Das Dokument nennt am Schluss den Stand der Daten (letzter Kettenwert, Prüfsumme von
`befunde.json`). Daran erkennt die Oberfläche, ob es noch aktuell ist.

## Grenzen

- **Die Steuerung von Claude Code ist nur gegen ein Programm geprüft, das Claude Code spielt.** Mit dem echten Claude
  Code ist weder die Form seiner JSON-Ausgabe noch der Weg der Rückfrage gesehen, und keine Ermittlung ist je aus der
  Oberfläche gelaufen. Dasselbe gilt für den Chat: dass Vorgaben nach der Fall-ID beim Skill ankommen, dass `--resume`
  mit einer Nachricht die Sitzung fortsetzt und dass die Erlaubt-Regeln für die Arbeitsdateien eines Falls greifen.
  Schalter, Antwortform der Rückfrage und die Meldung der MCP-Server beim Start folgen der Dokumentation (gelesen am
  16.11.2026). Nicht nachgelesen ist, ob die Variable `MCP_TOOL_TIMEOUT` eine Rückfrage wirklich 30 Minuten warten
  lässt. Die Probe dafür: `python3 tools/oberflaeche.py --sitzungsprobe`.
- **Pflichtquellen.** Ob das Team sie in einer echten Ermittlung abarbeitet, ist nicht geprüft: Das hängt an der
  Steuerung mit dem echten Claude Code. Geprüft ist die Auswertung am Protokoll und dass der Rapport eine Lücke meldet.
  Zu einem Indikator gehört eine Abfrage, wenn sie seinen Wert zum Ziel hatte, Grundlage einer Auswertung zu ihm ist
  oder unter seinen Belegen steht. Fragt ein Analyst eine Quelle mit einer anderen Schreibweise des Werts, erkennt die
  Auswertung das erst, wenn der Beleg beim Indikator eingetragen ist.
- **Anhalten unter Windows.** Dort beendet das System den Prozess hart. Ob Befehle, die Claude Code gerade ausführt,
  dabei mit enden, ist nicht geprüft.
- **Der Akten-Eingang lebt im Speicher.** Was hochgeladen, aber noch nicht in einen Fall aufgenommen ist, ist nach dem
  Beenden der Oberfläche weg. Dasselbe gilt für eine Pseudonymisierung, die noch nicht übernommen ist.
- **Formate.** Gelesen werden Text, Word (.docx), OpenDocument, Excel (.xlsx), PowerPoint (.pptx), RTF, E-Mail (.eml)
  und PDF mit Text. Bilder, Ton, gescannte PDF und die alten Office-Formate nicht: Es gibt keine Texterkennung. Die
  Textfassung eines Office-Dokuments enthält den Text, nicht das Layout, keine Kommentare und keine Bilder.
- **Ordner hineinziehen** stützt sich auf eine Schnittstelle des Browsers (`webkitGetAsEntry`, `webkitdirectory`), die
  alle grossen Browser kennen. Geprüft ist Chromium.
- **Nachrichten warten auf das Ende eines Auftrags.** Claude Code nimmt im Skriptbetrieb keine Eingabe in einen
  laufenden Auftrag an. Eine Nachricht wartet deshalb oder unterbricht den Auftrag.
- **Der Verlauf im Chat** zeigt, was Claude Code in seiner JSON-Ausgabe meldet. Nach einem Neustart der Oberfläche ist
  der Chat leer, der bisherige Verlauf liegt als Textdatei im Arbeitsstand des Falls und im Archiv.
- **Ein Fenster.** Bedienen lässt sich die Oberfläche aus dem Fenster, das sie beim Start öffnet. Wer es schliesst und
  die Sitzung des Browsers verliert, startet die Oberfläche neu.
- **Grosse Rohdateien.** Rohdateien über 3 MB ordnet die Oberfläche nicht zu und durchsucht sie nicht. Sie zeigt den
  Anfang und verweist auf die Datei. Ein Baum zeigt höchstens 6000 Angaben, der Rest steht in der Rohdatei.
- **Suche.** Höchstens 200 Treffer. Bilder werden nicht durchsucht.
- **Analyst je Abfrage.** Wer eine Abfrage ausgelöst hat, steht nur da, wenn das Sitzungsprotokoll des Falls auf dem Rechner liegt.
- **Darsteller ohne echte Vorlage.** Siehe oben: Für aktive Massnahmen, Abfragen mit Personenbezug, Spur, Telegram
  über RapidAPI, Shodan-DNS, die Wayback Machine und Robin ist nicht geprüft, ob der Darsteller zur echten Antwort passt.
- **Keine Anmeldung, kein Mehrbenutzerbetrieb.** Siehe Schutz.

Was geprüft ist und was nicht, mit Datum, steht im README unter «Stand der Prüfung und Grenzen».
