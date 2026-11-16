# Die Oberfläche

Die Oberfläche zeigt alle Ergebnisse eines Falls an einem Ort: den Rapport, jedes Datenblatt, jeden Beleg und jede
Rohdatei. Sie liest die Fallakte und schreibt nie. Abschlussrapport und Ermittlungsprotokoll bleiben die Dokumente
für die Akte. Die Oberfläche ersetzt sie nicht, sie macht sie durchsuchbar und nachprüfbar.

Dieses Dokument beschreibt Teil 1 (nur lesen). Stand: 16.11.2026.

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
| Links: Navigation | Fälle, der geöffnete Fall (Fallübersicht, Rapport, Indikatoren, Rohdaten, Suche, Dokumente), Quellen. Darunter der Schalter Hell / Dunkel. |
| Oben: Kopf des Falls | Fall-ID, Titel, Freigaben (erteilt oder nicht, durch wen, wann) und die Schrittleiste. |
| Schrittleiste | Fall angelegt, Indikatoren, Plan, Abfragen, Gegenprüfung, Rapport. Jeder Schritt sagt, woran die Oberfläche ihn erkennt (zum Beispiel «12 von 13 Befunden gegengeprüft»). Fehlt ein Schritt in der Akte, steht «nicht abgelegt». |
| Mitte | Die Ansichten, siehe unten. |
| Rechts: Arbeitsspur | Das Abfrageprotokoll, laufend nachgeführt (alle drei Sekunden). Filter: Abfragen, «kein Treffer», Fehlschläge, Auswertungen, Freigaben. Darunter Zahl der Einträge und Stand der Protokollkette. |

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
| `#/fall/<Fall-ID>/dokumente` und `…/dokument/Abschlussrapport` | Dokumente der Akte |
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

### 6. Dokumente

Abschlussrapport, Ermittlungsprotokoll und Datenblätter: ansehen, als PDF holen, dazu `indikatoren.csv` und
`Ermittlungsprotokoll.csv`. Bei jedem Dokument steht, ob es dem Stand der Daten entspricht oder älter ist und warum
(«seit der Erzeugung kamen 3 Protokolleinträge dazu», «befunde.json wurde seit der Erzeugung geändert»).

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
- **Musterfall:** erfunden, in der Form der echten Antwort.
- **Erfunden:** Für diese Werkzeuge lag keine echte Antwort vor. Die Vorlage folgt der Dokumentation der Quelle. Das
  betrifft die aktiven Massnahmen (nie ausgelöst), die Abfragen mit Personenbezug, die Werkzeuge ohne Schlüssel
  (Telegram über RapidAPI, Shodan-DNS) und Robin (Dark Web). **Ob diese Darsteller zur echten Antwort passen, ist
  nicht geprüft.** Passen sie nicht, stehen die Angaben unter «Weitere Angaben».

`fall_status` hat keine Vorlage: Es fragt keine Quelle ab und hinterlässt keinen Protokolleintrag.

<!-- darsteller:anfang -->
| Werkzeug | Eigener Darsteller | Angaben in der Vorlage | zugeordnet | unter «Weitere Angaben» | Vorlage |
|---|---|---:|---:|---:|---|
| `abklaerung_von_hand` | ja | 13 | 13 | 0 | erfunden |
| `abuseipdb_meldungen` | ja | 19 | 17 | 2 | echte Antwort |
| `abuseipdb_pruefen` | ja | 28 | 28 | 0 | echte Antwort |
| `chan_katalog` | ja | 133 | 49 | 84 | echte Antwort |
| `chan_thread` | ja | 36 | 17 | 19 | echte Antwort |
| `ip_abruf (AbuseIPDB)` | ja | 14 | 14 | 0 | echte Antwort |
| `ip_abruf (RIPEstat)` | ja | 42 | 9 | 33 | echte Antwort |
| `ip_abruf (Spur)` | ja | 20 | 13 | 7 | Musterfall (erfunden, echte Form) |
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
| `krypto_adresse_pruefen` | ja | 12 | 9 | 3 | Musterfall (erfunden, echte Form) |
| `krypto_geldfluss` | ja | 158 | 76 | 82 | echte Antwort |
| `krypto_kurs` | ja | 22 | 15 | 7 | echte Antwort |
| `krypto_transaktion` | ja | 36 | 30 | 6 | echte Antwort |
| `krypto_transaktionen` | ja | 49 | 40 | 9 | echte Antwort |
| `krypto_zuordnung` | ja | 29 | 22 | 7 | echte Antwort |
| `mastodon_instanz` | ja | 140 | 13 | 127 | echte Antwort |
| `mastodon_konto` | ja | 15 | 13 | 2 | erfunden |
| `onion_sperrliste` | ja | Text | – | – | Musterfall (erfunden, echte Form) |
| `ransomware_aktuell` | ja | 59 | 32 | 27 | erfunden |
| `ransomware_gruppe` | ja | 285 | 243 | 42 | erfunden |
| `ransomware_iocs` | ja | 8 | 6 | 2 | erfunden |
| `ransomware_opfer` | ja | 64 | 37 | 27 | erfunden |
| `robin_scrape` | ja | 3 | 3 | 0 | erfunden |
| `robin_search` | ja | 8 | 8 | 0 | erfunden |
| `shodan_dns` | ja | 13 | 13 | 0 | erfunden |
| `shodan_host` | ja | 86 | 22 | 64 | echte Antwort |
| `shodan_internetdb` | ja | 8 | 8 | 0 | echte Antwort |
| `shodan_suche` | ja | 14 | 13 | 1 | echte Antwort |
| `spur_kontext` | ja | 20 | 13 | 7 | Musterfall (erfunden, echte Form) |
| `telegram_entitaet` | ja | 7 | 7 | 0 | erfunden |
| `telegram_kanal` | ja | Text | – | – | Musterfall (erfunden, echte Form) |
| `telegram_kanalinfo` | ja | 6 | 6 | 0 | erfunden |
| `telegram_suche` | ja | 8 | 8 | 0 | erfunden |
| `urlquery_bericht` | ja | 428 | 51 | 377 | echte Antwort |
| `urlquery_einreichen` | ja | 5 | 5 | 0 | erfunden |
| `urlquery_reputation` | ja | 3 | 3 | 0 | echte Antwort |
| `urlquery_status` | ja | 4 | 4 | 0 | erfunden |
| `urlquery_suche` | ja | 188 | 23 | 165 | echte Antwort |
| `urlscan_abruf (urlscan.io)` | nein (allgemeiner) | 506 | 0 | 506 | echte Antwort |
| `urlscan_einreichen` | ja | 10 | 6 | 4 | erfunden |
| `urlscan_ergebnis` | ja | 77 | 56 | 21 | echte Antwort |
| `urlscan_kontingent` | ja | 50 | 47 | 3 | echte Antwort |
| `urlscan_suche` | ja | 83 | 28 | 55 | echte Antwort |
| `virustotal_beziehungen` | ja | 38 | 14 | 24 | echte Antwort |
| `virustotal_datei` | ja | 156 | 56 | 100 | echte Antwort |
| `virustotal_domain` | ja | 222 | 55 | 167 | echte Antwort |
| `virustotal_ip` | ja | 278 | 42 | 236 | echte Antwort |
| `virustotal_url` | ja | 74 | 46 | 28 | echte Antwort |
| `wayback_abruf` | ja | Text | – | – | erfunden |
| `wayback_sichern` | ja | 4 | 4 | 0 | erfunden |
| `wayback_verlauf` | ja | 18 | 18 | 0 | Musterfall (erfunden, echte Form) |
| `webcheck_aktiv` | ja | 163 | 132 | 31 | erfunden (27 Prüfungen) |
| `webcheck_passiv` | ja | 129 | 96 | 33 | erfunden (13 Prüfungen) |
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
| Nur lesen | Der Server kennt nur GET und HEAD. In der Datenschicht und im Server gibt es keinen Aufruf, der eine Datei anlegt, ändert oder löscht. Ein Selbsttest vergleicht die Fallakten vor und nach dem Abruf aller Adressen. |
| Fremdinhalte sind Text | Alles, was aus einer Quelle stammt, wird als Text ausgegeben und nie als HTML ausgeführt: Werte, Schlüssel, Ziele, Zweck, Fehlermeldungen, Seitentexte. Rohdateien liefert der Server als `text/plain` oder als Bild, nie als HTML. |
| Bilder nur aus den Rohdaten | Ein Bild erscheint nur, wenn es als Datei in den Rohdaten des gezeigten Falls liegt. Eine fremde Bildadresse in einer Antwort ergibt Text, kein Bild. |
| Nichts von aussen | Eine Content-Security-Policy erlaubt Skripte, Stile, Bilder und Abrufe nur vom eigenen Server. Es gibt eine Skriptdatei (`app.js`), keine Bibliothek, keine Schrift und kein Bild von aussen. Die Oberfläche läuft ohne Internet. |
| Adressen aus dem Fall | URLs, Domains und Onion-Adressen aus dem Fall stehen als Text da und sind nie anklickbar. Verweise führen nur in die Oberfläche selbst. |
| Gespeicherte Dokumente | Der Abschlussrapport der Akte läuft in einem Rahmen ohne Skripte (Sandbox). |
| Platzhalter | `[PERSON_01]` und die übrigen Platzhalter bleiben, wie sie sind. Die Oberfläche löst nichts auf und kennt keine Zuordnungstabelle. |
| CSV | Beginnt eine Zelle mit `=`, `+`, `-` oder `@`, setzt die Ausgabe ein Hochkomma davor, damit eine Tabellenkalkulation sie nicht als Formel liest. |

Die Oberfläche hat keine Anmeldung. Wer am Rechner angemeldet ist und den Port erreicht, sieht die Fälle. Sie gehört
deshalb auf den Arbeitsplatz des Sachbearbeiters und nicht auf einen Server, den mehrere Personen teilen.

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

- **Teil 1 liest nur.** Fall anlegen, Freigaben, Ermittlung starten und Dokumente erzeugen geschehen weiterhin am Terminal.
- **Grosse Rohdateien.** Rohdateien über 3 MB ordnet die Oberfläche nicht zu und durchsucht sie nicht. Sie zeigt den
  Anfang und verweist auf die Datei. Ein Baum zeigt höchstens 6000 Angaben, der Rest steht in der Rohdatei.
- **Suche.** Höchstens 200 Treffer. Bilder werden nicht durchsucht.
- **Analyst je Abfrage.** Wer eine Abfrage ausgelöst hat, steht nur da, wenn das Sitzungsprotokoll des Falls auf dem Rechner liegt.
- **Darsteller ohne echte Vorlage.** Siehe oben: Für aktive Massnahmen, Abfragen mit Personenbezug, Telegram über
  RapidAPI, Shodan-DNS und Robin ist nicht geprüft, ob der Darsteller zur echten Antwort passt.
- **Keine Anmeldung, kein Mehrbenutzerbetrieb.** Siehe Schutz.

Was geprüft ist und was nicht, mit Datum, steht im README unter «Stand der Prüfung und Grenzen».
