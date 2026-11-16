# Die Oberfläche

Die Oberfläche zeigt alle Ergebnisse eines Falls an einem Ort: den Rapport, jedes Datenblatt, jeden Beleg und jede
Rohdatei. Abschlussrapport und Ermittlungsprotokoll bleiben die Dokumente für die Akte. Die Oberfläche ersetzt sie
nicht, sie macht sie durchsuchbar und nachprüfbar.

Sie hat zwei Teile. Die **Ansichten** lesen die Fallakte und schreiben nie. Die **Bedienung** lässt den Sachbearbeiter
ohne Terminal arbeiten: Fall anlegen, Ermittlung starten, freigeben, Dokumente erzeugen. Sie ändert nichts selbst,
sondern ruft die bestehenden Werkzeuge auf, und nur für den, der die Oberfläche am Terminal gestartet hat.

Stand: 16.11.2026.

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

Mit der Bedienung arbeitet der Sachbearbeiter ohne Terminal: Dokument hineinziehen, Ermittlung starten, zusehen,
freigeben, Rapport holen. Ein Terminal braucht es nur noch für den Start.

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
startet, bekommt so kein Geheimnis in die Hand. Ein zweites Browserfenster kann lesen, aber nicht bedienen.

### Was sich bedienen lässt

| Funktion | Was geschieht | Womit |
|---|---|---|
| **Neuer Fall** | Dokument hineinziehen, Fall-ID und Titel. «Schon geschwärzt»: PII-Prüfung, dann in den Fall. «Klartext»: zuerst der lokale Bildschirm der Pseudonymisierung. Lehnt die PII-Prüfung ab, zeigt die Seite die Stellen maskiert, und es entsteht nichts. | `tools/fall.py neu`, `tools/pii_pruefung.py`, `tools/_pseudo.py` |
| **Weiteres Dokument** | Dasselbe für einen bestehenden Fall. Bei Klartext gilt die Zuordnungstabelle des Falls weiter: gleiche Angabe, gleicher Platzhalter. | `tools/fall.py aufnehmen` |
| **Ermittlung** | Starten, anhalten, fortsetzen. Sichtbar ist, welcher Analyst woran arbeitet. Neue Ergebnisse erscheinen laufend in Arbeitsspur und Ansichten. | Claude Code mit `/ermittlung <Fall-ID>` |
| **Freigaben** | Aktive Massnahmen, Dark Web und Kontoabfragen per Klick, mit «Durch» und «Grundlage». Fragt Claude Code für eine einzelne aktive Massnahme nach, erscheint die Frage als Dialog. | `tools/fall.py` (Funktion `freigabe_setzen`) |
| **Abklärung von Hand** | Formular für Indikator, Quelle, Zeit und Wortlaut. Der Eintrag geht in die Kette und ist als «von Hand erfasst» gekennzeichnet. | `tools/beleg.py` |
| **Dokumente** | Abschlussrapport, Ermittlungsprotokoll, Datenblätter und PDF neu erzeugen, Kette prüfen. Die Seite zeigt die Ausgabe des Werkzeugs. | `tools/rapport.py`, `protokoll.py`, `anhang.py`, `pdf.py`, `audit_pruefen.py` |
| **Zurückführen** | Der fertige Rapport mit echten Angaben, lokal, mit der Zuordnungstabelle. | `tools/reidentifizieren.py` |
| **Quellen** | Welche bereit sind und welche fehlen, eine Testabfrage je Quelle, das Kontingent von urlscan.io, Stand der lokalen Listen. Von Schlüsseln nur der Name der Variablen. | wie `tools/pruefen.py --live` |

Jeder dieser Schritte steht im Sitzungsprotokoll des Falls (`protokoll/sitzungen/`), mit Zeit und dem Vermerk
«Oberfläche», und erscheint im Ermittlungsprotokoll unter «Sitzungsverlauf». Eine Freigabe trägt den Vermerk zusätzlich
in `fall.json` (`"weg": "Oberfläche"`).

### Der Weg des Klartexts

Klartext bearbeitet nur der lokale Server, nie eine Claude-Sitzung.

1. Das Dokument geht vom Browser an den Server und liegt dort im Speicher. Word- und PDF-Dateien liegen für das Auslesen
   kurz in einem Ordner ausserhalb des Projekts, der danach verschwindet.
2. Der Bildschirm «Pseudonymisieren» zeigt den Text mit markierten Fundstellen: was ersetzt wird, was noch offen ist
   (Kandidaten), was stehen bleibt. Technische Indikatoren sind eigens gekennzeichnet und bleiben immer stehen.
   Annehmen, verwerfen, ergänzen: Jede Eingabe rechnet neu, damit sich eine Angabe im ganzen Dokument fortpflanzt.
   Dahinter steht dieselbe Bibliothek wie hinter `tools/pseudonymisieren.py`, ohne Sprachmodell und ohne Netz.
3. Erst das Ergebnis geht in die PII-Prüfung und über `tools/fall.py` in den Fall.
4. Die Zuordnungstabelle geht in die Ablage ausserhalb des Projektordners (`<Ablage>/<Fall-ID>/zuordnung.csv`, nur für
   den Benutzer lesbar). Sie steht in keinem Protokoll. Für Agenten sperrt der Wächter die Ablage.
5. Zurückführen schreibt den Rapport mit echten Angaben ebenfalls in die Ablage und zeigt ihn nur auf dem Bildschirm
   «Zurückführen».

Echte Angaben zeigt die Oberfläche nur auf diesen zwei Bildschirmen. Beide tragen das Band **«lokal, Klartext»**, und
ihren Inhalt gibt der Server nur gegen das Geheimnis heraus. Überall sonst stehen Platzhalter.

### Claude Code steuern

Die Oberfläche startet die Kommandozeile von Claude Code im Skriptbetrieb, mit fortlaufender JSON-Ausgabe:

```
claude -p "/ermittlung <Fall-ID>" --output-format stream-json --verbose
       --permission-prompt-tool mcp__oberflaeche__rueckfrage --mcp-config <Datei ausserhalb des Projekts>
```

- **Im Projektordner, ohne abschaltende Schalter.** Die Sitzung läuft im Projektordner. Die Oberfläche setzt keinen
  Schalter, der Einstellungen, Hooks oder MCP-Server des Projekts abschaltet (`--bare`, `--safe-mode`, `--restricted`,
  `--setting-sources`, `--strict-mcp-config`, `--dangerously-skip-permissions`). Wächter, Verbotsregeln, `.mcp.json`
  und die Protokoll-Hooks gelten also wie am Terminal.
- **Abbruch ohne Einstellungen des Projekts.** Claude Code meldet beim Start, welche MCP-Server es geladen hat. Fehlt
  darunter das Gateway des Projekts (`osint`), sind die Einstellungen des Projekts nicht geladen, und Wächter und
  Protokoll gälten nicht. Die Oberfläche beendet die Sitzung dann sofort und sagt es.
- **Modelle.** Kein Schalter für das Modell. Es bleibt, wie das Projekt es festlegt.
- **Rückfragen.** Verlangen die Einstellungen für ein Werkzeug eine Rückfrage (aktive Massnahmen), ruft Claude Code das
  Werkzeug `rueckfrage` eines kleinen MCP-Servers auf (`tools/ui/rueckfrage.py`). Der gibt die Frage an die Oberfläche
  weiter, und sie erscheint im Browser als Dialog. Erlauben gilt für diesen einen Aufruf. Ohne Antwort innert
  30 Minuten gilt die Frage als abgelehnt. Die Karte, mit der sich der MCP-Server bei der Oberfläche ausweist, taugt nur
  zum Fragen: Erlauben kann nur das Browserfenster mit dem Geheimnis. Eine Rückfrage stellt Claude Code für jeden
  Aufruf, den die Einstellungen des Projekts weder erlauben noch verbieten, nicht nur für aktive Massnahmen. Die
  Antwort geht als ein Textblock mit JSON zurück, wie die Dokumentation es verlangt.
- **Anhalten und fortsetzen.** Anhalten beendet den Prozess. Claude Code bricht dabei den laufenden Schritt ab. Was bis
  dahin abgefragt wurde, steht im Protokoll. Fortsetzen nimmt dieselbe Sitzung wieder auf (`--resume`) und gibt ihr
  den Auftrag weiterzumachen.
- **Wer woran arbeitet** liest die Oberfläche aus der JSON-Ausgabe: je Analyst der letzte Werkzeugaufruf und die Zahl
  der Schritte.

**Abrechnung: Abo oder API.** Eine Sitzung aus der Oberfläche rechnet über denselben Zugang ab wie `claude` am Terminal
desselben Benutzers. Einen eigenen API-Schlüssel braucht dieser Weg nicht. Stand: Dokumentation von Claude Code
(code.claude.com/docs, Seiten «Authentication», «Manage costs effectively» und «Run Claude Code programmatically»,
gelesen am 16.11.2026).

- **Mit einem Abo angemeldet** (`/login` mit Pro, Max, Ultra, Team oder Enterprise): Die Ermittlung zählt gegen das
  Kontingent des Abos, wie am Terminal. Sie verbraucht deutlich mehr als ein Gespräch, weil mehrere Analysten
  nebeneinander arbeiten.
- **Mit einem Console-Konto angemeldet oder `ANTHROPIC_API_KEY` gesetzt:** Abrechnung über die API, nach Verbrauch. Ist
  die Variable gesetzt, nimmt Claude Code im Skriptbetrieb immer den Schlüssel, auch wenn ein Abo angemeldet ist.
- Die Seite «Bedienen» sagt vor dem Start, über welchen Zugang abgerechnet wird, soweit es an der Umgebung abzulesen ist.
  Sie nennt nur den Namen der Variablen. Einen `apiKeyHelper` in den Einstellungen des Benutzers sieht sie nicht.
- **Nicht gewählt: das Agent SDK für Python.** Seine Dokumentation verweist für die Anmeldung auf API-Schlüssel, also
  Abrechnung nach Verbrauch, und es wäre eine neue Pflicht-Abhängigkeit. Es startet dieselbe Kommandozeile.

Zwei Dinge sind offen. Erstens die Bedingungen: Die Dokumentation zum Agent SDK hält fest, dass Dritte in ihren Produkten
ohne Zustimmung von Anthropic keine Anmeldung mit claude.ai anbieten dürfen. Die Oberfläche bietet keine Anmeldung an,
sie startet das installierte Claude Code des Sachbearbeiters mit dessen eigener Anmeldung. Ob ein Abo den Betrieb in
einer Dienststelle deckt, ist damit nicht gesagt. Die Bedingungen der Abos selbst sind nicht gelesen. Zweitens kündigt
die Dokumentation an, dass der Skriptbetrieb künftig von sich aus ohne die Einstellungen des Projekts startet (`--bare`
als Vorgabe) und dann nur noch mit API-Schlüssel läuft. Die Oberfläche merkt das am Start der Sitzung und beendet sie,
statt ohne Wächter zu arbeiten.

**Die Probe am eigenen Arbeitsplatz.** Dass eine aus der Oberfläche gestartete Sitzung wirklich unter Wächter und
Verbotsregeln läuft, zeigt ein Befehl mit dem echten Claude Code:

```bash
python3 tools/oberflaeche.py --sitzungsprobe          # am Terminal, verbraucht etwas Kontingent
```

Er startet zwei kurze Sitzungen auf demselben Weg wie «Ermittlung starten». In der ersten soll Claude Code zwei
gesperrte Befehle versuchen (sich eine Freigabe erteilen, die Schlüsseldatei anfassen). In der zweiten soll es ein
Werkzeug aufrufen, das eine Rückfrage verlangt, und die Probe lehnt ab. Erwartet wird: beide Befehle abgelehnt,
`fall.json` unverändert, die Rückfrage kommt bei der Oberfläche an. Die Probe nennt dazu, über welchen Zugang
abgerechnet wird und welche MCP-Server Claude Code geladen hat.

### Schutz der Bedienung

| Schutz | Wie er umgesetzt ist |
|---|---|
| Ändern nur mit Geheimnis | Jede ändernde Anfrage ist ein POST mit JSON und trägt das Geheimnis in einer Kopfzeile. Ohne es antwortet der Server mit 403 und ändert nichts. Host-Kopf und Herkunft prüft er wie beim Lesen. |
| Kein Geheimnis für Agenten | Der Startcode gilt einmal. Das Geheimnis steht in keiner Datei und in keiner Umgebung. Aus Claude Code oder ohne Terminal gestartet, läuft die Oberfläche «nur lesen». Ein Agent kann sich so über die Oberfläche keine Freigabe erteilen und keinen Beleg erfassen. |
| Die Kette bleibt die eine Wahrheit | Die Oberfläche schreibt nie selbst in Protokoll, Rohdaten oder `fall.json`. Sie ruft die bestehenden Werkzeuge auf. Das Sitzungsprotokoll schreibt der Hook, der es immer schreibt. |
| Wächter | Für Agenten bleiben Freigabe, Beleg von Hand, Pseudonymisieren und Zurückführen gesperrt. Neu lehnt der Wächter auch ab: den Aufruf der Funktionen an der Kommandozeile vorbei (`freigabe_setzen`, `beleg … erfassen`), den Aufruf der Bedienschicht aus der Shell (`tools/ui/bedienung.py`, `sitzung.py`: dort gäbe es kein Geheimnis, das einen Agenten aufhält), den Start der Oberfläche ohne `--nur-lesen` und jeden Zugriff auf die Ablage. Eine Ausnahme im Wächter oder in den Einstellungen braucht die Oberfläche nicht, der Wächter ist nur strenger geworden. |
| Die Ablage ist für Agenten gesperrt | Der Wächter lehnt Lesen, Suchen, Schreiben und Shell-Befehle ab, die in die Ablage zeigen. Er erkennt sie am Namen (Ordner `OSINT-Ablage`, Dateien `zuordnung….csv`) und an der Variablen `OSINT_ABLAGE`. Sitzungen, die die Oberfläche startet, bekommen die Variable mit. Wer eine eigene Ablage nimmt und Claude Code auch am Terminal startet, setzt `OSINT_ABLAGE` dauerhaft: Dann nimmt die Oberfläche diesen Ordner, und der Wächter kennt ihn in jeder Sitzung. |
| Klartext bleibt draussen | Siehe «Der Weg des Klartexts». Ablage und Zwischendateien liegen ausserhalb des Projektordners. Eine Ablage im Projektordner lehnt die Oberfläche ab. |

**Grenzen dieses Schutzes.** Er hält Agenten auf, die über die Werkzeuge von Claude Code arbeiten und dabei dem Wächter
unterliegen. Der Wächter prüft Shell-Befehle anhand ihres Textes: Er hält Versehen und fremdgesteuerte Agenten auf, keinen
Befehl, der die gesperrten Namen gezielt verschleiert. Ein solcher Befehl steht aber nicht auf der Erlaubt-Liste des
Projekts. In einer Sitzung aus der Oberfläche erscheint er deshalb als Rückfrage beim Sachbearbeiter, sofern dessen
eigene Einstellungen von Claude Code nicht mehr erlauben. Eine frei gewählte Ablage ohne `OSINT_ABLAGE` erkennt der
Wächter nur an den Namen der Dateien. Ein Programm mit den Rechten des Benutzers, das gezielt den Speicher des Servers ausliest oder den
Startcode in der halben Sekunde zwischen Start und Browserfenster aus der Prozessliste fischt, hält er nicht auf. Der
zweite Fall fiele auf: Das Browserfenster des Sachbearbeiters könnte dann nicht bedienen und sagt es.

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
  Oberfläche gelaufen. Schalter, Antwortform der Rückfrage und die Meldung der MCP-Server beim Start folgen der
  Dokumentation (gelesen am 16.11.2026). Nicht nachgelesen ist, ob die Variable `MCP_TOOL_TIMEOUT` eine Rückfrage
  wirklich 30 Minuten warten lässt. Die Probe dafür: `python3 tools/oberflaeche.py --sitzungsprobe`.
- **Anhalten unter Windows.** Dort beendet das System den Prozess hart. Ob Befehle, die Claude Code gerade ausführt,
  dabei mit enden, ist nicht geprüft.
- **Eine Rückfrage auf einmal.** Stellt Claude Code eine zweite, während die erste offen ist, gilt die zweite als abgelehnt.
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
