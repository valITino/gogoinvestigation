# Pseudonymisierung

Rapporte und Nachträge enthalten Personendaten. Bevor ein Dokument diesen Arbeitsplatz erreicht, ersetzt euer
eigenes LLM im Haus diese Daten durch Platzhalter. Dieses Dokument beschreibt, wie die Platzhalter aussehen
müssen, was stehen bleibt, eine fertige Anweisung für euer LLM, und wie der fertige Rapport wieder zu echten
Angaben kommt.

## Der Weg eines Dokuments

```
Klartext ──(eigenes LLM, im Haus)──► pseudonymisiert + Zuordnungstabelle
                                          │                    │
                                          ▼                    └─ bleibt im Haus, ausserhalb des Projektordners
                             tools/fall.py  (PII-Prüfung)
                                          │
                                          ▼
                              Fallakte ► Ermittlung ► Abschlussrapport (pseudonymisiert)
                                                              │
                                tools/reidentifizieren.py ◄───┘  (im Haus, am Terminal, mit Zuordnungstabelle)
                                          │
                                          ▼
                                 Rapport mit echten Angaben
```

Claude Code sieht zu keinem Zeitpunkt die Zuordnungstabelle oder den zurückgeführten Rapport.

Fällt das LLM im Haus aus, übernimmt `tools/pseudonymisieren.py` den ersten Schritt: auf demselben Rechner, ohne
Sprachmodell und ohne Netz. Siehe [Rückfall ohne LLM](#rückfall-ohne-llm-toolspseudonymisierenpy).

**Nachbessern in der Oberfläche.** Kommt ein Dokument mit einer Lücke aus dem ersten Schritt (eine Telefonnummer blieb
stehen, ein Name wurde übersehen), braucht es keinen zweiten Lauf im Haus. In der Oberfläche unter «Neuer Fall» die Akten
hineinziehen: Jede Datei geht durch die PII-Prüfung, und die Seite zeigt, wo etwas stehen blieb. Die betroffenen Dateien
anhaken und «Nochmals pseudonymisieren»: Ein lokaler Bildschirm zeigt das Dokument mit markierten Fundstellen. Das
geschieht auf demselben Rechner, mit derselben Bibliothek wie der Rückfall, ohne Sprachmodell.

- Platzhalter aus dem ersten Schritt bleiben, wie sie sind. Neue zählen hinter der höchsten Nummer weiter: Steht im
  Dokument `[PERSON_08]`, heisst die nächste Person `[PERSON_09]`.
- Was die Oberfläche ersetzt, steht in einer eigenen Zuordnungstabelle in ihrer Ablage ausserhalb des Projekts
  (`<Ablage>/<Fall-ID>/zuordnung.csv`). Die Tabelle aus dem Haus kennt die Oberfläche nicht.
- In den Fall kommt von jedem Dokument die Textfassung, nie das Original, und nur, wenn die PII-Prüfung nichts mehr findet.

Einzelheiten: [OBERFLAECHE.md](OBERFLAECHE.md), «Akten-Eingang» und «Nochmals pseudonymisieren».

## Platzhalter

Form: eckige Klammern, Typ in Grossbuchstaben, Unterstrich, laufende Nummer. `[PERSON_01]`

| Platzhalter | Steht für |
|---|---|
| `[PERSON_01]` | natürliche Person (Geschädigte, Zeugen, Beschuldigte, Sachbearbeiter) |
| `[ORG_01]` | Firma, Behörde, Verein auf Geschädigten- oder Zeugenseite |
| `[ADRESSE_01]` | Wohn- oder Geschäftsadresse |
| `[TEL_01]` | Telefonnummer |
| `[EMAIL_01]` | E-Mail-Adresse einer Person oder der geschädigten Organisation |
| `[GEBDAT_01]` | Geburtsdatum |
| `[AHV_01]` | AHV-Nummer |
| `[KONTO_01]` | Bankverbindung, IBAN |
| `[KFZ_01]` | Kontrollschild |
| `[AUSWEIS_01]` | Ausweis- oder Aktennummer mit Personenbezug |
| `[DOMAIN_01]`, `[IP_01]` | Domain oder IP-Adresse, die der geschädigten Organisation gehört |

Drei Regeln, die über die Qualität der Ermittlung entscheiden:

1. **Nummerieren, nicht vereinheitlichen.** Wird jede Person zu «Hans Muster», weiss niemand mehr, wer die E-Mail
   erhielt und wer sie meldete. Jede Person bekommt ihre eigene Nummer.
2. **Gleiches bleibt gleich.** Dieselbe Person heisst im ganzen Dokument und in allen Nachträgen desselben Falls
   gleich. Die Zuordnungstabelle wird pro Fall fortgeschrieben.
3. **Die Rolle darf stehen bleiben.** «[PERSON_02], Sachbearbeiter der [ORG_01]» ist richtig. Die Rolle hilft
   der Ermittlung und identifiziert niemanden.

## Was stehen bleibt

Nach technischen Indikatoren wird gesucht. Sind sie ersetzt, gibt es nichts zu ermitteln.

| Bleibt stehen | Warum |
|---|---|
| IP-Adressen, Domains, URLs der Täterseite | Kern jeder Abfrage |
| Datei-Hashes, Dateinamen von Schadsoftware | Abfrage bei VirusTotal |
| E-Mail-Adressen der Täterseite (Absender der Phishing-Mail, Kontakt im Erpresserschreiben) | Domain und Adresse sind Indikatoren |
| Onion-Adressen | Abgleich mit Gruppen und Leak-Seiten |
| Wallet-Adressen und Transaktions-IDs von Zahlungen in Kryptowährungen, mit Währung, Betrag und Datum | Ohne sie lässt sich kein Geldfluss verfolgen. Das gilt auch für die Zahlung der geschädigten Person: Ihre Transaktions-ID bleibt stehen, ihr Name und ihr Kundenkonto bei der Börse nicht. |
| Namen von Tätergruppen, Malware-Familien, Kampagnen | Abfrage bei ransomware.live |
| Benutzernamen und Kanäle der Täterseite | nur mit Freigabe `personenbezug` abfragbar |
| Datum und Uhrzeit von Ereignissen | Zeitachse |

| Wird ersetzt | Hinweis |
|---|---|
| Alle natürlichen Personen | auch Sachbearbeiter und Unterzeichnende |
| Geschädigte Organisationen | siehe unten |
| Adressen, Telefonnummern, Geburtsdaten, AHV-Nummern, Bankverbindungen, Kontrollschilder | |
| E-Mail-Adressen und Domains der Geschädigten | Die Domain der geschädigten Firma verrät die Firma |
| Interne Aktenzeichen mit Personenbezug | Die Fall-ID im Arbeitsplatz ist eine eigene, neutrale Nummer |

**Grenzfälle, die ihr entscheiden müsst**

- *IP-Adressen und Konten der Täterseite sind auch Personendaten.* Sie müssen stehen bleiben, damit ermittelt
  werden kann, und gehen damit an Anthropic und an die abgefragten Dienste. Klärt mit Rechtsdienst und
  Datenschutz, für welche Arten von Indikatoren das zulässig ist.
- *Name der geschädigten Organisation.* Pseudonymisiert ist er sicher, aber dann lässt sich nicht prüfen, ob die
  Organisation auf einer Leak-Seite steht. Der Rapport nennt diese Abfrage unter «Lücken» als im Haus
  nachzuholen. Die Opferliste der Gruppe liegt dafür in den Rohdaten.
- *Infrastruktur der Geschädigten* (deren Server, deren Domain). In der Regel ersetzen. Soll sie untersucht
  werden, muss sie stehen bleiben, und der Auftrag muss es ausdrücklich sagen.

## Anweisung für euer LLM

Als Systemanweisung für das Modell im Haus. Anpassen, wo eure Dokumente anders aufgebaut sind.

```text
Du pseudonymisierst polizeiliche Rapporte und Nachträge. Du gibst zwei Dinge aus: das pseudonymisierte
Dokument und eine Zuordnungstabelle.

ERSETZEN durch Platzhalter der Form [TYP_NN] mit zweistelliger laufender Nummer je Typ:
- natürliche Personen (Vor- und Nachnamen, auch Kürzel und Unterschriften) → [PERSON_NN]
- Organisationen auf Geschädigten- und Zeugenseite → [ORG_NN]
- Wohn- und Geschäftsadressen → [ADRESSE_NN]
- Telefonnummern → [TEL_NN]
- E-Mail-Adressen von Personen und von geschädigten Organisationen → [EMAIL_NN]
- Geburtsdaten → [GEBDAT_NN]
- AHV-Nummern → [AHV_NN]
- Bankverbindungen und IBAN → [KONTO_NN]
- Kontrollschilder → [KFZ_NN]
- Ausweisnummern und Aktenzeichen mit Personenbezug → [AUSWEIS_NN]
- Domains und Hostnamen, die der geschädigten Organisation gehören → [DOMAIN_NN]
- IP-Adressen, die der geschädigten Organisation gehören → [IP_NN]

NICHT ERSETZEN, zeichengenau übernehmen:
- IP-Adressen, Domains und URLs, die der Täterseite zugeschrieben werden
- Datei-Hashes und Dateinamen verdächtiger Dateien
- E-Mail-Adressen, von denen Phishing, Betrug oder Erpressung ausging
- Onion-Adressen
- Wallet-Adressen und Transaktions-IDs von Zahlungen in Kryptowährungen, samt Währung, Betrag und Datum
- Namen von Tätergruppen, Schadsoftware, Kampagnen
- Benutzernamen und Kanäle, über die Täter auftraten
- Datum und Uhrzeit von Ereignissen
- Rollen und Funktionen ("Leiterin Finanzen", "Geschädigter", "Beschuldigte")

REGELN:
1. Dieselbe Person, Organisation oder Angabe erhält im ganzen Dokument denselben Platzhalter.
2. Liegt eine Zuordnungstabelle aus einem früheren Dokument desselben Falls vor, führst du sie fort und
   vergibst für bereits bekannte Einträge keine neuen Nummern.
3. Die Rolle einer Person bleibt neben dem Platzhalter stehen.
4. Bist du unsicher, ob eine Angabe der Täter- oder der Geschädigtenseite gehört, ersetzt du sie und
   vermerkst sie am Ende unter "Zur Klärung".
5. Du änderst sonst nichts am Text: keine Zusammenfassung, keine Korrekturen, keine Auslassungen.
6. Nummerierung der Ziffern und Abschnitte bleibt erhalten, damit Fundstellen zitierbar sind.

AUSGABE:
--- DOKUMENT ---
(der pseudonymisierte Text)
--- ZUORDNUNG ---
(eine Zeile je Platzhalter im Format [TYP_NN];Klartext)
--- ZUR KLÄRUNG ---
(Angaben, bei denen die Zuordnung zu Täter- oder Geschädigtenseite unklar war, mit Fundstelle)
```

Die Zuordnung speichert ihr als CSV-Datei **ausserhalb des Projektordners**, das Dokument als `.txt`, `.md`
oder `.docx`.

## Rückfall ohne LLM: tools/pseudonymisieren.py

**Stand: nicht abgeschlossen.** Feldmarken und Vornamenliste sind vorläufig (siehe unten). Die Messwerte im
[README](../README.md#pseudonymisieren-ohne-llm-der-rückfall) gelten für diese vorläufigen Listen und für erfundene
Rapporte.

### Wofür

Für den Tag, an dem das LLM im Haus nicht läuft. Das Werkzeug ersetzt Personendaten durch dieselben Platzhalter
wie oben und schreibt dieselbe Zuordnungstabelle. Es rechnet nur auf dem eigenen Rechner: Standardbibliothek von
Python, kein Download, kein Sprachmodell, keine Netzverbindung (es sperrt sich das Netz beim Start selbst). Es
schlägt vor, ein Mensch entscheidet.

### Aufruf

```bash
python3 tools/pseudonymisieren.py /sicher/rapport.docx \
    --zuordnung /sicher/2026-0412_zuordnung.csv \
    --ausgabe   /sicher/pseudonymisiert/ \
    --namen     /sicher/2026-0412_namen.txt        # wahlweise
```

| Angabe | Bedeutung |
|---|---|
| Dokument | `.txt`, `.md`, `.docx` oder `.pdf` mit Text. Ausserhalb des Projektordners. |
| `--zuordnung` | Zuordnungstabelle des Falls. Fehlt sie, wird sie angelegt. Gibt es sie, wird sie fortgeschrieben. |
| `--ausgabe` | Ordner für das Ergebnis `<Name>_pseudonymisiert.txt`. Ausserhalb des Projektordners. |
| `--namen` | Namensliste zum Fall: eine Angabe je Zeile, `Hans Muster` oder `ORG;Muster AG`. Was darin steht, wird ohne Rückfrage ersetzt. |
| `--feldmarken` | Eine andere Feldmarken-Liste als `tools/feldmarken.txt`. |

Das Werkzeug läuft nur an einem Terminal. Aus Claude Code heraus startet es nicht, auch nicht über `!`: Was es
auf den Bildschirm schreibt, ist Klartext und stünde sonst im Gespräch. Die Berechtigungen verbieten den Aufruf
für Agenten.

### Ablauf am Bildschirm

Das Werkzeug liest das Dokument, zeigt eine Übersicht und führt durch vier Schritte. Jede Fundstelle erscheint mit
ihrer Zeile und dem Text davor und danach.

1. **E-Mail-Adressen.** Die Adresse der Täterseite ist ein Indikator und bleibt stehen. Die Adresse der
   Geschädigten wird ersetzt. Das Werkzeug kann die Seite nicht kennen und fragt, ausser die Adresse steht hinter
   einer Feldmarke oder trägt den Namen einer bekannten Person. Entschärft geschriebene Adressen
   (`name[at]beispiel[.]ch`) gelten als Indikator.
2. **Kandidaten.** Mögliche Namen und Firmen im Fliesstext. `[j]` ersetzen, `[n]` stehen lassen, `[t]` mit anderem
   Typ ersetzen, `[k]` den Wortlaut korrigieren (aus «Keller» wird «Anna Keller»). Was du annimmst, sucht das
   Werkzeug sofort im ganzen Dokument.
3. **Sichere Funde.** Jede Angabe mit ihren Fundstellen: alle ersetzen, einzeln durchgehen, stehen lassen oder
   den Typ ändern. Passt ein Nachname auf zwei Personen, steht «ACHTUNG: passt auf mehrere Personen» dabei.
4. **Ergänzen.** Was fehlt, gibst du ein: einen Namen, eine Firma, eine Nummer. Das Werkzeug sucht die Angabe in
   allen Schreibweisen.

Erst danach wird geschrieben. `[q]` bricht jederzeit ab, ohne etwas zu schreiben. Am Schluss läuft die PII-Prüfung
über das Ergebnis und zeigt ihre Funde maskiert. **Lies das Ergebnis, bevor du es aufnimmst.** Die Aufnahme in
einen Fall prüft noch einmal (`tools/fall.py`), sie bleibt die letzte Schranke.

### Die Schichten

| Schicht | Was sie tut |
|---|---|
| 0 Schutz | Markiert, was stehen bleiben muss (Tabelle «Bleibt stehen» oben): IP-Adressen, Domains, URLs, Hashes, Wallet-Adressen, Transaktions-IDs, Onion-Adressen, Dateinamen, auch entschärft geschrieben (`hxxp`, `[.]`). Keine spätere Schicht ersetzt diese Stellen. Kommt ein bekannter Name darin vor (`…/hans.muster/…`, `Rechnung_Muster.pdf`), legt das Werkzeug die Stelle vor, statt sie zu ersetzen. |
| 1 Feldmarken | Liest den Wert hinter jeder Marke aus `tools/feldmarken.txt`. |
| 2 Fortpflanzung | Sucht jede bekannte Angabe im ganzen Dokument: Gross- und Kleinschreibung, «Muster, Hans», «Muster Hans», «H. Muster», Genitiv, Zeilenumbruch, Silbentrennung am Zeilenende, «Mueller» und «Muller» für «Müller», Telefonnummern mit `+41`, `0041`, Schrägstrich oder ohne Trennzeichen, Daten als `1.2.1980`, `1. Februar 1980` oder `1980-02-01`, IBAN mit und ohne Leerzeichen, «Dorfstr. 12» für «Dorfstrasse 12». |
| 3 Muster | Die Muster der PII-Prüfung (`tools/pii_pruefung.py`), dieselben, nicht nachgebaut. Beim Geburtsdatum bleibt das Stichwort stehen («geb. [GEBDAT_01]»), bei der Strassenadresse gehört der Ort mit Postleitzahl dazu. Das Datum eines Ereignisses ist kein Geburtsdatum und bleibt. |
| 4 Namensliste | Was mit `--namen` mitgegeben wird. |
| 5 Kandidaten | Wörter nach «Herr», «Frau», «Hr.», «Fr.», «Dr.», «Familie», «Monsieur», «Madame», «M.», «Mme», «Signor», «Signora», «Sig.», «Sig.ra» und nach Dienstgraden; ein Vorname aus `tools/vornamen.txt` mit einem Namen danach; ein Wort in Grossbuchstaben mit einem Namen danach; eine Initiale mit einem Namen danach; Wörter vor einer Rechtsform («AG», «GmbH», «SA», «Sàrl», «Sagl») oder nach «Firma», «Garage», «Bäckerei». Diese Schicht ersetzt nie selbst. |
| 6 Bestätigung | Der Dialog oben. |

### Die Feldmarken

`tools/feldmarken.txt` ist eine Textdatei, eine Zeile je Marke: `Marke ; Typ ; Teil`. Der Kopf der Datei erklärt
die Spalten. **Die mitgelieferte Liste ist vorläufig**: übliche Marken aus Formularen, deutsch, französisch und
italienisch. Sie ist nicht die Liste eurer Rapporte. Eure Liste ersetzt die Datei, am Code ändert sich nichts.
Danach neu messen:

```bash
python3 tools/pseudo_messen.py            # Tabellen ansehen
python3 tools/pseudo_messen.py --readme   # Tabellen ins README schreiben
```

Der Prüfsatz baut seine Rapporte aus genau den Marken der Datei. Mit einer neuen Liste entstehen also neue
Rapporte, und die Messung gilt für die neue Liste.

Gelesen wird der Wert auf derselben Zeile («Name: Muster», «Name    Muster», «Name Muster»), auf der nächsten
Zeile, in der nächsten Tabellenzelle und unter einem Spaltenkopf. «Name» und «Vorname» nahe beieinander ergeben
eine Person, «Strasse» und «PLZ/Ort» eine Adresse. Steht hinter einer Marke nichts Brauchbares («Name: unbekannt»),
wird nichts geerntet. Ein Wort mit Doppelpunkt mitten in einem Satz («… Sitz der Firma: …») ist keine Marke.

### Mehrere Dokumente eines Falls

Gleiche Angabe, gleicher Platzhalter. Mit `--zuordnung` auf die Tabelle des Falls erkennt das Werkzeug im Nachtrag,
wer im Rapport schon vorkam, auch wenn die Person dort nur noch als «Herr Muster» im Fliesstext steht. Neue
Angaben bekommen die nächste freie Nummer. Bestehende Zeilen der Tabelle bleiben, wie sie sind, auch Zeilen mit
Platzhaltern, die das Werkzeug nicht kennt.

### Die Vornamenliste

`tools/vornamen.txt` dient nur Schicht 5. **Sie ist vorläufig**: rund 800 häufige Vornamen, von Hand
zusammengestellt, aus keiner fremden Datei. Vorgesehen ist die Vornamenstatistik des Bundesamtes für Statistik
(BFS), «Vornamen der Bevölkerung nach Jahrgang, Schweiz und Sprachgebiete», BFS-Nummer su-d-01.04.00.11.

- Nutzungsbedingung laut Seite des Datensatzes, gesehen am 16.11.2026: «OPEN-BY: Freie Nutzung. Quellenangabe ist
  Pflicht.»
- Die allgemeine Seite «Nutzungsbedingungen» des BFS nennt daneben eine Bewilligung für die Weitergabe von Daten
  zu Erwerbszwecken. Ob das eine Liste von Vornamen in einem Repository betrifft, entscheidet der Eigentümer des
  Repositorys, bevor die Liste des BFS darin abgelegt wird.
- Die Datei liess sich aus der Entwicklungsumgebung nicht abrufen (die Berechtigungsprüfung hat den Abruf
  abgelehnt). Wer die beiden Tabellen (Männer, Frauen) von Hand heruntergeladen hat:
  `python3 tools/vornamen.py bauen maenner.xlsx frauen.xlsx --stand 2025`. Das Werkzeug schreibt Quelle, Ausgabe,
  Datum der Kopie und Nutzungsbedingung in den Kopf der Liste. Es ist an erfundenen Tabellen geprüft, nicht an
  der Datei des BFS.

### Messwerte

Die Tabellen stehen im [README](../README.md#pseudonymisieren-ohne-llm-der-rückfall) und werden vom Messwerkzeug
geschrieben. In Worten:

- Angaben, die in einem Feld stehen, werden an allen ihren Stellen fast vollständig ersetzt, ohne Zutun des
  Menschen. Voraussetzung ist, dass die Marke in der Liste steht.
- Angaben, die nur im Fliesstext stehen (Drittpersonen, weitere Firmen), ersetzt keine Schicht von selbst.
  Schicht 5 legt den grössten Teil vor. Was auch dann stehen bleibt: Namen ohne Anrede, deren Vorname nicht in
  der Liste steht, Firmen ohne Rechtsform, Ausweisnummern ohne Feld.
- Kein technischer Indikator wird verändert.
- Die Messung läuft an erfundenen Rapporten, die derselbe Verfasser geschrieben hat wie die Erkennung. Sie zeigt,
  ob die Schichten tun, was sie sollen. Wie eure Rapporte aussehen, zeigt sie nicht.

### Grenzen

- **Kein Werkzeug findet alles.** Das Ergebnis wird gelesen, bevor es aufgenommen wird.
- **Scans ohne Text gehen nicht.** Ein gescanntes PDF braucht zuerst eine Texterkennung im Haus.
- **Die Gestaltung geht verloren.** Aus `.docx` und `.pdf` entsteht eine Textdatei. Tabellen werden zu Zeilen mit
  Tabulatoren.
- **Namen ohne jeden Hinweis** (keine Anrede, kein Feld, Vorname nicht in der Liste) sieht das Werkzeug nicht.
  Dafür sind die Namensliste und Schritt 4 da.
- **Firmen ohne Rechtsform** («Velo Meier») sieht es nur nach einem Gewerbewort aus einer kurzen Liste.
- **Der blosse Wohnort** ohne Postleitzahl bleibt stehen, ebenso Heimatort, Beruf, Nationalität und Alter. Wo das
  jemanden erkennbar macht, in Schritt 4 ergänzen.
- **«Herr Muster» und «Frau Muster»** kann es nicht auseinanderhalten. Bei zwei Personen mit demselben Nachnamen
  meldet es die Stelle als mehrdeutig und nimmt den ersten.
- **Doppelte Vornamen und Doppelnamen ohne Bindestrich** («Maria Grazia Schmid») lassen sich nicht sicher trennen.
  Das Werkzeug nimmt dann jede Trennung an und ersetzt lieber einen Namensteil zu viel.
- **Die Seite einer E-Mail-Adresse, Domain oder IP-Adresse** kennt es nicht. Domains und IP-Adressen bleiben
  stehen. Gehören sie den Geschädigten, in Schritt 4 als «Domain der Geschädigten» oder «IP-Adresse der
  Geschädigten» ergänzen.
- **Kontrollschilder** erkennt das Muster auch in «ZH 2024» (Kanton und Jahr). In Schritt 3 verwerfen. Die
  PII-Prüfung sperrt an derselben Stelle, dort mit Begründung übersteuern.
- **Rechtschreibfehler im Namen** («Mustre») findet es nicht.

### Zwei Wege, die verworfen sind

- **Claude liest den Klartext und pseudonymisiert ihn selbst.** Dann sind die Personendaten an Anthropic
  übermittelt, bevor der erste Platzhalter steht. Genau das soll die Pseudonymisierung verhindern.
- **Ein Inkognito-Chat.** Er ändert, was aufbewahrt wird, nicht, dass der Text das Haus verlässt und dort
  verarbeitet wird.

### Ein lokales Sprachmodell als spätere Schicht

Für Namen ohne jeden Hinweis ist ein Modell, das auf dem eigenen Rechner läuft (GLiNER, Flair), die naheliegende
Ergänzung. Es ist nicht eingebaut: Es bräuchte ein Zusatzpaket und ein heruntergeladenes Modell, beides sind
Entscheide des Hauses. Die Schnittstelle steht bereit. `erkennen(text, erkenner=[funktion])` in `tools/_pseudo.py`
nimmt eine Funktion, die einen Text liest und Kandidaten liefert: `(Beginn, Ende, Typ, Grund)`. Sie erscheinen
in Schritt 2 neben den Kandidaten von Schicht 5 und werden wie diese nie ohne Bestätigung ersetzt. Geschützte
Stellen und schon gefundene Angaben kann ein solcher Erkenner nicht überschreiben.

## Das Sicherheitsnetz: PII-Prüfung

Kein Modell pseudonymisiert fehlerfrei. Deshalb durchläuft jedes Dokument bei der Aufnahme eine Musterprüfung:

```bash
python3 tools/fall.py neu 2026-0412 --rapport rapport_pseudonymisiert.docx
```

| Erkannt wird | Stufe | Folge |
|---|---|---|
| AHV-Nummer, IBAN (mit Prüfziffer), Telefonnummer, Geburtsdatum mit Stichwort, Kontrollschild, Kreditkartennummer | Sperre | Dokument wird nicht aufgenommen |
| E-Mail-Adresse, Strassenadresse | Hinweis | Aufnahme, mit Meldung. Adressen der Täterseite dürfen bleiben. |
| Keine Platzhalter im Dokument | Hinweis | Vermutlich nicht pseudonymisiert |

Telefonnummern erkennt die Prüfung in den Schreibungen `079 123 45 67`, `+41 79 123 45 67`, `0041 79 …`,
`079/123 45 67` und ohne Trennzeichen (`0791234567`).

Die Ausgabe zeigt Fundstellen maskiert (`07••••••••7`, Zeile 14), nie den Wert.

**Die Prüfung erkennt keine Namen.** Ein übersehener Name geht durch. Sie fängt die Ausrutscher ab, die sich an
ihrer Form erkennen lassen, mehr nicht.

Fehlalarm? Am Terminal übersteuern, mit Begründung, die im Register festgehalten wird:

```bash
python3 tools/fall.py aufnehmen 2026-0412 rapport.docx --trotzdem "ZH 2024 ist eine Jahreszahl" --durch "ABC"
```

Nach der Aufnahme wacht ein Hook darüber, dass Agenten im Eingang nur lesen, was die Prüfung freigegeben hat.
Eine von Hand hineinkopierte oder nachträglich geänderte Datei ist für sie gesperrt.

Zwei Dinge umgehen das Netz und sind deshalb zu unterlassen:

- Dokumente mit `@datei` in den Prompt hängen. Claude Code fügt sie ohne Prüfung ein.
- Text aus einem Rapport direkt in den Prompt kopieren.

## Zurückführen

Der Abschlussrapport enthält dieselben Platzhalter wie das Eingangsdokument. Zurückgeführt wird im Haus, am
Terminal, ausserhalb von Claude Code:

```bash
python3 tools/reidentifizieren.py 2026-0412 \
    --zuordnung /sicher/2026-0412_zuordnung.csv \
    --ausgabe   /sicher/ablage/
```

Das Werkzeug

- läuft nur an einem Terminal, nicht aus einem Agenten heraus,
- verlangt, dass Zuordnungstabelle und Ausgabeordner ausserhalb des Projektordners liegen,
- zeigt auf dem Bildschirm nur Zahlen,
- meldet Platzhalter, für die die Tabelle keinen Eintrag hat.

Format der Zuordnungstabelle: zwei Spalten, Strichpunkt, keine Kopfzeile.

```
[PERSON_01];Hans Muster
[ORG_01];Muster AG
```

**Zwei Tabellen.** Wurde in der Oberfläche nachgebessert, gibt es zwei Zuordnungstabellen: die aus dem Haus und die
der Oberfläche (`<Ablage>/<Fall-ID>/zuordnung.csv`). Sie teilen keinen Platzhalter, solange alle Dokumente des Falls
durch den Akten-Eingang der Oberfläche gingen, denn neue Platzhalter zählen hinter den vorhandenen weiter. Zum
Zurückführen hängt ihr die beiden Dateien aneinander und gebt die gemeinsame Tabelle an, am Terminal mit `--zuordnung`
oder in der Oberfläche unter «Bedienen», «Zurückführen». Mit ihrer eigenen Tabelle allein führt die Oberfläche nur
zurück, was sie selbst ersetzt hat. Die übrigen Platzhalter bleiben stehen und werden genannt.

## Wenn doch etwas durchrutscht

Findet ein Agent im Dokument offensichtlich echte Personendaten, hält er an und meldet die Stelle mit
Zeilennummer, ohne den Wert zu wiederholen. Dann:

1. Sitzung beenden.
2. Dokument im Haus nachpseudonymisieren.
3. Neu aufnehmen: `python3 tools/fall.py aufnehmen <Fall-ID> <Datei>`.
4. Nach euren internen Regeln beurteilen, ob der Vorfall zu melden ist. Die Daten waren zu diesem Zeitpunkt
   bereits bei Anthropic in Verarbeitung.
