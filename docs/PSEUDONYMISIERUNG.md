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

## Wenn doch etwas durchrutscht

Findet ein Agent im Dokument offensichtlich echte Personendaten, hält er an und meldet die Stelle mit
Zeilennummer, ohne den Wert zu wiederholen. Dann:

1. Sitzung beenden.
2. Dokument im Haus nachpseudonymisieren.
3. Neu aufnehmen: `python3 tools/fall.py aufnehmen <Fall-ID> <Datei>`.
4. Nach euren internen Regeln beurteilen, ob der Vorfall zu melden ist. Die Daten waren zu diesem Zeitpunkt
   bereits bei Anthropic in Verarbeitung.
