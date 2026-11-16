---
name: abschlussrapport
description: Schreibt befunde.json für einen Fall und erzeugt daraus den Abschlussrapport mit Diagrammen, Beziehungsgraf, Geldfluss und Zeitachse. Enthält das Schema von befunde.json, die Prüfregeln und die Schreibregeln für verständliche Befunde. Verwenden, wenn Befundmeldungen zu einem Rapport verdichtet oder ein Rapport überarbeitet werden soll.
argument-hint: "<Fall-ID>"
model: claude-fable-5-2
---

# Abschlussrapport

Fall: `$ARGUMENTS`

Der Rapport entsteht nicht als Fliesstext, sondern aus `faelle/<Fall-ID>/befunde.json`. `tools/rapport.py` prüft
die Datei und baut daraus das Dokument mit Diagrammen. So ist jede Aussage an ihre Belege gebunden, und die
Darstellung ist in jedem Fall dieselbe.

## Ablauf

1. Lies `arbeitsstand/indikatoren.json` und alle Befundmeldungen in `arbeitsstand/`.
2. Lies zu jeder Zahl und jedem Datum, das du übernimmst, die Rohdatei oder das Protokoll nach, wenn die
   Befundmeldung nicht eindeutig ist. `protokoll/abfragen.jsonl` (P-Nummern) und `protokoll/extern.jsonl`
   (X-Nummern) sagen zu jedem Beleg Quelle, Ziel und Ergebnis.
3. Schreibe `befunde.json`.
4. `python3 tools/rapport.py <Fall-ID> --nur-pruefen`, Mängel beheben, wiederholen.
5. Nach der Gegenprüfung: `python3 tools/rapport.py <Fall-ID>` und `python3 tools/protokoll.py <Fall-ID>`.

## Schema von befunde.json

```json
{
  "fall_id": "<Fall-ID>",
  "stand": "2026-11-12T09:30:00Z",
  "zusammenfassung": ["Absatz 1: was geschah und was die Ermittlung ergab.", "Absatz 2: was offen ist."],
  "kernaussagen": [
    {"text": "Ein Satz.", "sicherheit": "hoch", "befunde": ["B-01", "B-03"]}
  ],
  "ausgangslage": ["Optional: Sachverhalt in zwei bis drei Sätzen, nur mit Platzhaltern."],
  "vorgehen": ["Optional: Besonderheiten des Vorgehens. Fehlt das Feld, steht ein Standardtext."],
  "indikatoren": [
    {"id": "I-01", "typ": "ip", "wert": "203.0.113.7", "herkunft": "Rapport Ziff. 5",
     "rolle": "Server der Täter", "bewertung": "boesartig",
     "kennzahlen": {"abuse_score": 87, "vt_boesartig": 9, "vt_gesamt": 93, "offene_ports": [22, 443]},
     "belege": ["P-0001", "P-0002"]}
  ],
  "befunde": [
    {"id": "B-01", "titel": "Aussage als ganzer Satz", "art": "feststellung",
     "text": "Was die Quellen zeigen, mit Zahlen und Daten.",
     "erlaeuterung": "Dasselbe für jemanden ohne IT-Kenntnisse, mit einem Vergleich aus dem Alltag und der Folge für den Fall.",
     "sicherheit": "hoch", "quellenbewertung": "B2",
     "indikatoren": ["I-01"], "belege": ["P-0001", "P-0011"],
     "gegenpruefung": "offen", "gegenpruefung_notiz": ""}
  ],
  "beziehungen": [
    {"von": "I-02", "nach": "I-01", "art": "zeigt auf", "sicherheit": "hoch", "belege": ["P-0011"]},
    {"von": "I-04", "nach": "I-02", "art": "Anmeldung nach Abgriff", "sicherheit": "mittel", "quelle": "Rapport Ziff. 3"}
  ],
  "geldfluesse": [
    {"beleg": "P-0042", "titel": "Verbleib der Lösegeldzahlung vom 10.09.2026",
     "text": "Optional: ein bis zwei Sätze, was das Bild zeigt.", "befunde": ["B-06"]}
  ],
  "zeitachse": [
    {"zeit": "2026-09-26T07:41:00Z", "ereignis": "Registrierung der Domain.", "belege": ["P-0011"]},
    {"zeit": "2026-10-01", "ereignis": "Erpresserschreiben trifft ein.", "quelle": "Rapport Ziff. 6"}
  ],
  "luecken": ["Was nicht geklärt werden konnte und warum, mit P-Nummer bei fehlgeschlagenen Abfragen."],
  "empfehlungen": [{"text": "Nächster Schritt.", "prioritaet": "hoch"}],
  "glossar": [{"begriff": "VPN", "erklaerung": "Ein Satz in Alltagssprache."}]
}
```

Erlaubte Werte:

| Feld | Werte |
|---|---|
| `typ` | `ip` `domain` `url` `hash` `email` `onion` `wallet` `transaktion` `gruppe` `konto` `sonstiges` |
| `bewertung` | `boesartig` `verdaechtig` `unauffaellig` `unbekannt` |
| `art` | `feststellung` `bewertung` `hypothese` |
| `sicherheit` | `hoch` `mittel` `tief` |
| `gegenpruefung` | `offen` `bestaetigt` `eingeschraenkt` `widerlegt` |
| `prioritaet` | `hoch` `mittel` `tief` |
| `kennzahlen` | `abuse_score` (0–100), `vt_boesartig` und `vt_gesamt` (Anzahl Scanner), `offene_ports` (Liste). Diese erscheinen als Diagramm. Weitere Schlüssel sind erlaubt und erscheinen in der Tabelle. |

Zeiten als UTC mit `Z` oder als reines Datum. Der Generator rechnet in Ortszeit um.

## Was rapport.py verlangt

- Jeder Beleg (`P-…` vom Gateway, `X-…` von Robin und anderen Werkzeugen) existiert im Protokoll der Fallakte
  und war keine fehlgeschlagene oder abgelehnte Abfrage.
- Feststellung und Bewertung haben mindestens einen Beleg. Eine Hypothese darf ohne Beleg sein, aber nie `hoch`.
- `sicherheit: hoch` verlangt Belege aus mindestens zwei verschiedenen Quellen.
- Jeder Befund hat eine `erlaeuterung`.
- Jeder Indikator hat `herkunft`. Wer als `boesartig` oder `verdaechtig` gilt, hat einen Beleg.
- Beziehungen und Zeitpunkte stützen sich auf `belege` oder auf `quelle` (Fundstelle im Eingangsdokument).
- Für den endgültigen Rapport ist jeder Befund gegengeprüft. `widerlegt` darf nicht stehen bleiben.
- Bei einer Auswertung des Gateways (`krypto_…`) zählen für `hoch` die Quellen, aus denen ihre Tatsachen stammen
  (Feld `quellen` im Protokolleintrag). Ein Geldfluss aus einer Quelle ist also höchstens `mittel`.
- `geldfluesse`: `beleg` ist die `protokoll_id` eines Laufs von `krypto_geldfluss`, wie sie in der Befundmeldung des
  Blockchain-Analysten steht. Das Flussbild, die Tabellen und die Ansatzpunkte darunter erzeugt der Generator aus der
  Rohdatei dieser Auswertung. Du schreibst dazu nur Titel und einen kurzen Text.

Meldet das Werkzeug einen Mangel, behebst du ihn an der Sache: Beleg nachtragen, Sicherheit senken, Aussage zur
Hypothese machen oder streichen. Du erfindest keine P-Nummern und verbiegst keine Aussage, damit sie durchgeht.

## Bewertung der Indikatoren

- `boesartig`: Mehrere Quellen oder eine eindeutige Quelle belegen die schädliche Nutzung.
- `verdaechtig`: Hinweise, aber auch harmlose Erklärungen möglich. Auch: Dienste, die von Tätern und Unbeteiligten
  genutzt werden (VPN-Ausgang, geteiltes Hosting).
- `unauffaellig`: abgefragt, nichts Belastendes. Das heisst nicht «harmlos».
- `unbekannt`: nicht abfragbar oder keine Quelle kennt ihn.

## Schreibregeln

**Titel sind Aussagen.** «Die Domain wurde drei Tage vor der Tat registriert», nicht «Domain-Analyse».

**`text` nennt die Quelle und die Zahl.** «AbuseIPDB führt 64 Meldungen von 23 Meldern, zuletzt am 05.10.2026.»
Keine Wertungen wie «hochgradig verdächtig» ohne Zahl dahinter.

**`erlaeuterung` übersetzt.** Zwei bis vier Sätze für jemanden, der nicht weiss, was eine IP-Adresse ist. Ein
Vergleich aus dem Alltag hilft («wie ein Name im Telefonbuch und die Nummer dahinter»). Der letzte Satz sagt,
was der Befund für den Fall bedeutet. Keine Abkürzung, die nicht im Glossar steht.

**Die Zusammenfassung steht für sich.** Wer nur sie liest, kennt das Ergebnis und die wichtigste offene Frage.
Erst das Ergebnis, dann die Einschränkung. Keine Methodenbeschreibung.

**Lücken sind Befunde.** Jede fehlgeschlagene oder abgelehnte Abfrage, jede fehlende Freigabe, jede Frage, die nur
mit Klarnamen zu klären wäre, steht unter `luecken`, mit dem Grund.

**Empfehlungen sind konkrete nächste Schritte** für die fallführende Stelle: wer, was, bei wem. Rechtliche Schritte
benennst du als Möglichkeit, die Würdigung liegt bei der Stelle.

**Geldflüsse sind Bewertungen.** Eine einzelne Zahlung ist eine Feststellung («Am 10.09.2026 gingen 0.5 BTC von
A an B»). Was über mehrere Stationen zugeordnet ist («60 % des Lösegelds landeten bei einer Börse»), ist eine
Bewertung: `art: "bewertung"`, höchstens `mittel`, und der Text nennt das Verfahren in einem Satz. Beträge,
Anteile und Gegenwerte übernimmst du wörtlich aus der Rohdatei der Auswertung. Gegenwerte immer mit dem Zusatz
«zum Kurs am Tag der Zahlung». Ein Etikett («laut WalletExplorer eine Adresse von …») bleibt die Angabe eines
Dritten. Empfehlungen nennen die Stelle, die den Kunden kennt oder sperren kann, nie eine Person.

**Platzhalter bleiben stehen**, genau so wie im Eingangsdokument: `[PERSON_01]`. So lässt sich der Rapport im Haus
wieder zuordnen.

**Glossar:** jeder Fachbegriff, der im Rapport vorkommt, ein Satz.

Zum Aufbau eines fertigen Falls siehe `faelle/MUSTER-2026-001/befunde.json`.
