# Muster: so sieht das Ergebnis aus

Die beiden Dokumente, die am Ende jeder Ermittlung stehen, am Beispiel eines **frei erfundenen Falls**
(Phishing gegen ein Kundenportal mit anschliessender Erpressung und Lösegeldzahlung). Alle Namen, Adressen,
Domains und Kennzahlen sind fiktiv: IP-Adressen aus den Dokumentationsbereichen, Domains unter `.example`,
Bitcoin-Adressen und Transaktionen aus einer erfundenen Kette. Sie haben gültige Prüfsummen, gehören aber niemandem.

| Dokument | Inhalt |
|---|---|
| [Abschlussrapport.pdf](Abschlussrapport.pdf) | Zusammenfassung, Indikatoren, zwölf Befunde mit «Einfach erklärt», Beziehungsgraf, Geldfluss der Lösegeldzahlung mit Flussbild, Zeitachse, Lücken, Empfehlungen, Glossar. 19 Seiten A4. |
| [Ermittlungsprotokoll.pdf](Ermittlungsprotokoll.pdf) | Alle 55 Abfragen und 4 Auswertungen mit Zeit, Quelle, Ziel, Zweck, Ergebnis, Prüfsumme, Rohdatei und ausführendem Agenten. Dazu Sitzungsverlauf und Integritätsprüfung. 19 Seiten A4. |

GitHub zeigt PDF direkt an. Die Originale sind HTML-Dateien, in denen jeder Beleg im Rapport auf seinen Eintrag
im Protokoll verlinkt. Sie liegen mit der ganzen Fallakte unter
[`faelle/MUSTER-2026-001/`](../faelle/MUSTER-2026-001/):

| Datei | Was sie zeigt |
|---|---|
| [`eingang/rapport_pseudonymisiert.md`](../faelle/MUSTER-2026-001/eingang/rapport_pseudonymisiert.md) | Das Eingangsdokument, wie es aus der Pseudonymisierung kommt |
| [`befunde.json`](../faelle/MUSTER-2026-001/befunde.json) | Die strukturierten Befunde, aus denen der Rapport gebaut wird |
| [`protokoll/abfragen.jsonl`](../faelle/MUSTER-2026-001/protokoll/abfragen.jsonl) | Das hash-verkettete Abfrageprotokoll |
| [`rohdaten/`](../faelle/MUSTER-2026-001/rohdaten/) | Die unveränderten Antworten der Quellen |
| [`rapport/`](../faelle/MUSTER-2026-001/rapport/) | Abschlussrapport und Ermittlungsprotokoll als HTML, Protokoll und Indikatoren als CSV |

## Was der Musterfall zeigt

- Vier Analysten arbeiten 55 Abfragen bei 19 Quellen ab. Die Antworten der Quellen sind vorgefertigt, alles
  andere läuft durch dieselben Werkzeuge wie eine echte Ermittlung.
- Der Blockchain-Analyst prüft die Lösegeldzahlung bei zwei Quellen, folgt dem Betrag über zwei Stationen und
  findet drei Enden: eine Börse (60 %), eine Adresse, auf der Geld liegt (20 %), einen Mischdienst (20 %). Der
  Rapport zeigt das als Flussbild und nennt das Editionsbegehren an die Börse als Empfehlung. Die 32 Abfragen
  dahinter stehen einzeln im Protokoll, die vier errechneten Ergebnisse als «Auswertung» mit Verweis darauf.
- Ein Treffer bleibt aus (VirusTotal kennt die URL nicht), eine Abfrage scheitert am Kontingent, eine aktive
  Massnahme wird mangels Freigabe abgelehnt, eine Abfrage kommt aus dem Fall-Cache. Alle vier stehen im
  Protokoll. Die gescheiterte und die abgelehnte Abfrage nennt der Rapport unter «Lücken», den fehlenden
  Treffer im Befund B-06.
- Sicherheit «hoch» tragen nur Befunde mit mindestens zwei verschiedenen Quellen. Die Zahlung selbst ist «hoch»
  (zwei Explorer zeigen dasselbe), ihr Weg über mehrere Stationen eine Bewertung mit «mittel». Eine Hypothese ist
  als solche gekennzeichnet. Zwei Befunde sind nur «mit Einschränkung» gegengeprüft, mit Begründung.
- Der Name der geschädigten Organisation bleibt ein Platzhalter. Was sich deshalb nicht prüfen liess, weist
  der Rapport als «im Haus nachzuholen» aus.

## Selbst erzeugen

```bash
python3 tools/musterfall.py                          # baut die Fallakte neu, ohne Netz und ohne Schlüssel
python3 tools/pdf.py MUSTER-2026-001 --nach muster   # erzeugt die beiden PDF (braucht Chrome, Chromium, Edge oder Brave)
```

Die Fallakte entsteht bei jedem Lauf bytegleich. Die PDF tragen ein Erstelldatum und unterscheiden sich darin.
