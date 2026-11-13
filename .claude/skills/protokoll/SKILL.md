---
name: protokoll
description: Erzeugt das Ermittlungsprotokoll eines Falls (wann wurde was, wo, wozu und durch wen abgefragt) als HTML und CSV und prüft die Unverändertheit der Protokollkette.
argument-hint: "<Fall-ID>"
disable-model-invocation: true
allowed-tools: Bash(python3 tools/protokoll.py *), Bash(python3 tools/audit_pruefen.py *)
---

# Ermittlungsprotokoll erzeugen

Fall: `$ARGUMENTS`

1. `python3 tools/protokoll.py <Fall-ID>` ausführen.
2. Die Ausgabe wiedergeben: Zahl der Abfragen, Ergebnis der Integritätsprüfung, letzter Kettenwert, Pfade der Dateien.
3. Meldet das Werkzeug Abweichungen in der Kette, nenne sie wörtlich und versuche nichts zu reparieren. Ein
   verändertes Protokoll ist ein Vorfall, den der Sachbearbeiter klären muss.

Das Protokoll speist sich aus zwei Quellen, die du nicht bearbeitest:

- `faelle/<Fall-ID>/protokoll/abfragen.jsonl`: jede Abfrage des Gateways mit Zeit, Quelle, Ziel, Zweck,
  maskierter Adresse, Status, Prüfsumme und Pfad der Rohdatei.
- `protokoll/sitzungen/*.jsonl`: Eingaben des Sachbearbeiters, alle Werkzeugaufrufe der Sitzung und der Subagenten.

Fragt der Sachbearbeiter, was zu einem bestimmten Indikator abgefragt wurde, durchsuche `abfragen.jsonl` nach dem
Wert und nenne P-Nummer, Zeit, Quelle und Ergebnis.
