---
name: ermittlung
description: Führt eine OSINT-Ermittlung zu einem Fall von Anfang bis Ende durch. Legt den Fall bei Bedarf an, zieht die Indikatoren, setzt das Ermittler-Team ein, lässt die Befunde gegenprüfen und erzeugt Abschlussrapport und Ermittlungsprotokoll.
argument-hint: "<Fall-ID> [Pfad zum pseudonymisierten Dokument]"
disable-model-invocation: true
model: claude-mythos-5-2
---

# Ermittlung durchführen

Argumente: `$ARGUMENTS`
Das erste Argument ist die Fall-ID. Alles danach sind Pfade zu pseudonymisierten Dokumenten (optional).

Du leitest die Ermittlung. Die Abfragen machen die Analysten in eigenen Kontexten, damit dein Kontext frei
bleibt für Überblick und Qualität. Arbeite die Phasen der Reihe nach ab. Halte nur an, wo es unten verlangt ist:
Der Sachbearbeiter will ein Ergebnis, keine Rückfragen.

Zwei Modelle teilen sich die Arbeit, und die Zuteilung steht fest in den Dateien: Dieser Skill und die vier
Analysten verlangen Claude Mythos 5.2, der Abschluss (`gegenpruefer`, `rapportfuehrer`) Claude Fable 5.2.
Claude Code schaltet nur dann auf Mythos, wenn es an diesem Arbeitsplatz freigeschaltet ist. Sonst läuft alles auf
dem Modell der Sitzung. Du musst nichts umstellen und nichts prüfen.
**Gib beim Start eines Subagenten kein Modell an**, sonst übersteuerst du diese Zuteilung.

Unter Windows heisst der Interpreter `python` statt `python3`. Die Befehle unten gelten sonst unverändert.

## Phase 0: Fall bereitstellen

1. Fehlt die Fall-ID, frage danach und halte an.
2. Rufe `mcp__osint__fall_status` auf.
   - Fall existiert nicht und ein Dokumentpfad wurde mitgegeben:
     `python3 tools/fall.py neu <Fall-ID> --rapport <Pfad…>` ausführen. Das Werkzeug prüft das Dokument auf
     übersehene Personendaten. **Lies das Dokument nicht selbst, bevor es aufgenommen ist.**
     Meldet die Prüfung Sperrfunde: Ausgabe zeigen, erklären, dass im Haus nachpseudonymisiert werden muss, anhalten.
   - Fall existiert nicht und kein Pfad: nach dem Pfad fragen, anhalten.
   - Wurde zu einem bestehenden Fall ein weiterer Pfad mitgegeben: `python3 tools/fall.py aufnehmen <Fall-ID> <Pfad>`.
3. Ist der Eingang leer, halte an und sage, wie ein Dokument aufgenommen wird.
4. Melde in drei bis fünf Zeilen: Titel und Auftrag, welche Freigaben erteilt sind, welche Quellen bereitstehen und
   welche fehlen (mit dem Namen des fehlenden Schlüssels). Fahre ohne Rückfrage fort.

## Phase 1: Indikatoren

Lies die Dokumente aus `eingang` (nur die von `fall_status` genannten) und folge dem Skill `ioc-extraktion`.
Ergebnis: `faelle/<Fall-ID>/arbeitsstand/indikatoren.json`. Findest du echte Personendaten im Dokument, halte an
und melde die Stelle, ohne den Wert zu wiederholen.

## Phase 2: Plan

Schreibe `arbeitsstand/plan.md`:
- die Fragen aus dem Auftrag, als prüfbare Fragen formuliert,
- je Analyst: welche Indikatoren, welche Fragen, welche Quellen,
- was sich nicht klären lässt (fehlende Quelle, fehlende Freigabe, nur mit Klarnamen möglich).

Zuteilung:

| Analyst | Bekommt | Nur wenn |
|---|---|---|
| `infrastruktur-analyst` | IPs, Domains (Hosting, Betreiber, VPN, Reputation, Nachbarn) | immer |
| `malware-url-analyst` | URLs, Hashes, Domains (Inhalt, Verhalten, Alter, Archivstände) | URLs, Hashes oder Domains vorhanden |
| `darkweb-analyst` | Gruppen, Onion-Adressen, Leak-Bezug, Breach-Feed | Erpressung, Leak oder Gruppenname im Fall |
| `socmint-analyst` | Konten, Kanäle, Stichworte in Foren | Konten oder Forenbezug im Fall |

Zeige dem Sachbearbeiter den Plan in höchstens zehn Zeilen und fahre fort.

## Phase 3: Ermitteln

Starte die Analysten gleichzeitig. Jeder Auftrag ist in sich vollständig, denn der Analyst kennt dein Gespräch nicht:

```
Fall: <Fall-ID>
Auftrag: <ein Satz aus fall.json>
Deine Indikatoren:
- I-03 ip 203.0.113.7 (Rapport Ziff. 5, einliefernder Host)
- …
Deine Fragen:
1. …
Grenzen: nur passive Abfragen. Keine Pivots ausführen, nur vorschlagen. Rückmeldung als Befundmeldung nach Ermittlungsstandard.
```

Speichere jede Befundmeldung unverändert als `arbeitsstand/<analyst>-runde1.md`.

## Phase 4: Pivots

Sichte die Pivot-Vorschläge. Ein Pivot wird verfolgt, wenn die Verbindung zum Fall belegt ist (P-Nummer) und er
eine Frage aus dem Auftrag beantworten kann. Trage angenommene Pivots mit neuer ID und `herkunft: "Pivot aus P-…"`
in `indikatoren.json` ein und starte eine zweite Runde bei den zuständigen Analysten (`…-runde2.md`).
Höchstens zwei Runden. Was danach offen ist, kommt unter Lücken oder Empfehlungen.

## Phase 5: Aktive Massnahmen

Nur wenn ein Analyst eine vorschlägt **und** die Freigabe `aktiv` erteilt ist. Dann je Massnahme einzeln fragen:
was genau, was man erfährt, was das Ziel bemerkt. Nach Zustimmung führst du sie selbst aus
(`urlquery_einreichen` mit `sichtbarkeit: private`, `webcheck_aktiv`, `wayback_sichern`). Ohne Freigabe oder
Zustimmung: als Empfehlung in den Rapport.

## Phase 6: Befunde schreiben

Beauftrage den `rapportfuehrer`: Er liest `arbeitsstand/` und schreibt `befunde.json` nach dem Skill
`abschlussrapport`, alle Befunde mit `gegenpruefung: "offen"`. Er führt `python3 tools/rapport.py <Fall-ID> --nur-pruefen`
aus und behebt formale Mängel.

## Phase 7: Gegenprüfung

Beauftrage den `gegenpruefer`. Sein Auftrag besteht nur aus der Fall-ID. Er bekommt bewusst keine Zusammenfassung von
dir, damit er unvoreingenommen prüft. Er liefert je Befund ein Urteil.

Gib die Urteile dem `rapportfuehrer` zurück. Er trägt sie ein, korrigiert oder streicht widerlegte Befunde und passt
Sicherheit, Zusammenfassung und Kernaussagen an. Wurde ein Befund inhaltlich geändert, geht dieser eine Befund
noch einmal zum `gegenpruefer`.

## Phase 8: Erzeugen

```
python3 tools/rapport.py <Fall-ID>
python3 tools/protokoll.py <Fall-ID>
```

Meldet `rapport.py` Mängel, behebt sie der `rapportfuehrer` an der Sache (Beleg ergänzen, herabstufen, streichen).
Höchstens drei Durchgänge. Bleiben Mängel, erzeuge mit `--entwurf` und sage dem Sachbearbeiter offen, was fehlt.

## Phase 9: Übergabe

Die Übergabe ist Teil des Abschlusses. Lass sie vom `rapportfuehrer` formulieren und gib seinen Text unverändert
weiter. Nenne ihm dafür, was nur du weisst: welche Freigaben fehlten, welche Massnahmen der Sachbearbeiter
abgelehnt hat, und den letzten Kettenwert aus der Ausgabe von `protokoll.py`. Die Übergabe nennt:
- wo die Ergebnisse liegen (`faelle/<Fall-ID>/rapport/Abschlussrapport.html`, `Ermittlungsprotokoll.html`, `indikatoren.csv`),
- die drei bis fünf wichtigsten Befunde mit ihrer Sicherheit,
- was offen blieb und warum,
- was nur er tun kann: Freigaben erteilen, Abfragen mit Klarnamen im Haus nachholen, Platzhalter im Rapport
  im Haus zurückführen (`tools/reidentifizieren.py`, ausserhalb dieser Sitzung),
- den letzten Kettenwert des Protokolls, falls er ihn im Journal festhalten will.

Keine Nacherzählung der Arbeitsschritte. Die stehen im Protokoll.
