# Mitmachen

Beiträge sind willkommen, besonders neue Quellen und Rückmeldungen aus `python3 tools/pruefen.py --live`.

## Was nie in ein Issue, einen Pull Request oder einen Commit gehört

Falldaten, echte Indikatoren aus einem Verfahren, Personendaten, Schlüssel. Beispiele arbeiten mit dem Musterfall,
mit Adressen aus den Dokumentationsnetzen (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24), mit Domains unter
`.example` und mit öffentlich bekannten, unpersönlichen Testwerten (8.8.8.8, der Hash der EICAR-Testdatei).

## Vor jedem Pull Request

```bash
python3 tools/selbsttest.py     # alle Selbsttests, ohne Netz
python3 tools/pruefen.py        # Einrichtung und Konfiguration
python3 tools/musterfall.py     # danach muss «git status» sauber sein
python3 tools/pseudo_messen.py --pruefen   # nur nach Änderungen an der lokalen Pseudonymisierung oder ihren Listen
```

Die CI baut den Musterfall auf drei Systemen und vergleicht ihn Byte für Byte. Ändert er sich gewollt, gehören
die neuen Dateien unter `faelle/MUSTER-2026-001/` und die PDFs unter `muster/` in denselben Pull Request
(`python3 tools/pdf.py MUSTER-2026-001 --nach muster` und `python3 tools/anhang.py MUSTER-2026-001 --nach muster`).
Zum Musterfall gehören auch die Datenblätter (`rapport/Datenblaetter.html`). Sie tragen den Stil der Oberfläche in sich:
Nach einer Änderung an `tools/ui/app.css` oder an einem Darsteller also `python3 tools/musterfall.py` laufen lassen.

## Eine Quelle hinzufügen

1. Bedingungen des Anbieters lesen: Darf eine Behörde den Dienst so nutzen? Was erfährt der Anbieter aus einer Abfrage?
2. Werkzeug in einem Modul `gateway/quellen_*.py`, jede Abfrage über `kern.abfrage` (Protokoll, Rohdatei, Cache,
   Drossel). Der Schlüssel als Kopfzeile, sonst als Parameter mit `geheim=(…)`. Fremdinhalt mit `saeubern` kürzen.
3. Eintrag in `gateway/quellen.py` mit einer harmlosen Testabfrage, Schlüssel in `.env.example`, Werkzeug bei den
   Agenten und in `.claude/settings.json` (aktive Werkzeuge unter `ask`, nie bei einem Agenten).
4. Die echte Antwort ansehen (Fallakte `SELBSTTEST`), ihre Form als Vorlage in `tools/_vorlagen.py` ablegen, mit
   erfundenem Inhalt, und einen Selbsttest dagegen schreiben. Eine frei erfundene Form findet die Fehler nicht.
5. `docs/QUELLEN.md`: Endpunkt, Stand der Prüfung mit Datum, Betreiber und Sitz, was der Anbieter erfährt.

## Einen Darsteller der Oberfläche ergänzen

Wie eine Rohantwort in der Oberfläche erscheint, beschreibt je Werkzeug ein Darsteller in `tools/ui/darsteller.py`.
Zu jedem gehört eine Rohantwort als Vorlage unter `tools/ui/vorlagen/`, ohne Angaben zu Personen und mit Herkunft in
`verzeichnis.json`. Die Selbsttests prüfen an den Vorlagen, dass keine Angabe verloren geht und jeder gezeigte Wert an
der genannten Stelle der Rohdatei steht. Die Schritte stehen in [docs/OBERFLAECHE.md](docs/OBERFLAECHE.md).

## Schreibweise

Deutsch in Schweizer Schreibweise (ss, kein ß), Bezeichner im Code ebenfalls deutsch. Kommentare sagen, warum
etwas so ist, nicht was die Zeile tut. «Geprüft» heisst in der Doku: gesehen, mit Datum. Was nicht geprüft
werden konnte, steht als «nicht geprüft» mit Grund da.

## Schutzmechanismen

Wächter, Hooks, Berechtigungen, Protokollkette und die Prüfregeln des Rapports ändert nur, wer vom Eigentümer
des Repositorys damit beauftragt ist, auf einem Branch und per Pull Request. Eine Lockerung gehört in die
Beschreibung des Pull Requests, mit Begründung.
