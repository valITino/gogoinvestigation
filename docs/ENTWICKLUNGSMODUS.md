# Vorschlag: ein sauberer Entwicklungsmodus

**Stand: Vorschlag vom 16.11.2026, nicht umgesetzt.** Er beschreibt, wie die heutige Aufbauphase abgelöst werden
kann. Die Entscheide am Ende gehören dem Eigentümer des Repositorys.

## Was heute gilt und woran es krankt

Im Wächter steht ein Schalter (`AUFBAUPHASE = True` in `.claude/hooks/waechter.py`). Solange er ein ist, dürfen
Sitzungen Gateway, Tools, Hooks, Einstellungen und Einrichtung ändern. Das hat vier Schwächen:

1. **Der Schalter steht in der Datei, die er schützt.** Wer den Wächter ändern darf, kann jede Sperre entfernen.
   Die übrigen Sperren schützen in dieser Zeit vor Versehen, nicht vor Absicht.
2. **Der Schalter reist mit.** Er steht auf `main`. Jeder Klon ist damit im Aufbau, auch der an einem Arbeitsplatz,
   an dem ermittelt werden soll.
3. **«Keine echten Fälle» ist eine Abmachung.** Nichts hindert eine Sitzung in der Aufbauphase daran, einen echten
   Fall zu öffnen.
4. **Das Zurückschalten ist Handarbeit an drei Stellen** (Wächter, `settings.json`, Hinweise in README und CLAUDE.md).
   Ein Selbsttest nennt, was fehlt, aber ein halb zurückgeschalteter Stand ist möglich.

## Ziele

- Ein Arbeitsplatz im Betrieb ist immer voll geschützt. Aus einer Sitzung heraus gibt es keinen Weg, das zu ändern.
- Entwickelt wird trotzdem mit Claude Code, ohne den Betrieb zu schwächen.
- Welcher Modus gilt, ist jederzeit sichtbar und prüfbar.
- Im Entwicklungsmodus lassen sich keine echten Falldaten anfassen.

## Der Vorschlag

**1. Zwei Orte statt eines Schalters.** Betrieb ist der Klon eines freigegebenen Standes. Entwicklung ist ein
eigener Klon in einem anderen Ordner. Welcher Ordner ein Entwicklungsordner ist, steht nicht im Repository, sondern
in einer Marke **ausserhalb**: `~/.config/osint-arbeitsplatz/entwicklung.json` mit dem absoluten Pfad des Klons, dem
Kürzel dessen, der sie gesetzt hat, und einem Ablaufdatum. Gesetzt wird sie am Terminal
(`python3 tools/entwicklung.py ein`, verlangt ein Terminal wie `tools/fall.py freigabe`). Der Wächter liest die
Marke. Im Wächter selbst steht kein Schalter mehr.

Eine Sitzung kann die Marke nicht setzen: Sie liegt ausserhalb des Projekts, der Wächter sperrt den Pfad für
Schreibzugriffe und Shell-Befehle, die Berechtigungen ebenfalls. Fehlt die Marke, ist sie abgelaufen oder nennt sie
einen anderen Ordner, gilt der volle Schutz.

**2. Im Entwicklungsordner gibt es keine echten Fälle.** Gateway und Wächter nehmen dort nur Fallakten an, die in
`fall.json` als `muster` oder `test` gekennzeichnet sind. `tools/fall.py neu` legt dort nur solche an. Umgekehrt
startet das Gateway in einem Ordner mit Marke nicht, wenn darin eine Fallakte ohne dieses Kennzeichen liegt. Damit
ist «keine echten Fälle» keine Abmachung mehr.

**3. Im Betrieb sind die Grundlagen an eine Prüfsumme gebunden.** Beim Freigeben eines Standes schreibt die CI die
Prüfsummen von Wächter, Hooks, Einstellungen und Gateway in eine Datei (`.claude/GRUNDLAGEN.sha256`).
`tools/pruefen.py` und `fall_status` vergleichen sie bei jedem Start. Weicht eine ab, arbeitet das Gateway nicht
und sagt, welche Datei verändert ist. Ein veränderter Wächter fällt damit beim nächsten Aufruf auf, nicht erst bei
einer Durchsicht.

**4. Die CI ist die Schranke zwischen den Modi.** Auf `main` und auf jedem Stand, der freigegeben wird, läuft eine
Prüfung: kein Entwicklungsschalter im Code, die Verbote für die Grundlagen stehen in `settings.json`, die
Selbsttests laufen mit vollem Schutz. Die Selbsttests fahren den Wächter schon heute in beiden Zuständen
(`OSINT_WAECHTER=voll`).

**5. Der Modus ist sichtbar.** `fall_status` nennt ihn. Ein Rapport oder Protokoll aus einem Entwicklungsordner
trägt oben einen Balken «ENTWICKLUNG, nicht für ein Verfahren», so wie der Musterfall «MUSTER» trägt.

**6. Schlüssel getrennt.** Ein Entwicklungsordner bekommt eigene Testschlüssel in seiner eigenen `.env`, nicht die
des Betriebs. Kontingente und Protokolle der Anbieter bleiben so auseinander.

## Der Weg dorthin

1. `tools/entwicklung.py` (ein, aus, stand) und das Lesen der Marke im Wächter. Der Schalter `AUFBAUPHASE` bleibt
   vorerst als zweite Bedingung stehen.
2. Kennzeichen `test` in `fall.json`, Prüfung in Gateway und Wächter (Punkt 2).
3. Prüfsummen der Grundlagen und ihre Prüfung (Punkt 3), CI-Prüfung (Punkt 4), Balken (Punkt 5).
4. `AUFBAUPHASE` aus dem Wächter entfernen, die Verbote in `settings.json` zurückholen (Liste
   `GRUNDLAGEN_VERBOTE` in `tools/selbsttest.py`), die Hinweise «Aufbauphase» in README und CLAUDE.md streichen.

Schritt 4 beendet die Aufbauphase. Bis dahin ändert sich am Betrieb nichts.

## Was der Vorschlag nicht löst

- Wer am Terminal alle Rechte hat, kann die Marke setzen und den Wächter ändern. Der Vorschlag schützt vor einem
  Agenten, nicht vor dem Menschen, der ihn bedient. Dafür sind Rechte des Betriebssystems da: Im Betrieb gehört
  der Projektordner einem anderen Benutzerkonto als dem, unter dem Claude Code läuft, und ist für dieses nur lesbar,
  ausgenommen `faelle/` und `protokoll/`.
- Der Wächter beurteilt Shell-Befehle weiterhin an ihrem Text. Das bleibt eine von mehreren Schichten.

## Entscheide für den Eigentümer

| Frage | Empfehlung |
|---|---|
| Wo liegt die Marke: je Benutzer oder je Rechner? | Je Benutzer (`~/.config/…`). Ein gemeinsamer Rechner im Betrieb bekommt gar keine. |
| Läuft die Marke ab? | Ja, nach 30 Tagen. Verlängern ist ein Befehl am Terminal. |
| Getrennte Benutzerkonten für Betrieb und Claude Code? | Ja, wo die Informatik es zulässt. Es ist der einzige Schutz, den ein Agent nicht umgehen kann. |
| Dürfen im Entwicklungsordner Live-Abfragen laufen? | Ja, mit Testschlüsseln und nur mit öffentlich bekannten, unpersönlichen Testwerten, wie in `tools/pruefen.py --live`. |
