# Sicherheit

Dieses Projekt ist ein Arbeitsplatz für Ermittlungen. Eine Schwachstelle kann heissen, dass ein Agent etwas tut,
was er nicht dürfte, dass ein Schlüssel oder eine Personenangabe an eine Stelle gerät, an die sie nicht gehört,
oder dass sich ein Protokoll unbemerkt verändern lässt.

## Eine Schwachstelle melden

Bitte **nicht** als öffentliches Issue. Nutzt die vertrauliche Meldung von GitHub: im Repository unter
«Security» → «Report a vulnerability». Ist sie nicht eingeschaltet, schreibt dem Eigentümer des Repositorys direkt.

In die Meldung gehört: was sich umgehen oder auslesen lässt, mit welchem Schritt, auf welchem System und mit
welcher Version von Claude Code. **Nie** hinein gehören Falldaten, echte Indikatoren aus einem Verfahren,
Schlüssel oder Personendaten. Ein Nachweis mit dem Musterfall oder mit erfundenen Werten genügt.

## Was als Schwachstelle zählt

- Ein Weg, auf dem ein Agent ohne Zustimmung des Sachbearbeiters Fallakte, Protokoll, Rohdaten, Eingang oder
  Freigaben verändert oder am Gateway vorbei ins Netz kommt.
- Ein Schlüssel oder eine Kontoangabe in Protokoll, Rohdaten, Rapport, Fehlertext oder Log.
- Fremdinhalt, der im Rapport oder Protokoll als ausführbares HTML erscheint oder einen Agenten steuert.
- Eine Änderung am Protokoll, die `tools/audit_pruefen.py` nicht erkennt, über das hinaus, was dort als Grenze steht.
- Ein Weg, auf dem ein Agent die Oberfläche bedient: sich eine Freigabe erteilt, eine Rückfrage selbst beantwortet,
  an das Geheimnis des Starts kommt oder Klartext und Zuordnungstabelle zu sehen bekommt.
- Ein Weg, auf dem der Inhalt einer hochgeladenen Datei, ihr ursprünglicher Name oder eine Eingabe im Chat ohne
  PII-Prüfung in eine Fallakte, in ein Protokoll oder zu einem Sprachmodell gelangt.

## Grenzen, die bekannt sind

- **Den Wächter gibt es nicht mehr.** Bis zum 17.11.2026 prüfte ein Hook jeden Werkzeugaufruf vorab. Er ist auf
  Entscheid des Eigentümers entfernt. Was Agenten dürfen, regeln seither die Berechtigungen von Claude Code
  (Erlaubt- und Verbotsliste, für alles andere eine Rückfrage an den Menschen), die Werkzeuge selbst (Freigabe,
  Beleg von Hand, Pseudonymisieren und Zurückführen verlangen ein Terminal oder das Geheimnis der Oberfläche) und
  das Gateway (Freigaben für aktive Massnahmen und Kontoabfragen, Schlüssel, Einreichen nur privat).
  Seit dem 20.11.2026 schreibt der Sitzungs-Hook mit, was verlangt wird, bevor es ausgeführt wird. Er prüft dabei
  nichts und lehnt nichts ab: Er ist kein neuer Wächter. So steht auch ein abgelehnter Aufruf im Ermittlungsprotokoll.
- Nicht mehr technisch verhindert ist: dass ein Agent ein Dokument liest, das von Hand in den Eingang kopiert wurde,
  dass ein Shell-Befehl nach Zustimmung des Menschen Fallakte, Schlüsseldatei oder Grundlagen anfasst, und dass
  Robin am Terminal ohne Freigabe `darkweb` läuft, wenn der Mensch den Aufruf erlaubt. Wer Claude Code so startet,
  dass es nicht mehr nachfragt, schaltet die Rückfrage ab. Verhindert wird ein solcher Aufruf von Robin nicht, aber
  er bleibt sichtbar: Der Beleg hält fest, welche Regel er nicht einhielt (Freigabe, Untersuchungsbereich, Prüfung
  gegen die Sperrliste), und das Ermittlungsprotokoll zeigt «Regel verletzt».
- Wegen Personendaten in einem aufgenommenen Dokument hält die Ermittlung nicht an (Entscheid des Eigentümers vom
  20.11.2026). Was in einen Fall kommt, entscheidet die PII-Prüfung bei der Aufnahme, und nur der Sachbearbeiter kann
  sie übersteuern. Danach nennt die Ermittlung die Stellen ohne die Werte und verwendet sie nicht. Dass sie das einhält,
  ist eine Anweisung an ein Sprachmodell, keine Sperre.
- Ist ein Proxy eingestellt, geht jede Abfrage des Gateways über ihn. Antwortet er nicht, scheitert die Abfrage: Einen
  Weg am Proxy vorbei gibt es nicht. Ob Tor auf diesem Rechner Verbindungen aufbaut, prüfen Einrichtung und
  `tools/pruefen.py` mit einer Verbindung über Tor zu `check.torproject.org`, die sie gleich wieder schliessen. Dabei
  geht nichts aus einem Fall hinaus.
- Beim Start fragt die Oberfläche einmal beim Git-Server des Repositorys nach (`git ls-remote origin HEAD`), ob dort
  eine neuere Fassung des Arbeitsplatzes liegt. `tools/pruefen.py --live` tut dasselbe. Die Anfrage geht direkt hinaus,
  wie `git pull`, nicht über `OSINT_PROXY`: Der Server sieht, dass und wann von diesem Anschluss gefragt wird. Aus einem
  Fall steht nichts darin. Abstellen für beide: `OSINT_STAND_PRUEFEN=0`.
- Den Vertrauensdialog von Claude Code für den Projektordner beantwortet immer ein Mensch. Die Einrichtung startet
  Claude Code dafür auf Wunsch, sie trägt das Vertrauen nicht selbst ein. Ob der Ordner bestätigt ist, liest sie aus
  der Datei von Claude Code ab (`~/.claude.json`, nur die Angabe `hasTrustDialogAccepted` zu diesem Ordner). Sie
  schreibt dort nie.
- Pflichtquellen (Quellen, die der Sachbearbeiter für einen Fall vorgibt) lassen sich nur am Terminal oder in der
  Oberfläche setzen und aufheben. Sie führen zu mehr Abfragen bei Dritten, nie zu anderen: Abgefragt werden nur
  Indikatoren des Falls, und eine Pflichtquelle ersetzt keine Freigabe. Ob die Vorgabe erfüllt ist, prüft der Rapport
  am Protokoll. Ein Agent, der eine Abfrage auslässt, fällt damit auf. Eine Abfrage erzwingen kann das System nicht.
- Ist Robin eingeschaltet, verbindet sich der Rechner zu Beginn jeder Sitzung mit dem Tor-Netz, auch ohne Freigabe
  `darkweb`: Claude Code startet den Container, und Tor läuft darin sofort an (nach dem Startskript des Projekts,
  nicht im Betrieb geprüft). Gesucht und gelesen wird erst mit Freigabe. Ohne Robin einrichten: `--ohne-robin`.
- Die Hash-Kette macht Veränderungen erkennbar, sie verhindert sie nicht. Eine Kürzung am Ende fällt erst auf, wenn
  der letzte Kettenwert ausserhalb des Systems hinterlegt wurde (`tools/audit_pruefen.py --erwartet`).
- Die Bedienung der Oberfläche schützt ein Geheimnis im Speicher des Servers und im Browserfenster des
  Sachbearbeiters. Das hält Agenten auf, die über die Werkzeuge von Claude Code arbeiten. Ein Programm mit den
  Rechten des Benutzers, das den Speicher des Servers ausliest, hält es nicht auf. Einzelheiten:
  `docs/OBERFLAECHE.md`, «Schutz der Bedienung».
- Der Akten-Eingang der Oberfläche hält hochgeladene Dateien im Speicher des Servers, bis sie in einen Fall
  aufgenommen oder entfernt sind. In den Fall geht nur die Textfassung dessen, was die PII-Prüfung besteht. Die
  Prüfung erkennt Muster (Telefonnummern, AHV-, Konto- und Kartennummern, Geburtsdaten, Kontrollschilder), keine Namen.
  Ein Name, der in einem Dokument oder in einer Eingabe im Chat stehen bleibt, erreicht das Sprachmodell.
- Die Steuerung von Claude Code aus der Oberfläche ist mit dem echten Claude Code noch nicht geprüft, auch nicht der
  Chat (Vorgaben, Nachrichten, Fortsetzen). Die Probe dafür: `python3 tools/oberflaeche.py --sitzungsprobe`.

Unterstützt wird der Stand auf `main`.
