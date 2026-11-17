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

## Grenzen, die bekannt sind

- **Den Wächter gibt es nicht mehr.** Bis zum 17.11.2026 prüfte ein Hook jeden Werkzeugaufruf vorab. Er ist auf
  Entscheid des Eigentümers entfernt. Was Agenten dürfen, regeln seither die Berechtigungen von Claude Code
  (Erlaubt- und Verbotsliste, für alles andere eine Rückfrage an den Menschen), die Werkzeuge selbst (Freigabe,
  Beleg von Hand, Pseudonymisieren und Zurückführen verlangen ein Terminal oder das Geheimnis der Oberfläche) und
  das Gateway (Freigaben für aktive Massnahmen und Kontoabfragen, Schlüssel, Einreichen nur privat).
- Nicht mehr technisch verhindert ist: dass ein Agent ein Dokument liest, das von Hand in den Eingang kopiert wurde,
  dass ein Shell-Befehl nach Zustimmung des Menschen Fallakte, Schlüsseldatei oder Grundlagen anfasst, und dass
  Robin am Terminal ohne Freigabe `darkweb` läuft, wenn der Mensch den Aufruf erlaubt. Wer Claude Code so startet,
  dass es nicht mehr nachfragt, schaltet die Rückfrage ab.
- Die Hash-Kette macht Veränderungen erkennbar, sie verhindert sie nicht. Eine Kürzung am Ende fällt erst auf, wenn
  der letzte Kettenwert ausserhalb des Systems hinterlegt wurde (`tools/audit_pruefen.py --erwartet`).
- Die Bedienung der Oberfläche schützt ein Geheimnis im Speicher des Servers und im Browserfenster des
  Sachbearbeiters. Das hält Agenten auf, die über die Werkzeuge von Claude Code arbeiten. Ein Programm mit den
  Rechten des Benutzers, das den Speicher des Servers ausliest, hält es nicht auf. Einzelheiten:
  `docs/OBERFLAECHE.md`, «Schutz der Bedienung».
- Die Steuerung von Claude Code aus der Oberfläche ist mit dem echten Claude Code noch nicht geprüft. Die Probe dafür:
  `python3 tools/oberflaeche.py --sitzungsprobe`.

Unterstützt wird der Stand auf `main`.
