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

- Ein Weg, auf dem ein Agent Fallakte, Protokoll, Rohdaten, Eingang, Freigaben, Gateway, Hooks oder Einstellungen
  verändert, ein ungeprüftes Dokument liest oder am Gateway vorbei ins Netz kommt.
- Ein Schlüssel oder eine Kontoangabe in Protokoll, Rohdaten, Rapport, Fehlertext oder Log.
- Fremdinhalt, der im Rapport oder Protokoll als ausführbares HTML erscheint oder einen Agenten steuert.
- Eine Änderung am Protokoll, die `tools/audit_pruefen.py` nicht erkennt, über das hinaus, was dort als Grenze steht.

## Grenzen, die bekannt sind

- Während der **Aufbauphase** (Schalter im Wächter, siehe README) ruht der Schreibschutz für die Grundlagen. In
  dieser Zeit schützen die Sperren vor Versehen, nicht vor Absicht. Echte Fälle gehören nicht auf einen
  Arbeitsplatz in der Aufbauphase.
- Der Wächter prüft Shell-Befehle anhand ihres Textes. Er ist eine von mehreren Schichten (Berechtigungen von
  Claude Code, Wächter, Prüfungen im Gateway, Hash-Kette) und kein Ersatz für einen Arbeitsplatz, auf dem der
  Agent nur darf, was er braucht.
- Die Hash-Kette macht Veränderungen erkennbar, sie verhindert sie nicht. Eine Kürzung am Ende fällt erst auf, wenn
  der letzte Kettenwert ausserhalb des Systems hinterlegt wurde (`tools/audit_pruefen.py --erwartet`).

Unterstützt wird der Stand auf `main`.
