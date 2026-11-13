---
name: ioc-extraktion
description: Zieht technische Indikatoren (IP-Adressen, Domains, URLs, Datei-Hashes, E-Mail-Adressen der Täterseite, Onion-Adressen, Wallets, Gruppennamen, Konten) aus pseudonymisierten Rapporten und Nachträgen und legt sie als indikatoren.json ab. Verwenden zu Beginn einer Ermittlung oder wenn ein weiteres Dokument in einen Fall aufgenommen wurde.
---

# Indikatoren aus Eingangsdokumenten ziehen

Ziel ist eine vollständige, saubere Liste dessen, was sich technisch abfragen lässt, mit Fundstelle. Was hier
fehlt, wird nie abgefragt. Was hier falsch abgeschrieben ist, führt zu falschen Befunden.

## Vorgehen

1. Lies nur Dokumente, die `fall_status` unter `eingang` nennt. Anderes ist nicht durch die PII-Prüfung gegangen.
2. Gehe das Dokument Absatz für Absatz durch. Notiere jeden Indikator mit der Fundstelle (Ziffer, Abschnitt oder Zeile).
3. Übernimm Werte zeichengenau. Vergleiche lange Werte (Hashes, Onion-Adressen) nach dem Abschreiben noch einmal mit dem Original.
4. Schreibe das Ergebnis nach `faelle/<Fall-ID>/arbeitsstand/indikatoren.json`.

## Was ein Indikator ist

| Typ | Erkennen | Normalisieren |
|---|---|---|
| `ip` | IPv4, IPv6 | Entschärfung auflösen: `203[.]0[.]113[.]7` → `203.0.113.7` |
| `domain` | Hostnamen | Kleinschreibung, ohne Punkt am Ende, `[.]` → `.` |
| `url` | http(s)-Adressen | `hxxp` → `http`, Pfad und Parameter unverändert lassen |
| `hash` | 32, 40 oder 64 Hex-Zeichen | Kleinschreibung. Dateiname als Anmerkung |
| `email` | Adressen der Täterseite (Absender, Kontaktadresse im Erpresserschreiben) | Kleinschreibung |
| `onion` | 56 Zeichen (oder 16) plus `.onion` | Kleinschreibung |
| `wallet` | Bitcoin-, Ethereum-, Monero-Adressen | unverändert, Gross- und Kleinschreibung zählt |
| `gruppe` | Namen von Tätergruppen, Malware-Familien, Kampagnen | Schreibweise des Dokuments |
| `konto` | Benutzernamen, Kanäle, Handles der Täterseite | mit Plattform als Anmerkung |

## Was kein Indikator ist

- **Platzhalter.** `[PERSON_01]`, `[ORG_01]`, `[TEL_01]`, `[EMAIL_01]` und alles in dieser Form. Sie stehen für
  Personendaten und werden nie abgefragt. Erwähne im Plan, wenn eine Abfrage nur mit dem Klarnamen möglich wäre
  (zum Beispiel die Suche nach der geschädigten Organisation auf Leak-Seiten). Sie wird im Haus nachgeholt.
- **Infrastruktur der Geschädigten.** Deren eigene Server, Domains und Adressen werden nicht untersucht,
  ausser der Auftrag verlangt es ausdrücklich. Im Zweifel als `rolle: "Geschädigtenseite, nicht abfragen"` aufnehmen.
- **Interne und reservierte Adressen** (10.x, 192.168.x, 127.x, 169.254.x). Als Kontext notieren, nicht abfragen.
- **Allgemeingut.** Adressen grosser Dienste (öffentliche DNS-Resolver, Mailanbieter, CDN) sagen nichts über den Täter.

## Auffälligkeiten sofort melden

- Im Dokument stehen offenbar echte Personendaten (Name, Telefonnummer, Adresse), die keine Platzhalter sind.
  Dann: nicht weiterverarbeiten, die Stelle mit Zeilennummer melden, ohne den Wert zu wiederholen. Der Sachbearbeiter
  pseudonymisiert nach und nimmt das Dokument neu auf.
- Ein Wert ist erkennbar verstümmelt (Hash mit 63 Zeichen, IP mit fünf Blöcken). Als `anmerkung` festhalten und nicht abfragen.

## Format

```json
{
  "fall_id": "<Fall-ID>",
  "quelle_dokumente": ["rapport_pseudonymisiert.md"],
  "indikatoren": [
    {"id": "I-01", "typ": "domain", "wert": "kundenportal-sicher.example",
     "herkunft": "Rapport Ziff. 2", "rolle": "Linkziel der Phishing-Mail", "abfragen": true},
    {"id": "I-02", "typ": "ip", "wert": "198.51.100.23",
     "herkunft": "Rapport Ziff. 3", "rolle": "Anmeldung mit erbeuteten Zugangsdaten", "abfragen": true},
    {"id": "I-03", "typ": "domain", "wert": "portal.geschaedigte.example",
     "herkunft": "Rapport Ziff. 3", "rolle": "Geschädigtenseite, nicht abfragen", "abfragen": false,
     "anmerkung": "Kundenportal der [ORG_01]"}
  ],
  "nur_im_haus_abfragbar": ["Name der [ORG_01] auf Leak-Seiten (ransomware.live)"],
  "fragen_aus_dem_auftrag": ["Wer betreibt die Phishing-Seite?", "Was ist der Mailanhang?"]
}
```

Die IDs (`I-01` …) bleiben für den ganzen Fall gültig. Indikatoren aus Pivots bekommen später fortlaufende
Nummern und als `herkunft` den Beleg, aus dem sie stammen («Pivot aus P-0009»).
