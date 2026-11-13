# Quellen im Einzelnen

Für jede Quelle: was abgefragt wird, was der Anbieter dabei erfährt, und worauf sich die Einbindung stützt.
Die Liste, aus der Gateway, Einrichtung und Selbsttest lesen, ist `gateway/quellen.py`.

**Zur Verlässlichkeit dieser Angaben.** Beim Bau standen weder Schlüssel noch Netzzugang zu den Diensten zur
Verfügung. Keine Quelle wurde live abgefragt. Die Spalte «Stützt sich auf» sagt, woher die Endpunkte stammen.
`python3 tools/pruefen.py --live` prüft jede eingerichtete Quelle. Schlägt eine fehl, steht die Antwort des
Anbieters in `faelle/SELBSTTEST/rohdaten/`, und der Endpunkt lässt sich in der genannten Datei anpassen.

## Über das Gateway

| Quelle | Werkzeug | Abfrage | Stützt sich auf |
|---|---|---|---|
| Shodan | `shodan_host` | `GET api.shodan.io/shodan/host/{ip}` | Dokumentation des Anbieters |
| | `shodan_dns` | `GET api.shodan.io/dns/domain/{domain}` | Dokumentation des Anbieters |
| | `shodan_suche` | `GET api.shodan.io/shodan/host/count` oder `/search` | Dokumentation des Anbieters |
| Shodan InternetDB | `shodan_internetdb` | `GET internetdb.shodan.io/{ip}` | Dokumentation des Anbieters |
| VirusTotal | `virustotal_ip`, `_domain`, `_datei`, `_url` | `GET www.virustotal.com/api/v3/{ip_addresses,domains,files,urls}/{id}` | Dokumentation des Anbieters (API v3) |
| | `virustotal_beziehungen` | `GET …/{sammlung}/{id}/{beziehung}` | Dokumentation des Anbieters |
| Spur | `spur_kontext` | `GET api.spur.us/v2/context/{ip}`, Kopfzeile `Token` | docs.spur.us, beim Bau nachgelesen |
| AbuseIPDB | `abuseipdb_pruefen`, `_meldungen` | `GET api.abuseipdb.com/api/v2/check` und `/reports`, Kopfzeile `Key` | Dokumentation des Anbieters (API v2) |
| urlquery | `urlquery_suche`, `_bericht`, `_reputation`, `_status`, `_einreichen` | `api.urlquery.net/public/v1/…`, Kopfzeile `x-apikey` | Quellcode des offiziellen Clients `urlquery/urlquery-cli` |
| Wayback Machine | `wayback_verlauf` | `GET web.archive.org/cdx/search/cdx` | Dokumentation der CDX-Schnittstelle |
| | `wayback_abruf` | `GET web.archive.org/web/{zeit}id_/{url}` | Dokumentation |
| | `wayback_sichern` | `GET web.archive.org/save/{url}` | Dokumentation |
| Web-Check | `webcheck_passiv`, `webcheck_aktiv` | `GET {WEBCHECK_URL}/api/{prüfung}?url=` | Quellcode `Lissy93/web-check` (Version 2.4.0) |
| ransomware.live | `ransomware_*` | API PRO: `api-pro.ransomware.live/{victims/recent, victims/search, victims/, groups/{g}, iocs/{g}}`, Kopfzeile `X-API-KEY` | Pfade aus einem Client eines Dritten. **Am wenigsten gesichert.** |
| | | API v2: `api.ransomware.live/v2/{recentvictims, searchvictims/{x}, groupvictims/{g}, countryvictims/{cc}, group/{g}}` | Dokumentationsseite des Anbieters, beim Bau nachgelesen |
| Ahmia | `onion_sperrliste` | `GET ahmia.fi/blacklist/banned/`, Vergleich lokal | Adresse aus dem Quellcode von Darkus. Annahme: Die Liste enthält MD5-Werte der Onion-Adressen. |
| Telegram | `telegram_kanal` | `GET t.me/s/{kanal}` | Öffentliche Web-Vorschau. Aufbau der Seite angenommen. |
| RapidAPI | `telegram_kanalinfo` | `GET telegram-channel.p.rapidapi.com/channel/info` | Quellcode von TeleGramSint |
| | `telegram_entitaet`, `telegram_suche` | `GET telegram-scraper-api.p.rapidapi.com/entity/{fetch,search}` | Quellcode von TeleGramSint |
| 4chan | `chan_katalog`, `chan_thread` | `GET a.4cdn.org/{board}/catalog.json`, `/thread/{nr}.json` | Quellcode von OSINT-Chan, offizielle Lese-API |
| Mastodon | `mastodon_instanz` | `GET {instanz}/api/v2/instance`, sonst `/api/v1/instance` | Quellcode von Masto, Mastodon-API |
| | `mastodon_konto` | `GET {instanz}/api/v2/search?type=accounts` oder `/api/v1/accounts/lookup` | Quellcode von Masto, Mastodon-API |

## Was der Anbieter erfährt

Passiv heisst nicht unsichtbar. Jede Abfrage hinterlässt beim Anbieter eine Spur.

| Quelle | Der Anbieter sieht | Das Ziel sieht |
|---|---|---|
| Shodan, VirusTotal, Spur, AbuseIPDB, urlquery (Suche), ransomware.live | euren Schlüssel, eure Adresse (oder die des Proxys), den Indikator | nichts |
| Shodan InternetDB, Wayback Machine | eure Adresse, den Indikator | nichts |
| Web-Check passiv | je nach Prüfung DNS-Resolver, RDAP, crt.sh, Tranco und weitere Dritte: eure Adresse und die Domain | nichts vom Webserver. Die Nameserver des Ziels sehen DNS-Anfragen der Resolver. |
| Web-Check aktiv | | die Adresse eurer Web-Check-Instanz, in seinen Serverprotokollen |
| `urlquery_einreichen` | urlquery: die URL | einen Besuch von urlquery. Je nach `sichtbarkeit` ist der Bericht öffentlich. |
| `wayback_sichern` | archive.org: die URL | einen Besuch von archive.org. Die Aufnahme ist öffentlich und bleibt. |
| `onion_sperrliste` | Ahmia: dass jemand die Liste lädt. **Nicht** die geprüfte Adresse. | nichts |
| `telegram_kanal`, `chan_*` | Telegram oder 4chan: eure Adresse, Kanal oder Board. **Nicht** das Stichwort, es wird lokal gefiltert. | nichts |
| `telegram_kanalinfo`, `_entitaet`, `_suche` | RapidAPI und den Betreiber der jeweiligen API: Schlüssel, Adresse, Kanal- oder Benutzername | nichts Bekanntes. Wie der Betreiber die Daten beschafft, ist nicht dokumentiert. |
| `mastodon_*` | die abgefragte Instanz: eure Adresse, den Suchbegriff | Betreibt das Ziel die Instanz selbst, sieht es die Abfrage. |
| Robin | Tor-Ausgangsknoten sehen nichts Zuordenbares. Die Onion-Suchmaschinen sehen den Suchbegriff. | Aufruf über Tor |

Mit `OSINT_PROXY` in `.env` laufen alle Abfragen des Gateways über einen Proxy. Das Protokoll vermerkt je
Abfrage, ob ein Proxy verwendet wurde. Web-Check auf dem eigenen Rechner wird immer direkt angesprochen. Für
aktive Prüfungen muss die Web-Check-Instanz selbst auf einer Infrastruktur laufen, die nicht auf euch zurückführt.

## Hinweise je Quelle

**VirusTotal.** Das Gateway fragt nur ab. Es lädt keine Dateien hoch und löst keine neuen Scans aus, denn
Hochgeladenes ist für andere Kunden des Dienstes einsehbar. Zur eigenen Drossel: `VT_INTERVALL` in Sekunden.

**Spur.** `datum` (JJJJMMTT) fragt den Stand an einem früheren Tag ab und braucht laut Dokumentation ein Abo mit
historischen Abfragen. Für die Zuordnung einer IP zur Tatzeit ist das der entscheidende Parameter: Die Auskunft
von heute beschreibt den Besitzer von heute.

**AbuseIPDB.** Meldungen stammen von jedermann. Der Score fasst zusammen, er beweist nichts.

**urlquery.** `urlquery_einreichen` steht standardmässig auf `private`. Vor jeder Einreichung sucht der Analyst
nach vorhandenen Berichten.

**Web-Check.** 13 passive und 27 aktive Prüfungen. Passiv: `archives`, `block-lists`, `breaches`, `caa-records`,
`dns`, `dnssec`, `get-ip`, `rank`, `shodan`, `subdomains`, `threats`, `txt-records`, `whois`. Die Prüfung
`threats` bleibt nur passiv, solange in der Web-Check-Instanz kein Cloudmersive-Schlüssel hinterlegt ist: Mit
Schlüssel lässt sie die Seite von Cloudmersive aufrufen. `mail-config` gilt hier als aktiv, weil sie die
MTA-STS-Richtlinie vom Server des Ziels holt.

**ransomware.live.** Der Dienst gibt wieder, was Tätergruppen auf ihren Leak-Seiten behaupten. Die schlüssellose
API v2 ist laut Anbieter für die private Nutzung gedacht. Das Gateway nutzt sie nur, wenn `RANSOMWARE_LIVE_V2=1`
gesetzt ist. Für den Dienstgebrauch: API PRO mit Schlüssel, Bedingungen des Anbieters lesen.

**Ahmia-Sperrliste.** Liefert die Liste nichts, was wie eine Liste von MD5-Werten aussieht, meldet das Werkzeug
einen Fehler und rät vom Öffnen ab. «Nicht auf der Liste» ist keine Unbedenklichkeitserklärung.

**Telegram Breach Monitor.** Die Seite auf osintcabal.org ist eine Hinweisseite auf den Telegram-Kanal
`breachdetect` und bietet selbst keinen maschinenlesbaren Feed. `telegram_kanal` liest die öffentliche
Web-Vorschau dieses Kanals (oder jedes anderen öffentlichen Kanals) ohne Telegram-Konto.

**TeleGramSint.** Das Werkzeug ist menügesteuert und für Agenten nicht bedienbar. Übernommen sind drei seiner
Abfragen. Weggelassen sind die Suche nach Telefonnummern, Mitgliederlisten, Online-Status und Stories:
Telefonnummern erreichen diesen Arbeitsplatz nach der Pseudonymisierung gar nicht, und die übrigen Abfragen
gehen über das hinaus, was für die Einordnung eines Kanals nötig ist. Die Anbieter hinter den RapidAPI-Diensten
sind Einzelpersonen unbekannter Herkunft. Vor dem Einsatz prüfen, ob Selektoren dorthin dürfen.

**Darkus.** Menügesteuert. Seine drei Suchmaschinen (Ahmia, Torch, notEvil) sind in Robin enthalten oder durch
dessen 16 Suchmaschinen ersetzt. Übernommen ist die Prüfung gegen die Ahmia-Sperrliste.

**Robin.** Eigener MCP-Server, läuft als Container (`apurvsg/robin`), Tor inklusive. Der Analyst nutzt
`robin_search` und `robin_scrape` und wertet selbst aus, dafür braucht Robin kein eigenes Sprachmodell. Nach
Angabe des Projekts liest Robin nur Seitentext und lädt keine Dateien. Weil Robin am Gateway vorbeiläuft, übernehmen die Hooks: Der
Wächter verlangt die Freigabe `darkweb`, der Sitzungs-Hook sichert jede Antwort als Beleg `X-0001` … in der
Fallakte und verkettet sie. Für eine Behörde: aus dem eigenen Fork bauen und `ROBIN_IMAGE` setzen.

```bash
docker build -t robin-intern /pfad/zu/eurem/robin-fork
echo 'ROBIN_IMAGE=robin-intern' >> .env
./setup.sh
```

**4chan.** Die Lese-API liefert den Katalog eines Boards. Gesucht wird lokal darin. Threads verschwinden nach
kurzer Zeit, `chan_thread` sichert sie in den Rohdaten.

**Mastodon.** `mastodon_instanz` funktioniert auch bei Instanzen, die sich nicht auffindbar machen.
`mastodon_konto` sucht über eine Instanz eurer Wahl (Standard `mastodon.social`) und braucht die Freigabe
`personenbezug`.
