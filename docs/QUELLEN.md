# Quellen im Einzelnen

Für jede Quelle: was abgefragt wird, was der Anbieter dabei erfährt, und worauf sich die Einbindung stützt.
Die Liste, aus der Gateway, Einrichtung und Selbsttest lesen, ist `gateway/quellen.py`.

**Zur Verlässlichkeit dieser Angaben.** Beim Bau standen keine Schlüssel zur Verfügung. Die Quellen im Abschnitt
«Über das Gateway» wurden nie live abgefragt. Die Blockchain-Quellen ohne Schlüssel sind gegen die echten Dienste
geprüft, siehe [Blockchain](#blockchain). Die Spalte «Stützt sich auf» sagt, woher die Endpunkte stammen.
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

## Blockchain

Die Werkzeuge `krypto_…` fragen je nach Kette verschiedene Dienste. Im Abfrageprotokoll steht der Dienst, der
tatsächlich gefragt wurde, als Werkzeug der einzelnen Abfrage `krypto_abruf`, und darüber die Auswertung des
aufgerufenen Werkzeugs. «Live geprüft» heisst: Am 13.11.2026 in GitHub Actions gegen den echten Dienst gelaufen,
wiederholbar mit `python3 tools/krypto_live.py`.

| Dienst | Wofür | Abfrage | Stützt sich auf |
|---|---|---|---|
| mempool.space, Ausweichquelle Blockstream | Bitcoin: Adresse, Transaktionen, Verbleib der Ausgänge | `GET {mempool.space,blockstream.info}/api/address/{a}`, `/address/{a}/txs`, `/tx/{id}`, `/tx/{id}/outspends` | live geprüft |
| Blockscout | Ethereum, Optimism: Adresse, Zähler, Token-Guthaben, Transaktion | `GET eth.blockscout.com/api/v2/addresses/{a}`, `/counters`, `/token-balances`, `/api/v2/transactions/{id}` | live geprüft |
| | Zahlungen einer Adresse, jüngste zuerst, 50 je Abruf | `GET …/api/v2/addresses/{a}/transactions` und `/token-transfers` mit `filter`, `type=ERC-20`, `token`, weiter mit den Angaben aus `next_page_params` | live geprüft |
| | Älteste Zahlungen einer Adresse mit über 200 Einträgen, zweiter Versuch bei sehr grossen Adressen | `GET …/api?module=account&action={txlist,tokentx}` mit `startblock` und `sort=asc` | live geprüft. Ohne Schlüssel gedrosselt: zehn Abfragen, dann rund 40 Minuten HTTP 429 (Kopfzeilen `x-ratelimit-limit: 10`, `x-ratelimit-reset` in Millisekunden). |
| | Etiketten | `GET metadata.services.blockscout.com/api/v1/metadata?addresses=…&chainId=…` | live geprüft (Ethereum) |
| | Polygon, Arbitrum, Gnosis, Base | dieselben Pfade auf `{kette}.blockscout.com` | Aus dem Rechenzentrum der Prüfung mit HTTP 403 abgewiesen. Nicht geprüft. |
| | Zugang mit `BLOCKSCOUT_API_KEY`, alle sechs Ketten | dieselben Pfade auf `api.blockscout.com/{chain_id}/api/v2/…` und `api.blockscout.com/{chain_id}/api?module=…`, Schlüssel als `apikey`. Frei: 100'000 Credits am Tag, 20 bis 30 je Abfrage. | Dokumentation des Anbieters. Ohne Schlüssel gesehen: HTTP 402 mit der Aufforderung, einen Schlüssel anzugeben. Mit Schlüssel nicht geprüft. |
| | Drossel | Antwort HTTP 429. Das Gateway wartet einmal (Kopfzeile `Retry-After`, sonst sechs Sekunden) und schreibt die Angaben der Quelle zur Drossel ins Protokoll. Laut Anbieter wird der Zugang je Kette ohne Schlüssel eingestellt. | live gesehen |
| Etherscan | Ketten der Ethereum-Familie, Gegenprüfung | `GET api.etherscan.io/v2/api?chainid=…&module=…&action=…`, dazu `module=proxy` für Transaktion, Quittung und Blockzeit | Dokumentation des Anbieters. Ohne Schlüssel gesehen: nur die Fehlermeldungen. |
| TronGrid | TRON: Konto, Zahlungen in TRX und Token | `GET api.trongrid.io/v1/accounts/{a}`, `/transactions`, `/transactions/trc20` | live geprüft (ohne Schlüssel) |
| | Transaktion, Leseaufrufe an Verträge (Sperrliste von Tether, Kürzel und Dezimalstellen fremder Token) | `POST /wallet/gettransactionbyid`, `/wallet/gettransactioninfobyid`, `/wallet/triggerconstantcontract` | live geprüft |
| OFAC | Sanktionsliste SDN mit Krypto-Adressen | `GET sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV` und `SDN_COMMENTS.CSV`, Ausweichadresse `www.treasury.gov/ofac/downloads/` | live geprüft |
| TRM Labs | Sanktionsprüfung | `POST api.trmlabs.com/public/v1/sanctions/screening`. Ohne Schlüssel laut Anbieter eine Anfrage je Sekunde, 100 am Tag, höchstens 1 KB je Anfrage. Das Gateway teilt längere Listen auf (rund 15 Adressen je Anfrage). | live geprüft. Grössere Anfragen wies der Dienst mit HTTP 413 ab. |
| Ransomwhere | bekannte Lösegeld-Adressen (Bitcoin) | `GET api.ransomwhe.re/export` | live geprüft |
| WalletExplorer | Bitcoin: Zuordnung zu benannten Diensten | `GET www.walletexplorer.com/api/1/address-lookup` | live geprüft |
| Tronscan | TRON: Etiketten, Risikohinweise | `GET apilist.tronscanapi.com/api/accountv2`, `/api/security/account/data`, Kopfzeile `TRON-PRO-API-KEY` | Dokumentation des Anbieters. Nicht geprüft. |
| Chainabuse | Betrugsmeldungen | `GET api.chainabuse.com/v0/reports?address=`, Basic-Anmeldung mit dem Schlüssel | Dokumentation des Anbieters. Nicht geprüft. |
| Iknaio | GraphSense: Etiketten, Cluster | `GET api.ikna.io/{btc,eth,trx}/addresses/{a}/tag_summary`, `/entity`, Kopfzeile `Authorization` | Dokumentation von GraphSense. Nicht geprüft. |
| DefiLlama | Kurs in US-Dollar, aktuell und am Stichtag | `GET coins.llama.fi/prices/{current,historical/{zeit}}/{kennung}` | live geprüft |
| Europäische Zentralbank | Referenzkurse USD und CHF je EUR | `GET data-api.ecb.europa.eu/service/data/EXR/D.USD+CHF.EUR.SP00.A` | live geprüft |

**Was die Werkzeuge daraus rechnen.** `gateway/krypto_fluss.py` beschreibt die Verfahren am Kopf der Datei: bei
Bitcoin je Zahlungsausgang mit anteiliger Zuordnung, bei Konto-Ketten in der zeitlichen Reihenfolge der Abgänge.
Die Schwellen der Mustererkennung stehen dort als Konstanten (`SAMMEL_EINGAENGE`, `SAMMEL_AUSGAENGE`,
`MISCH_GLEICHE`, in `krypto_ketten.py` `SEITE`).

**Bekannte Token.** Ein Token wird am Vertrag erkannt, nie am Namen: Jeder kann einen Token «USDT» nennen. Die
eingebaute Liste (`_BEKANNT` in `gateway/krypto_ketten.py`) führt USDT, USDC, DAI und WETH auf sieben Ketten. Jeder
Eintrag ist gegen DefiLlama geprüft (Kürzel, Dezimalstellen). Andere Token werden mit den Angaben der Quelle
geführt und als unbestätigt gekennzeichnet.

**Sanktionsliste.** Die SDN-Liste wird je Fall höchstens einmal in 24 Stunden geladen und liegt als Rohdatei in
der Fallakte (rund 6 MB). Lange Bemerkungen setzt OFAC in einer zweiten Datei fort, mitten im Wort. Das Gateway
fügt beide zusammen, bevor es Adressen sucht. Findet es in der Liste keine einzige Krypto-Adresse, wertet es das
als Störung und meldet «nicht geprüft», nicht «kein Eintrag».

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
| Block-Explorer (mempool.space, Blockstream, Blockscout, Etherscan, TronGrid) | eure Adresse, bei Blockscout, Etherscan und TronGrid den Schlüssel, soweit eingetragen, und jede abgefragte Wallet-Adresse und Transaktion. Bei einem Geldfluss also die ganze Kette der Stationen. | nichts. Eine Blockchain lässt sich lesen, ohne dass der Inhaber einer Adresse es merkt. |
| WalletExplorer, Tronscan, Chainabuse, Iknaio, Blockscout-Etiketten | eure Adresse, die abgefragten Wallet-Adressen | nichts |
| TRM Labs | eure Adresse und alle Wallet-Adressen eines Laufs, in Sammelabfragen | nichts |
| OFAC, Ransomwhere | dass jemand die Liste lädt. **Nicht** die geprüfte Adresse, der Vergleich läuft lokal. | nichts |
| DefiLlama, EZB | eure Adresse, Währung und Stichtag. **Nicht** den Betrag und keine Wallet-Adresse. | nichts |

Wer einem Explorer nicht zeigen will, welche Adressen in einem Verfahren stehen, betreibt ihn selbst:
`KRYPTO_BITCOIN_API` nimmt die Adresse einer eigenen Esplora-Schnittstelle (mempool oder electrs),
`KRYPTO_ETHEREUM_API` und die Entsprechungen je Kette die einer eigenen Blockscout-Instanz, `KRYPTO_TRON_API` die
einer Schnittstelle nach Art von TronGrid.

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
