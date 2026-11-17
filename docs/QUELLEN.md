# Quellen im Einzelnen

Für jede Quelle: was abgefragt wird, was der Anbieter dabei erfährt, und worauf sich die Einbindung stützt.
Die Liste, aus der Gateway, Einrichtung und Selbsttest lesen, ist `gateway/quellen.py`.

**Zur Verlässlichkeit dieser Angaben.** Die Spalte «Stand» sagt, was gegen den echten Dienst gelaufen ist und
wann. «Geprüft» heisst: Das Werkzeug wurde über das Gateway aufgerufen, und die gekürzte Antwort wurde Feld für
Feld mit der Rohdatei verglichen (Fallakte `SELBSTTEST`). «Nicht geprüft» nennt den Grund. Die Antwortformen der
geprüften Dienste stehen als Vorlagen in `tools/_vorlagen.py`, die Selbsttests laufen dagegen.
`python3 tools/pruefen.py --live` prüft jede eingerichtete Quelle mit einem harmlosen Testwert. Schlägt eine fehl,
steht die Antwort des Anbieters in `faelle/SELBSTTEST/rohdaten/`, und der Endpunkt lässt sich in der genannten
Datei anpassen.

## Über das Gateway

| Quelle | Werkzeug | Abfrage | Stand |
|---|---|---|---|
| Shodan | `shodan_host` | `GET api.shodan.io/shodan/host/{ip}` | geprüft am 16.11.2026 (8.8.8.8, 1.1.1.1) |
| | `shodan_dns` | `GET api.shodan.io/dns/domain/{domain}` | nicht prüfbar mit einem kostenlosen Konto: HTTP 403 «Requires membership or higher to access». Die Antwortform ist nicht gesehen. |
| | `shodan_suche` | `GET api.shodan.io/shodan/host/count` oder `/search` | Zählen mit Verteilung geprüft am 16.11.2026 (geht mit kostenlosem Konto). Die Trefferliste (`/search`) ist nicht geprüft, sie kostet Query-Credits. |
| Shodan InternetDB | `shodan_internetdb` | `GET internetdb.shodan.io/{ip}` | geprüft am 16.11.2026 |
| VirusTotal | `virustotal_ip`, `_domain`, `_datei`, `_url` | `GET www.virustotal.com/api/v3/{ip_addresses,domains,files,urls}/{id}` | geprüft am 16.11.2026 (8.8.8.8, example.com, Hash der EICAR-Testdatei, `https://example.com/`) |
| | `virustotal_beziehungen` | `GET …/{sammlung}/{id}/{beziehung}` | geprüft am 16.11.2026 mit `resolutions` einer Domain. Andere Beziehungen sind nicht geprüft, manche verlangen ein Premium-Abo. |
| Spur | `spur_kontext` | `GET api.spur.us/v2/context/{ip}`, Kopfzeile `Token` | nicht geprüft, kein Schlüssel. Endpunkt nach docs.spur.us. |
| AbuseIPDB | `abuseipdb_pruefen`, `_meldungen` | `GET api.abuseipdb.com/api/v2/check` und `/reports`, Kopfzeile `Key` | geprüft am 16.11.2026 (8.8.8.8, 1.1.1.1) |
| proxycheck.io | `ip_einordnung` | `GET proxycheck.io/v3/{ip}?key=…&tag=0`, mit Tatzeit in den letzten 60 Tagen zusätzlich `days` und `history=1` | geprüft am 16.11.2026 (8.8.8.8, 1.1.1.1, ein öffentlich gelisteter Tor-Ausgang), mit und ohne Historie. Die Antwort weicht von der Dokumentation ab, siehe [Hinweise](#hinweise-je-quelle). Ein gelöschter Eintrag ohne heutige Erkennung ist nicht gesehen. |
| ipapi.is | `ip_einordnung` | `POST api.ipapi.is` mit `{"q": ip, "key": …}` | geprüft am 16.11.2026 mit Schlüssel (dieselben drei Adressen) und einmal ohne (gekürzte Antwort). Das Objekt `vpn` trug keine der Adressen: Es steht nach der Dokumentation in der Vorlage. |
| RIPEstat | `ip_einordnung` | `GET stat.ripe.net/data/{network-info, prefix-overview, whois, abuse-contact-finder}/data.json`, mit Tatzeit auch `routing-history` und `historical-whois` | alle sechs Aufrufe geprüft am 16.11.2026, an einem Netz der RIPE-Datenbank und an zweien bei ARIN und APNIC |
| urlscan.io | `urlscan_suche` | `GET urlscan.io/api/v1/search/?q=…&size=`, Kopfzeile `API-Key` | geprüft am 16.11.2026: Domain, URL, IP, AS, SHA-256 (fünf Suchen) |
| | `urlscan_ergebnis` | `GET urlscan.io/api/v1/result/{uuid}/`, `/dom/{uuid}/`, `/screenshots/{uuid}.png` | geprüft am 16.11.2026 an einem öffentlichen Scan von example.com: Ergebnis, Seitentext, Bildschirmfoto (PNG, 1600 × 1200). Ein Scan mit Urteil «bösartig» und einer, der noch läuft (HTTP 404), sind nicht gesehen. |
| | `urlscan_kontingent` | `GET urlscan.io/api/v1/quotas/` | geprüft am 16.11.2026 |
| | `urlscan_einreichen` | `POST urlscan.io/api/v1/scan/` mit `{"url": …, "visibility": "private"}` | nicht geprüft (aktive Massnahme). Antwortform nach der Dokumentation. |
| urlquery | `urlquery_suche`, `_reputation` | `GET api.urlquery.net/public/v1/search/reports/`, `/reputation/check/`, Kopfzeile `x-apikey` | geprüft am 16.11.2026. Die Suche fragt Felder ab, siehe [Hinweise](#hinweise-je-quelle). |
| | `urlquery_bericht` | `GET …/report/{id}` | geprüft am 16.11.2026 an einem öffentlichen Bericht: Alarme, Aufrufe, Hosts. Ein Bericht mit heruntergeladenen Dateien (`artifacts.files`) kam nicht vor. |
| | `urlquery_status`, `_einreichen` | `GET …/submit/status/{id}`, `POST …/submit/url` | nicht geprüft: Beides setzt eine Einreichung voraus, und die ist eine aktive Massnahme. Eine erfundene Kennung beantwortet der Dienst mit HTTP 400. |
| Wayback Machine | `wayback_verlauf` | `GET web.archive.org/cdx/search/cdx` | nicht prüfbar aus der Prüfumgebung vom 16.11.2026: Die Verbindung zu `web.archive.org` brach jedes Mal ab. Endpunkte nach der Dokumentation der CDX-Schnittstelle. |
| | `wayback_abruf` | `GET web.archive.org/web/{zeit}id_/{url}` | wie oben |
| | `wayback_sichern` | `GET web.archive.org/save/{url}` | nicht geprüft (aktive Massnahme) |
| Web-Check | `webcheck_passiv` | `GET {WEBCHECK_URL}/api/{prüfung}?url=` | geprüft am 16.11.2026 auf einem GitHub-Runner (Workflow «Web-Check live», Abbild vom 15.11.2026): Zwölf der 13 Prüfungen lieferten für example.com ein Ergebnis, `shodan` fehlt in der Instanz der Schlüssel. Hinter einem Proxy gesehen: Der Container startet, das Gateway erreicht die Instanz, die Prüfungen scheitern und das Gateway sagt es. Siehe [Hinweise](#hinweise-je-quelle). |
| | `webcheck_aktiv` | wie oben | nicht geprüft (aktive Massnahme) |
| ransomware.live | `ransomware_aktuell`, `_opfer`, `_gruppe`, `_iocs` | API PRO: `api-pro.ransomware.live/{victims/recent, victims/search?q=, victims/?group=, victims/?country=, groups/{g}, iocs/{g}}`, Kopfzeile `X-API-KEY` | alle sechs Pfade geprüft am 16.11.2026 |
| | | API v2: `api.ransomware.live/v2/{recentvictims, searchvictims/{x}, groupvictims/{g}, countryvictims/{cc}, group/{g}}` | nicht geprüft: laut Anbieter nur für private Nutzung |
| Ahmia | `onion_sperrliste` | `GET ahmia.fi/blacklist/banned/`, Vergleich lokal | geprüft am 16.11.2026: Die Liste enthielt 60'371 Zeilen, jede ein MD5-Wert. Ein Treffer ist nicht geprüft: Dafür bräuchte es eine gesperrte Adresse. |
| Telegram | `telegram_kanal` | `GET t.me/s/{kanal}` | geprüft am 16.11.2026 mit dem Kanal `telegram` (20 Beiträge gelesen). Für `breachdetect` zeigte Telegram keine Web-Vorschau mehr, siehe [Hinweise](#hinweise-je-quelle). |
| RapidAPI | `telegram_kanalinfo` | `GET telegram-channel.p.rapidapi.com/channel/info` | nicht geprüft, kein Schlüssel. Endpunkt aus dem Quellcode von TeleGramSint. |
| | `telegram_entitaet`, `telegram_suche` | `GET telegram-scraper-api.p.rapidapi.com/entity/{fetch,search}` | nicht geprüft, kein Schlüssel. Kontoabfragen. |
| 4chan | `chan_katalog`, `chan_thread` | `GET a.4cdn.org/{board}/catalog.json`, `/thread/{nr}.json` | geprüft am 16.11.2026 |
| Mastodon | `mastodon_instanz` | `GET {instanz}/api/v2/instance`, sonst `/api/v1/instance` | geprüft am 16.11.2026 (mastodon.social, Schnittstelle v2). Der Rückfall auf v1 ist nicht geprüft. |
| | `mastodon_konto` | `GET {instanz}/api/v2/search?type=accounts` oder `/api/v1/accounts/lookup` | nicht geprüft: Kontoabfrage zu einer Person |

Ohne Abfrage nach aussen: `tools/beleg.py` trägt eine Abklärung von Hand als Beleg `X-…` ein (Quelle, Zeitpunkt,
Wortlaut, wer). Das Gateway ist daran nicht beteiligt, der Eintrag steht in `protokoll/extern.jsonl`.

Was die Prüfung vom 16.11.2026 gezeigt hat und seither behoben ist, jeweils mit Selbsttest:

- Das MCP-SDK stellt das Logging des Gateways auf INFO. `httpx` schrieb damit jede Adresse ins Log des MCP-Servers,
  bei Shodan, Etherscan und Blockscout samt Schlüssel. Im Gateway schweigt `httpx` jetzt.
- Web-Check meldet eine gescheiterte Prüfung mit HTTP 200. Das Gateway wertete sie als Treffer.
- ransomware.live: Als Zahl der Opfer stand die Länge der gekürzten Liste da (60) statt der Zahl der Quelle
  (zum Beispiel 2016). Der Steckbrief einer Gruppe las Felder, die es in der API PRO nicht gibt. Die API PRO
  wiederholt in jeder Antwort die E-Mail-Adresse des eigenen Kontos: Sie ging an den Agenten und in die Rohdatei.
- VirusTotal: Bei Beziehungen stand nur die Zahl der gelieferten Einträge da, nicht die Gesamtzahl.
- Telegram und Wayback: «nichts da» stand im Protokoll als Treffer.
- urlquery: Die Suche lief im Volltext, und der Bericht las Alarme und Dateien aus Feldern, die es nicht gibt.
- Der Sitzungs-Hook legte die Antwort jedes MCP-Servers als Beleg `X-…` in den Fall, den die Sitzung zuletzt berührt
  hatte, auch die von GitHub. Belege sind jetzt nur noch Antworten von Quellen (Robin).
- Blockscout: siehe [Blockchain](#blockchain).

## Blockchain

Die Werkzeuge `krypto_…` fragen je nach Kette verschiedene Dienste. Im Abfrageprotokoll steht der Dienst, der
tatsächlich gefragt wurde, als Werkzeug der einzelnen Abfrage `krypto_abruf`, und darüber die Auswertung des
aufgerufenen Werkzeugs. «Live geprüft» heisst: Am 13.11.2026 in GitHub Actions gegen den echten Dienst gelaufen,
ohne Schlüssel, wiederholbar mit `python3 tools/krypto_live.py`. Die Zugänge mit Schlüssel (Blockscout, TronGrid,
Etherscan, Tronscan, Chainabuse) sind am 16.11.2026 mit kostenlosen Schlüsseln geprüft, das steht bei der Zeile.

| Dienst | Wofür | Abfrage | Stützt sich auf |
|---|---|---|---|
| mempool.space, Ausweichquelle Blockstream | Bitcoin: Adresse, Transaktionen, Verbleib der Ausgänge | `GET {mempool.space,blockstream.info}/api/address/{a}`, `/address/{a}/txs`, `/tx/{id}`, `/tx/{id}/outspends` | live geprüft |
| Blockscout | Ethereum, Optimism: Adresse, Zähler, Token-Guthaben, Transaktion | `GET eth.blockscout.com/api/v2/addresses/{a}`, `/counters`, `/token-balances`, `/api/v2/transactions/{id}` | live geprüft |
| | Zahlungen einer Adresse, jüngste zuerst, 50 je Abruf | `GET …/api/v2/addresses/{a}/transactions` und `/token-transfers` mit `filter`, `type=ERC-20`, `token`, weiter mit den Angaben aus `next_page_params` | live geprüft |
| | Älteste Zahlungen einer Adresse mit über 200 Einträgen, zweiter Versuch bei sehr grossen Adressen | `GET …/api?module=account&action={txlist,tokentx}` mit `startblock` und `sort=asc` | live geprüft. Ohne Schlüssel gedrosselt: zehn Abfragen, dann rund 40 Minuten HTTP 429 (Kopfzeilen `x-ratelimit-limit: 10`, `x-ratelimit-reset` in Millisekunden). |
| | Etiketten | `GET metadata.services.blockscout.com/api/v1/metadata?addresses=…&chainId=…` | live geprüft (Ethereum) |
| | Polygon, Arbitrum, Gnosis, Base | dieselben Pfade auf `{kette}.blockscout.com` | Aus dem Rechenzentrum der Prüfung mit HTTP 403 abgewiesen. Nicht geprüft. |
| | Zugang mit `BLOCKSCOUT_API_KEY` | dieselben Pfade auf `api.blockscout.com/{chain_id}/api/v2/…` und `api.blockscout.com/{chain_id}/api?module=…`, Schlüssel als `apikey`. Frei: 100'000 Credits am Tag, 20 bis 30 je Abfrage. | Geprüft am 16.11.2026 mit einem kostenlosen Schlüssel: Ethereum, Optimism, Arbitrum und Gnosis antworten. Polygon und Base weist der Dienst mit HTTP 402 ab («Featured chain 137 requires one of the following plans: Builder, Business, Pro»). Das Gateway nennt den Grund und fragt für diese Ketten die öffentliche Instanz der Kette, danach Etherscan. Ohne Schlüssel antwortet der Zugang mit HTTP 402 und der Aufforderung, einen anzugeben. |
| | Drossel | Antwort HTTP 429. Das Gateway wartet einmal (Kopfzeile `Retry-After`, sonst sechs Sekunden) und schreibt die Angaben der Quelle zur Drossel ins Protokoll. Laut Anbieter wird der Zugang je Kette ohne Schlüssel eingestellt. | live gesehen |
| Etherscan | Ketten der Ethereum-Familie, Gegenprüfung | `GET api.etherscan.io/v2/api?chainid=…&module=…&action=…`, dazu `module=proxy` für Transaktion, Quittung und Blockzeit | Geprüft am 16.11.2026 mit einem kostenlosen Schlüssel: Gegenprüfung einer Ethereum-Transaktion («stimmt überein»), Adresse und Token-Guthaben auf Polygon und Arbitrum. Gnosis und Base lehnt der Dienst im kostenlosen Paket ab («Free API access is not supported for this chain», mit HTTP 200). BNB Smart Chain und Optimism sind nicht geprüft. |
| TronGrid | TRON: Konto, Zahlungen in TRX und Token | `GET api.trongrid.io/v1/accounts/{a}`, `/transactions`, `/transactions/trc20` | live geprüft, ohne Schlüssel am 13.11.2026 und mit Schlüssel am 16.11.2026 |
| | Transaktion, Leseaufrufe an Verträge (Sperrliste von Tether, Kürzel und Dezimalstellen fremder Token) | `POST /wallet/gettransactionbyid`, `/wallet/gettransactioninfobyid`, `/wallet/triggerconstantcontract` | live geprüft |
| OFAC | Sanktionsliste SDN mit Krypto-Adressen | `GET sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN.CSV` und `SDN_COMMENTS.CSV`, Ausweichadresse `www.treasury.gov/ofac/downloads/` | live geprüft |
| TRM Labs | Sanktionsprüfung | `POST api.trmlabs.com/public/v1/sanctions/screening`. Ohne Schlüssel laut Anbieter eine Anfrage je Sekunde, 100 am Tag, höchstens 1 KB je Anfrage. Das Gateway teilt längere Listen auf (rund 15 Adressen je Anfrage). | live geprüft. Grössere Anfragen wies der Dienst mit HTTP 413 ab. |
| Ransomwhere | bekannte Lösegeld-Adressen (Bitcoin) | `GET api.ransomwhe.re/export` | live geprüft |
| WalletExplorer | Bitcoin: Zuordnung zu benannten Diensten | `GET www.walletexplorer.com/api/1/address-lookup` | live geprüft |
| Tronscan | TRON: Etiketten, Risikohinweise | `GET apilist.tronscanapi.com/api/accountv2`, `/api/security/account/data`, Kopfzeile `TRON-PRO-API-KEY` | Geprüft am 16.11.2026: Für die Adresse einer Börse stehen `publicTag` und `addressTag` in der Antwort («Binance-Hot 2»). Ohne Etikett fehlen beide Felder ganz. Das Feld `name` ist der Name, den sich der Inhaber selbst gegeben hat, und wird nicht als Etikett gewertet. Ein Geldfluss, der bei einem so benannten Dienst endet, ist in der Prüfung nicht vorgekommen. |
| Chainabuse | Betrugsmeldungen | `GET api.chainabuse.com/v0/reports?address=`, Basic-Anmeldung mit dem Schlüssel | Geprüft am 16.11.2026 mit einer Abfrage: `count`, je Meldung `scamCategory`, `createdAt`, `checked`, `trusted`. |
| Iknaio | GraphSense: Etiketten, Cluster | `GET api.ikna.io/{btc,eth,trx}/addresses/{a}/tag_summary`, `/entity`, Kopfzeile `Authorization` | nicht geprüft, kein Schlüssel. Endpunkte nach der Dokumentation von GraphSense. |
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

### Etikettenliste: GraphSense TagPacks

Eine lokale Liste, kein Dienst. Quelle ist das Repo [graphsense/graphsense-tagpacks](https://github.com/graphsense/graphsense-tagpacks)
der Iknaio Cryptoasset Analytics GmbH und des AIT Austrian Institute of Technology (Österreich), MIT-Lizenz.
Festgelegt ist der Commit `83754852bd65b697055ae03aceb7b655eefb4259` vom 5.11.2026. Das Verzeichnis
`gateway/listen/tagpacks.json` nennt jede der 87 Dateien mit Prüfsumme, die Zahl der übernommenen Einträge und bei
jeder ausgelassenen Datei den Grund.

| Teil | Inhalt | Wo |
|---|---|---|
| Kern | 31'718 Einträge aus 61 Dateien: Börsen und ihre Reserve-Adressen, Mischdienste, Märkte, DeFi-Protokolle, Glücksspiel, Lösegeld-, Betrugs- und Phishing-Adressen, Adressen aus Einbrüchen bei Diensten | im Repo, `gateway/listen/tagpacks.csv.gz` (680 KB) |
| Massenlisten | 481'322 Einträge aus elf Dateien: Reserve-Adressen der Börse BitMEX, Adressen aus Erpresser-Spam, Mining-Adressen, CoinJoin-Adressen von Samourai | nicht im Repo (rund 12 MB). `python3 tools/listen.py laden` holt die Dateien einzeln von raw.githubusercontent.com, prüft jede gegen das Verzeichnis und legt die Tabelle unter `listen/` ab |
| Ausgelassen | 15 Dateien: zwei mit natürlichen Personen (Sanktionslisten, OFAC lädt das Gateway selbst), sechs aus Etherscan-Etiketten abgeleitete (dessen Bedingungen untersagen die Wiedergabe), zwei mit politischen Zuschreibungen, eine mit Adressen von Privatpersonen, die Beispieldatei, drei ohne Adresse einer verfolgten Kette | |

Übernommen werden Bitcoin, Ethereum und TRON. Ein Eintrag für Ethereum gilt nur auf Ethereum, nicht auf den
verwandten Ketten. Zuordnung der Kategorien: «Dienst» (dort endet eine Verfolgung, ein Editionsbegehren kann
ansetzen) ist nur `exchange`, `payment_processor` und `wallet_service`. `mixing_service` und `coinjoin` sind
Mischdienste. Trägt ein Eintrag einen Missbrauch (`ransomware`, `scam`, `phishing`, `service_hack` und weitere),
ist die Adresse nie ein Dienst, auch wenn daneben eine Kategorie steht. Alles andere bleibt ein Name ohne Folge
für die Verfolgung. Geprüft am 16.11.2026: Bau der Tabelle aus allen Dateien, Laden der Massenlisten samt
Prüfsummen, Nachschlagen bekannter Adressen. Mit Massenlisten braucht das Gateway rund 85 MB Arbeitsspeicher und
zwei Sekunden zum Einlesen, ohne sie ist beides vernachlässigbar.

Nicht eingebaut ist die Sammlung «eth-labels» (MIT-Lizenz für den Code). Ihre Daten sind nach eigener Angabe aus
der Etikettenwolke von Etherscan ausgelesen, und die Bedingungen von Etherscan untersagen genau das und die
Wiedergabe der Etiketten. Iknaio als Abfragequelle bleibt, wie bisher, eine Zugabe mit eigenem Schlüssel.

## Was der Anbieter erfährt

Passiv heisst nicht unsichtbar. Jede Abfrage hinterlässt beim Anbieter eine Spur.

| Quelle | Der Anbieter sieht | Das Ziel sieht |
|---|---|---|
| Shodan, VirusTotal, Spur, AbuseIPDB, urlquery (Suche), ransomware.live | euren Schlüssel, eure Adresse (oder die des Proxys), den Indikator | nichts |
| Shodan InternetDB, Wayback Machine | eure Adresse, den Indikator | nichts |
| `ip_einordnung`: proxycheck.io, ipapi.is | euren Schlüssel, eure Adresse, die IP-Adresse. proxycheck.io legt eine Adresse mit Treffer sonst 180 Tage im Konto ab: Das Gateway bittet mit `tag=0` darum, das zu lassen. Die Tatzeit erfährt proxycheck.io nur als Zahl von Tagen (`days`). | nichts |
| `ip_einordnung`: RIPEstat | eure Adresse, die IP-Adresse oder ihr Netz, bei einer Tatzeit den Tag, und den Namen der Anwendung (`sourceapp`) | nichts |
| `urlscan_suche`, `urlscan_ergebnis`, `urlscan_kontingent` | urlscan.io: euren Schlüssel, eure Adresse, den Suchbegriff oder die Kennung des Scans | nichts |
| `urlscan_einreichen` | urlscan.io: die URL. Der Scan ist «private»: sichtbar für das eigene Konto und für urlscan.io, nicht in der öffentlichen Suche. | einen Besuch von einem Server von urlscan.io |
| Web-Check passiv | je nach Prüfung DNS-Resolver, RDAP, crt.sh, Tranco und weitere Dritte: eure Adresse und die Domain | nichts vom Webserver. Die Nameserver des Ziels sehen DNS-Anfragen der Resolver. |
| Web-Check aktiv | | die Adresse eurer Web-Check-Instanz, in seinen Serverprotokollen |
| `urlquery_einreichen` | urlquery: die URL. Der Bericht ist «private», das Gateway reicht nie öffentlich ein. | einen Besuch von urlquery |
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
| Etikettenliste (GraphSense TagPacks) | niemand etwas: Die Liste liegt im Repo. Nur wer mit `tools/listen.py laden` die Massenlisten holt, zeigt GitHub, dass dieser Rechner die öffentlichen TagPacks abruft. **Nie** eine geprüfte Adresse. | nichts |
| DefiLlama, EZB | eure Adresse, Währung und Stichtag. **Nicht** den Betrag und keine Wallet-Adresse. | nichts |

Rohdateien mit HTML einer fremden Seite (Wayback, Telegram, Seitentext von urlscan.io) liegen als `.html.txt` in der
Akte: unverändert im Inhalt, aber so benannt, dass ein Klick sie als Text zeigt und nicht als Seite öffnet.

Wer einem Explorer nicht zeigen will, welche Adressen in einem Verfahren stehen, betreibt ihn selbst:
`KRYPTO_BITCOIN_API` nimmt die Adresse einer eigenen Esplora-Schnittstelle (mempool oder electrs),
`KRYPTO_ETHEREUM_API` und die Entsprechungen je Kette die einer eigenen Blockscout-Instanz, `KRYPTO_TRON_API` die
einer Schnittstelle nach Art von TronGrid.

Zugangsdaten in der Adresse einer eigenen Instanz (`https://name:passwort@host`) schwärzt das Gateway im Protokoll.
Einen Schlüssel im Pfad einer solchen Adresse kann es nicht erkennen: Er stünde im Protokoll. Dafür also keinen
Pfad verwenden, sondern Benutzername und Passwort.

Mit `OSINT_PROXY` in `.env` laufen alle Abfragen des Gateways über einen Proxy. Das Protokoll vermerkt je
Abfrage, ob ein Proxy verwendet wurde. Web-Check auf dem eigenen Rechner wird immer direkt angesprochen. Für
aktive Prüfungen muss die Web-Check-Instanz selbst auf einer Infrastruktur laufen, die nicht auf euch zurückführt.

Antwortet der Proxy nicht, kommt keine Abfrage durch, und keine geht an ihm vorbei. Das Gateway prüft dann, ob der
Proxy selbst eine Verbindung annimmt, und nennt ihn in der Fehlermeldung als Ursache. `fall_status` meldet
`proxy_antwortet: false`, und die Ermittlung hält an, bevor sie eine Abfrage versucht. Wer in der Einrichtung
«Tor auf diesem Rechner» wählt, bekommt Tor installiert und gestartet (Paket `tor`, Port 9050). Dieses Tor ist
nicht das von Robin: Robin bringt sein eigenes im Container mit und braucht `OSINT_PROXY` nicht.

## Hinweise je Quelle

**VirusTotal.** Das Gateway fragt nur ab. Es lädt keine Dateien hoch und löst keine neuen Scans aus, denn
Hochgeladenes ist für andere Kunden des Dienstes einsehbar. Zur eigenen Drossel: `VT_INTERVALL` in Sekunden.

**Spur.** `datum` (JJJJMMTT) fragt den Stand an einem früheren Tag ab und braucht laut Dokumentation ein Abo mit
historischen Abfragen. Für die Zuordnung einer IP zur Tatzeit ist das der entscheidende Parameter: Die Auskunft
von heute beschreibt den Besitzer von heute.

**AbuseIPDB.** Meldungen stammen von jedermann. Der Score fasst zusammen, er beweist nichts.

**Einordnung einer IP (`ip_einordnung`).** Ein Werkzeug, mehrere Stimmen. Jede Teilabfrage steht einzeln im
Protokoll (Werkzeug `ip_abruf`), die Auswertung als eigener Eintrag. Der Wert zum Anonymisierungsdienst ist «ja»
(mindestens eine Quelle führt die Adresse, bei Widerspruch mit dem Vermerk «Quellen uneinig»), «kein Hinweis»
(mindestens eine Quelle hat geantwortet, keine führt sie) oder «nicht geprüft». Kontaktpersonen aus den Registern
und aus der Antwort von ipapi.is gibt das Werkzeug nicht weiter: Gebraucht wird, wem das Netz gehört, nicht wer
dort arbeitet. In den Rohdateien stehen sie, unverändert.

**proxycheck.io.** Betreiber und Sitz nennt der Dienst auf seinen Seiten nicht (Bedingungen, Datenschutz und
Kontakt gelesen am 16.11.2026). Server laut eigener Angabe in Kanada, Grossbritannien, Deutschland, Finnland, Polen
und Singapur. Bedingungen vom 12.7.2026: Die Daten dürfen den eigenen Dienst anreichern, das ganze Ergebnis der
Schnittstelle darf nicht wörtlich weitergegeben werden (der Rapport nennt deshalb nur die einschlägigen Angaben),
ein kostenloses Konto je Kunde, der Schlüssel bleibt in der Organisation. Den Einsatz durch Behörden regeln sie
nicht eigens, eine Nennung verlangen sie nicht. Die echte Antwort weicht von der Dokumentation ab: Das Risiko steht
unter `detections`, der Ort unter `location.country_code` und `city_name`, die Löschung unter
`detection_history.delisted` und `delist_datetime`. Ein Feld für Residential Proxies gibt es nicht: Sie zeigen sich
an der Art des Netzes (`Residential`, `Wireless`) zusammen mit einer Erkennung. Der Parameter `history` steht nur im
Blog des Dienstes vom 11.2.2026, der Dienst nimmt ihn an.

**ipapi.is.** Betreiber ist ein Einzelunternehmer in Berlin (Impressum des Dienstes). Bedingungen vom 3.10.2026: Das
kostenlose Paket liefert die volle Antwort für jeden zulässigen Zweck, die Nutzung ist intern, einzelne Ergebnisse
dürfen in eigenen Aufzeichnungen bleiben, Weitergabe der Daten als solche ist ausgeschlossen. Juristische Personen
des öffentlichen Rechts sind als Kunden genannt. Abgefragte Adressen speichert der Dienst laut seiner Vereinbarung
zur Auftragsverarbeitung nicht. Ohne Schlüssel antwortet er seit dem 1.9.2026 gekürzt (30 Abfragen am Tag, keine
Merkmale `is_vpn`, `is_proxy`, `is_tor`) und sperrt einen Anschluss, der nach einer Abweisung weiterfragt. Das
Gateway fragt deshalb nur mit Schlüssel und wiederholt nach einer Abweisung nicht. Der Schlüssel geht im Körper der
Anfrage mit, nicht in der Adresse. Laut eigener Dokumentation erkennt `is_proxy` vor allem offene Proxys,
Residential und mobile Proxys meist nicht.

**RIPEstat.** Betreiber ist das RIPE NCC in Amsterdam, die Vergabestelle für Europa. Kein Schlüssel. Der Dienst
bittet um einen Namen der Anwendung (`sourceapp`, einstellbar über `OSINT_RIPESTAT_APP`), um höchstens acht
gleichzeitige Anfragen und ab rund 1'000 Anfragen am Tag um eine Anmeldung. Die Bedingungen nennen Netzanalyse und
Forschung als Zweck, verbieten die Weitergabe der Daten als eigenes Angebot und verlangen bei Veröffentlichungen
die Nennung des RIPE NCC. Den Einsatz durch Behörden regeln sie nicht eigens. Wer das Netz zur Tatzeit ankündigte,
kommt aus den Routing-Daten (alle Register). Wem es damals zugeteilt war, kennt der Dienst nur für Netze der
RIPE-Datenbank: Für ARIN, APNIC, LACNIC und AFRINIC sagt das Ergebnis, dass nur der heutige Eintrag bekannt ist.

**urlscan.io.** Betreiber ist die urlscan GmbH in Deutschland. Die Suche findet öffentliche Scans, mit dem
kostenlosen Konto die der letzten 365 Tage. Eine Suche nach einer Domain findet auch Scans, in denen die Domain nur
nachgeladen wurde. Der Seitentext (`/dom/`) ist Fremdinhalt: Das Werkzeug gibt ihn als Text zurück, gekürzt und
gekennzeichnet, nie als HTML. Das Bildschirmfoto liegt als PNG in den Rohdaten. Einreichen: nur mit Freigabe
`aktiv`, nach einer Suche nach vorhandenen Scans, nach einem Blick aufs Kontingent, und immer mit
`visibility: private`. Dafür gibt es keinen Parameter, und im Kern des Gateways sitzt eine Schranke: Eine
Einreichung ohne «private» verlässt das Gateway nicht, egal welches Werkzeug sie schickt. Reicht das Kontingent
für private Scans nicht (kostenlos 50 am Tag, 5 je Minute), wird nicht eingereicht. Meldet der Dienst für den Scan
eine andere Sichtbarkeit zurück, steht das als Warnung im Ergebnis. Die Bedingungen vom 22.7.2020 sprechen von
persönlicher, nicht kommerzieller Nutzung. Die Hilfeseite des Dienstes nennt die Nutzung im Arbeitsalltag
(Sicherheitsbetrieb, Untersuchungen, Berichte) ausdrücklich in Ordnung und bittet bei grossen Mengen um Rückfrage.
Ob das den Einsatz einer Behörde deckt, entscheidet ihr: im Zweifel den Anbieter fragen oder ein bezahltes Konto nehmen.

**Abklärung von Hand und Spur.** `tools/beleg.py` ist an keine Quelle gebunden. Zum kostenlosen Zugang von Spur
steht in der Hilfe des Anbieters (gelesen am 16.11.2026): «No. Spur does not offer free or discounted accounts for
law enforcement or government investigative agencies. Standard commercial licensing applies». Die kostenlose
Lizenz ist nach den Bedingungen für die eigene Erprobung gedacht. Für Ermittlungen deckt sie das Nachschlagen von
Hand also nicht: Dafür braucht es eine bezahlte Lizenz.

**urlquery.** `urlquery_einreichen` reicht immer mit dem Zugriff `private` ein. Einen Parameter dafür gibt es nicht mehr,
und die Schranke im Kern des Gateways lässt eine Einreichung mit anderem Zugriff nicht hinaus. Vor jeder Einreichung sucht der Analyst
nach vorhandenen Berichten.

Ohne Feldnamen sucht urlquery im Volltext der Berichte ([Hilfe des Anbieters](https://urlquery.net/help/search)). Am
16.11.2026 lieferte «example.com» so 25'280 Treffer, die obersten ohne Bezug zur Domain. `urlquery_suche` erkennt
deshalb, ob der Suchtext eine Domain, IP, URL oder ein Hash ist, und fragt die passenden Felder ab, für eine Domain
`url.domain`, `url.fqdn`, `final.url.*` und `http.url.*`. Mit `art=text` bleibt die Volltextsuche möglich, das
Ergebnis sagt es dann dazu. Ein Treffer heisst: Der Wert kommt im Bericht vor. In welcher Rolle, zeigt erst der
Bericht. Dessen Form weicht von dem ab, was beim Bau angenommen war: Alarme stehen je Sensorgruppe unter
`detection`, Dateien unter `artifacts.files`. Beides ist behoben.

Die Nutzungsbedingungen von urlquery sprechen von «lawful, personal, non-commercial purposes». Ob euer Einsatz
darunter fällt, klärt ihr mit dem Anbieter.

**Web-Check.** 13 passive und 27 aktive Prüfungen. Passiv: `archives`, `block-lists`, `breaches`, `caa-records`,
`dns`, `dnssec`, `get-ip`, `rank`, `shodan`, `subdomains`, `threats`, `txt-records`, `whois`. Die Prüfung
`threats` bleibt nur passiv, solange in der Web-Check-Instanz kein Cloudmersive-Schlüssel hinterlegt ist: Mit
Schlüssel lässt sie die Seite von Cloudmersive aufrufen. `mail-config` gilt hier als aktiv, weil sie die
MTA-STS-Richtlinie vom Server des Ziels holt.

Web-Check meldet eine gescheiterte Prüfung mit HTTP 200 und dem Feld `error`, eine ausgelassene mit dem Feld
`skipped`. Das Gateway deutet beides: `error` ist ein Fehlschlag («nicht geprüft»), `skipped` ist «kein Treffer»,
wenn es nichts gab («No TXT records for this host»), und ein Fehlschlag, wenn der Instanz ein Schlüssel fehlt oder
keine der befragten Stellen geantwortet hat. Die Prüfung `shodan` braucht einen Shodan-Schlüssel im Container. Den
gibt die Einrichtung nicht weiter, die Prüfung meldet deshalb «nicht eingerichtet». Für Shodan gibt es die eigenen
Werkzeuge `shodan_host` und `shodan_internetdb`.

Die Prüfung `threats` befragt fünf Stellen und antwortet je Stelle. Am 16.11.2026 antworteten zwei (PhishTank,
NetAPI), drei nicht: Google Safe Browsing und Cloudmersive verlangen einen Schlüssel in der Instanz, URLhaus wies
die Anfrage mit HTTP 401 ab. Das Gateway nennt das unter `teilweise_nicht_geprueft`: Das Ergebnis gilt dann nur für
die Stellen, die geantwortet haben. Antwortet keine, ist die Prüfung ein Fehlschlag.

Die Instanz muss DNS, WHOIS und die befragten Dienste selbst erreichen. Hinter einem HTTPS-Proxy tut sie das oft
nicht: Dann scheitern die meisten Prüfungen, und das Gateway sagt es. `python3 tools/webcheck_live.py` ruft jede
passive Prüfung einmal auf und zeigt das Urteil samt Rohantwort. Derselbe Lauf wiederholt sich jede Woche im
Workflow «Web-Check live».

**ransomware.live.** Der Dienst gibt wieder, was Tätergruppen auf ihren Leak-Seiten behaupten. Die schlüssellose
API v2 ist laut Anbieter für die private Nutzung gedacht. Das Gateway nutzt sie nur, wenn `RANSOMWARE_LIVE_V2=1`
gesetzt ist. Für den Dienstgebrauch: API PRO mit Schlüssel, Bedingungen des Anbieters lesen.

Listen sind gekürzt: An den Agenten gehen die ersten 60 Einträge in der Reihenfolge der Quelle (neueste zuerst),
`anzahl` nennt die Zahl der Quelle, `gezeigt` die der gelieferten Einträge. Die ganze Liste liegt in der Rohdatei.
Die API PRO wiederholt in jeder Antwort unter `client` die E-Mail-Adresse, auf die der Schlüssel lautet. Das
Gateway ersetzt sie in der Rohdatei durch `***` und vermerkt das im Protokolleintrag (`antwort.bereinigt`). Sonst
bleibt die Rohdatei, wie die Quelle sie geliefert hat.

**Ahmia-Sperrliste.** Liefert die Liste nichts, was wie eine Liste von MD5-Werten aussieht, meldet das Werkzeug
einen Fehler und rät vom Öffnen ab. «Nicht auf der Liste» ist keine Unbedenklichkeitserklärung.

**Telegram Breach Monitor.** Die Seite auf osintcabal.org ist eine Hinweisseite auf den Telegram-Kanal
`breachdetect` und bietet selbst keinen maschinenlesbaren Feed. `telegram_kanal` liest die öffentliche
Web-Vorschau eines Kanals ohne Telegram-Konto. Nicht jeder Kanal hat eine: Am 16.11.2026 leitete Telegram für
`breachdetect` auf die Kanalseite um, ohne Beiträge. Das Werkzeug meldet dann «kein Treffer» mit dem Grund und
gibt wieder, was die Kanalseite zeigt (Titel, Beschreibung, Zahl der Abonnenten). Das ist eine Lücke, kein
«nichts gefunden»: Die Beiträge lassen sich so nicht lesen.

**TeleGramSint.** Das Werkzeug ist menügesteuert und für Agenten nicht bedienbar. Übernommen sind drei seiner
Abfragen. Weggelassen sind die Suche nach Telefonnummern, Mitgliederlisten, Online-Status und Stories:
Telefonnummern erreichen diesen Arbeitsplatz nach der Pseudonymisierung gar nicht, und die übrigen Abfragen
gehen über das hinaus, was für die Einordnung eines Kanals nötig ist. Die Anbieter hinter den RapidAPI-Diensten
sind Einzelpersonen unbekannter Herkunft. Vor dem Einsatz prüfen, ob Selektoren dorthin dürfen.

**Darkus.** Menügesteuert. Seine drei Suchmaschinen (Ahmia, Torch, notEvil) sind in Robin enthalten oder durch
dessen 16 Suchmaschinen ersetzt. Übernommen ist die Prüfung gegen die Ahmia-Sperrliste.

**Robin.** Eigener MCP-Server, läuft als Container (`apurvsg/robin`), Tor inklusive. Das Abbild ist auf eine
Prüfsumme festgelegt (Stand bei Docker Hub vom 3.10.2026), ebenso das von Web-Check (Stand vom 15.11.2026): Was
läuft, ändert sich nicht von selbst. Ein neuer Stand ist ein bewusster Schritt. Der Analyst nutzt
`robin_search` und `robin_scrape` und wertet selbst aus, dafür braucht Robin kein eigenes Sprachmodell. Nach
Angabe des Projekts liest Robin nur Seitentext und lädt keine Dateien. Weil Robin am Gateway vorbeiläuft, gilt: Jeder
Aufruf braucht die Zustimmung des Sachbearbeiters (Regel «ask», die Oberfläche lehnt ihn ohne Freigabe `darkweb` von
selbst ab), und der Sitzungs-Hook sichert jede Antwort als Beleg `X-0001` … in der
Fallakte und verkettet sie. Das gilt für die Server, die der Hook als Quelle kennt (`BELEG_SERVER` in
`.claude/hooks/protokoll_hook.py`, heute Robin). Andere MCP-Server sind Arbeitsmittel: Ihre Aufrufe stehen im
Sitzungsprotokoll, ihre Antworten sind kein Beleg. Für eine Behörde: aus dem eigenen Fork bauen und `ROBIN_IMAGE` setzen.

```bash
docker build -t robin-intern /pfad/zu/eurem/robin-fork
echo 'ROBIN_IMAGE=robin-intern' >> .env
./setup.sh
```

Was Robin vom Rechner und vom Netz braucht. Die Angaben stammen aus Startskript, Quelltext und Fehlerhilfe des
Projekts (gelesen am 17.11.2026). Im Betrieb geprüft sind sie nicht, und das festgelegte Abbild ist älter als
dieser Stand.

- **Kein Tor und kein SOCKS5 auf dem Rechner.** Tor läuft im Container. Robin spricht es dort über
  `socks5h://127.0.0.1:9050` an, der Port ist nach aussen nicht veröffentlicht. `OSINT_PROXY` hat damit nichts zu
  tun: Die Einstellung lenkt nur die Abfragen des Gateways.
- **Der Container muss das Tor-Netz direkt erreichen.** Robin kennt keine Einstellung für Brücken (Bridges:
  Zugänge für Netze, die Tor sperren) und keine für einen vorgeschalteten Proxy. In einem Netz, das Tor sperrt oder
  nur über einen Web-Proxy nach aussen lässt, kommt Tor nicht hoch. Dann braucht es ein Netz, das Tor zulässt,
  oder ein eigenes Abbild mit eigener Tor-Konfiguration (`ROBIN_IMAGE`).
- **Claude Code startet den Container zu Beginn jeder Sitzung** und entfernt ihn an ihrem Ende. Von Hand ist
  nichts zu starten. Tor läuft dabei sofort an und verbindet sich mit dem Tor-Netz, auch wenn der Fall keine
  Freigabe `darkweb` hat. Gesucht und gelesen wird erst mit einem Werkzeugaufruf, und der braucht die Freigabe. Wer
  diese Verbindung an einem Arbeitsplatz nicht will, richtet ihn ohne Robin ein: `./setup.sh --ohne-robin`.
- **Tor braucht nach dem Start zehn Sekunden bis zwei Minuten.** Bis dahin melden `robin_search` und
  `robin_scrape` den Stand `tor_bootstrapping` und tun nichts. `robin_health` zeigt, ob Tor läuft und welche
  Suchmaschinen antworten. Bleibt es bei `tor_bootstrapping`, erreicht der Container das Tor-Netz nicht.
- **Ein Schlüssel für ein Sprachmodell ist nicht nötig.** Ohne ihn fragt Robin beim Start keinen Anbieter an.

**4chan.** Die Lese-API liefert den Katalog eines Boards. Gesucht wird lokal darin. Threads verschwinden nach
kurzer Zeit, `chan_thread` sichert sie in den Rohdaten.

**Mastodon.** `mastodon_instanz` funktioniert auch bei Instanzen, die sich nicht auffindbar machen.
`mastodon_konto` sucht über eine Instanz eurer Wahl (Standard `mastodon.social`) und braucht die Freigabe
`personenbezug`.
