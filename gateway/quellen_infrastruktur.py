"""Infrastruktur-Quellen: Shodan, Spur, AbuseIPDB, VirusTotal. Alle passiv.

Passiv heisst: Wir fragen die Datenbank eines Dritten ab. Das Ziel selbst
bekommt davon nichts mit. Der Anbieter sieht aber den abgefragten Indikator.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Annotated

from pydantic import Field

from .kern import (Abbruch, Fall, Zweck, abfrage, nimm, pruef_domain, pruef_hash, pruef_ip,
                   pruef_muster, pruef_url, saeubern, schluessel, werkzeug)

# --------------------------------------------------------------------------- Shodan

SHODAN = "https://api.shodan.io"


def _shodan_host(d: dict) -> dict:
    dienste = []
    for s in (d.get("data") or [])[:30]:
        e = nimm(s, "port", "transport", "product", "version", "timestamp")
        http = s.get("http") or {}
        if http:
            e["http"] = nimm(http, "title", "server", "host", "status")
            if (http.get("favicon") or {}).get("hash") is not None:
                e["http"]["favicon_hash"] = http["favicon"]["hash"]
        cert = (s.get("ssl") or {}).get("cert") or {}
        if cert:
            e["tls"] = {"subject_cn": (cert.get("subject") or {}).get("CN"),
                        "issuer_cn": (cert.get("issuer") or {}).get("CN"),
                        "sha256": (cert.get("fingerprint") or {}).get("sha256"),
                        "gueltig_bis": cert.get("expires")}
        if (s.get("ssh") or {}).get("fingerprint"):
            e["ssh_fingerprint"] = s["ssh"]["fingerprint"]
        dienste.append(e)
    return {**nimm(d, "ip_str", "org", "isp", "asn", "os", "country_code", "country_name", "city",
                   "hostnames", "domains", "ports", "tags", "last_update"),
            "vulns": sorted(d.get("vulns") or [])[:40], "dienste": dienste}


@werkzeug
async def shodan_host(fall: Fall, zweck: Zweck, ip: str,
                      verlauf: Annotated[bool, Field(description="Auch frühere Banner liefern")] = False) -> dict:
    """Shodan: offene Ports, Dienste, TLS-Zertifikate, Hostnamen und Betreiber einer IP.
    Zeigt, was auf dem Server läuft. Verbraucht keine Query-Credits."""
    ip = pruef_ip(ip)
    a = await abfrage(fall, zweck, werkzeug="shodan_host", quelle="Shodan", ziel=ip, ziel_typ="ip",
                      url=f"{SHODAN}/shodan/host/{ip}",
                      params={"key": schluessel("SHODAN_API_KEY", "Shodan"),
                              "history": "true" if verlauf else None}, geheim=("key",))
    return a.als_dict(_shodan_host(a.daten) if a.ergebnis == "ok" else None)


@werkzeug
async def shodan_internetdb(fall: Fall, zweck: Zweck, ip: str) -> dict:
    """Shodan InternetDB: Schnellübersicht einer IP (Ports, Hostnamen, CPEs, Tags, bekannte
    Schwachstellen). Kein Schlüssel nötig, wöchentlich aktualisiert. Gut für die erste Sichtung."""
    ip = pruef_ip(ip)
    a = await abfrage(fall, zweck, werkzeug="shodan_internetdb", quelle="Shodan InternetDB", ziel=ip,
                      ziel_typ="ip", url=f"https://internetdb.shodan.io/{ip}")
    return a.als_dict(a.daten if a.ergebnis == "ok" else None)


@werkzeug
async def shodan_dns(fall: Fall, zweck: Zweck, domain: str) -> dict:
    """Shodan: bekannte Subdomains und DNS-Einträge einer Domain. Verbraucht 1 Query-Credit."""
    domain = pruef_domain(domain)
    a = await abfrage(fall, zweck, werkzeug="shodan_dns", quelle="Shodan", ziel=domain, ziel_typ="domain",
                      url=f"{SHODAN}/dns/domain/{domain}",
                      params={"key": schluessel("SHODAN_API_KEY", "Shodan")}, geheim=("key",))
    if a.ergebnis != "ok":
        return a.als_dict()
    d = a.daten
    eintraege = [nimm(e, "subdomain", "type", "value", "last_seen") for e in (d.get("data") or [])[:120]]
    return a.als_dict({"domain": d.get("domain"), "subdomains": (d.get("subdomains") or [])[:200],
                       "tags": d.get("tags"), "eintraege": eintraege})


@werkzeug
async def shodan_suche(fall: Fall, zweck: Zweck,
                       abfrage_text: Annotated[str, Field(description=(
                           "Shodan-Suchausdruck, z. B. 'ssl.cert.fingerprint:<sha1>', "
                           "'http.favicon.hash:<zahl>' oder 'hostname:beispiel.ch'"))],
                       nur_zaehlen: Annotated[bool, Field(description=(
                           "true: nur Trefferzahl und Verteilung (kostet nichts). "
                           "false: Trefferliste (kostet Query-Credits)"))] = True) -> dict:
    """Shodan-Suche über alle Hosts. Für Pivots: Wo taucht dasselbe Zertifikat, Favicon oder
    Banner noch auf? Immer zuerst mit nur_zaehlen=true prüfen, wie viele Treffer es gibt."""
    q = " ".join(abfrage_text.split())
    if len(q) < 4:
        raise Abbruch("Suchausdruck zu kurz.")
    pfad = "count" if nur_zaehlen else "search"
    a = await abfrage(fall, zweck, werkzeug="shodan_suche", quelle="Shodan", ziel=q, ziel_typ="suchausdruck",
                      url=f"{SHODAN}/shodan/host/{pfad}",
                      params={"key": schluessel("SHODAN_API_KEY", "Shodan"), "query": q,
                              "facets": "org:10,country:10,port:10" if nur_zaehlen else None},
                      geheim=("key",))
    if a.ergebnis != "ok":
        return a.als_dict()
    d = a.daten
    treffer = [nimm(m, "ip_str", "port", "org", "hostnames", "timestamp", "product")
               | {"land": (m.get("location") or {}).get("country_code")}
               for m in (d.get("matches") or [])[:50]]
    return a.als_dict({"gesamt": d.get("total"), "verteilung": d.get("facets"), "treffer": treffer})


# --------------------------------------------------------------------------- Spur

@werkzeug
async def spur_kontext(fall: Fall, zweck: Zweck, ip: str,
                       datum: Annotated[str | None, Field(description=(
                           "Optional JJJJMMTT für den Stand an einem früheren Tag "
                           "(braucht ein Spur-Abo mit historischen Abfragen)"))] = None) -> dict:
    """Spur: Ist die IP ein VPN-, Proxy- oder Tor-Ausgang, ein Rechenzentrum oder ein
    Privatanschluss? Nennt Anonymisierungsdienst, Betreiber und beobachtetes Nutzerverhalten.
    Entscheidend für die Frage, ob eine IP einer Person zugeordnet werden kann."""
    ip = pruef_ip(ip)
    if datum:
        pruef_muster(datum, r"20\d{6}", "datum (JJJJMMTT)")
    a = await abfrage(fall, zweck, werkzeug="spur_kontext", quelle="Spur", ziel=ip, ziel_typ="ip",
                      url=f"https://api.spur.us/v2/context/{ip}", params={"dt": datum},
                      kopf={"Token": schluessel("SPUR_TOKEN", "Spur")})
    if a.ergebnis != "ok":
        return a.als_dict()
    d = a.daten
    return a.als_dict({**nimm(d, "ip", "as", "organization", "infrastructure", "location", "risks",
                              "services", "tunnels"),
                       "client": nimm(d.get("client"), "behaviors", "types", "proxies", "count",
                                      "countries", "spread", "concentration")})


# --------------------------------------------------------------------------- AbuseIPDB

ABUSE = "https://api.abuseipdb.com/api/v2"
# Kategorienummern laut AbuseIPDB
_KAT = {1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
        6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
        11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan", 15: "Hacking",
        16: "SQL Injection", 17: "Spoofing", 18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
        21: "Web App Attack", 22: "SSH", 23: "IoT Targeted"}


def _meldungen(liste: list | None, n: int) -> list:
    return [{"zeit": m.get("reportedAt"), "kategorien": [_KAT.get(k, k) for k in m.get("categories") or []],
             "kommentar": saeubern(m.get("comment"), 200), "melder_land": m.get("reporterCountryCode")}
            for m in (liste or [])[:n]]


@werkzeug
async def abuseipdb_pruefen(fall: Fall, zweck: Zweck, ip: str,
                            tage: Annotated[int, Field(ge=1, le=365, description="Betrachteter Zeitraum in Tagen")] = 90) -> dict:
    """AbuseIPDB: Wurde die IP als missbräuchlich gemeldet? Liefert den Abuse-Score (0–100),
    Anzahl und Art der Meldungen, Provider und Nutzungsart. Der Score beruht auf Meldungen
    Dritter und ist ein Hinweis, kein Beweis."""
    ip = pruef_ip(ip)
    a = await abfrage(fall, zweck, werkzeug="abuseipdb_pruefen", quelle="AbuseIPDB", ziel=ip, ziel_typ="ip",
                      url=f"{ABUSE}/check", params={"ipAddress": ip, "maxAgeInDays": tage, "verbose": ""},
                      kopf={"Key": schluessel("ABUSEIPDB_API_KEY", "AbuseIPDB")})
    if a.ergebnis != "ok":
        return a.als_dict()
    d = (a.daten or {}).get("data") or {}
    return a.als_dict({**nimm(d, "ipAddress", "abuseConfidenceScore", "totalReports", "numDistinctUsers",
                              "lastReportedAt", "isp", "usageType", "domain", "countryCode", "hostnames",
                              "isTor", "isWhitelisted", "isPublic"),
                       "letzte_meldungen": _meldungen(d.get("reports"), 10)})


@werkzeug
async def abuseipdb_meldungen(fall: Fall, zweck: Zweck, ip: str,
                              tage: Annotated[int, Field(ge=1, le=365)] = 30,
                              seite: Annotated[int, Field(ge=1)] = 1) -> dict:
    """AbuseIPDB: einzelne Missbrauchsmeldungen zu einer IP mit Zeit, Kategorie und Kommentar.
    Für die Zeitachse: Wann fiel die IP womit auf?"""
    ip = pruef_ip(ip)
    a = await abfrage(fall, zweck, werkzeug="abuseipdb_meldungen", quelle="AbuseIPDB", ziel=ip, ziel_typ="ip",
                      url=f"{ABUSE}/reports",
                      params={"ipAddress": ip, "maxAgeInDays": tage, "page": seite, "perPage": 50},
                      kopf={"Key": schluessel("ABUSEIPDB_API_KEY", "AbuseIPDB")})
    if a.ergebnis != "ok":
        return a.als_dict()
    d = (a.daten or {}).get("data") or {}
    return a.als_dict({**nimm(d, "total", "page", "lastPage"), "meldungen": _meldungen(d.get("results"), 50)})


# --------------------------------------------------------------------------- VirusTotal

VT = "https://www.virustotal.com/api/v3"


def _lesbar(befund: dict) -> dict:
    """Wandelt VirusTotals Unix-Zeitstempel in ISO-Zeit (UTC), damit niemand rechnen muss."""
    for k, v in list(befund.items()):
        if (k == "date" or k.endswith("_date")) and isinstance(v, int) and v > 0:
            befund[k] = datetime.fromtimestamp(v, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return befund


def _vt_kopf() -> dict:
    return {"x-apikey": schluessel("VIRUSTOTAL_API_KEY", "VirusTotal")}


def _vt_basis(d: dict) -> tuple[dict, dict]:
    daten = (d or {}).get("data") or {}
    return daten, daten.get("attributes") or {}


def _vt_urteil(attr: dict) -> dict:
    stats = attr.get("last_analysis_stats") or {}
    benannt = sorted({r.get("result") for r in (attr.get("last_analysis_results") or {}).values()
                      if r.get("category") in ("malicious", "suspicious") and r.get("result")})
    return {"erkennungen": stats, "gesamt_scanner": sum(v for v in stats.values() if isinstance(v, int)),
            "bezeichnungen": benannt[:15], **nimm(attr, "reputation", "tags", "last_analysis_date")}


@werkzeug
async def virustotal_ip(fall: Fall, zweck: Zweck, ip: str) -> dict:
    """VirusTotal: Einschätzung einer IP durch Sicherheitsanbieter, dazu Netz, AS und Land."""
    ip = pruef_ip(ip)
    a = await abfrage(fall, zweck, werkzeug="virustotal_ip", quelle="VirusTotal", ziel=ip, ziel_typ="ip",
                      url=f"{VT}/ip_addresses/{ip}", kopf=_vt_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    _, attr = _vt_basis(a.daten)
    return a.als_dict(_lesbar({**_vt_urteil(attr), **nimm(attr, "as_owner", "asn", "country", "network",
                                                          "regional_internet_registry")}))


@werkzeug
async def virustotal_domain(fall: Fall, zweck: Zweck, domain: str) -> dict:
    """VirusTotal: Einschätzung einer Domain, Registrar, Erstelldatum, letzte DNS-Einträge,
    Kategorien. Das Erstelldatum zeigt, ob eine Domain eigens für die Tat registriert wurde."""
    domain = pruef_domain(domain)
    a = await abfrage(fall, zweck, werkzeug="virustotal_domain", quelle="VirusTotal", ziel=domain,
                      ziel_typ="domain", url=f"{VT}/domains/{domain}", kopf=_vt_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    _, attr = _vt_basis(a.daten)
    dns = [nimm(r, "type", "value", "ttl") for r in (attr.get("last_dns_records") or [])[:40]]
    cert = attr.get("last_https_certificate") or {}
    return a.als_dict(_lesbar({
        **_vt_urteil(attr),
        **nimm(attr, "registrar", "creation_date", "last_update_date", "categories", "tld"),
        "dns": dns,
        "zertifikat": {"sha256": cert.get("thumbprint_sha256"),
                       "subject_cn": (cert.get("subject") or {}).get("CN"),
                       "issuer": (cert.get("issuer") or {}).get("O")} if cert else None}))


@werkzeug
async def virustotal_datei(fall: Fall, zweck: Zweck,
                           hashwert: Annotated[str, Field(description="MD5, SHA-1 oder SHA-256 der Datei")]) -> dict:
    """VirusTotal: Ist eine Datei mit diesem Hash als Schadsoftware bekannt? Liefert
    Erkennungsrate, Malware-Familie, Dateityp, Namen und das Datum der Ersteinreichung.
    Es wird nur der Hash abgefragt. Dateien werden nie hochgeladen."""
    h = pruef_hash(hashwert)
    a = await abfrage(fall, zweck, werkzeug="virustotal_datei", quelle="VirusTotal", ziel=h, ziel_typ="hash",
                      url=f"{VT}/files/{h}", kopf=_vt_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    _, attr = _vt_basis(a.daten)
    klass = attr.get("popular_threat_classification") or {}
    return a.als_dict(_lesbar({
        **_vt_urteil(attr),
        **nimm(attr, "sha256", "sha1", "md5", "type_description", "size", "meaningful_name",
               "first_submission_date", "last_submission_date", "times_submitted"),
        "namen": (attr.get("names") or [])[:10],
        "familie": klass.get("suggested_threat_label"),
        "kategorien": [k.get("value") for k in klass.get("popular_threat_category") or []]}))


@werkzeug
async def virustotal_url(fall: Fall, zweck: Zweck, url: str) -> dict:
    """VirusTotal: vorhandene Analyse zu einer URL abrufen. Es wird kein neuer Scan ausgelöst,
    die Zielseite wird nicht kontaktiert. Unbekannte URLs ergeben 'kein_treffer'."""
    u = pruef_url(url)
    url_id = base64.urlsafe_b64encode(u.encode()).decode().rstrip("=")
    a = await abfrage(fall, zweck, werkzeug="virustotal_url", quelle="VirusTotal", ziel=u, ziel_typ="url",
                      url=f"{VT}/urls/{url_id}", kopf=_vt_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    _, attr = _vt_basis(a.daten)
    return a.als_dict(_lesbar({
        **_vt_urteil(attr),
        **nimm(attr, "url", "last_final_url", "title", "categories", "first_submission_date",
               "last_http_response_code", "threat_names")}))


_VT_SAMMLUNG = {"ip": "ip_addresses", "domain": "domains", "datei": "files", "url": "urls"}


@werkzeug
async def virustotal_beziehungen(fall: Fall, zweck: Zweck,
                                 typ: Annotated[str, Field(description="ip | domain | datei | url")],
                                 wert: str,
                                 beziehung: Annotated[str, Field(description=(
                                     "z. B. resolutions (IP↔Domain über die Zeit), subdomains, "
                                     "communicating_files, contacted_domains, contacted_ips, "
                                     "dropped_files. Manche brauchen ein Premium-Abo."))],
                                 limit: Annotated[int, Field(ge=1, le=40)] = 20) -> dict:
    """VirusTotal: Verknüpfungen eines Indikators. Wichtigstes Pivot-Werkzeug: Welche Domains
    zeigten wann auf diese IP? Welche Dateien sprechen mit dieser Domain?"""
    if typ not in _VT_SAMMLUNG:
        raise Abbruch("typ muss ip, domain, datei oder url sein.")
    pruef_muster(beziehung, r"[a-z_]{3,40}", "beziehung")
    if typ == "ip":
        ident = pruef_ip(wert)
    elif typ == "domain":
        ident = pruef_domain(wert)
    elif typ == "datei":
        ident = pruef_hash(wert)
    else:
        ident = base64.urlsafe_b64encode(pruef_url(wert).encode()).decode().rstrip("=")
    a = await abfrage(fall, zweck, werkzeug="virustotal_beziehungen", quelle="VirusTotal",
                      ziel=f"{wert} → {beziehung}", ziel_typ=typ,
                      url=f"{VT}/{_VT_SAMMLUNG[typ]}/{ident}/{beziehung}", params={"limit": limit},
                      kopf=_vt_kopf())
    if a.ergebnis != "ok":
        return a.als_dict()
    eintraege = []
    for e in (a.daten or {}).get("data") or []:
        attr = e.get("attributes") or {}
        eintraege.append(_lesbar({"id": e.get("id"), "typ": e.get("type"),
                                  **nimm(attr, "ip_address", "host_name", "date", "meaningful_name",
                                         "type_description", "last_analysis_stats", "creation_date")}))
    return a.als_dict({"anzahl": len(eintraege), "eintraege": eintraege})
