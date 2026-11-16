/* Die Oberfläche im Browser. Eine Datei, keine Bibliothek, nichts von aussen.
   Der Server liefert jede Ansicht als fertiges HTML. Dieses Skript holt sie, setzt sie ein und macht sie bedienbar:
   Navigation, feste Adressen, sortierbare Tabellen mit Filter und CSV, Arbeitsspur, Filter und Bilder im Rapport.
   Was aus Quellen stammt, hat der Server als Text maskiert. Dieses Skript setzt eigene Texte nur über textContent. */
"use strict";

const $ = (s, w = document) => w.querySelector(s);
const $$ = (s, w = document) => Array.from(w.querySelectorAll(s));
const el = (name, attribute = {}, ...kinder) => {
  const e = document.createElement(name);
  for (const [k, v] of Object.entries(attribute)) {
    if (k === "text") e.textContent = v; else if (k === "klasse") e.className = v; else e.setAttribute(k, v);
  }
  for (const kind of kinder) e.append(kind);
  return e;
};
const zustand = { fall: null, ansicht: "", spurStand: 0, spurFall: null, spurFilter: new Set(), spurTimer: null, indikatoren: [] };

async function holen(weg) {
  const antwort = await fetch(weg, { headers: { Accept: "application/json" } });
  let daten = null;
  try { daten = await antwort.json(); } catch (e) { /* keine lesbare Antwort */ }
  if (!antwort.ok || !daten) throw new Error((daten && daten.fehler) || `Der Server antwortet nicht wie erwartet (HTTP ${antwort.status}).`);
  return daten;
}

function weg(...teile) { return "#/" + teile.map(encodeURIComponent).join("/"); }

/* ---------- Navigation und Adressen ---------- */

function adresse() {
  const teile = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (teile[0] === "fall" && teile[1]) return { fall: teile[1], ansicht: teile[2] || "uebersicht", arg: teile.slice(3).join("/") };
  return { fall: null, ansicht: teile[0] || "faelle", arg: "" };
}

function navigation(a) {
  const nav = $("#nav");
  nav.replaceChildren();
  nav.append(el("div", { klasse: "marke-app", text: "OSINT-Arbeitsplatz" }));
  const liste = el("ul");
  const punkt = (text, ziel, aktiv, unter = false) => {
    const verweis = el("a", { href: ziel, text });
    if (aktiv) verweis.setAttribute("aria-current", "page");
    liste.append(el("li", unter ? { klasse: "unter" } : {}, verweis));
  };
  punkt("Fälle", "#/", !a.fall && a.ansicht === "faelle");
  if (a.fall) {
    liste.append(el("li", { klasse: "gruppe", text: a.fall }));
    const eintraege = [["uebersicht", "Fallübersicht"], ["rapport", "Rapport"], ["indikatoren", "Indikatoren"], ["rohdaten", "Rohdaten"], ["suche", "Suche"], ["dokumente", "Dokumente"]];
    const gleich = { indikator: "indikatoren", beleg: "rohdaten", roh: "rohdaten", dokument: "dokumente" };
    for (const [name, text] of eintraege) punkt(text, weg("fall", a.fall, name), (gleich[a.ansicht] || a.ansicht) === name, true);
  }
  punkt("Quellen", "#/quellen", !a.fall && a.ansicht === "quellen");
  nav.append(liste);
  const farbe = el("button", { type: "button", klasse: "farbwahl", text: "Hell / Dunkel" });
  farbe.addEventListener("click", () => {
    const jetzt = document.documentElement.dataset.farbe || (matchMedia("(prefers-color-scheme: dark)").matches ? "dunkel" : "hell");
    document.documentElement.dataset.farbe = jetzt === "dunkel" ? "hell" : "dunkel";
    try { localStorage.setItem("farbe", document.documentElement.dataset.farbe); } catch (e) { /* ohne Speicher gilt die Wahl bis zum Neuladen */ }
  });
  nav.append(farbe, el("p", { klasse: "klein", text: "Die Oberfläche liest nur. Adressen aus dem Fall sind nie anklickbar." }));
}

async function laden() {
  const a = adresse();
  navigation(a);
  const mitte = $("#mitte");
  mitte.setAttribute("aria-busy", "true");
  try {
    if (a.fall !== zustand.fall) {
      zustand.fall = a.fall;
      $("#kopf").replaceChildren();
      spurNeu(a.fall);
    }
    if (a.fall) await kopfLaden(a.fall);
    const pfad = a.fall ? `/api/fall/${encodeURIComponent(a.fall)}/${encodeURIComponent(a.ansicht === "rapport" ? "rapport" : a.ansicht)}`
      + (a.arg && a.ansicht !== "rapport" ? "/" + a.arg.split("/").map(encodeURIComponent).join("/") : "") : `/api/${a.ansicht === "quellen" ? "quellen" : "faelle"}`;
    const daten = await holen(pfad);
    mitte.innerHTML = daten.html;      // HTML des eigenen Servers: Fremdinhalte sind dort als Text maskiert
    document.title = `${daten.titel} · OSINT-Arbeitsplatz`;
    einrichten(mitte, a);
    if (a.ansicht === "rapport" && a.arg) { const ziel = document.getElementById(a.arg); if (ziel) { ziel.scrollIntoView(); ziel.classList.add("ziel"); } } else mitte.scrollTop = 0;
    mitte.focus({ preventScroll: true });
  } catch (e) {
    mitte.replaceChildren(el("h1", { text: "Das hat nicht geklappt" }), el("p", { klasse: "banner", text: e.message }),
      el("p", {}, el("a", { href: a.fall ? weg("fall", a.fall) : "#/", text: a.fall ? "Zur Fallübersicht" : "Zur Liste der Fälle" })));
  }
  mitte.removeAttribute("aria-busy");
}

async function kopfLaden(fall) {
  const daten = await holen(`/api/fall/${encodeURIComponent(fall)}/kopf`);
  $("#kopf").innerHTML = daten.html;
  zustand.indikatoren = daten.indikatoren || [];
}

/* ---------- Tabellen: sortieren, filtern, CSV ---------- */

function zellwert(td) {
  const roh = td.querySelector("[data-roh]");
  if (roh) { const n = Number(roh.dataset.roh); if (!Number.isNaN(n)) return n; }
  const text = td.textContent.trim();
  const zahl = Number(text.replace(/'/g, "").replace(/\s/g, ""));
  return text !== "" && !Number.isNaN(zahl) ? zahl : text.toLocaleLowerCase("de-CH");
}

function csvSicher(text) {      // eine Zelle, die mit = + - @ beginnt, hält eine Tabellenkalkulation für eine Formel
  const t = /^[=+\-@\t\r]/.test(text) ? "'" + text : text;
  return /[";\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t;
}

function tabelleEinrichten(tabelle) {
  if (tabelle.dataset.fertig) return;
  if (!tabelle.tHead) {     // Tabellen des Rapports haben ihre Kopfzeile als erste Zeile: Sie wird zum Tabellenkopf
    const erste = tabelle.rows[0];
    if (!erste || !Array.from(erste.cells).every(c => c.tagName === "TH")) return;
    tabelle.createTHead().append(erste);
  }
  const koerper = tabelle.tBodies[0];
  if (!koerper) return;
  tabelle.dataset.fertig = "1";
  const zeilen = () => Array.from(koerper.rows);
  const leiste = el("div", { klasse: "tabellenleiste nicht-drucken" });
  const zahl = el("span", { klasse: "klein" });
  const feld = el("input", { type: "search", placeholder: "Tabelle filtern", "aria-label": "Tabelle filtern: " + (tabelle.dataset.name || "") });
  const csv = el("button", { type: "button", text: "CSV" });
  const zaehlen = () => { const sichtbar = zeilen().filter(z => !z.hidden).length; zahl.textContent = `${sichtbar} von ${zeilen().length} Zeilen`; };
  feld.addEventListener("input", () => {
    const q = feld.value.trim().toLocaleLowerCase("de-CH");
    for (const z of zeilen()) z.hidden = q !== "" && !z.textContent.toLocaleLowerCase("de-CH").includes(q);
    zaehlen();
  });
  csv.addEventListener("click", () => {
    const text = (zelle) => { const k = zelle.cloneNode(true); k.querySelectorAll(".hilfe, .nicht-csv, summary").forEach(x => x.remove()); return k.textContent.replace(/\s+/g, " ").trim(); };
    const kopf = Array.from(tabelle.tHead.rows[0].cells).map(text);
    const inhalt = [kopf].concat(zeilen().filter(z => !z.hidden).map(z => Array.from(z.cells).map(text)));
    const blob = new Blob(["﻿" + inhalt.map(z => z.map(csvSicher).join(";")).join("\r\n")], { type: "text/csv;charset=utf-8" });
    const verweis = el("a", { href: URL.createObjectURL(blob), download: ((zustand.fall ? zustand.fall + "_" : "") + (tabelle.dataset.name || "tabelle")).replace(/[^\w.-]+/g, "_") + ".csv" });
    document.body.append(verweis); verweis.click(); verweis.remove(); setTimeout(() => URL.revokeObjectURL(verweis.href), 1000);
  });
  leiste.append(feld, csv, zahl);
  (tabelle.closest(".tabelle-breit") || tabelle).before(leiste);
  Array.from(tabelle.tHead.rows[0].cells).forEach((th, spalte) => {
    const knopf = el("button", { type: "button", klasse: "sortieren", title: "Nach dieser Spalte sortieren" });
    while (th.firstChild) knopf.append(th.firstChild);
    th.append(knopf);
    knopf.addEventListener("click", () => {
      const ab = th.getAttribute("aria-sort") === "ascending";
      for (const andere of tabelle.tHead.rows[0].cells) andere.removeAttribute("aria-sort");
      th.setAttribute("aria-sort", ab ? "descending" : "ascending");
      const sortiert = zeilen().sort((x, y) => {
        const a = zellwert(x.cells[spalte]), b = zellwert(y.cells[spalte]);
        const v = typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b), "de-CH", { numeric: true });
        return ab ? -v : v;
      });
      koerper.append(...sortiert);
    });
  });
  zaehlen();
}

/* ---------- Was jede Ansicht bekommt ---------- */

function einrichten(wurzel, a) {
  $$("table", wurzel).forEach(tabelleEinrichten);       // jede Tabelle: sortieren, filtern, CSV
  $$(".hilfe", wurzel).forEach(h => h.addEventListener("click", () => { h.classList.toggle("offen"); h.dataset.text = h.getAttribute("title"); }));
  const form = $(".suchform", wurzel);
  if (form) form.addEventListener("submit", (e) => { e.preventDefault(); location.hash = weg("fall", a.fall, "suche", $("#suchfeld").value.trim()); });
  $$("[data-stelle]", wurzel).forEach(w => { if (!w.title) w.title = "Stelle in der Rohdatei: " + (w.dataset.stelle || "(die ganze Antwort)"); });
  const rapport = $(".rapport", wurzel);
  if (rapport) rapportEinrichten(rapport, a);
}

/* ---------- Arbeitsspur ---------- */

const SPUR_FILTER = [["abfrage", "Abfragen"], ["kein_treffer", "kein Treffer"], ["fehlschlag", "Fehlschläge"], ["auswertung", "Auswertungen"], ["freigabe", "Freigaben"]];
const SPUR_ZEICHEN = { ok: "●", kein_treffer: "○", fehler: "✕", abgelehnt: "⊘" };

function spurNeu(fall) {
  clearTimeout(zustand.spurTimer);
  zustand.spurStand = 0; zustand.spurFall = fall;
  const spur = $("#spur");
  spur.replaceChildren();
  if (!fall) { spur.hidden = true; return; }
  spur.hidden = false;
  spur.append(el("h2", { text: "Arbeitsspur" }));
  const filter = el("div", { klasse: "spurfilter", role: "group", "aria-label": "Arbeitsspur filtern" });
  for (const [name, text] of SPUR_FILTER) {
    const knopf = el("button", { type: "button", "aria-pressed": "false", text });
    knopf.addEventListener("click", () => {
      if (zustand.spurFilter.has(name)) zustand.spurFilter.delete(name); else zustand.spurFilter.add(name);
      knopf.setAttribute("aria-pressed", String(zustand.spurFilter.has(name)));
      spurFiltern();
    });
    knopf.setAttribute("aria-pressed", String(zustand.spurFilter.has(name)));
    filter.append(knopf);
  }
  spur.append(filter, el("ol", { id: "spurliste", "aria-live": "polite" }), el("div", { id: "spurfuss", klasse: "klein" }));
  spurHolen();
}

function spurFiltern() {
  const f = zustand.spurFilter;
  for (const li of $$("#spurliste li")) li.hidden = f.size > 0 && !Array.from(f).some(name => li.dataset.klassen.split(" ").includes(name));
}

async function spurHolen() {
  const fall = zustand.spurFall;
  if (!fall) return;
  try {
    const daten = await holen(`/api/fall/${encodeURIComponent(fall)}/spur?ab=${zustand.spurStand}`);
    if (fall !== zustand.spurFall) return;
    const liste = $("#spurliste");
    for (const e of daten.eintraege) {
      const klassen = [e.klasse].concat(e.freigabe || e.ergebnis === "abgelehnt" ? ["freigabe"] : []);
      const zeit = e.zeit_anzeige || "";       // Zeitzone des Arbeitsplatzes, vom Server gerechnet
      const art = e.art === "auswertung" ? "Auswertung" : e.art === "lokal" ? "lokale Liste" : e.art === "aktiv" ? "aktiv" : e.art === "von_hand" ? "von Hand" : "passiv";
      const kopf = el("div", { klasse: "spurkopf" }, el("a", { href: weg("fall", fall, "beleg", e.id), text: e.id }), el("time", { text: zeit, title: (e.zeit || "") + " (UTC)" }),
        el("span", { klasse: "marke", text: art }));
      const text = el("div", { klasse: "spurtext" });
      text.append(el("span", { klasse: "z-" + (e.ergebnis === "ok" ? "gut" : e.ergebnis === "kein_treffer" ? "neutral" : "kritisch"), text: (SPUR_ZEICHEN[e.ergebnis] || "?") + " " }),
        el("b", { text: e.quelle || "" }), document.createTextNode(" · "), el("span", { klasse: "mono", text: e.ziel || "" }));
      const li = el("li", { "data-klassen": klassen.join(" ") }, kopf, text);
      if (e.aus_cache) li.append(el("div", { klasse: "klein", text: `aus dem Fall-Cache (${e.aus_cache})` }));
      if (e.fehler) li.append(el("div", { klasse: "klein", text: e.fehler }));
      liste.prepend(li);
    }
    if (daten.eintraege.length) { zustand.spurStand = daten.anzahl; spurFiltern(); if (zustand.fall === fall) kopfLaden(fall).catch(() => {}); }
    const fuss = $("#spurfuss");
    fuss.replaceChildren(el("span", { text: `${daten.anzahl} Einträge · ` }),
      el("span", { klasse: daten.kette_ok ? "z-gut" : "z-kritisch", text: daten.kette_ok ? "✓ Kette unversehrt" : "✕ Kette gebrochen: " + (daten.kette_fehler[0] || "") }));
    for (const f of daten.freigaben) fuss.append(el("div", { text: `Freigabe ${f.name}: erteilt durch ${f.durch}` }));
  } catch (e) {
    const fuss = $("#spurfuss");
    if (fuss) fuss.textContent = "Die Arbeitsspur ist nicht erreichbar. Läuft die Oberfläche noch? " + e.message;
  }
  zustand.spurTimer = setTimeout(spurHolen, 3000);
}

/* ---------- Rapport: filtern, aufklappen, Graf, Zeitachse, Geldfluss ---------- */

function auswahl(titel, werte) {
  const wahl = el("select", { "aria-label": titel });
  wahl.append(el("option", { value: "", text: titel + ": alle" }));
  for (const [wert, text] of werte) wahl.append(el("option", { value: wert, text }));
  return wahl;
}

function rapportEinrichten(rapport, a) {
  const fall = rapport.dataset.fall;
  const karten = $$(".karte[data-sicherheit]", rapport);
  if (karten.length) {
    const einzig = (name) => Array.from(new Set(karten.flatMap(k => k.dataset[name].split(" ").filter(Boolean)))).sort();
    const s = auswahl("Sicherheit", [["hoch", "hoch"], ["mittel", "mittel"], ["tief", "tief"]]);
    const art = auswahl("Art", [["feststellung", "Feststellung"], ["bewertung", "Bewertung"], ["hypothese", "Hypothese"]]);
    const ind = auswahl("Indikator", einzig("indikatoren").map(i => [i, i]));
    const wer = auswahl("Analyst", einzig("analysten").map(i => [i, i]));
    const zahl = el("span", { klasse: "klein" });
    const filtern = () => {
      let n = 0;
      for (const k of karten) {
        const zeigen = (!s.value || k.dataset.sicherheit === s.value) && (!art.value || k.dataset.art === art.value)
          && (!ind.value || k.dataset.indikatoren.split(" ").includes(ind.value)) && (!wer.value || k.dataset.analysten.split(" ").includes(wer.value));
        k.hidden = !zeigen; n += zeigen ? 1 : 0;
      }
      zahl.textContent = `${n} von ${karten.length} Befunden`;
    };
    const leiste = el("div", { klasse: "filterleiste nicht-drucken", role: "group", "aria-label": "Befunde filtern" }, s, art, ind, wer, zahl);
    [s, art, ind, wer].forEach(w => w.addEventListener("change", filtern));
    karten[0].before(leiste);
    filtern();
    for (const k of karten) {       // Befund aufklappen bis zum Beleg und zur Rohdatei
      const belege = k.dataset.belege.split(" ").filter(Boolean);
      if (!belege.length) continue;
      const auf = el("details", { klasse: "belege nicht-drucken" }, el("summary", { text: `Belege und Rohdateien (${belege.length})` }));
      const liste = el("ul");
      for (const b of belege) liste.append(el("li", {}, el("a", { href: weg("fall", fall, "beleg", b), text: `${b}: was die Quelle sagt` }), document.createTextNode(" · "),
        el("a", { href: weg("fall", fall, "roh", b), text: "Rohdatei" })));
      auf.append(liste);
      k.append(auf);
      if (k.dataset.analysten) k.append(el("p", { klasse: "klein nicht-drucken", text: "Abfragen durch: " + k.dataset.analysten.split(" ").join(", ") }));
    }
  }
  const graf = $('svg[aria-label="Beziehungsgraf der Indikatoren"]', rapport);
  if (graf) grafEinrichten(graf, fall);
  const fluss = $('svg[aria-label="Geldfluss vom Start zu den Enden"]', rapport);
  if (fluss) flussEinrichten(fluss, fall, JSON.parse(rapport.dataset.fluesse || "[]"));
  const achse = $("ol.zeitachse", rapport);
  if (achse) zeitachseEinrichten(achse, JSON.parse(rapport.dataset.zeitachse || "[]"));
}

function schwenkbar(svg, leiste) {
  const start = svg.getAttribute("viewBox").split(/\s+/).map(Number);
  let box = start.slice();
  const setzen = () => svg.setAttribute("viewBox", box.join(" "));
  const zoom = (faktor) => { const b = box[2] * faktor, h = box[3] * faktor; box = [box[0] + (box[2] - b) / 2, box[1] + (box[3] - h) / 2, b, h]; setzen(); };
  const knopf = (text, titel, tun) => { const k = el("button", { type: "button", title: titel, "aria-label": titel, text }); k.addEventListener("click", tun); leiste.append(k); };
  knopf("+", "Vergrössern", () => zoom(0.8)); knopf("−", "Verkleinern", () => zoom(1.25));
  knopf("←", "Nach links", () => { box[0] -= box[2] * 0.15; setzen(); }); knopf("→", "Nach rechts", () => { box[0] += box[2] * 0.15; setzen(); });
  knopf("↑", "Nach oben", () => { box[1] -= box[3] * 0.15; setzen(); }); knopf("↓", "Nach unten", () => { box[1] += box[3] * 0.15; setzen(); });
  knopf("Ganz", "Ganzes Bild zeigen", () => { box = start.slice(); setzen(); });
  let zug = null;
  svg.style.cursor = "grab";
  svg.addEventListener("pointerdown", (e) => { zug = { x: e.clientX, y: e.clientY, box: box.slice() }; svg.setPointerCapture(e.pointerId); });
  svg.addEventListener("pointermove", (e) => {
    if (!zug) return;
    const mass = box[2] / svg.clientWidth;
    box[0] = zug.box[0] - (e.clientX - zug.x) * mass; box[1] = zug.box[1] - (e.clientY - zug.y) * mass; setzen();
  });
  svg.addEventListener("pointerup", () => { zug = null; });
  svg.addEventListener("wheel", (e) => { if (e.ctrlKey || e.metaKey) { e.preventDefault(); zoom(e.deltaY < 0 ? 0.9 : 1.1); } }, { passive: false });
}

function grafEinrichten(svg, fall) {
  const leiste = el("div", { klasse: "bildleiste nicht-drucken", role: "group", "aria-label": "Beziehungsgraf bedienen" });
  svg.before(leiste);
  schwenkbar(svg, leiste);
  const gruppen = $$("g", svg).map(g => ({ g, titel: (g.querySelector("title") || {}).textContent || "" }));
  const knoten = gruppen.filter(x => /^I-\d+ · /.test(x.titel));
  const kanten = gruppen.filter(x => /^I-\d+ .* I-\d+$/.test(x.titel) && !/ · /.test(x.titel));
  const aus = new Set();
  const zeigen = () => {
    for (const k of knoten) k.g.style.display = aus.has(k.titel.split(" ")[0]) ? "none" : "";
    for (const k of kanten) { const ids = k.titel.match(/I-\d+/g) || []; k.g.style.display = ids.some(i => aus.has(i)) ? "none" : ""; }
  };
  const wahl = el("details", { klasse: "ausblenden" }, el("summary", { text: "Teile ausblenden" }));
  for (const k of knoten) {
    const id = k.titel.split(" ")[0];
    const haken = el("input", { type: "checkbox", checked: "" });
    haken.addEventListener("change", () => { if (haken.checked) aus.delete(id); else aus.add(id); zeigen(); });
    wahl.append(el("label", {}, haken, document.createTextNode(" " + k.titel)));
    k.g.style.cursor = "pointer"; k.g.setAttribute("tabindex", "0"); k.g.setAttribute("role", "link"); k.g.setAttribute("aria-label", "Datenblatt " + k.titel);
    const gehen = () => { location.hash = weg("fall", fall, "indikator", id); };
    k.g.addEventListener("click", gehen); k.g.addEventListener("keydown", (e) => { if (e.key === "Enter") gehen(); });
  }
  leiste.append(wahl, el("span", { klasse: "klein", text: "Ziehen verschiebt, Strg und Mausrad vergrössert. Ein Klick auf einen Knoten öffnet das Datenblatt." }));
}

function flussEinrichten(svg, fall, belege) {
  const tafel = el("div", { klasse: "tafel nicht-drucken", "aria-live": "polite" }, el("p", { klasse: "klein", text: "Eine Station oder ein Band anklicken zeigt die Einzelheiten." }));
  svg.after(tafel);
  for (const g of $$("g", svg)) {
    const titel = (g.querySelector("title") || {}).textContent || "";
    if (!/^Station \d+/.test(titel)) continue;
    g.style.cursor = "pointer"; g.setAttribute("tabindex", "0"); g.setAttribute("role", "button"); g.setAttribute("aria-label", titel);
    const zeigen = () => {
      tafel.replaceChildren(el("h4", { text: titel.split(":")[0] }));
      const liste = el("ul");
      for (const teil of titel.slice(titel.indexOf(":") + 1).split(" · ")) liste.append(el("li", { klasse: "mono", text: teil.trim() }));
      tafel.append(liste);
      const adresse = (titel.match(/^Station \d+: (\S+)/) || [])[1];
      const ind = zustand.indikatoren.find(i => i.wert === adresse);
      if (ind) tafel.append(el("p", {}, el("a", { href: weg("fall", fall, "indikator", ind.id), text: `Datenblatt ${ind.id}` })));
      for (const b of belege.filter(Boolean)) tafel.append(el("p", {}, el("a", { href: weg("fall", fall, "beleg", b), text: `Alle Stationen und Flüsse im Beleg ${b}` })));
    };
    g.addEventListener("click", zeigen); g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); zeigen(); } });
  }
}

function zeitachseEinrichten(liste, ereignisse) {
  const zeiten = ereignisse.map(z => Date.parse(z.zeit)).filter(t => !Number.isNaN(t));
  const punkte = $$("li", liste);
  if (zeiten.length < 2 || punkte.length !== ereignisse.length) return;
  const sortiert = ereignisse.map(z => Date.parse(z.zeit)).sort((x, y) => x - y);
  const anfang = sortiert[0], ende = sortiert[sortiert.length - 1];
  let von = anfang, bis = ende;
  const breite = 760, hoehe = 44, ns = "http://www.w3.org/2000/svg";
  const bild = document.createElementNS(ns, "svg");
  bild.setAttribute("viewBox", `0 0 ${breite} ${hoehe}`); bild.setAttribute("role", "img"); bild.setAttribute("aria-label", "Zeitachse, zoombar");
  const text = el("span", { klasse: "klein" });
  const datum = (t) => new Date(t).toLocaleString("de-CH", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
  const malen = () => {
    bild.replaceChildren();
    const linie = document.createElementNS(ns, "line");
    for (const [k, v] of Object.entries({ x1: 10, y1: 22, x2: breite - 10, y2: 22, stroke: "var(--achse)", "stroke-width": 1.5 })) linie.setAttribute(k, v);
    bild.append(linie);
    let sichtbar = 0;
    sortiert.forEach((t, i) => {
      const drin = t >= von && t <= bis;
      punkte[i].hidden = !drin;
      if (!drin) return;
      sichtbar += 1;
      const kreis = document.createElementNS(ns, "circle");
      for (const [k, v] of Object.entries({ cx: 10 + (bis === von ? 0.5 : (t - von) / (bis - von)) * (breite - 20), cy: 22, r: 5, fill: "var(--serie)" })) kreis.setAttribute(k, v);
      const titel = document.createElementNS(ns, "title"); titel.textContent = datum(t); kreis.append(titel);
      bild.append(kreis);
    });
    text.textContent = `${datum(von)} bis ${datum(bis)} · ${sichtbar} von ${sortiert.length} Ereignissen`;
  };
  const zoom = (faktor) => { const mitte = (von + bis) / 2, halb = Math.max(60000, (bis - von) * faktor / 2); von = Math.max(anfang, mitte - halb); bis = Math.min(ende, mitte + halb); malen(); };
  const schieben = (anteil) => { const d = (bis - von) * anteil; if (von + d < anfang || bis + d > ende) return; von += d; bis += d; malen(); };
  const leiste = el("div", { klasse: "bildleiste nicht-drucken", role: "group", "aria-label": "Zeitachse bedienen" });
  const knopf = (zeichen, titel, tun) => { const k = el("button", { type: "button", title: titel, "aria-label": titel, text: zeichen }); k.addEventListener("click", tun); leiste.append(k); };
  knopf("+", "Zeitraum enger", () => zoom(0.5)); knopf("−", "Zeitraum weiter", () => zoom(2)); knopf("←", "Früher", () => schieben(-0.25)); knopf("→", "Später", () => schieben(0.25));
  knopf("Ganz", "Ganzen Zeitraum zeigen", () => { von = anfang; bis = ende; malen(); });
  leiste.append(text);
  liste.before(el("div", { klasse: "zeitleiste nicht-drucken" }, leiste, bild));
  malen();
}

/* ---------- Start ---------- */

try { const farbe = localStorage.getItem("farbe"); if (farbe) document.documentElement.dataset.farbe = farbe; } catch (e) { /* ohne Speicher gilt die Vorgabe des Systems */ }
addEventListener("hashchange", laden);
addEventListener("beforeprint", () => $$("details").forEach(d => { d.dataset.war = d.open ? "1" : ""; d.open = true; }));
addEventListener("afterprint", () => $$("details").forEach(d => { d.open = d.dataset.war === "1"; }));
laden();
