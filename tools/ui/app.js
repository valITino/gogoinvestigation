/* Die Oberfläche im Browser. Eine Datei, keine Bibliothek, nichts von aussen.
   Der Server liefert jede Ansicht als fertiges HTML. Dieses Skript holt sie, setzt sie ein und macht sie bedienbar:
   Navigation, feste Adressen, sortierbare Tabellen mit Filter und CSV, Arbeitsspur, Filter und Bilder im Rapport,
   dazu die Bedienung: Akten hochladen und ordnen, Chat mit der Ermittlung, Rückfragen.
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
const zustand = { fall: null, ansicht: "", adresse: "", lauf: 0, spurStand: 0, spurFall: null, spurFilter: new Set(), spurTimer: null, indikatoren: [],
  bedienung: false, geheimnis: "", auswahl: {}, warteschlange: null, hochgeladen: null, titel: "OSINT-Arbeitsplatz",
  chat: { fall: null, feld: null, v: 0, timer: null, knoten: new Map(), merkmal: "", feldStand: "", tafelStand: "", pflichtStand: null }, rueckfrage: "", rueckfrageTimer: null,
  fehler: { zahl: 0, gesehen: 0, lauf: "", gemeldet: 0 },      // Fehlerprotokoll: Fehler in diesem Lauf, wie viele davon schon gesehen sind, was dieses Fenster selbst gemeldet hat
  quellen: { filter: "", suche: "", offen: new Set() },        // Seite «Quellen»: Filter, Suche und was aufgeklappt ist, bleiben über ein Speichern hinweg
  aus: false };       // wahr nach «Alles abschalten»: Der Server ist beendet, das Fenster fragt nichts mehr ab
const DATEI_GROESSE = 60 * 1024 * 1024;     // wie auf dem Server: grösste einzelne Datei im Akten-Eingang

async function antwortLesen(antwort) {
  let daten = null;
  try { daten = await antwort.json(); } catch (e) { /* keine lesbare Antwort */ }
  if (!antwort.ok || !daten) {
    const fehler = new Error((daten && daten.fehler) || `Der Server antwortet nicht wie erwartet (HTTP ${antwort.status}).`);
    fehler.daten = daten || {};       // was der Server neben dem Text mitgibt, etwa dass sich eine gesperrte Nachricht bewusst doch senden lässt
    throw fehler;
  }
  return daten;
}

async function holen(weg) {
  return antwortLesen(await fetch(weg, { headers: { Accept: "application/json" } }));
}

function weg(...teile) { return "#/" + teile.map(encodeURIComponent).join("/"); }

// Die eine Stelle, an der HTML eingesetzt wird. Es kommt immer aus einer Antwort des eigenen Servers: Fremdinhalte hat er dort als Text maskiert
function einsetzen(ziel, html) { ziel.innerHTML = html; }

/* ---------- Bedienung: Ändern geht nur mit dem Geheimnis, das der Server beim Start vergeben hat ---------- */

async function senden(pfad, angaben) {
  return antwortLesen(await fetch(pfad, { method: "POST", headers: { "Content-Type": "application/json", "X-OSINT-Geheimnis": zustand.geheimnis }, body: JSON.stringify(angaben || {}) }));
}

async function dateiSenden(ziel, name, datei) {
  // Eine Datei für den Akten-Eingang: der Rohinhalt als Körper, der Name (mit Ordnern) im Kopf. Nichts davon geht nach aussen: Der Server ist dieser Rechner
  return antwortLesen(await fetch("/api/hochladen?ziel=" + encodeURIComponent(ziel), { method: "POST",
    headers: { "Content-Type": "application/octet-stream", "X-OSINT-Geheimnis": zustand.geheimnis, "X-OSINT-Name": encodeURIComponent(name) }, body: datei }));
}

async function anmelden() {
  // Der Server öffnet den Browser mit einem Startcode in der Adresse. Er gilt einmal und wird sofort gegen das Geheimnis getauscht.
  try { zustand.geheimnis = sessionStorage.getItem("geheimnis") || ""; } catch (e) { /* ohne Speicher gilt das Geheimnis bis zum Neuladen */ }
  const m = location.hash.match(/^#start=([A-Za-z0-9_-]+)(?:&nach=(.*))?$/);
  if (m) {
    history.replaceState(null, "", location.pathname + (m[2] ? "#/fall/" + encodeURIComponent(decodeURIComponent(m[2])) : "#/"));
    try {
      const antwort = await fetch("/api/anmelden", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ startcode: m[1] }) });
      const daten = await antwort.json();
      if (antwort.ok && daten.geheimnis) {
        zustand.geheimnis = daten.geheimnis;
        try { sessionStorage.setItem("geheimnis", daten.geheimnis); } catch (e) { /* siehe oben */ }
      } else zustand.anmeldefehler = (daten && daten.fehler) || "Die Anmeldung ist nicht gelungen.";
    } catch (e) { zustand.anmeldefehler = e.message; }
  }
  try { const stand = await holen("/api/bedienung"); zustand.bedienung = Boolean(stand.aktiv); } catch (e) { zustand.bedienung = false; }
}

const bedienbar = () => Boolean(zustand.bedienung && zustand.geheimnis);

function ergebnisZeigen(feld, daten, fehler) {
  feld.replaceChildren();
  feld.className = "ergebnis " + (fehler ? "z-kritisch" : "");
  feld.append(el("p", { klasse: fehler ? "banner" : "meldung", text: fehler || daten.meldung || "Erledigt." }));
  // Verweist die Meldung auf das Fehlerprotokoll, führt ein Klick dorthin
  if (fehler && bedienbar() && /Fehlerprotokoll/.test(fehler)) feld.append(el("p", { klasse: "klein" }, el("a", { href: "#/fehler", text: "Zum Fehlerprotokoll" })));
  if (daten && daten.ausgabe) feld.append(el("pre", { klasse: "rohtext", text: daten.ausgabe }));
  if (daten && daten.zuordnung) feld.append(el("p", { klasse: "klein", text: "Zuordnungstabelle: " + daten.zuordnung + " (ausserhalb des Projektordners)" }));
  if (daten && daten.dateinamen) feld.append(el("p", { klasse: "klein", text: "Welche Datei unter welchem Namen im Fall liegt: " + daten.dateinamen + " (ausserhalb des Projektordners)" }));
}

function hinweisZeigen(text) {
  // Eine Meldung, die einen Wechsel der Ansicht übersteht: unten im Fenster, bis sie weggeklickt wird oder ihre Zeit um ist
  let feld = $("#hinweis");
  if (!feld) { feld = el("div", { id: "hinweis", role: "status" }); document.body.append(feld); }
  clearTimeout(feld.zeit);
  const zu = el("button", { type: "button", "aria-label": "Meldung schliessen", text: "×" });
  zu.addEventListener("click", () => { feld.hidden = true; });
  feld.replaceChildren(el("span", { text }), zu);
  feld.hidden = false;
  feld.zeit = setTimeout(() => { feld.hidden = true; }, 15000);
}

/* ---------- Rückfrage vor einem Schritt, Eingabe eines Namens: ein eigenes Fenster statt der Dialoge des Browsers ---------- */

function dialogZeigen({ titel, text, ja = "Ja", nein = "Abbrechen", gefahr = false, eingabe = null }) {
  // Gibt bei einer Rückfrage wahr oder falsch zurück, bei einer Eingabe den Text oder null. Esc und ein Klick daneben brechen ab.
  return new Promise((fertig) => {
    const vorher = document.activeElement;
    const ebene = el("div", { klasse: "dialog-ebene" });
    const feld = eingabe !== null ? el("input", { type: "text", value: eingabe, "aria-labelledby": "dialog-text", autocomplete: "off", spellcheck: "false" }) : null;
    const knopfJa = el("button", { type: "button", klasse: gefahr ? "gefahr" : "haupt", text: ja });
    const knopfNein = el("button", { type: "button", text: nein });
    const dialog = el("div", { klasse: "dialog" + (gefahr ? " gefahr" : ""), role: gefahr ? "alertdialog" : "dialog", "aria-modal": "true", "aria-labelledby": "dialog-titel", "aria-describedby": "dialog-text" },
      el("h2", { id: "dialog-titel", text: titel }), el("p", { id: "dialog-text", text }), ...(feld ? [feld] : []), el("div", { klasse: "knopfzeile" }, knopfJa, knopfNein));
    const ziele = [feld, knopfJa, knopfNein].filter(Boolean);
    const ende = (wert) => {
      document.removeEventListener("keydown", tasten, true);
      ebene.remove();
      if (vorher && vorher.isConnected && vorher.focus) vorher.focus();
      fertig(wert);
    };
    const tasten = (e) => {
      if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); ende(feld ? null : false); }
      else if (e.key === "Enter" && feld && document.activeElement === feld) { e.preventDefault(); ende(feld.value); }
      else if (e.key === "Tab") {         // der Fokus bleibt im Fenster
        e.preventDefault();
        const i = ziele.indexOf(document.activeElement);
        ziele[(i + (e.shiftKey ? ziele.length - 1 : 1) + ziele.length) % ziele.length].focus();
      }
    };
    knopfJa.addEventListener("click", () => ende(feld ? feld.value : true));
    knopfNein.addEventListener("click", () => ende(feld ? null : false));
    ebene.addEventListener("mousedown", (e) => { if (e.target === ebene) ende(feld ? null : false); });
    document.addEventListener("keydown", tasten, true);
    ebene.append(dialog);
    document.body.append(ebene);
    // Bei einem Schritt, der etwas entfernt oder beendet, steht der Fokus auf «Abbrechen»: Die Eingabetaste löst ihn nicht versehentlich aus
    (feld || (gefahr ? knopfNein : knopfJa)).focus();
    if (feld) feld.select();
  });
}

function fragen(frage, ja, gefahr) {
  // Die Frage eines Formulars: Ihr erster Satz wird die Überschrift, der Rest die Erklärung. Der Knopf zum Bestätigen heisst wie der Schritt
  const m = String(frage).match(/^(.{3,110}?\?)\s+([\s\S]+)$/);
  return dialogZeigen({ titel: m ? m[1] : "Bitte bestätigen", text: m ? m[2] : String(frage), ja: (ja || "Ja").trim(), gefahr: Boolean(gefahr) });
}

const auswahlName = (bereich) => bereich.dataset.auswahl + ":" + (bereich.dataset.ziel || bereich.dataset.fall || "");

async function formularSenden(form) {
  const feld = $(".ergebnis", form) || form.appendChild(el("div", { klasse: "ergebnis" }));
  const angaben = {};
  for (const [name, wert] of new FormData(form).entries()) if (!(wert instanceof File)) angaben[name] = wert;
  for (const kasten of $$("input[type=checkbox]", form)) angaben[kasten.name] = kasten.checked ? "1" : "";
  // Formulare, die mit der Auswahl einer Tabelle arbeiten: Sie bekommen, was dort angehakt ist
  const bereich = form.closest("[data-auswahl]") || (form.classList.contains("aufnehmen") ? $('[data-auswahl="korb"]') : null);
  const gewaehlt = bereich ? Array.from(zustand.auswahl[auswahlName(bereich)] || []) : [];
  if (form.classList.contains("mit-auswahl")) {
    if (!gewaehlt.length) return ergebnisZeigen(feld, null, "Bitte zuerst Dokumente auswählen.");
    angaben.namen = gewaehlt;
  }
  if (form.classList.contains("aufnehmen")) angaben.ids = gewaehlt;
  const knopf = $("button[type=submit]", form);
  if (form.dataset.frage && !(await fragen(form.dataset.frage, knopf.textContent, form.hasAttribute("data-gefahr")))) return;
  // Ein Schlüssel bleibt nie im Feld stehen: Er ist in den Angaben, das Feld wird gleich geleert
  for (const geheim of $$("input[type=password]", form)) geheim.value = "";
  knopf.disabled = true;
  ergebnisZeigen(feld, { meldung: "Läuft …" });
  try {
    const aktion = form.dataset.aktion;
    const daten = await senden("/api/aktion/" + aktion, angaben);
    if (daten.abgeschaltet) return abgeschaltet(daten);
    ergebnisZeigen(feld, daten);
    if (aktion === "zurueckfuehren") klartextZeigen(daten);
    const gelungen = (daten.aufgenommen !== false || daten.angelegt === true) && daten.gelungen !== false && daten.uebernommen !== false;
    const danach = gelungen ? (form.dataset.danach || "") : "";
    if (gelungen && bereich && (form.classList.contains("mit-auswahl") || form.classList.contains("aufnehmen"))) delete zustand.auswahl[auswahlName(bereich)];
    if (danach && daten.meldung && danach !== "rueckfrage") hinweisZeigen(daten.meldung);
    if (danach === "fall" && daten.fall) location.hash = weg("fall", daten.fall, daten.bleibt ? "akten" : "ermittlung");
    else if (danach === "weiter") await naechstesDokument(daten.ziel || "");
    else if (danach === "rueckfrage") rueckfragenHolen();
    else if (danach === "neu-laden") await laden();
    else if (danach.startsWith("#/")) { if (aktion === "pseudo_verwerfen") zustand.warteschlange = null; if (location.hash === danach) await laden(); else location.hash = danach; }
    if (aktion.startsWith("ermittlung_")) chatHolen();
    if (zustand.fall) kopfLaden(zustand.fall).catch(() => {});
  } catch (e) {
    ergebnisZeigen(feld, null, e.message);
  } finally { knopf.disabled = false; }
}

function abgeschaltet(daten) {
  // «Alles abschalten»: Der Server beendet sich gleich. Nichts mehr abfragen, das Geheimnis vergessen und sagen, was jetzt gilt
  zustand.aus = true;
  clearTimeout(zustand.spurTimer); clearTimeout(zustand.chat.timer); clearTimeout(zustand.rueckfrageTimer);
  zustand.geheimnis = "";
  try { sessionStorage.removeItem("geheimnis"); } catch (e) { /* ohne Speicher gibt es nichts zu räumen */ }
  const liste = el("ul");
  for (const punkt of daten.punkte || []) liste.append(el("li", { text: punkt }));
  if (daten.geloescht) {
    // «Alles löschen»: Der Arbeitsplatz ist weg. Die Seite sagt, was gelöscht wurde, wo die Sicherung liegt und was bleibt
    const bleibt = el("ul");
    for (const punkt of daten.bleibt || []) bleibt.append(el("li", { text: punkt }));
    document.body.replaceChildren(el("main", { klasse: "abgeschaltet" }, el("h1", { text: "Arbeitsplatz gelöscht" }),
      el("p", { text: daten.meldung || "Der Arbeitsplatz ist von diesem Rechner gelöscht." }), liste,
      el("h2", { text: "Was bleibt" }), bleibt,
      el("p", {}, "Der Bericht dazu: ", el("code", { text: daten.bericht || "" })),
      el("p", { text: "Dieses Fenster kann geschlossen werden." })));
    document.title = "Gelöscht · OSINT-Arbeitsplatz";
    return;
  }
  document.body.replaceChildren(el("main", { klasse: "abgeschaltet" }, el("h1", { text: "Abgeschaltet" }),
    el("p", { text: daten.meldung || "Die Oberfläche ist beendet." }), liste,
    el("p", {}, "Dieses Fenster kann geschlossen werden. Wieder starten, im Terminal: ", el("code", { text: daten.start || "python3 tools/oberflaeche.py" }))));
  document.title = "Abgeschaltet · OSINT-Arbeitsplatz";
}

function klartextZeigen(daten) {
  // Der zurückgeführte Rapport: echte Angaben, nur auf diesem Bildschirm, je Datei eine Karte für genau einen Abruf
  const ziel = $("#klartext-ergebnis");
  if (!ziel) return;
  ziel.replaceChildren(el("p", { klasse: "klein", text: "Ablage: " + daten.ordner }));
  for (const d of daten.dateien || []) {
    ziel.append(el("h3", { text: d.name }));
    if (d.name.endsWith(".html")) ziel.append(el("iframe", { klasse: "dokument", title: d.name, src: "/klartext/" + encodeURIComponent(d.ticket), sandbox: "allow-same-origin" }));
    else ziel.append(el("p", {}, el("a", { href: "/klartext/" + encodeURIComponent(d.ticket), target: "_blank", rel: "noopener", text: "ansehen (einmal abrufbar)" })));
  }
}

function bedienungEinrichten(wurzel) {
  for (const form of $$("form.aktion", wurzel)) form.addEventListener("submit", (e) => { e.preventDefault(); formularSenden(form); });
  for (const verweis of $$("[data-zeigen]", wurzel)) verweis.addEventListener("click", (e) => {
    e.preventDefault();
    const ziel = document.getElementById(verweis.dataset.zeigen);
    if (ziel) { ziel.scrollIntoView({ block: "center" }); ziel.classList.add("ziel"); setTimeout(() => ziel.classList.remove("ziel"), 1600); }
  });
  for (const zone of $$("[data-hochladen]", wurzel)) hochladenEinrichten(zone);
  for (const bereich of $$("[data-auswahl]", wurzel)) auswahlEinrichten(bereich);
  for (const feld of $$("[data-pflicht]", wurzel)) pflichtEinrichten(feld);
  const schlange = $("[data-warteschlange]", wurzel), w = zustand.warteschlange;
  if (schlange && w && w.gesamt > 1) schlange.textContent = `Dokument ${w.gesamt - w.ids.length} von ${w.gesamt} · `;
}

/* ---------- Akten-Eingang: Dateien, Ordner und ZIP hochladen ---------- */

function abgelegtes(uebertragung) {
  // Dateien und Ordner aus einem Ablegen. Die Einträge müssen gelesen sein, bevor das Ereignis zu Ende ist: deshalb zuerst alle holen, dann warten
  const liste = [], wurzeln = [];
  for (const item of Array.from(uebertragung.items || [])) {
    if (item.kind !== "file") continue;
    const eintrag = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
    if (eintrag) wurzeln.push(eintrag);
    else { const datei = item.getAsFile(); if (datei) liste.push({ name: datei.name, datei }); }
  }
  if (!wurzeln.length && !liste.length) for (const datei of Array.from(uebertragung.files || [])) liste.push({ name: datei.name, datei });
  const gehen = async (eintrag) => {
    if (eintrag.isFile) {
      const datei = await new Promise((gut, schlecht) => eintrag.file(gut, schlecht));
      liste.push({ name: (eintrag.fullPath || "").replace(/^\//, "") || datei.name, datei });
    } else if (eintrag.isDirectory) {
      const leser = eintrag.createReader();
      for (;;) {        // ein Ordner kommt in Portionen
        const teil = await new Promise((gut, schlecht) => leser.readEntries(gut, schlecht));
        if (!teil.length) break;
        for (const kind of teil) await gehen(kind);
      }
    }
  };
  return (async () => {
    for (const wurzel of wurzeln) { try { await gehen(wurzel); } catch (e) { /* was sich nicht lesen lässt, fehlt in der Liste und damit in der Meldung */ } }
    return liste;
  })();
}

const hochladeSchlange = [];
let hochladenLaeuft = false;

async function hochladen(zone, eintraege) {
  const ziel = zone.dataset.ziel || "", stand = $(".hochladen-stand", zone), meldungen = [];
  if (!eintraege.length) { stand.replaceChildren(el("li", { text: "Darin war keine Datei." })); return; }
  for (const e of eintraege) hochladeSchlange.push({ ziel, name: e.name, datei: e.datei });
  if (hochladenLaeuft) return;        // der laufende Durchgang nimmt mit, was eben dazugekommen ist
  hochladenLaeuft = true;
  zone.setAttribute("aria-busy", "true");
  const zeile = el("li");
  stand.replaceChildren(zeile);
  let angenommen = 0, nr = 0;
  while (hochladeSchlange.length) {
    const e = hochladeSchlange.shift();
    nr += 1;
    zeile.textContent = `Datei ${nr} von ${nr + hochladeSchlange.length} wird gelesen und geprüft: ${e.name}`;
    if (e.datei.size > DATEI_GROESSE) { meldungen.push(`${e.name}: grösser als ${DATEI_GROESSE / 1048576} MB, nicht angenommen.`); continue; }
    try {
      const daten = await dateiSenden(e.ziel, e.name, e.datei);
      angenommen += daten.neu || 0;
      meldungen.push(...(daten.meldungen || []));
    } catch (f) { meldungen.push(`${e.name}: ${f.message}`); }
  }
  hochladenLaeuft = false;
  zone.removeAttribute("aria-busy");
  zustand.hochgeladen = { ziel, text: `${angenommen} ${angenommen === 1 ? "Datei" : "Dateien"} in den Akten-Eingang gelegt.`, meldungen };
  await laden();
}

function hochladenEinrichten(zone) {
  const dateien = $("[data-dateien]", zone), ordner = $("[data-ordner]", zone);
  const ausEingabe = (eingabe) => { const liste = Array.from(eingabe.files).map(d => ({ name: d.webkitRelativePath || d.name, datei: d })); eingabe.value = ""; hochladen(zone, liste); };
  dateien.addEventListener("change", () => ausEingabe(dateien));
  ordner.addEventListener("change", () => ausEingabe(ordner));
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("ziel"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("ziel"));
  zone.addEventListener("drop", (e) => { e.preventDefault(); zone.classList.remove("ziel"); abgelegtes(e.dataTransfer).then(liste => hochladen(zone, liste)); });
  const h = zustand.hochgeladen;
  if (h && h.ziel === (zone.dataset.ziel || "")) {
    const stand = $(".hochladen-stand", zone);
    stand.replaceChildren(el("li", { klasse: "meldung", text: h.text }), ...h.meldungen.map(text => el("li", { text })));
  }
}

/* ---------- Auswahl in Tabellen: einzeln, alle, ein Bereich mit der Umschalttaste ---------- */

function auswahlEinrichten(bereich) {
  const name = auswahlName(bereich);
  const gemerkt = zustand.auswahl[name] || (zustand.auswahl[name] = new Set());
  const kaesten = () => $$('tbody input[name="auswahl"]', bereich);
  const sichtbar = () => kaesten().filter(k => !k.closest("tr").hidden);
  const alle = $("[data-alle]", bereich), zaehler = $("[data-gewaehlt]", bereich);
  const vorhanden = new Set(kaesten().map(k => k.value));
  for (const wert of Array.from(gemerkt)) if (!vorhanden.has(wert)) gemerkt.delete(wert);      // was nicht mehr da ist, fällt aus der Auswahl
  let letzter = null;
  const zeigen = () => {
    const liste = kaesten(), zu_sehen = sichtbar();
    for (const k of liste) { k.checked = gemerkt.has(k.value); k.closest("tr").classList.toggle("gewaehlt", k.checked); }
    if (alle) { alle.checked = zu_sehen.length > 0 && zu_sehen.every(k => k.checked); alle.indeterminate = !alle.checked && zu_sehen.some(k => k.checked); }
    if (zaehler) zaehler.textContent = gemerkt.size ? `${gemerkt.size} von ${liste.length} gewählt` : "nichts gewählt";
    for (const knopf of $$(".auswahlleiste button", bereich)) knopf.disabled = gemerkt.size === 0;
    const hinweis = bereich.dataset.auswahl === "korb" ? $("[data-aufnehmen-hinweis]") : null;
    if (hinweis) {      // beim Knopf steht, was er aufnehmen wird: Eine Auswahl von vorhin soll niemanden überraschen
      // bereit ist auch, wofür der Sachbearbeiter das Risiko übernommen hat
      const bereit = liste.filter(k => k.dataset.stand === "sauber" || k.dataset.stand === "risiko"), davon = bereit.filter(k => gemerkt.has(k.value)).length;
      hinweis.textContent = gemerkt.size ? `Aufgenommen werden die ${gemerkt.size} gewählten Dateien, soweit sie bereit sind: ${davon} von ${gemerkt.size}. Für alle: die Auswahl aufheben.`
        : `Nichts gewählt: Aufgenommen wird alles, was bereit ist (${bereit.length} von ${liste.length} Dateien).`;
    }
  };
  for (const k of kaesten()) k.addEventListener("click", (e) => {
    const liste = sichtbar();
    if (e.shiftKey && letzter && liste.includes(letzter)) {     // mit der Umschalttaste: alles zwischen dem letzten und diesem Haken
      const [von, bis] = [liste.indexOf(letzter), liste.indexOf(k)].sort((x, y) => x - y);
      for (const x of liste.slice(von, bis + 1)) { if (k.checked) gemerkt.add(x.value); else gemerkt.delete(x.value); }
    } else if (k.checked) gemerkt.add(k.value); else gemerkt.delete(k.value);
    letzter = k;
    zeigen();
  });
  if (alle) alle.addEventListener("click", () => {       // «alle» meint, was gerade zu sehen ist: Der Filter der Tabelle zählt
    for (const k of sichtbar()) { if (alle.checked) gemerkt.add(k.value); else gemerkt.delete(k.value); }
    zeigen();
  });
  bereich.addEventListener("input", (e) => { if (e.target.type === "search") zeigen(); });
  for (const knopf of $$("[data-korb]", bereich)) knopf.addEventListener("click", () => korbAktion(bereich, knopf, gemerkt));
  zeigen();
}

async function korbAktion(bereich, knopf, gemerkt) {
  const ziel = bereich.dataset.ziel || "", art = knopf.dataset.korb, feld = $("[data-korb-ergebnis]", bereich);
  const ids = knopf.dataset.id ? [knopf.dataset.id] : Array.from(gemerkt);
  if (!ids.length) return;
  if (knopf.dataset.frage && !(await fragen(knopf.dataset.frage, knopf.textContent, true))) return;
  try {
    if (art === "pseudo" || art === "pseudo-auswahl") {
      // In der Reihenfolge der Tabelle, und nur, was sich lesen lässt
      const lesbar = $$('tbody input[name="auswahl"]', bereich).filter(k => ids.includes(k.value) && $('[data-korb="pseudo"], a[href^="#/klartext/"]', k.closest("tr"))).map(k => k.value);
      if (!lesbar.length) throw new Error("Keine der gewählten Dateien lässt sich lesen. Pseudonymisieren lässt sich nur, was sich lesen lässt.");
      zustand.warteschlange = { ziel, ids: lesbar, gesamt: lesbar.length, ausAuswahl: art === "pseudo-auswahl" };
      return await naechstesDokument(ziel);
    }
    if (art === "umbenennen") {
      const neu = await dialogZeigen({ titel: "Datei umbenennen", text: "Neuer Name der Datei. Die Endung bleibt.", ja: "Umbenennen", eingabe: knopf.dataset.name || "" });
      if (!neu || !neu.trim()) return;
      await senden("/api/aktion/korb_umbenennen", { ziel, id: ids[0], name: neu });
    } else if (art === "rolle" || art === "rolle-auswahl") await senden("/api/aktion/korb_rolle", { ziel, ids, rolle: knopf.dataset.rolle });
    else if (art === "verschieben") { const daten = await senden("/api/aktion/korb_verschieben", { ziel, ids, nach: $("[data-korb-nach]", bereich).value }); gemerkt.clear(); hinweisZeigen(daten.meldung); }
    else if (art === "entfernen") { const daten = await senden("/api/aktion/korb_entfernen", { ziel, ids }); for (const id of ids) gemerkt.delete(id); hinweisZeigen(daten.meldung); }
    await laden();
  } catch (e) { ergebnisZeigen(feld, null, e.message); }
}

async function naechstesDokument(ziel) {
  // Nach «Übernehmen»: das nächste gewählte Dokument auf den lokalen Bildschirm holen. Ist keines mehr da: zurück zum Akten-Eingang
  const w = zustand.warteschlange;
  while (w && w.ids.length) {
    const id = w.ids.shift();
    try {
      const daten = await senden("/api/aktion/korb_pseudo", { ziel: w.ziel, id });
      location.hash = weg("klartext", daten.vorgang);
      return;
    } catch (e) { hinweisZeigen(e.message); }     // die Datei ist nicht mehr da oder nicht lesbar: weiter mit der nächsten
  }
  if (w && w.ausAuswahl) delete zustand.auswahl["korb:" + w.ziel];      // die Auswahl galt dem Pseudonymisieren und ist damit erledigt
  zustand.warteschlange = null;
  const zurueck = ziel ? weg("fall", ziel, "akten") : "#/neu";
  if (location.hash === zurueck) await laden(); else location.hash = zurueck;
}

/* ---------- Pflichtquellen: vor dem Start anwählen, was die Ermittlung abfragen muss ---------- */

const pflichtGewaehlt = (feld) => $$("input[name=quelle]:checked", feld).map(k => k.value);

function pflichtZeigen(feld) {
  // Zähler, Marke und der Hinweis, ob die Auswahl vom gespeicherten Stand abweicht
  const alle = $$("input[name=quelle]", feld), an = pflichtGewaehlt(feld);
  let gespeichert = [];
  try { gespeichert = JSON.parse(feld.dataset.gespeichert || "[]"); } catch (e) { /* dann gilt: nichts gespeichert */ }
  const geaendert = [...gespeichert].sort().join("\n") !== [...an].sort().join("\n");
  feld.dataset.geaendert = geaendert ? "1" : "";
  $("[data-pflicht-zahl]", feld).textContent = `${an.length} von ${alle.filter(k => !k.disabled).length} angewählt`;
  $("[data-pflicht-hinweis]", feld).textContent = geaendert ? "Auswahl geändert, noch nicht gespeichert. Der Start der Ermittlung übernimmt sie." : "";
  $("[data-pflicht-speichern]", feld).disabled = !geaendert;
  const marke = $("[data-pflicht-marke]", feld);
  marke.textContent = gespeichert.length ? (gespeichert.length === 1 ? "1 Quelle vorgegeben" : `${gespeichert.length} Quellen vorgegeben`) : "keine Vorgabe";
  marke.className = "marke z-" + (gespeichert.length ? "gut" : "leer");
}

async function pflichtSpeichern(feld) {
  // Speichert die Auswahl im Fall. Gibt zurück, ob es gelungen ist: Der Start der Ermittlung wartet darauf
  const ergebnis = $(".ergebnis", feld);
  try {
    const daten = await senden("/api/aktion/pflichtquellen", { fall: feld.dataset.fall, quellen: pflichtGewaehlt(feld) });
    feld.dataset.gespeichert = JSON.stringify(daten.quellen || []);
    ergebnisZeigen(ergebnis, daten);
    pflichtZeigen(feld);
    return true;
  } catch (e) {
    ergebnisZeigen(ergebnis, null, e.message);
    feld.open = true;
    return false;
  }
}

function pflichtEinrichten(feld) {
  const alle = () => $$("input[name=quelle]", feld);
  for (const kasten of alle()) kasten.addEventListener("change", () => pflichtZeigen(feld));
  $("[data-pflicht-alle]", feld).addEventListener("click", () => { for (const k of alle()) if (!k.disabled) k.checked = true; pflichtZeigen(feld); });
  $("[data-pflicht-keine]", feld).addEventListener("click", () => { for (const k of alle()) k.checked = false; pflichtZeigen(feld); });
  $("[data-pflicht-speichern]", feld).addEventListener("click", async () => { if (await pflichtSpeichern(feld)) chatHolen(); });
  pflichtZeigen(feld);
}

/* ---------- Chat mit der Ermittlung: Vorgaben, Nachrichten, jeder Schritt ---------- */

const STATUS_WORT = { aus: "nicht gestartet", laeuft: "läuft", wartet: "wartet auf dich", angehalten: "angehalten", beendet: "beendet", fehler: "abgebrochen" };
const STATUS_FARBE = { laeuft: "gut", wartet: "warnung", fehler: "kritisch" };
const ERGEBNIS_WORT = { ok: ["● Treffer", "gut"], kein_treffer: ["○ kein Treffer", "neutral"], fehler: ["✕ Fehlschlag", "kritisch"], abgelehnt: ["⊘ abgelehnt", "warnung"],
  nicht_ausgefuehrt: ["⊘ nicht ausgeführt", "warnung"] };
const ENTSCHEID_FARBE = { offen: "warnung", erlaubt: "gut", beantwortet: "gut", abgelehnt: "kritisch", "nicht beantwortet": "kritisch" };
// Wer im Team arbeitet, wie ein Mensch es liest. Der Name des Agenten steht als Hinweis am Wort
const TEAM = { hauptsitzung: "Ermittlungsleitung", "infrastruktur-analyst": "Infrastruktur", "malware-url-analyst": "Malware und URLs", "darkweb-analyst": "Dark Web",
  "socmint-analyst": "Kanäle und Foren", "blockchain-analyst": "Blockchain", gegenpruefer: "Gegenprüfung", rapportfuehrer: "Rapport" };

/* Antworten der Ermittlung lesbar machen: Überschriften, Listen, Tabellen, Hervorhebungen.
   Claude schreibt Markdown. Daraus werden hier Elemente gebaut, nie HTML eingesetzt: Jeder Text geht über textContent.
   Verweise werden nicht anklickbar, denn was die Ermittlung nennt, kann eine Adresse der Täterseite sein. Ein Beleg (P-0007) führt zu seiner Ansicht. */
function zeileBauen(text, fall) {
  const teile = document.createDocumentFragment();
  const muster = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\*[^*\s][^*\n]*\*)|(\[[^\]\n]+\]\([^)\s]+\))|(\b[PX]-\d{4,}\b)/g;
  let pos = 0, m;
  while ((m = muster.exec(text))) {
    if (m.index > pos) teile.append(text.slice(pos, m.index));
    const t = m[0];
    if (m[1]) teile.append(el("code", { text: t.slice(1, -1) }));
    else if (m[2]) { const fett = el("strong"); fett.append(zeileBauen(t.slice(2, -2), fall)); teile.append(fett); }
    else if (m[3]) teile.append(el("em", { text: t.slice(1, -1) }));
    else if (m[4]) { const v = t.match(/^\[([^\]]+)\]\(([^)]+)\)$/); teile.append(v[1] === v[2] ? v[1] : `${v[1]} (${v[2]})`); }
    else teile.append(fall ? el("a", { href: weg("fall", fall, "beleg", t), text: t }) : t);
    pos = m.index + t.length;
  }
  if (pos < text.length) teile.append(text.slice(pos));
  return teile;
}

function antwortBauen(text, fall) {
  const feld = el("div", { klasse: "chat-text md" });
  const zeilen = String(text).replace(/\r\n?/g, "\n").split("\n");
  const LISTE = /^(\s*)([-*+]|\d{1,3}[.)])\s+(.*)$/, TABELLE = /^\s*\|.*\|\s*$/, TRENNER = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;
  let i = 0, absatz = [];
  const absatzEnde = () => {
    if (!absatz.length) return;
    const p = el("p");
    absatz.forEach((z, n) => { if (n) p.append(el("br")); p.append(zeileBauen(z, fall)); });
    feld.append(p);
    absatz = [];
  };
  while (i < zeilen.length) {
    const z = zeilen[i];
    let m;
    if (/^\s*```/.test(z)) {            // Block im Wortlaut
      absatzEnde();
      const block = [];
      for (i += 1; i < zeilen.length && !/^\s*```/.test(zeilen[i]); i += 1) block.push(zeilen[i]);
      i += 1;
      feld.append(el("pre", { klasse: "rohtext", text: block.join("\n") }));
    } else if (!z.trim()) { absatzEnde(); i += 1; }
    else if ((m = z.match(/^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$/))) {      // Überschrift: im Chat zwei Stufen tiefer als auf der Seite
      absatzEnde();
      const h = el("h" + Math.min(6, m[1].length + 2));
      h.append(zeileBauen(m[2], fall));
      feld.append(h);
      i += 1;
    } else if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(z)) { absatzEnde(); feld.append(el("hr")); i += 1; }
    else if (TABELLE.test(z) && i + 1 < zeilen.length && TRENNER.test(zeilen[i + 1])) {
      absatzEnde();
      const zellen = (s) => s.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(c => c.trim());
      const reihe = (s, art) => { const tr = el("tr"); for (const c of zellen(s)) { const zelle = el(art); zelle.append(zeileBauen(c, fall)); tr.append(zelle); } return tr; };
      const rumpf = el("tbody");
      const tabelle = el("table", {}, el("thead", {}, reihe(z, "th")), rumpf);
      for (i += 2; i < zeilen.length && TABELLE.test(zeilen[i]); i += 1) rumpf.append(reihe(zeilen[i], "td"));
      feld.append(el("div", { klasse: "md-tabelle" }, tabelle));
    } else if (LISTE.test(z)) {         // Liste, auch verschachtelt: Die Einrückung entscheidet über die Stufe
      absatzEnde();
      const stapel = [];
      while (i < zeilen.length) {
        const zeile = zeilen[i], treffer = zeile.match(LISTE);
        if (treffer) {
          const tiefe = treffer[1].replace(/\t/g, "    ").length, geordnet = /\d/.test(treffer[2]);
          while (stapel.length && stapel[stapel.length - 1].tiefe > tiefe) stapel.pop();
          if (!stapel.length || stapel[stapel.length - 1].tiefe < tiefe) {
            const liste = el(geordnet ? "ol" : "ul");
            (stapel.length && stapel[stapel.length - 1].punkt ? stapel[stapel.length - 1].punkt : feld).append(liste);
            stapel.push({ tiefe, liste, punkt: null });
          }
          const oben = stapel[stapel.length - 1];
          oben.punkt = el("li");
          oben.punkt.append(zeileBauen(treffer[3], fall));
          oben.liste.append(oben.punkt);
          i += 1;
        } else if (zeile.trim() && /^\s{2,}/.test(zeile) && stapel.length && stapel[stapel.length - 1].punkt) {      // Fortsetzung eines Punkts
          stapel[stapel.length - 1].punkt.append(" ", zeileBauen(zeile.trim(), fall));
          i += 1;
        } else if (!zeile.trim() && i + 1 < zeilen.length && LISTE.test(zeilen[i + 1])) i += 1;       // Leerzeile zwischen zwei Punkten
        else break;
      }
    } else if ((m = z.match(/^\s*>\s?(.*)$/))) {
      absatzEnde();
      const zitat = el("blockquote");
      for (; i < zeilen.length && (m = zeilen[i].match(/^\s*>\s?(.*)$/)); i += 1) { if (zitat.childNodes.length) zitat.append(el("br")); zitat.append(zeileBauen(m[1], fall)); }
      feld.append(zitat);
    } else { absatz.push(z.trim()); i += 1; }
  }
  absatzEnde();
  return feld;
}

function chatEintrag(z, fall) {
  const li = el("li", { klasse: "c-" + z.art + (z.wartet ? " wartet" : "") + (z.zurueck ? " zurueck" : "") + (z.wichtig ? " wichtig" : ""), "data-nr": String(z.nr) });
  const team = (name) => { const wort = el("span", { klasse: "chat-quelle", text: TEAM[name] || name }); if (TEAM[name] && name !== "hauptsitzung") wort.title = "Agent " + name; return wort; };
  if (z.art === "sachbearbeiter" || z.art === "claude") {
    const wer = el("b", { text: z.art === "sachbearbeiter" ? "Du" : z.wer === "hauptsitzung" ? "Ermittlung" : (TEAM[z.wer] || z.wer) });
    li.append(el("div", { klasse: "chat-wer" }, wer, el("time", { text: z.zeit })), z.art === "claude" ? antwortBauen(z.text, fall) : el("div", { klasse: "chat-text", text: z.text }));
    if (z.wartet) li.append(el("div", { klasse: "klein", text: "wartet auf das Ende des laufenden Auftrags" }));
    if (z.zurueck) li.append(el("div", { klasse: "klein", text: "zurückgenommen, nicht zugestellt" }));
    return li;
  }
  const zeile = el("div", { klasse: "chat-zeile" }, el("time", { text: z.zeit }));
  if (z.wer && z.wer !== "oberfläche") zeile.append(team(z.wer));
  zeile.append(el("span", { klasse: "chat-was", text: z.text }));
  if (z.beleg) zeile.append(el("a", { href: weg("fall", fall, "beleg", z.beleg), text: z.beleg }));
  if (z.ergebnis) { const [wort, farbe] = ERGEBNIS_WORT[z.ergebnis] || [z.ergebnis, "neutral"]; zeile.append(el("span", { klasse: "z-" + farbe, text: wort })); }
  if (z.entscheid) zeile.append(el("span", { klasse: "marke z-" + (ENTSCHEID_FARBE[z.entscheid] || "neutral"), text: z.entscheid }));
  if (z.ergebnisse) zeile.append(el("a", { klasse: "knopf", href: weg("fall", fall, "ergebnisse"), text: "Ergebnisse ansehen" }));
  li.append(zeile);
  // Unter einem Schritt: wozu er dient (das Gateway verlangt den Zweck bei jeder Abfrage) und der Name des Werkzeugs, wie er im Protokoll steht
  if (z.art === "schritt" && (z.zweck || (z.technik && z.quelle))) {
    const dazu = el("div", { klasse: "chat-dazu" });
    if (z.zweck) dazu.append(el("span", { text: "Zweck: " + z.zweck }));
    if (z.technik && z.quelle) dazu.append(el("span", { klasse: "mono", title: "Name des Werkzeugs im Protokoll", text: z.technik }));
    li.append(dazu);
  }
  return li;
}

function chatBauen(feld, fall, gross) {
  const c = zustand.chat;
  clearTimeout(c.timer);
  Object.assign(c, { fall, feld, v: 0, knoten: new Map(), merkmal: "", feldStand: "", tafelStand: "", pflichtStand: null });
  feld.replaceChildren();
  feld.classList.add("chat");
  feld.dataset.fall = fall;
  const kopf = el("div", { klasse: "chat-kopf" }, el("h2", { text: "Chat mit der Ermittlung" }), el("span", { klasse: "marke", "data-chat-status": "", text: "…" }),
    // nach einem Abbruch: der Weg zu dem, was dazu im Fehlerprotokoll steht
    el("a", { klasse: "klein", href: "#/fehler", "data-chat-fehler": "", hidden: "", text: "Fehlerprotokoll" }));
  // Die Lage in einem Satz: was die Ermittlung gerade tut, worauf sie wartet, wie es weitergeht
  const lage = el("p", { klasse: "chat-lage", "data-chat-lage": "", role: "status", hidden: "" });
  const verlauf = el("ol", { klasse: "chat-verlauf", "aria-live": "polite", "aria-label": "Verlauf der Ermittlung", tabindex: "0" });
  const schritte = el("input", { type: "checkbox", checked: "" });
  let zeigeSchritte = true;
  try { zeigeSchritte = sessionStorage.getItem("chat-schritte") !== "0"; } catch (e) { /* ohne Speicher gilt die Vorgabe */ }
  schritte.checked = zeigeSchritte;
  feld.classList.toggle("ohne-schritte", !zeigeSchritte);
  schritte.addEventListener("change", () => {
    feld.classList.toggle("ohne-schritte", !schritte.checked);
    try { sessionStorage.setItem("chat-schritte", schritte.checked ? "1" : "0"); } catch (e) { /* siehe oben */ }
    verlauf.scrollTop = verlauf.scrollHeight;
  });
  kopf.append(el("label", { klasse: "klein" }, schritte, document.createTextNode(" jeden Schritt zeigen")));
  if (!gross) {
    const zu = el("button", { type: "button", klasse: "klein-knopf", "aria-expanded": "true", text: "einklappen" });
    const klappen = (eingeklappt) => { feld.classList.toggle("zu", eingeklappt); zu.textContent = eingeklappt ? "aufklappen" : "einklappen"; zu.setAttribute("aria-expanded", String(!eingeklappt)); };
    zu.addEventListener("click", () => { const jetzt = !feld.classList.contains("zu"); klappen(jetzt); try { sessionStorage.setItem("chat-zu", jetzt ? "1" : "0"); } catch (e) { /* siehe oben */ } });
    try { klappen(sessionStorage.getItem("chat-zu") === "1"); } catch (e) { /* siehe oben */ }
    kopf.append(zu);
  }
  const text = el("textarea", { name: "text", rows: "2", id: "chat-text", "aria-label": "Nachricht an die Ermittlung" });
  const form = el("form", { klasse: "chat-eingabe" }, text, el("div", { klasse: "knopfzeile", "data-chat-knoepfe": "" }), el("div", { klasse: "ergebnis", "aria-live": "polite" }));
  form.addEventListener("submit", (e) => { e.preventDefault(); const erster = $("[data-chat-knoepfe] button", form); if (erster) erster.click(); });
  text.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); const erster = $("[data-chat-knoepfe] button", form); if (erster) erster.click(); } });
  feld.append(kopf, lage, verlauf, el("div", { klasse: "chat-wartend" }), form);
  if (c.beobachter) c.beobachter.disconnect();
  c.beobachter = null;
  if (gross) {
    chatHoehe();
    // Was über dem Chat steht, ändert seine Höhe (Pflichtquellen aufgeklappt, eine Meldung kommt dazu): Der Chat passt sich an
    if (typeof ResizeObserver === "function") {
      c.beobachter = new ResizeObserver(chatHoehe);
      for (const davor of [$("#ermittlung"), $("[data-pflicht]"), $("#kopf")]) if (davor) c.beobachter.observe(davor);
    }
  }
  chatHolen();
}

function chatHoehe() {
  // Der grosse Chat füllt, was vom Fenster unter ihm bleibt: So steht die Eingabe immer am unteren Rand, und der Verlauf hat den Platz
  const feld = zustand.chat.feld, mitte = $("#mitte");
  if (!feld || !feld.isConnected || !feld.classList.contains("gross")) return;
  const oben = feld.getBoundingClientRect().top - mitte.getBoundingClientRect().top + mitte.scrollTop;
  feld.style.height = Math.max(440, mitte.clientHeight - oben - 18) + "px";
}

async function chatSenden(aktion, zusatz, textfeld, frage, ja) {
  const c = zustand.chat, feld = c.feld;
  if (!feld) return;
  const eingabe = $("textarea", feld), ergebnis = $(".chat-eingabe .ergebnis", feld);
  const text = eingabe.value.trim();
  if (textfeld === "text" && !text) { ergebnisZeigen(ergebnis, null, "Bitte zuerst eine Nachricht schreiben."); eingabe.focus(); return; }
  if (frage && !(await fragen(frage, ja))) return;
  const knoepfe = $$("[data-chat-knoepfe] button", feld);
  knoepfe.forEach(k => { k.disabled = true; });
  try {
    // Wer Pflichtquellen angewählt und noch nicht gespeichert hat, meint sie für diesen Start: erst speichern, dann starten
    const pflicht = aktion === "ermittlung_starten" ? $("[data-pflicht]") : null;
    if (pflicht && pflicht.dataset.geaendert && !(await pflichtSpeichern(pflicht))) {
      knoepfe.forEach(k => { k.disabled = false; });
      ergebnisZeigen(ergebnis, null, "Die Ermittlung ist nicht gestartet: Die Pflichtquellen liessen sich nicht speichern. Der Grund steht bei der Auswahl.");
      return;
    }
    const angaben = { fall: c.fall, ...zusatz };
    if (textfeld) angaben[textfeld] = text;
    await senden("/api/aktion/" + aktion, angaben);
    if (pflicht) pflicht.open = false;       // die Ermittlung läuft: Der Chat bekommt den Platz. Der Stand steht in der Kopfzeile der Auswahl
    if (textfeld) eingabe.value = "";
    ergebnis.replaceChildren();
  } catch (e) {
    ergebnisZeigen(ergebnis, null, e.message);
    if (e.daten && e.daten.sperrfund && textfeld && !(zusatz && zusatz.trotzdem)) {
      // Die Prüfung sieht einer Nachricht nicht an, zu wem eine Angabe gehört. Gehört sie zur Täterseite, entscheidet der Sachbearbeiter
      const trotzdem = el("button", { type: "button", text: "Trotzdem senden: Die Angabe gehört zur Täterseite" });
      trotzdem.addEventListener("click", () => chatSenden(aktion, { ...zusatz, trotzdem: "1" }, textfeld));
      ergebnis.append(el("p", { klasse: "knopfzeile" }, trotzdem), el("p", { klasse: "klein", text: "Das Sitzungsprotokoll hält fest, dass die Nachricht trotz Fund gesendet wurde." }));
    }
  }
  knoepfe.forEach(k => { k.disabled = false; });
  chatHolen();
}

function chatKnoepfe(d) {
  const feld = zustand.chat.feld, zeile = $("[data-chat-knoepfe]", feld), eingabe = $("textarea", feld);
  zeile.replaceChildren();
  const knopf = (text, tun, haupt, titel) => { const k = el("button", { type: "button", klasse: haupt ? "haupt" : "", text }); if (titel) k.title = titel; k.addEventListener("click", tun); zeile.append(k); };
  eingabe.disabled = Boolean(d.claude);
  if (d.claude) { zeile.append(el("p", { klasse: "banner", text: d.claude })); return; }
  const arbeitet = d.status === "laeuft" || d.status === "wartet";
  eingabe.placeholder = arbeitet || d.sitzung || d.frueher ? "Nachricht an die Ermittlung, ohne Personendaten" : "Vorgaben für die Ermittlung (freiwillig), ohne Personendaten";
  if (arbeitet) {
    knopf("Senden", () => chatSenden("ermittlung_nachricht", {}, "text"), true, "Die Nachricht wartet, bis der laufende Auftrag zu Ende ist (Strg+Eingabe)");
    knopf("Jetzt unterbrechen und senden", () => chatSenden("ermittlung_nachricht", { jetzt: "1" }, "text"), false, "Bricht den laufenden Schritt ab und gibt der Ermittlung die Nachricht sofort");
    knopf("Anhalten", () => chatSenden("ermittlung_anhalten", {}, ""), false, "Hält die Ermittlung an. Sie lässt sich fortsetzen");
  } else if (d.sitzung || d.frueher) {
    knopf("Senden", () => chatSenden("ermittlung_nachricht", {}, "text"), true, "Setzt die Sitzung mit dieser Nachricht fort (Strg+Eingabe)");
    knopf("Fortsetzen", () => chatSenden("ermittlung_fortsetzen", {}, ""), false, "Setzt die Sitzung fort, wo sie aufgehört hat");
    knopf("Neu starten", () => chatSenden("ermittlung_starten", {}, "vorgaben", "Eine neue Ermittlung starten? Sie beginnt von vorn, mit dem Text im Feld als Vorgabe. Was schon abgefragt ist, bleibt im Protokoll.", "Neu starten"), false,
      "Beginnt eine neue Sitzung mit /ermittlung. Der Text im Feld geht als Vorgabe mit");
  } else knopf("Ermittlung starten", () => chatSenden("ermittlung_starten", {}, "vorgaben"), true, "Startet Claude Code mit /ermittlung für diesen Fall. Der Text im Feld geht als Vorgabe mit");
}

function chatZeigen(d) {
  const c = zustand.chat, feld = c.feld, liste = $(".chat-verlauf", feld);
  const unten = liste.scrollHeight - liste.scrollTop - liste.clientHeight < 60;
  if (d.neu_beginnen) { liste.replaceChildren(); c.knoten = new Map(); }
  for (const z of d.verlauf || []) {
    const neu = chatEintrag(z, c.fall), alt = c.knoten.get(z.nr);
    if (alt) alt.replaceWith(neu); else liste.append(neu);
    c.knoten.set(z.nr, neu);
  }
  c.v = d.v || 0;
  const leer = $(".chat-leer", liste);
  if (!c.knoten.size && !leer) liste.append(el("li", { klasse: "chat-leer klein", text: d.frueher ? "Zu diesem Fall gibt es eine frühere Sitzung. Eine Nachricht setzt sie fort." :
    "Hier erscheint jeder Schritt der Ermittlung. Vorgaben eintragen, wenn es welche gibt, und starten." }));
  else if (c.knoten.size && leer) leer.remove();
  const marke = $("[data-chat-status]", feld);
  marke.textContent = STATUS_WORT[d.status] || d.status;
  marke.className = "marke z-" + (STATUS_FARBE[d.status] || "leer");
  $("[data-chat-fehler]", feld).hidden = d.status !== "fehler";
  const lage = $("[data-chat-lage]", feld);
  lage.textContent = d.lage || "";
  lage.hidden = !d.lage;
  lage.className = "chat-lage l-" + d.status;
  const wartend = $(".chat-wartend", feld);
  wartend.replaceChildren();
  for (const w of d.wartend || []) {
    const zurueck = el("button", { type: "button", klasse: "verweis klein", text: "zurücknehmen" });
    zurueck.addEventListener("click", () => chatSenden("ermittlung_nachricht_zurueck", { nachricht: w.id }, ""));
    wartend.append(el("p", { klasse: "klein" }, document.createTextNode("Wartet: " + (w.text.length > 80 ? w.text.slice(0, 79) + "…" : w.text) + " "), zurueck));
  }
  const merkmal = [d.status, d.claude, d.sitzung || "", d.frueher || ""].join("|");
  if (merkmal !== c.merkmal) {
    const vorher = c.merkmal;
    c.merkmal = merkmal;
    chatKnoepfe(d);
    if (vorher && zustand.fall === c.fall) kopfLaden(c.fall).catch(() => {});        // der Stand der Schritte im Kopf ändert sich mit der Ermittlung
  }
  const stand = $("#ermittlung"), tafel = $("#ermittlung-wer");        // Stand mit Knöpfen und die Tafel «Wer arbeitet woran» in der Ansicht Ermittlung
  if (stand && d.feld && d.feld !== c.feldStand) { c.feldStand = d.feld; einsetzen(stand, d.feld); bedienungEinrichten(stand); }
  if (tafel && (d.tafel || "") !== c.tafelStand) { c.tafelStand = d.tafel || ""; einsetzen(tafel, d.tafel || ""); }
  const pflicht = $("#pflicht-stand"), felder = $("[data-pflicht-felder]");       // Pflichtquellen: der Stand laut Protokoll, und die Auswahl ruht, solange gearbeitet wird
  if (pflicht && (d.pflicht || "") !== c.pflichtStand) { c.pflichtStand = d.pflicht || ""; einsetzen(pflicht, d.pflicht || ""); }
  if (felder) felder.disabled = d.status === "laeuft" || d.status === "wartet";
  const kurz = $("[data-pflicht-kurz]");
  if (kurz) kurz.textContent = d.pflicht_kurz || "";
  if (unten) liste.scrollTop = liste.scrollHeight;        // wer unten war, bleibt unten: auch wenn sich nur die Höhe der Eingabe geändert hat
}

async function chatHolen() {
  const c = zustand.chat, fall = c.fall;
  clearTimeout(c.timer);
  if (!fall || !c.feld || !c.feld.isConnected) return;
  let pause = 4000;
  try {
    const d = await holen(`/api/fall/${encodeURIComponent(fall)}/verlauf?v=${c.v}`);
    if (fall !== zustand.chat.fall || !c.feld.isConnected) return;
    chatZeigen(d);
    pause = d.status === "laeuft" || d.status === "wartet" ? 1200 : 4000;
  } catch (e) { /* der nächste Abruf versucht es wieder */ }
  clearTimeout(c.timer);
  c.timer = setTimeout(chatHolen, pause);
}

function chatEinrichten(a) {
  // Der Chat steht gross in der Ansicht «Ermittlung» und sonst klein am rechten Rand, unter der Arbeitsspur
  const rand = $("#chatrand"), gross = $("#mitte [data-chat]");
  const klein = bedienbar() && a.fall && !gross && a.ansicht !== "klartext";
  rand.hidden = !klein;
  if (gross && bedienbar()) { rand.replaceChildren(); chatBauen(gross, a.fall, true); }
  else if (klein) { if (zustand.chat.feld !== rand || zustand.chat.fall !== a.fall || !rand.firstChild) chatBauen(rand, a.fall, false); }
  else {
    clearTimeout(zustand.chat.timer);
    if (zustand.chat.beobachter) { zustand.chat.beobachter.disconnect(); zustand.chat.beobachter = null; }
    zustand.chat.feld = null; zustand.chat.fall = null; rand.replaceChildren();
  }
}

/* ---------- Rückfrage: erscheint in jeder Ansicht, über allem anderen ---------- */

function titelSetzen() { document.title = (zustand.rueckfrage ? "● Rückfrage · " : "") + zustand.titel; }

async function rueckfragenHolen() {
  clearTimeout(zustand.rueckfrageTimer);
  if (!bedienbar()) return;
  try {
    const d = await holen("/api/rueckfragen");
    if (d.fehler) fehlerStand(d.fehler);      // derselbe Abruf sagt, wie viele Fehler das Fehlerprotokoll in diesem Lauf hat
    if (d.html !== zustand.rueckfrage) {
      zustand.rueckfrage = d.html;
      const ebene = $("#rueckfrage-ebene"), hinweis = $("#rueckfrage-hinweis");
      if (hinweis) hinweis.remove();
      einsetzen(ebene, d.html);         // Werkzeug und Eingabe der Rückfrage sind dort als Text maskiert
      ebene.hidden = !d.html;
      if (d.html) {
        bedienungEinrichten(ebene);
        const dialog = $(".rueckfrage", ebene);
        const spaeter = el("button", { type: "button", klasse: "verweis klein", text: "Erst nachsehen: Dialog ausblenden" });
        spaeter.addEventListener("click", () => {
          ebene.hidden = true;
          const zurueck = el("button", { type: "button", id: "rueckfrage-hinweis", klasse: "banner", text: "Claude Code fragt nach und wartet: zur Rückfrage" });
          zurueck.addEventListener("click", () => { ebene.hidden = false; zurueck.remove(); dialog.focus(); });
          $("#kopf").after(zurueck);
        });
        dialog.append(spaeter);
        dialog.setAttribute("tabindex", "-1");
        dialog.focus();
      }
      titelSetzen();
    }
  } catch (e) { /* der nächste Abruf versucht es wieder */ }
  clearTimeout(zustand.rueckfrageTimer);        // nie zwei Zeitgeber nebeneinander, auch wenn zwei Abrufe sich überholt haben
  zustand.rueckfrageTimer = setTimeout(rueckfragenHolen, 1500);
}

/* ---------- Fehlerprotokoll: ansehen, kopieren, speichern. Und was in diesem Fenster schiefgeht, steht auch dort ---------- */

function fehlerMarke() {
  // Die Zahl in der Navigation: Fehler, die seit dem letzten Blick ins Fehlerprotokoll dazugekommen sind
  const marke = $("#nav-fehler"), f = zustand.fehler;
  if (!marke) return;
  const neu = Math.max(0, f.zahl - f.gesehen);
  marke.hidden = neu === 0;
  marke.textContent = neu > 99 ? "99+" : String(neu);
  marke.title = neu === 1 ? "1 neuer Fehler seit dem letzten Blick ins Fehlerprotokoll" : `${neu} neue Fehler seit dem letzten Blick ins Fehlerprotokoll`;
  marke.setAttribute("aria-label", marke.title);
}

function fehlerStand(stand, gesehen) {
  // `stand`: was der Server zählt, mit der Kennung seines Laufs. Nach einem Neustart der Oberfläche oder nach «Leeren» beginnt die Zählung neu
  const f = zustand.fehler;
  if (!f.lauf) { try { const alt = JSON.parse(sessionStorage.getItem("fehler-gesehen") || "{}"); if (alt.lauf === stand.lauf) f.gesehen = Number(alt.zahl) || 0; } catch (e) { /* ohne Speicher gilt: nichts gesehen */ } }
  else if (f.lauf !== stand.lauf) f.gesehen = 0;
  f.lauf = stand.lauf || "";
  f.zahl = Number(stand.fehler) || 0;
  if (gesehen || f.gesehen > f.zahl) {
    f.gesehen = f.zahl;
    try { sessionStorage.setItem("fehler-gesehen", JSON.stringify({ lauf: f.lauf, zahl: f.gesehen })); } catch (e) { /* siehe oben */ }
  }
  fehlerMarke();
}

async function inZwischenablage(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); return; } catch (e) { /* dann der Weg über ein Textfeld */ }
  }
  const feld = el("textarea", { "aria-hidden": "true", tabindex: "-1" });
  feld.value = text;
  feld.style.cssText = "position:fixed;left:-999px;top:0;opacity:0";
  document.body.append(feld);
  feld.select();
  let gut = false;
  try { gut = document.execCommand("copy"); } catch (e) { /* gilt als nicht gelungen */ }
  feld.remove();
  if (!gut) throw new Error("Der Browser gibt die Zwischenablage nicht frei. «Als Datei speichern» geht immer.");
}

function dateiGeben(name, inhalt, typ) {
  // Eine Datei aus dem Fenster zum Speichern anbieten. Sie entsteht im Browser, nichts geht dafür nach aussen
  const verweis = el("a", { href: URL.createObjectURL(new Blob([inhalt], { type: typ })), download: name });
  document.body.append(verweis); verweis.click(); verweis.remove(); setTimeout(() => URL.revokeObjectURL(verweis.href), 1000);
}

function fehlerEinrichten(wurzel, daten) {
  const seite = $("[data-fehlerprotokoll]", wurzel);
  if (!seite) return;
  if (daten.zahl) fehlerStand(daten.zahl, true);     // wer die Seite sieht, hat die Fehler gesehen
  const meldung = $("[data-fehler-meldung]", seite);
  const sagen = (text) => { if (!meldung) return; meldung.textContent = text; clearTimeout(meldung.zeit); meldung.zeit = setTimeout(() => { meldung.textContent = ""; }, 8000); };
  // Der Text wird beim Klick frisch geholt: So fehlt nichts, was seit dem Laden der Seite dazugekommen ist
  const holenText = () => senden("/api/klartext/fehler", {});
  const kopieren = $("[data-fehler-kopieren]", seite), speichern = $("[data-fehler-speichern]", seite);
  if (kopieren) kopieren.addEventListener("click", async () => {
    try { const d = await holenText(); await inZwischenablage(d.text); sagen("In die Zwischenablage kopiert."); } catch (e) { sagen("Kopieren ist nicht gelungen: " + e.message); }
  });
  if (speichern) speichern.addEventListener("click", async () => {
    try { const d = await holenText(); dateiGeben(d.name, d.text, "text/plain;charset=utf-8"); sagen(`Gespeichert als ${d.name}, im Ordner für Downloads des Browsers.`); }
    catch (e) { sagen("Speichern ist nicht gelungen: " + e.message); }
  });
  const eintraege = $$("li.eintrag", seite), koepfe = $$("li.lauf-kopf", seite);
  const einzelheiten = (li) => { const mehr = $("pre", li); return mehr ? mehr.textContent : ""; };
  for (const li of eintraege) $("[data-fehler-eintrag]", li).addEventListener("click", async () => {
    const mehr = einzelheiten(li);
    try { await inZwischenablage(li.dataset.kopf + (mehr ? "\n" + mehr.split("\n").map(z => "    " + z).join("\n") : "") + "\n"); sagen("Eintrag kopiert."); }
    catch (e) { sagen("Kopieren ist nicht gelungen: " + e.message); }
  });
  // Filter: Suche im Text der Einträge, nur Fehler, nur dieser Lauf. Eine Zwischenzeile bleibt nur, wenn unter ihr etwas zu sehen ist
  const suche = $("[data-fehler-suche]", seite), knoepfe = $$("[data-fehler-filter]", seite), zahl = $("[data-fehler-zahl]", seite), nichts = $("[data-fehler-nichts]", seite);
  if (!suche) return;
  const texte = new Map(eintraege.map(li => [li, (li.dataset.kopf + "\n" + einzelheiten(li)).toLocaleLowerCase("de-CH")]));
  const filtern = () => {
    const q = suche.value.trim().toLocaleLowerCase("de-CH");
    const an = new Set(knoepfe.filter(k => k.getAttribute("aria-pressed") === "true").map(k => k.dataset.fehlerFilter));
    let n = 0;
    for (const li of eintraege) {
      const zeigen = (!an.has("fehler") || li.dataset.stufe === "fehler") && (!an.has("dieser") || li.dataset.lauf === "dieser") && (!q || texte.get(li).includes(q));
      li.hidden = !zeigen;
      n += zeigen ? 1 : 0;
    }
    for (const kopf of koepfe) {
      let etwas = false;
      for (let x = kopf.nextElementSibling; x && !x.classList.contains("lauf-kopf"); x = x.nextElementSibling) if (!x.hidden) etwas = true;
      kopf.hidden = !etwas;
    }
    zahl.textContent = `${n} von ${eintraege.length} ${eintraege.length === 1 ? "Eintrag" : "Einträgen"}`;
    if (nichts) nichts.hidden = n > 0;
  };
  suche.addEventListener("input", filtern);
  for (const k of knoepfe) k.addEventListener("click", () => { k.setAttribute("aria-pressed", String(k.getAttribute("aria-pressed") !== "true")); filtern(); });
  filtern();
}

/* ---------- Seite «Quellen»: filtern und suchen. Was aufgeklappt war, bleibt es nach einem Speichern ---------- */

function quellenEinrichten(wurzel) {
  const seite = $("[data-quellen]", wurzel);
  if (!seite) return;
  const merk = zustand.quellen, eintraege = $$("li.quelle", seite), knoepfe = $$("[data-quellen-filter]", seite);
  const suche = $("[data-quellen-suche]", seite), zahl = $("[data-quellen-zahl]", seite), nichts = $("[data-quellen-nichts]", seite);
  suche.value = merk.suche;
  const texte = new Map(eintraege.map(li => [li, (li.dataset.suche + " " + $(".quelle-zweck", li).textContent).toLocaleLowerCase("de-CH")]));
  for (const li of eintraege) {
    const mehr = $("details.quelle-mehr", li);
    mehr.open = merk.offen.has(li.dataset.name);
    mehr.addEventListener("toggle", () => { if (mehr.open) merk.offen.add(li.dataset.name); else merk.offen.delete(li.dataset.name); });
    const oeffnen = $("[data-schluessel-oeffnen]", li), feld = $("input[name=wert]", li);
    if (oeffnen && feld) oeffnen.addEventListener("click", () => { mehr.open = true; feld.focus(); feld.scrollIntoView({ block: "nearest" }); });
  }
  const filtern = () => {
    const q = suche.value.trim().toLocaleLowerCase("de-CH");
    let n = 0;
    for (const li of eintraege) {
      const zeigen = (!merk.filter || li.dataset.stand === merk.filter) && (!q || texte.get(li).includes(q));
      li.hidden = !zeigen;
      n += zeigen ? 1 : 0;
    }
    for (const k of knoepfe) k.setAttribute("aria-pressed", String(k.dataset.quellenFilter === merk.filter));
    zahl.textContent = `${n} von ${eintraege.length} Quellen`;
    nichts.hidden = n > 0;
  };
  suche.addEventListener("input", () => { merk.suche = suche.value; filtern(); });
  for (const k of knoepfe) k.addEventListener("click", () => { merk.filter = k.dataset.quellenFilter; filtern(); });
  filtern();
}

function fehlerMelden(meldung, einzelheiten) {
  // Ein Fehler im Skript dieses Fensters. Höchstens zwanzig je Fenster: Ein Fehler in einer Schleife füllt das Protokoll nicht
  const f = zustand.fehler;
  if (!bedienbar() || zustand.aus || f.gemeldet >= 20) return;
  f.gemeldet += 1;
  const ort = (text) => String(text || "").split(location.origin).join("");
  senden("/api/aktion/fehler_melden", { meldung: ort(meldung).slice(0, 600), einzelheiten: (`Ansicht: ${zustand.ansicht || "(Start)"}\n` + ort(einzelheiten)).slice(0, 4000),
    fall: zustand.fall || "" }).catch(() => { /* ist der Server nicht erreichbar, bleibt der Fehler in der Konsole des Browsers */ });
}

/* ---------- Navigation und Adressen ---------- */

function adresse() {
  const teile = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (teile[0] === "fall" && teile[1]) return { fall: teile[1], ansicht: teile[2] || "uebersicht", arg: teile.slice(3).join("/") };
  if (teile[0] === "klartext" && teile[1]) return { fall: null, ansicht: "klartext", arg: teile[1] };
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
    return verweis;
  };
  punkt("Fälle", "#/", !a.fall && a.ansicht === "faelle");
  if (zustand.bedienung) punkt("Neuer Fall", "#/neu", !a.fall && (a.ansicht === "neu" || a.ansicht === "klartext"));
  if (a.fall) {
    liste.append(el("li", { klasse: "gruppe", text: a.fall }));
    const eintraege = [["uebersicht", "Fallübersicht"], ["akten", "Akten"]];
    if (zustand.bedienung) eintraege.push(["ermittlung", "Ermittlung"]);
    eintraege.push(["rapport", "Rapport"], ["indikatoren", "Indikatoren"], ["rohdaten", "Rohdaten"], ["suche", "Suche"], ["ergebnisse", "Ergebnisse"]);
    if (zustand.bedienung) eintraege.push(["bedienen", "Bedienen"]);
    const gleich = { indikator: "indikatoren", beleg: "rohdaten", roh: "rohdaten", dokument: "ergebnisse", dokumente: "ergebnisse", zurueck: "bedienen" };
    for (const [name, text] of eintraege) punkt(text, weg("fall", a.fall, name), (gleich[a.ansicht] || a.ansicht) === name, true);
  }
  punkt("Quellen", "#/quellen", !a.fall && a.ansicht === "quellen");
  punkt("Arbeitsplatz", "#/arbeitsplatz", !a.fall && a.ansicht === "arbeitsplatz");
  if (zustand.bedienung) {        // mit der Zahl der Fehler, die seit dem letzten Blick dazugekommen sind
    punkt("Fehlerprotokoll", "#/fehler", !a.fall && a.ansicht === "fehler").append(el("span", { klasse: "nav-zahl", id: "nav-fehler", hidden: "" }));
  }
  nav.append(liste);
  fehlerMarke();
  const farbe = el("button", { type: "button", klasse: "farbwahl", text: "Hell / Dunkel" });
  farbe.addEventListener("click", () => {
    const jetzt = document.documentElement.dataset.farbe || (matchMedia("(prefers-color-scheme: dark)").matches ? "dunkel" : "hell");
    document.documentElement.dataset.farbe = jetzt === "dunkel" ? "hell" : "dunkel";
    try { localStorage.setItem("farbe", document.documentElement.dataset.farbe); } catch (e) { /* ohne Speicher gilt die Wahl bis zum Neuladen */ }
  });
  const modus = !zustand.bedienung ? "Die Oberfläche liest nur." : zustand.geheimnis ? "Bedienbar aus diesem Fenster." :
    "Dieses Fenster kann nur lesen: Bedienen lässt sich die Oberfläche aus dem Fenster, das sie beim Start geöffnet hat.";
  nav.append(farbe, el("p", { klasse: "klein", text: modus + " Adressen aus dem Fall sind nie anklickbar." }));
  if (zustand.anmeldefehler) nav.append(el("p", { klasse: "banner", text: zustand.anmeldefehler }));
}

async function laden() {
  if (zustand.aus) return;          // nach «Alles abschalten» gibt es nichts mehr zu laden, auch nicht über «Zurück» im Browser
  const a = adresse(), lauf = ++zustand.lauf;
  const gleiche = zustand.adresse === location.hash;
  navigation(a);
  const mitte = $("#mitte"), hoehe = mitte.scrollTop;
  mitte.setAttribute("aria-busy", "true");
  try {
    if (a.fall !== zustand.fall) {
      zustand.fall = a.fall;
      $("#kopf").replaceChildren();
      spurNeu(a.fall);
    }
    if (!gleiche && !["neu", "akten", "klartext"].includes(a.ansicht)) zustand.hochgeladen = null;       // die Meldung zum Hochladen gehört zum Akten-Eingang
    if (a.fall) await kopfLaden(a.fall);
    if (lauf !== zustand.lauf) return;          // inzwischen wurde eine andere Ansicht verlangt
    zustand.ansicht = a.ansicht;
    const pfad = a.fall ? `/api/fall/${encodeURIComponent(a.fall)}/${encodeURIComponent(a.ansicht)}`
      + (a.arg && a.ansicht !== "rapport" ? "/" + a.arg.split("/").map(encodeURIComponent).join("/") : "") : `/api/${["quellen", "neu", "arbeitsplatz", "fehler"].includes(a.ansicht) ? a.ansicht : "faelle"}`;
    // Was echte Angaben zeigen kann, gibt der Server nur gegen das Geheimnis heraus: den Bildschirm der Pseudonymisierung, den Akten-Eingang
    // und das Fehlerprotokoll (bereinigt, aber Namen erkennt die Bereinigung nicht)
    const daten = a.ansicht === "klartext" ? await senden("/api/klartext/pseudo", { vorgang: a.arg })
      : bedienbar() && ((!a.fall && a.ansicht === "neu") || (a.fall && a.ansicht === "akten")) ? await senden("/api/klartext/korb", { ziel: a.fall || "" })
      : bedienbar() && !a.fall && a.ansicht === "fehler" ? await senden("/api/klartext/fehler", {})
      : await holen(pfad);
    if (lauf !== zustand.lauf) return;
    einsetzen(mitte, daten.html);
    zustand.titel = `${daten.titel} · OSINT-Arbeitsplatz`;
    titelSetzen();
    einrichten(mitte, a);
    bedienungEinrichten(mitte);
    fehlerEinrichten(mitte, daten);
    quellenEinrichten(mitte);
    chatEinrichten(a);
    if (a.ansicht === "rapport" && a.arg) { const ziel = document.getElementById(a.arg); if (ziel) { ziel.scrollIntoView(); ziel.classList.add("ziel"); } }
    else mitte.scrollTop = gleiche ? hoehe : 0;        // dieselbe Ansicht neu geladen: Die Stelle bleibt
    if (!gleiche) mitte.focus({ preventScroll: true });
    zustand.adresse = location.hash;
  } catch (e) {
    if (lauf !== zustand.lauf) return;
    zustand.adresse = "";
    const zurueck = a.ansicht === "klartext" ? ["#/neu", "Zum Akten-Eingang"] : a.fall ? [weg("fall", a.fall), "Zur Fallübersicht"] : ["#/", "Zur Liste der Fälle"];
    const wege = el("p", {}, el("a", { href: zurueck[0], text: zurueck[1] }));
    if (bedienbar() && a.ansicht !== "fehler") wege.append(" · ", el("a", { href: "#/fehler", text: "Zum Fehlerprotokoll" }));
    mitte.replaceChildren(el("h1", { text: "Das hat nicht geklappt" }), el("p", { klasse: "banner", text: e.message }), wege);
    chatEinrichten({ fall: null, ansicht: "" });
  }
  mitte.removeAttribute("aria-busy");
}

async function kopfLaden(fall) {
  const daten = await holen(`/api/fall/${encodeURIComponent(fall)}/kopf`);
  if (fall !== zustand.fall) return;
  einsetzen($("#kopf"), daten.html);
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
  if (tabelle.dataset.fertig || tabelle.closest("[data-ohne-leiste]")) return;      // eine Tafel, die sich laufend erneuert, bekommt keine Leiste
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
    dateiGeben(((zustand.fall ? zustand.fall + "_" : "") + (tabelle.dataset.name || "tabelle")).replace(/[^\w.-]+/g, "_") + ".csv",
      "﻿" + inhalt.map(z => z.map(csvSicher).join(";")).join("\r\n"), "text/csv;charset=utf-8");
  });
  leiste.append(feld, csv, zahl);
  (tabelle.closest(".tabelle-breit") || tabelle).before(leiste);
  Array.from(tabelle.tHead.rows[0].cells).forEach((th, spalte) => {
    if (th.querySelector("input")) return;        // die Spalte mit den Haken zum Auswählen sortiert nicht
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

function spurNeu(fall) {
  clearTimeout(zustand.spurTimer);
  zustand.spurStand = 0; zustand.spurFall = fall;
  const spur = $("#spur");
  spur.replaceChildren();
  $("#rand").hidden = !fall;        // der rechte Rand gehört zum Fall: Arbeitsspur und, wenn bedienbar, der Chat
  if (!fall) return;
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
  if (!fall || zustand.aus) return;
  try {
    const daten = await holen(`/api/fall/${encodeURIComponent(fall)}/spur?ab=${zustand.spurStand}`);
    if (fall !== zustand.spurFall) return;
    const liste = $("#spurliste");
    for (const e of daten.eintraege) {
      const klassen = [e.klasse].concat(e.freigabe || e.ergebnis === "abgelehnt" ? ["freigabe"] : []);
      const zeit = e.zeit_anzeige || "";       // Zeitzone des Arbeitsplatzes, vom Server gerechnet
      const art = e.art_wort || "passiv";      // das Wort kommt vom Server (tools/ui/daten.py), wie Zeichen und Farbe des Ergebnisses
      const kopf = el("div", { klasse: "spurkopf" }, el("a", { href: weg("fall", fall, "beleg", e.id), text: e.id }), el("time", { text: zeit, title: (e.zeit || "") + " (UTC)" }),
        el("span", { klasse: "marke", text: art }));
      const text = el("div", { klasse: "spurtext" });
      text.append(el("span", { klasse: "z-" + (e.farbe || "kritisch"), text: (e.zeichen || "?") + " " }),
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
addEventListener("beforeprint", () => $$("details").forEach(d => { d.dataset.war = d.open ? "1" : ""; d.open = true; }));
addEventListener("afterprint", () => $$("details").forEach(d => { d.open = d.dataset.war === "1"; }));
addEventListener("resize", chatHoehe);
// Was im Skript dieses Fensters schiefgeht, steht sonst nur in der Konsole des Browsers: Es geht ins Fehlerprotokoll
addEventListener("error", (e) => fehlerMelden(e.message || "Fehler im Skript der Oberfläche", (e.filename ? `${e.filename}:${e.lineno}:${e.colno}\n` : "") + ((e.error && e.error.stack) || "")));
addEventListener("unhandledrejection", (e) => { const g = e.reason; fehlerMelden("Unbehandelter Fehler: " + ((g && g.message) || String(g)), (g && g.stack) || ""); });
anmelden().then(() => { addEventListener("hashchange", laden); laden(); rueckfragenHolen(); });
