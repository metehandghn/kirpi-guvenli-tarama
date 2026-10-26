// Test yardımcıları: eklenti dosyalarını taklit edilmiş Chrome API'leriyle Node.js'te çalıştırır.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { IDBFactory, IDBKeyRange } = require("fake-indexeddb");
const { JSDOM } = require("jsdom");

const EXT = path.join(__dirname, "..", "extension");
const BACKGROUND = fs.readFileSync(path.join(EXT, "background.js"), "utf8");
const CONTENT = fs.readFileSync(path.join(EXT, "content.js"), "utf8");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const clone = (v) => (v === undefined ? v : JSON.parse(JSON.stringify(v)));

/**
 * background.js'i yeni bir "servis worker" olarak başlatır.
 * storage ve idb, servisler arasında paylaşılabilir (servisin kapanıp yeniden açılmasını taklit eder).
 * fetchImpl(url, env) -> {ok,status,text(),json()} döndürmeli; env.kill() servisi "öldürür".
 */
function startBackground({ storage, idb, fetchImpl }) {
  const listeners = {};
  const on = (name) => ({ addListener: (fn) => { (listeners[name] ||= []).push(fn); } });
  const env = { dead: false, dl: [], notifs: [], redirects: [], kill() { env.dead = true; } };
  const session = {};
  const guard = () => { if (env.dead) throw new Error("servis kapatıldı"); };

  const chrome = {
    storage: { local: {
      get: async (keys) => {
        const ks = Array.isArray(keys) ? keys : [keys];
        const o = {};
        for (const k of ks) if (k in storage) o[k] = clone(storage[k]);
        return o;
      },
      set: async (obj) => { guard(); for (const k in obj) storage[k] = clone(obj[k]); },
      remove: async (k) => { guard(); for (const key of [].concat(k)) delete storage[key]; }
    },
    session: {
      get: async (keys) => { const ks = Array.isArray(keys) ? keys : [keys]; const o = {}; for (const k of ks) if (k in session) o[k] = clone(session[k]); return o; },
      set: async (obj) => { for (const k in obj) session[k] = clone(obj[k]); }
    } },
    runtime: {
      onMessage: on("message"), onInstalled: on("installed"), onStartup: on("startup"),
      getURL: (p) => "chrome-extension://kirpi/" + p, getPlatformInfo: (cb) => cb && cb({})
    },
    alarms: {
      create: (name, info) => { (env.alarms ||= {})[name] = info; },
      get: async (name) => (env.alarms && env.alarms[name]) ? { name, ...env.alarms[name] } : undefined,
      onAlarm: on("alarm")
    },
    webNavigation: { onBeforeNavigate: on("beforeNavigate"), onCommitted: on("committed") },
    downloads: {
      onCreated: on("download"),
      cancel: async (id) => env.dl.push(["cancel", id]), erase: async (q) => env.dl.push(["erase", q.id]),
      pause: async (id) => env.dl.push(["pause", id]), resume: async (id) => env.dl.push(["resume", id])
    },
    notifications: {
      create: (id, opts) => { env.notifs.push(typeof id === "string" ? { id, ...opts } : id); },
      clear: () => {}, onButtonClicked: on("notifButton")
    },
    tabs: { update: async (tabId, props) => { env.redirects.push(props.url); }, query: async () => [] },
    declarativeNetRequest: { updateDynamicRules: async (u) => { env.dnrRules = u.addRules; } }
  };
  const fetch = async (url) => { guard(); return fetchImpl(url, env); };
  const ctx = {
    chrome, fetch, indexedDB: idb, IDBKeyRange,
    console: { log() {}, warn() {} },
    setTimeout, clearTimeout, setInterval, clearInterval, AbortController, URL
  };
  vm.createContext(ctx);
  vm.runInContext(BACKGROUND, ctx);

  const send = (msg) => new Promise((res) => listeners.message[0](msg, { tab: null }, res));
  return { env, listeners, send };
}

async function waitUntil(fn, ms = 10000) {
  const t0 = Date.now();
  while (Date.now() - t0 < ms) { if (await fn()) return true; await sleep(25); }
  return false;
}

const ok = (text, json) => ({ ok: true, status: 200, text: async () => text, json: async () => json });

/** content.js'i verilen HTML ve adresle çalıştırır; blocked = zararlı sayılacak hostlar. */
function runContent(html, url, blocked = []) {
  const dom = new JSDOM(html, { url, runScripts: "outside-only", pretendToBeVisual: true });
  const w = dom.window;
  const reports = [];
  const blockedSet = new Set(blocked);
  w.chrome = { runtime: {
    getURL: (p) => "chrome-extension://kirpi/" + p,
    sendMessage: (m, cb) => {
      if (m.type === "getSettings") cb && cb({ enabled: true, blockRedirects: true, blockMiners: true, detectPhishing: true });
      else if (m.type === "checkHost") cb && cb({ blocked: blockedSet.has(m.host) });
      else if (m.type === "threatDetected") reports.push(m);
    }
  } };
  w.eval(CONTENT);
  return { window: w, document: w.document, reports };
}

/** Her test için ayrı, boş bir IndexedDB. */
const newIDB = () => new IDBFactory();

/** Engelleme/beyaz liste testleri için hazır kurulu bir arka plan. */
module.exports = { startBackground, runContent, waitUntil, sleep, ok, newIDB };
