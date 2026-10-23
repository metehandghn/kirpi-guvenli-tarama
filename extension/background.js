// Kirpi - Güvenli Tarama | Arka plan servisi (MV3 service worker)
// Not: Proje önceden "Kalkan" adını taşıyordu. Tarayıcıda kayıtlı verinin (liste, istatistikler,
// güncelleme durumu) silinmemesi için iç depolama anahtarları ve alarm adları "kalkan..." olarak bırakıldı.
// Zararlı domain kontrolü — KOVALI (bucket) IndexedDB mimarisi.
//
// Domainler ~1024 gruba (bucket) bölünür; her grup TEK bir IDB kaydı olarak yazılır.
// Böylece milyonlarca yazma yerine ~1024 yazma olur: güncelleme saniyeler sürer,
// yarıda kalmaz. Arama için yalnızca ilgili küçük grup yüklenir -> hiç donma yok.

// --- Kaynaklar ---
const CURATED_FEEDS = [
  { id: "URLhaus", url: "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains-online.txt" },
  { id: "Ransomware", url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/ransomware.txt" },
  { id: "Scam", url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/scam.txt" },
  { id: "Fraud", url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/fraud.txt" },
  { id: "BLP-Phish", url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/phishing.txt" }
  // Not: OpenPhish ücretsiz beslemesinin kullanım şartları verinin üçüncü kişilere sunulmasını
  // yazılı izin olmadan yasakladığı için herkese açık bu eklentide kullanılmıyor.
];
const BULK_FEEDS = [
  { id: "Malware", url: "https://raw.githubusercontent.com/blocklistproject/Lists/master/malware.txt" },
  { id: "PhishDB", url: "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt" }
];

// USOM / T.C. Siber Güvenlik Başkanlığı resmi API'si (anahtarsız)
const USOM_API = "https://siberguvenlik.gov.tr/api/address/index";
const USOM_PER_PAGE = 1000;
const USOM_MAX_PAGES = 200;    // en güncel ~200 bin TR kaydı (indirmeyi kısa tutar)

const HARD_CEILING = 1500000;  // toplam güvenlik tavanı
const BUCKETS = 1024;          // kova sayısı

const DEFAULTS = {
  enabled: true, blockRedirects: true, blockDownloads: true, blockMiners: true, detectPhishing: true,
  stats: { blockedSites: 0, blockedRedirects: 0, blockedDownloads: 0, blockedMiners: 0, blockedPhishing: 0 }
};

// Bilinen madencilik domainleri. Dosyada TERS ÇEVRİLMİŞ saklanır (antivirüsler düz metin
// imzaları görünce eklentiyi madenci sanabiliyor); çalışırken düzeltilir.
const unrev = (t) => t.split("").reverse().join("");
const MINER_DOMAINS = [
  "moc.evihnioc", "moc.evih-nioc", "moc.niocesj", "moc.tool-otpyrc", "orp.toolotpyrc", "cc.orenim", "moc.pminioc", "gnicar.duolcgnitsoh", "zc.enimbew", "moc.enimdehtua", "oc.vhnc", "moc.niocesj.daol", "moc.mmarg0rp.renim", "knil.agig2", "moc.dnilbnioc"
].map(unrev);
const DANGEROUS_EXT = [".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".apk", ".msi", ".vbs", ".js", ".jar", ".ps1", ".hta"];
const TEST_DOMAIN = "kirpi-test.example";

const memorySet = new Set([...MINER_DOMAINS, TEST_DOMAIN]);
const bucketCache = new Map();   // bucketId -> {domainObj} (okuma önbelleği)
const BUCKET_CACHE_MAX = 64;

// ---------- Kova (bucket) anahtarı ----------
function bucketId(domain) {
  let h = 0;
  for (let i = 0; i < domain.length; i++) h = (h * 31 + domain.charCodeAt(i)) >>> 0;
  return h % BUCKETS;
}

// ---------- IndexedDB ----------
const DB_NAME = "kalkanDB";
const STORE = "buckets";
let dbPromise = null;
function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 2);
    req.onupgradeneeded = (e) => {
      const db = e.target.result;
      // Eski sürüm store'unu temizle, yeni kova store'u kur
      for (const name of Array.from(db.objectStoreNames)) db.deleteObjectStore(name);
      db.createObjectStore(STORE); // key = bucketId
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}
function idbGet(db, key) {
  return new Promise((resolve) => {
    try { const r = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
      r.onsuccess = () => resolve(r.result); r.onerror = () => resolve(undefined);
    } catch (e) { resolve(undefined); }
  });
}
function idbPut(db, key, val) {
  return new Promise((resolve) => {
    try { const tx = db.transaction(STORE, "readwrite"); tx.objectStore(STORE).put(val, key);
      tx.oncomplete = () => resolve(true); tx.onerror = () => resolve(false); tx.onabort = () => resolve(false);
    } catch (e) { resolve(false); }
  });
}
function idbClear(db) {
  return new Promise((resolve) => {
    try { const tx = db.transaction(STORE, "readwrite"); tx.objectStore(STORE).clear();
      tx.oncomplete = () => resolve(true); tx.onerror = () => resolve(false);
    } catch (e) { resolve(false); }
  });
}

// ---------- Yardımcılar ----------
function getDomain(u) {
  try { return new URL(u).hostname.replace(/^www\./, "").toLowerCase(); } catch (e) { return ""; }
}
function parseFeedLines(text) {
  const out = [];
  for (let raw of text.split("\n")) {
    let line = raw.trim();
    if (!line || line[0] === "#" || line[0] === "!" || line[0] === ";") continue;
    const parts = line.split(/\s+/);
    if (parts.length >= 2 && /^(0\.0\.0\.0|127\.0\.0\.1|::1?|255\.255\.255\.255)$/.test(parts[0])) line = parts[1];
    let host;
    if (line.includes("://")) host = getDomain(line);
    else host = line.replace(/^www\./, "").split("/")[0].toLowerCase();
    if (host && host.includes(".") && !host.includes(" ") && !/^\d+\.\d+\.\d+\.\d+$/.test(host)) out.push(host);
  }
  return out;
}

// ---------- Arama ----------
async function getBucket(db, id) {
  if (bucketCache.has(id)) return bucketCache.get(id);
  const obj = (await idbGet(db, id)) || null;
  if (bucketCache.size >= BUCKET_CACHE_MAX) bucketCache.clear();
  bucketCache.set(id, obj);
  return obj;
}
async function isBlockedHost(host) {
  if (!host) return false;
  if (memorySet.has(host)) return true;
  const candidates = [host];
  const parts = host.split(".");
  for (let i = 1; i < parts.length - 1; i++) candidates.push(parts.slice(i).join("."));
  const db = await openDB();
  for (const c of candidates) {
    if (memorySet.has(c)) return true;
    const b = await getBucket(db, bucketId(c));
    if (b && b[c]) return true;
  }
  return false;
}

// ---------- Ağ ----------
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { cache: "no-store", redirect: "follow", signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}
async function fetchRetry(url, ms, tries = 3) {
  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetchWithTimeout(url, ms);
      if (res.ok) return res;
      lastErr = new Error("HTTP " + res.status);
      if (res.status < 500 && res.status !== 429) return res;
    } catch (e) { lastErr = e; }
    if (i < tries - 1) await sleep(1200 * (i + 1));
  }
  throw lastErr || new Error("fetch failed");
}

// ---------- USOM ----------
function usomHosts(models) {
  const out = [];
  for (const m of (models || [])) {
    let v = (m.url || "").trim().toLowerCase();
    if (!v) continue;
    if (v.includes("://")) v = getDomain(v);
    else v = v.replace(/^www\./, "").split("/")[0];
    if (v && v.includes(".") && !/^\d+\.\d+\.\d+\.\d+$/.test(v)) out.push(v);
  }
  return out;
}
async function usomPage(page) {
  const res = await fetchRetry(`${USOM_API}?per-page=${USOM_PER_PAGE}&page=${page}`, 20000, 3);
  if (!res.ok) throw new Error("HTTP " + res.status);
  return await res.json();
}

// ---------- Güncelleme (adım adım, kaldığı yerden devam eder) ----------
// MV3 servis worker'ı uzun işlerde kapatılabildiği için güncelleme küçük adımlara
// bölünür. Her adımın sonunda ilerleme kaydedilir; servis kapanırsa her dakika
// çalışan "kalkanResume" alarmı kaldığı yerden devam ettirir. Veri her adımda
// mevcut kovalara EKLENİR (birleştirme), bu yüzden güncelleme sırasında liste boşalmaz.

const USOM_PAGES_PER_STEP = 20;
const STATE_KEY = "kalkanUpdateState";

let keepAliveTimer = null;
function startKeepAlive() {
  if (keepAliveTimer) return;
  keepAliveTimer = setInterval(() => { try { chrome.runtime.getPlatformInfo(() => {}); } catch (e) {} }, 20000);
}
function stopKeepAlive() { if (keepAliveTimer) { clearInterval(keepAliveTimer); keepAliveTimer = null; } }

async function loadState() { return (await chrome.storage.local.get(STATE_KEY))[STATE_KEY] || null; }
async function saveState(st) { await chrome.storage.local.set({ [STATE_KEY]: st }); }

async function publish(st) {
  await chrome.storage.local.set({
    kalkanCount: (st.baseCount || 0) + (st.newAdds || 0),
    kalkanLastUpdate: Date.now(),
    kalkanFeedStatus: st.status
  });
}

// Domainleri IDB kovalarına birleştir; yeni eklenen benzersiz sayıyı döndür
// Uzun işlerde tarayıcıya nefes aldır: işlemci tek seferde uzun süre tutulmasın
const yieldCPU = () => sleep(8);

// Büyük metin listelerini parça parça ayrıştır (tek seferde milyonlarca satır işlenmez)
async function parseFeedLinesAsync(text) {
  const lines = text.split("\n");
  const out = [];
  const CHUNK = 20000;
  for (let i = 0; i < lines.length; i += CHUNK) {
    const part = parseFeedLines(lines.slice(i, i + CHUNK).join("\n"));
    for (const h of part) out.push(h);
    await yieldCPU();
  }
  return out;
}

async function mergeDomains(db, hosts, limit) {
  const groups = new Map();
  let n = 0;
  for (const d of hosts) {
    if (limit != null && n >= limit) break;
    const id = bucketId(d);
    let arr = groups.get(id); if (!arr) { arr = []; groups.set(id, arr); }
    arr.push(d); n++;
    if (n % 50000 === 0) await yieldCPU();
  }
  let added = 0, k = 0;
  for (const [id, arr] of groups) {
    const obj = (await idbGet(db, id)) || {};
    let changed = false;
    for (const d of arr) if (!obj[d]) { obj[d] = 1; added++; changed = true; }
    if (changed) await idbPut(db, id, obj);
    if (++k % 16 === 0) await yieldCPU();
  }
  bucketCache.clear();
  return { processed: n, added };
}

async function countAll(db) {
  let total = 0;
  for (let id = 0; id < BUCKETS; id++) {
    const obj = await idbGet(db, id);
    if (obj) total += Object.keys(obj).length;
    if (id % 64 === 63) await yieldCPU();
  }
  return total;
}

function errInfo(e) { return (e && e.name === "AbortError") ? "zaman aşımı" : ((e && e.message) || "hata"); }

// Tek bir adımı çalıştır, durumu güncelle
async function doStep(st) {
  const db = await openDB();

  if (st.step === "curated") {
    const feed = CURATED_FEEDS[st.feedIdx];
    if (!feed) { st.step = "usom"; st.usomPage = 1; return; }
    try {
      const res = await fetchRetry(feed.url, 25000, 3);
      if (!res.ok) st.status.push({ id: feed.id, ok: false, info: "HTTP " + res.status });
      else {
        const r = await mergeDomains(db, await parseFeedLinesAsync(await res.text()), null);
        st.newAdds += r.added;
        st.status.push({ id: feed.id, ok: true, added: r.processed });
      }
    } catch (e) { st.status.push({ id: feed.id, ok: false, info: errInfo(e) }); }
    st.feedIdx++;
    return;
  }

  if (st.step === "usom") {
    let us = st.status.find(s => s.id === "USOM");
    if (!us) { us = { id: "USOM", ok: false, added: 0, info: "indiriliyor…" }; st.status.push(us); }
    try {
      if (!st.usomPageCount) {
        const first = await usomPage(1);
        st.usomPageCount = Math.min(first.pageCount || 1, USOM_MAX_PAGES);
        const r = await mergeDomains(db, usomHosts(first.models), null);
        st.newAdds += r.added; us.added += r.processed; us.ok = true;
        st.usomPage = 2;
        return;
      }
      const stepEnd = Math.min(st.usomPage + USOM_PAGES_PER_STEP - 1, st.usomPageCount);
      const CONC = 4;
      for (let p = st.usomPage; p <= stepEnd; p += CONC) {
        const pages = [];
        for (let q = p; q < p + CONC && q <= stepEnd; q++) pages.push(q);
        const results = await Promise.allSettled(pages.map(usomPage));
        let hosts = [];
        for (const r of results) if (r.status === "fulfilled") hosts = hosts.concat(usomHosts(r.value.models));
        const m = await mergeDomains(db, hosts, null);
        st.newAdds += m.added; us.added += m.processed; us.ok = true;
      }
      st.usomPage = stepEnd + 1;
      if (st.usomPage > st.usomPageCount) { us.info = undefined; st.step = "bulk"; st.feedIdx = 0; }
    } catch (e) {
      us.info = us.added > 0 ? undefined : errInfo(e);
      us.ok = us.added > 0;
      st.step = "bulk"; st.feedIdx = 0; // USOM'a ulaşılamazsa sonraki aşamaya geç
    }
    return;
  }

  if (st.step === "bulk") {
    const feed = BULK_FEEDS[st.feedIdx];
    if (!feed) { st.step = "done"; return; }
    const current = (st.baseCount || 0) + st.newAdds;
    const remainingFeeds = BULK_FEEDS.length - st.feedIdx;
    const limit = Math.max(0, Math.floor((HARD_CEILING - current) / remainingFeeds));
    if (limit === 0) st.status.push({ id: feed.id, ok: false, info: "tavan dolu" });
    else {
      try {
        const res = await fetchRetry(feed.url, 30000, 3);
        if (!res.ok) st.status.push({ id: feed.id, ok: false, info: "HTTP " + res.status });
        else {
          const r = await mergeDomains(db, await parseFeedLinesAsync(await res.text()), limit);
          st.newAdds += r.added;
          st.status.push({ id: feed.id, ok: true, added: r.processed });
        }
      } catch (e) { st.status.push({ id: feed.id, ok: false, info: errInfo(e) }); }
    }
    st.feedIdx++;
    return;
  }

  if (st.step === "done") {
    const total = await countAll(db);
    st.baseCount = total; st.newAdds = 0;
    st.running = false;
    st.finishedAt = Date.now();
    await chrome.storage.local.set({ kalkanLastComplete: st.finishedAt });
    console.log("[Kirpi] Güncelleme tamamlandı:", total, "benzersiz domain", st.status);
  }
}

let stepping = false;
async function runSteps() {
  if (stepping) return;
  stepping = true;
  startKeepAlive();
  try {
    while (true) {
      const st = await loadState();
      if (!st || !st.running) break;

      // Aynı adım üst üste 3 kez yarıda kaldıysa atla (sonsuz döngüye girmesin)
      const key = st.step + ":" + st.feedIdx + ":" + st.usomPage;
      st.attempts = (st.attemptKey === key) ? (st.attempts || 0) + 1 : 1;
      st.attemptKey = key;
      if (st.attempts > 3) {
        const feedId = st.step === "usom" ? "USOM" : ((st.step === "curated" ? CURATED_FEEDS : BULK_FEEDS)[st.feedIdx] || {}).id;
        const existing = st.status.find(s => s.id === feedId);
        if (existing) { existing.info = "kısmen alındı"; }
        else if (feedId) st.status.push({ id: feedId, ok: false, info: "tamamlanamadı" });
        if (st.step === "usom") { st.step = "bulk"; st.feedIdx = 0; }
        else if (st.step === "curated" || st.step === "bulk") st.feedIdx++;
        st.attempts = 0; st.attemptKey = null;
        await saveState(st); await publish(st);
        continue;
      }
      await saveState(st); // deneme sayısını kaydet (servis ölürse sayılsın)

      await doStep(st);
      st.attempts = 0; st.attemptKey = null;
      await saveState(st);
      await publish(st);
    }
  } catch (e) {
    console.warn("[Kirpi] Güncelleme adımı hata verdi, alarm devam ettirecek:", e);
  } finally {
    stepping = false;
    stopKeepAlive();
  }
}

// Yeni bir güncelleme turu başlat (zaten sürüyorsa devam ettir)
async function updateThreatLists() {
  const st = await loadState();
  if (st && st.running) { runSteps(); return { busy: true }; }
  const { kalkanCount } = await chrome.storage.local.get("kalkanCount");
  await saveState({
    running: true, startedAt: Date.now(),
    step: "curated", feedIdx: 0, usomPage: 1, usomPageCount: 0,
    status: [], baseCount: kalkanCount || 0, newAdds: 0
  });
  runSteps();
  return { started: true };
}

async function isUpdating() {
  const st = await loadState();
  return !!(st && st.running);
}

// ---------- Uyarı / istatistik ----------
async function redirectToWarning(tabId, blockedUrl, reason) {
  const warnUrl = chrome.runtime.getURL("warning.html") + "?url=" + encodeURIComponent(blockedUrl) + "&reason=" + encodeURIComponent(reason);
  try { await chrome.tabs.update(tabId, { url: warnUrl }); } catch (e) {}
}
async function bumpStat(key) {
  const { stats } = await chrome.storage.local.get("stats");
  const s = stats || { ...DEFAULTS.stats };
  s[key] = (s[key] || 0) + 1;
  await chrome.storage.local.set({ stats: s });
}
async function getSettings() {
  const data = await chrome.storage.local.get(Object.keys(DEFAULTS));
  return { ...DEFAULTS, ...data };
}

// ---------- Beyaz liste ----------
// Kalıcı: kullanıcının "her zaman güven" dediği siteler (chrome.storage.local).
// Geçici: uyarı ekranında "yine de devam et" denen siteler; tarayıcı kapanınca silinir (chrome.storage.session).
const ALLOW_KEY = "kirpiAllowlist";
const TEMP_KEY = "kirpiTempAllow";
const tempMem = new Set();
const sessionStore = () => (chrome.storage && chrome.storage.session) || null;
const normHost = (h) => (h || "").replace(/^www\./, "").toLowerCase();
const hostMatches = (host, entry) => host === entry || host.endsWith("." + entry);

async function getAllowlist() {
  const r = await chrome.storage.local.get(ALLOW_KEY);
  return r[ALLOW_KEY] || [];
}
async function getTempAllow() {
  const ss = sessionStore();
  if (!ss) return [...tempMem];
  const r = await ss.get(TEMP_KEY);
  return r[TEMP_KEY] || [];
}
async function isAllowed(host) {
  host = normHost(host);
  if (!host) return false;
  if ((await getAllowlist()).some(e => hostMatches(host, e.host))) return true;
  return (await getTempAllow()).some(e => hostMatches(host, e));
}
async function allowHost(host, permanent) {
  host = normHost(host);
  if (!host) return false;
  if (permanent) {
    const list = await getAllowlist();
    if (!list.some(e => e.host === host)) {
      list.push({ host, addedAt: Date.now() });
      list.sort((a, b) => a.host.localeCompare(b.host));
      await chrome.storage.local.set({ [ALLOW_KEY]: list });
    }
  } else {
    const ss = sessionStore();
    if (ss) {
      const t = await getTempAllow();
      if (!t.includes(host)) { t.push(host); await ss.set({ [TEMP_KEY]: t }); }
    } else tempMem.add(host);
  }
  return true;
}
async function removeAllowed(host) {
  host = normHost(host);
  const list = (await getAllowlist()).filter(e => e.host !== host);
  await chrome.storage.local.set({ [ALLOW_KEY]: list });
}

// ---------- Navigasyon ----------
async function checkNavigation(d) {
  if (d.frameId !== 0) return;
  const s = await getSettings(); if (!s.enabled) return;
  const host = getDomain(d.url);
  if (!host || await isAllowed(host)) return;        // beyaz listedeki / izin verilen site
  if (await isBlockedHost(host)) { await bumpStat("blockedSites"); await redirectToWarning(d.tabId, d.url, "blocklist"); }
}
chrome.webNavigation.onBeforeNavigate.addListener(checkNavigation);
chrome.webNavigation.onCommitted.addListener(checkNavigation);

// ---------- İndirme ----------
// Zararlı listesindeki bir siteden gelen indirme doğrudan iptal edilir.
// Diğer sitelerden gelen çalıştırılabilir dosyalar (.exe, .msi, .apk...) ENGELLENMEZ:
// indirme duraklatılır ve kullanıcıya "devam et / iptal et" diye sorulur.
const DL_NOTIF = "kirpi-dl-";

function downloadName(item) {
  const raw = item.filename || item.finalUrl || item.url || "";
  return raw.split(/[?#]/)[0].split(/[\\/]/).pop().toLowerCase();
}

const NEW_DOWNLOAD_MS = 2 * 60 * 1000;

chrome.downloads.onCreated.addListener(async (item) => {
  // Chrome, indirme geçmişini yüklerken ESKİ kayıtlar için de bu olayı tetikleyebiliyor.
  // Yalnızca şu an süren ve yeni başlamış indirmelere bakılır; tamamlanmış/eski kayıtlara dokunulmaz.
  if (item.state && item.state !== "in_progress") return;
  const started = Date.parse(item.startTime || "");
  if (started && Date.now() - started > NEW_DOWNLOAD_MS) return;

  const s = await getSettings(); if (!s.enabled || !s.blockDownloads) return;
  const fname = downloadName(item);
  const hosts = [item.url, item.finalUrl, item.referrer].map(u => getDomain(u || "")).filter(Boolean);

  let fromBad = false;
  for (const h of hosts) if (!(await isAllowed(h)) && await isBlockedHost(h)) { fromBad = true; break; }

  if (fromBad) {
    try { await chrome.downloads.cancel(item.id); await chrome.downloads.erase({ id: item.id }); } catch (e) {}
    await bumpStat("blockedDownloads");
    chrome.notifications.create({ type: "basic", iconUrl: "icons/icon48.png",
      title: "Kirpi: İndirme engellendi",
      message: "Zararlı listesindeki bir siteden gelen indirme durduruldu:\n" + fname });
    return;
  }

  const dangerous = DANGEROUS_EXT.some(ext => fname.endsWith(ext));
  if (!dangerous || item.byExtensionId) return;

  // Bilinmeyen siteden çalıştırılabilir dosya: duraklat ve sor
  try { await chrome.downloads.pause(item.id); } catch (e) { return; } // tamamlanmış küçük dosya vb.
  const source = hosts[0] || "bilinmeyen kaynak";
  chrome.notifications.create(DL_NOTIF + item.id, {
    type: "basic", iconUrl: "icons/icon48.png", requireInteraction: true,
    title: "Kirpi: Bu dosyayı indirmek istiyor musun?",
    message: fname + "\nKaynak: " + source + "\nÇalıştırılabilir dosyalar bilgisayarına zarar verebilir. Kaynağına güveniyorsan devam et.",
    buttons: [{ title: "İndirmeye devam et" }, { title: "İptal et" }]
  });
});

chrome.notifications.onButtonClicked.addListener(async (notifId, buttonIndex) => {
  if (!notifId.startsWith(DL_NOTIF)) return;
  const id = Number(notifId.slice(DL_NOTIF.length));
  try {
    if (buttonIndex === 0) await chrome.downloads.resume(id);
    else { await chrome.downloads.cancel(id); await chrome.downloads.erase({ id }); await bumpStat("blockedDownloads"); }
  } catch (e) {}
  chrome.notifications.clear(notifId);
});

// ---------- Mesajlar ----------
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg.type === "getSettings") {
      const st = await getSettings();
      sendResponse({ ...st, allowed: msg.host ? await isAllowed(msg.host) : false });
      return;
    }
    if (msg.type === "allowHost") {
      const host = msg.host || getDomain(msg.url || "");
      sendResponse({ ok: await allowHost(host, !!msg.permanent), host: normHost(host) });
      return;
    }
    if (msg.type === "removeAllowed") { await removeAllowed(msg.host); sendResponse({ ok: true }); return; }
    if (msg.type === "listAllowed") { sendResponse({ hosts: (await getAllowlist()).map(e => e.host) }); return; }
    if (msg.type === "forceUpdate") {
      const r = await updateThreatLists();
      sendResponse({ ok: true, started: !!r.started, busy: !!r.busy });
      return;
    }
    if (msg.type === "updateStatus") { sendResponse({ updating: await isUpdating() }); return; }
    if (msg.type === "checkHost") { sendResponse({ blocked: await isBlockedHost(msg.host) }); return; }
    if (msg.type === "threatDetected" && sender.tab) {
      if (await isAllowed(getDomain(sender.tab.url || ""))) { sendResponse({ ok: false, allowed: true }); return; }
      const statKey = { miner: "blockedMiners", redirect: "blockedRedirects", phishing: "blockedPhishing", scam: "blockedPhishing", iframe: "blockedSites" }[msg.kind] || "blockedSites";
      await bumpStat(statKey);
      if (["phishing", "scam", "redirect"].includes(msg.kind)) await redirectToWarning(sender.tab.id, msg.url || sender.tab.url, msg.kind);
      chrome.notifications.create({ type: "basic", iconUrl: "icons/icon48.png",
        title: "Kirpi: Tehdit engellendi", message: msg.message || "Zararlı bir davranış durduruldu." });
      sendResponse({ ok: true }); return;
    }
    sendResponse({ ok: false });
  })();
  return true;
});

// ---------- Kurulum / zamanlanmış ----------
// Madenci domainlerine giden script/çerçeve/bağlantı isteklerini Chrome'un yerleşik motoruyla engelle
async function installMinerRules() {
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: [1],
      addRules: [{
        id: 1, priority: 1, action: { type: "block" },
        condition: { requestDomains: MINER_DOMAINS, resourceTypes: ["script", "sub_frame", "xmlhttprequest", "websocket"] }
      }]
    });
  } catch (e) { console.warn("[Kirpi] Madenci kuralı eklenemedi:", e); }
}

const FRESH_MS = 6 * 60 * 60 * 1000; // liste 6 saatten yeniyse tekrar indirme

async function updateIfStale() {
  if (await isUpdating()) { runSteps(); return; }          // yarıda kalan varsa devam et
  const { kalkanLastComplete, kalkanUpdateState } = await chrome.storage.local.get(["kalkanLastComplete", "kalkanUpdateState"]);
  // Önceki sürümler bitiş zamanını güncelleme durumunda tutuyordu
  const last = kalkanLastComplete || (kalkanUpdateState && kalkanUpdateState.finishedAt) || 0;
  if (!last || Date.now() - last > FRESH_MS) updateThreatLists();
}

chrome.runtime.onInstalled.addListener(async (details) => {
  const existing = await chrome.storage.local.get(Object.keys(DEFAULTS));
  const toSet = {};
  for (const k of Object.keys(DEFAULTS)) if (existing[k] === undefined) toSet[k] = DEFAULTS[k];
  if (Object.keys(toSet).length) await chrome.storage.local.set(toSet);
  // Eski sürümden kalan 3 milyonluk listeyi depodan sil (artık kullanılmıyor)
  await chrome.storage.local.remove("kalkanBlocklist");
  await installMinerRules();
  chrome.alarms.create("kalkanListUpdate", { periodInMinutes: 360 });
  chrome.alarms.create("kalkanResume", { periodInMinutes: 1 });
  // İlk kurulumda hemen güncelle; eklenti yenilendiğinde sadece liste eskiyse güncelle
  if (details && details.reason === "install") updateThreatLists();
  else updateIfStale();
});

chrome.runtime.onStartup.addListener(async () => {
  chrome.alarms.create("kalkanResume", { periodInMinutes: 1 });
  installMinerRules();
  updateIfStale();
});

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === "kalkanListUpdate") updateThreatLists();
  if (a.name === "kalkanResume") runSteps(); // yarıda kalan güncelleme varsa devam ettir
});
