"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { startBackground, waitUntil, sleep, ok, newIDB } = require("./helpers");

const lines = (prefix, n) => Array.from({ length: n }, (_, i) => `${prefix}${i}.com`).join("\n");

// Sahte kaynaklar: USOM 30 sayfa x 1000, Malware ve PhishDB 50.000'er, küçük listeler 100'er
function feeds({ killOnUsomCall = 0, malwareAlwaysKills = false } = {}) {
  let usomCalls = 0;
  return (url, env) => {
    if (url.includes("siberguvenlik.gov.tr")) {
      usomCalls++;
      if (killOnUsomCall && usomCalls === killOnUsomCall) { env.kill(); throw new Error("servis kapatıldı"); }
      const page = Number(new URL(url).searchParams.get("page"));
      const models = page <= 30 ? Array.from({ length: 1000 }, (_, i) => ({ url: `usom-p${page}-${i}.tr` })) : [];
      return ok("", { pageCount: 30, models });
    }
    if (url.includes("malware.txt")) {
      if (malwareAlwaysKills) { env.kill(); throw new Error("servis kapatıldı"); }
      return ok(lines("mal", 50000));
    }
    if (url.includes("phishing-domains-ACTIVE")) return ok(lines("pdb", 50000));
    if (url.includes("fraud.txt")) return ok("0.0.0.0 fraud1.com\n0.0.0.0 fraud2.com\n# yorum satırı");
    const name = url.split("/").pop().replace(".txt", "");
    return ok(lines(name + "-", 100));
  };
}

const isDone = (storage) => async () => storage.kalkanUpdateState && !storage.kalkanUpdateState.running;

test("güncelleme ortasında servis kapanırsa alarmla kaldığı yerden devam eder", async () => {
  const storage = {}; const idb = newIDB();
  const bg1 = startBackground({ storage, idb, fetchImpl: feeds({ killOnUsomCall: 12 }) });
  await bg1.listeners.installed[0]({ reason: "install" });
  assert.ok(await waitUntil(async () => bg1.env.dead), "servis kapatılmalıydı");
  await sleep(100);
  assert.equal(storage.kalkanUpdateState.running, true, "durum 'sürüyor' olarak kayıtlı kalmalı");

  const bg2 = startBackground({ storage, idb, fetchImpl: feeds() });
  bg2.listeners.alarm[0]({ name: "kalkanResume" });
  assert.ok(await waitUntil(isDone(storage), 30000), "güncelleme tamamlanmalı");

  const st = storage.kalkanUpdateState;
  assert.deepEqual(st.status.filter((s) => !s.ok), [], "tüm kaynaklar başarılı olmalı");
  assert.deepEqual(st.status.map((s) => s.id), ["URLhaus", "Ransomware", "Scam", "Fraud", "BLP-Phish", "USOM", "Malware", "PhishDB"]);
  // 4 x 100 + 2 (fraud) + 30.000 (USOM) + 50.000 + 50.000
  assert.equal(storage.kalkanCount, 130402);

  const blocked = async (host) => (await bg2.send({ type: "checkHost", host })).blocked;
  assert.equal(await blocked("usom-p25-7.tr"), true);
  assert.equal(await blocked("fraud1.com"), true);
  assert.equal(await blocked("alt.mal123.com"), true, "üst domain listedeyse alt alan adı da engellenmeli");
  assert.equal(await blocked("kirpi-test.example"), true, "test domaini her zaman engelli");
  assert.equal(await blocked("google.com"), false);
});

test("sürekli hata veren bir kaynak 3 denemeden sonra atlanır", async () => {
  const storage = {}; const idb = newIDB();
  const fetchImpl = feeds({ malwareAlwaysKills: true });
  let bg = startBackground({ storage, idb, fetchImpl });
  await bg.listeners.installed[0]({ reason: "install" });
  for (let i = 0; i < 6 && !(await isDone(storage)()); i++) {
    await waitUntil(async () => bg.env.dead || (await isDone(storage)()), 30000);
    if (await isDone(storage)()) break;
    bg = startBackground({ storage, idb, fetchImpl }); // dakikalık alarm yeni servisi uyandırır
    bg.listeners.alarm[0]({ name: "kalkanResume" });
  }
  assert.ok(await waitUntil(isDone(storage), 30000), "güncelleme sonsuz döngüye girmeden bitmeli");
  const st = storage.kalkanUpdateState.status;
  assert.equal(st.find((s) => s.id === "Malware").ok, false);
  assert.equal(st.find((s) => s.id === "PhishDB").ok, true, "sonraki kaynağa geçilmeli");
});

test("güncelleme sırasında liste boşalmaz", async () => {
  const storage = {}; const idb = newIDB();
  const bg = startBackground({ storage, idb, fetchImpl: feeds() });
  await bg.listeners.installed[0]({ reason: "install" });
  assert.ok(await waitUntil(isDone(storage), 30000));
  await bg.send({ type: "forceUpdate" });
  await sleep(30);
  assert.equal(storage.kalkanUpdateState.running, true, "ikinci güncelleme başlamış olmalı");
  assert.equal((await bg.send({ type: "checkHost", host: "usom-p25-7.tr" })).blocked, true);
  assert.ok(await waitUntil(isDone(storage), 30000));
});

test("eklenti yenilendiğinde liste tazeyse indirme yapılmaz, eskiyse yapılır", async () => {
  for (const [label, storage, expectFetch] of [
    ["10 dk önce güncellenmiş", { kalkanLastComplete: Date.now() - 10 * 60e3 }, false],
    ["eski sürümün bitiş kaydı", { kalkanUpdateState: { running: false, finishedAt: Date.now() - 10 * 60e3 } }, false],
    ["7 saat önce güncellenmiş", { kalkanLastComplete: Date.now() - 7 * 3600e3 }, true]
  ]) {
    storage.kalkanBlocklist = ["eski-3m-liste.com"];
    let fetches = 0;
    const bg = startBackground({ storage, idb: newIDB(), fetchImpl: (u, env) => { fetches++; return feeds()(u, env); } });
    await bg.listeners.installed[0]({ reason: "update" });
    await sleep(200);
    assert.equal(fetches > 0, expectFetch, label);
    assert.equal("kalkanBlocklist" in storage, false, "eski 3 milyonluk liste silinmeli");
    if (expectFetch) await waitUntil(isDone(storage), 30000);
  }
});

test("madenci domainleri engellenir ve ağ kuralı doğru kurulur", async () => {
  const storage = { kalkanLastComplete: Date.now() };
  const bg = startBackground({ storage, idb: newIDB(), fetchImpl: feeds() });
  await bg.listeners.installed[0]({ reason: "update" });
  // Domainler dosyada ters çevrilmiş saklanıyor; çalışırken doğru çözülmeli
  const host = ["coin", "hive", ".com"].join("");
  assert.equal((await bg.send({ type: "checkHost", host })).blocked, true);
  assert.equal((await bg.send({ type: "checkHost", host: "cdn." + host })).blocked, true);
  const rule = bg.env.dnrRules && bg.env.dnrRules[0];
  assert.ok(rule, "madenci ağ kuralı eklenmeli");
  assert.equal(rule.action.type, "block");
  assert.ok(rule.condition.requestDomains.includes(host));
  assert.equal(rule.condition.requestDomains.length, 15);
});

test("bilinçli indirilen kurulum dosyası iptal edilmez, kullanıcıya sorulur", async () => {
  const storage = { kalkanLastComplete: Date.now() };
  const bg = startBackground({ storage, idb: newIDB(), fetchImpl: feeds() });
  await bg.listeners.installed[0]({ reason: "update" });

  // Node.js resmi sitesinden .msi (gerçek senaryo)
  await bg.listeners.download[0]({ id: 7, url: "https://nodejs.org/dist/v24.22.0/node-v24.22.0-x64.msi",
    referrer: "https://nodejs.org/en/download", filename: "" });
  assert.deepEqual(bg.env.dl, [["pause", 7]], "iptal değil, duraklatma olmalı");
  const ask = bg.env.notifs.find((n) => n.id === "kirpi-dl-7");
  assert.ok(ask && ask.buttons.length === 2, "kullanıcıya iki düğmeli soru gösterilmeli");
  assert.match(ask.message, /node-v24\.22\.0-x64\.msi/);

  // "İndirmeye devam et"
  await bg.listeners.notifButton[0]("kirpi-dl-7", 0);
  assert.deepEqual(bg.env.dl.at(-1), ["resume", 7]);

  // Başka bir dosyada "İptal et"
  await bg.listeners.download[0]({ id: 8, url: "https://ornek.com/kurulum.exe", filename: "" });
  await bg.listeners.notifButton[0]("kirpi-dl-8", 1);
  assert.deepEqual(bg.env.dl.slice(-2), [["cancel", 8], ["erase", 8]]);

  // Normal dosyalara (pdf, zip) hiç dokunulmaz
  const before = bg.env.dl.length;
  await bg.listeners.download[0]({ id: 9, url: "https://ornek.com/rapor.pdf", filename: "" });
  assert.equal(bg.env.dl.length, before);
});

test("zararlı listesindeki siteden gelen indirme doğrudan iptal edilir", async () => {
  const storage = { kalkanLastComplete: Date.now() };
  const bg = startBackground({ storage, idb: newIDB(), fetchImpl: feeds() });
  await bg.listeners.installed[0]({ reason: "update" });
  await bg.listeners.download[0]({ id: 3, url: "http://kirpi-test.example/fatura.pdf", filename: "" });
  assert.deepEqual(bg.env.dl, [["cancel", 3], ["erase", 3]]);
});

test("indirme geçmişindeki eski kayıtlara dokunulmaz", async () => {
  const storage = { kalkanLastComplete: Date.now() };
  const bg = startBackground({ storage, idb: newIDB(), fetchImpl: feeds() });
  await bg.listeners.installed[0]({ reason: "update" });
  const old = new Date(Date.now() - 3 * 24 * 3600e3).toISOString();
  // Tamamlanmış eski kurulum dosyaları (Chrome geçmişi yüklerken olay tetikleyebiliyor)
  await bg.listeners.download[0]({ id: 1, url: "https://store.steampowered.com/SteamSetup.exe", filename: "C:\\Users\\x\\Downloads\\steamsetup.exe", state: "complete", startTime: old });
  // Zararlı siteden gelmiş olsa bile eski kayıt geçmişten silinmez
  await bg.listeners.download[0]({ id: 2, url: "http://kirpi-test.example/a.exe", state: "complete", startTime: old });
  // Yarıda kalmış eski indirme
  await bg.listeners.download[0]({ id: 3, url: "https://ornek.com/kurulum.exe", state: "interrupted", startTime: old });
  assert.deepEqual(bg.env.dl, [], "eski kayıtlara hiçbir işlem yapılmamalı");
  assert.equal(bg.env.notifs.length, 0, "bildirim gösterilmemeli");

  // Şu an başlayan indirme yine denetlenir
  await bg.listeners.download[0]({ id: 4, url: "https://ornek.com/yeni.exe", state: "in_progress", startTime: new Date().toISOString() });
  assert.deepEqual(bg.env.dl, [["pause", 4]]);
});

// ---------- Tekrarlanan güncellemeler ----------

test("ikinci güncellemede listeden çıkarılan domainler silinir, sayı şişmez", async () => {
  const storage = {}; const idb = newIDB();
  let round = 1;
  const fetchImpl = (url, env) => {
    if (url.includes("scam.txt")) return ok(round === 1 ? "eski-dolandirici.com\nkalici-dolandirici.com" : "kalici-dolandirici.com\nyeni-dolandirici.com");
    return feeds()(url, env);
  };
  const bg = startBackground({ storage, idb, fetchImpl });
  await bg.listeners.installed[0]({ reason: "install" });
  assert.ok(await waitUntil(isDone(storage), 30000));
  const firstCount = storage.kalkanCount;
  const blocked = async (host) => (await bg.send({ type: "checkHost", host })).blocked;
  assert.equal(await blocked("eski-dolandirici.com"), true);

  round = 2;
  await bg.send({ type: "forceUpdate" });
  assert.ok(await waitUntil(isDone(storage), 30000));
  assert.equal(await blocked("eski-dolandirici.com"), false, "kaynaktan kaldırılan site artık engellenmemeli");
  assert.equal(await blocked("kalici-dolandirici.com"), true);
  assert.equal(await blocked("yeni-dolandirici.com"), true);
  assert.equal(storage.kalkanCount, firstCount, "aynı büyüklükte liste aynı sayıyı vermeli");
});

test("tekrar güncellemede büyük kaynaklar tavan yüzünden boş kalmaz", async () => {
  const storage = {}; const idb = newIDB();
  const big = lines("mal", 1600000);   // tavanı (1,5 milyon) aşan büyük liste
  const fetchImpl = (url, env) => url.includes("malware.txt") ? ok(big) : feeds()(url, env);
  const bg = startBackground({ storage, idb, fetchImpl });
  await bg.listeners.installed[0]({ reason: "install" });
  assert.ok(await waitUntil(isDone(storage), 120000));
  const r1 = storage.kalkanUpdateState.status.find((s) => s.id === "Malware");
  const c1 = storage.kalkanCount;

  await bg.send({ type: "forceUpdate" });
  assert.ok(await waitUntil(isDone(storage), 120000));
  const r2 = storage.kalkanUpdateState.status.find((s) => s.id === "Malware");
  assert.equal(r2.ok, true, "ikinci turda Malware 'tavan dolu' olmamalı");
  assert.equal(r2.added, r1.added, "her turda aynı miktar alınmalı");
  assert.equal(storage.kalkanCount, c1);
  assert.ok(storage.kalkanCount <= 1500000, "tavan aşılmamalı");
});

test("güncelleme tamamen başarısız olursa eski liste korunur", async () => {
  const storage = {}; const idb = newIDB();
  let offline = false;
  const fetchImpl = (url, env) => { if (offline) throw new TypeError("Failed to fetch"); return feeds()(url, env); };
  const bg = startBackground({ storage, idb, fetchImpl });
  await bg.listeners.installed[0]({ reason: "install" });
  assert.ok(await waitUntil(isDone(storage), 30000));
  const c1 = storage.kalkanCount;

  offline = true;
  await bg.send({ type: "forceUpdate" });
  assert.ok(await waitUntil(isDone(storage), 60000));
  assert.equal(storage.kalkanCount, c1, "internet yokken liste silinmemeli");
  assert.equal((await bg.send({ type: "checkHost", host: "usom-p25-7.tr" })).blocked, true);
});

test("eski sürümden yükseltmede mevcut liste kaybolmaz", async () => {
  const idb = newIDB();
  // Sürüm 2 veritabanı: tek "buckets" deposu, içinde bir domain
  await new Promise((res, rej) => {
    const req = idb.open("kalkanDB", 2);
    req.onupgradeneeded = (e) => e.target.result.createObjectStore("buckets");
    req.onsuccess = () => {
      const db = req.result; const host = "eski-liste-sitesi.com";
      let h = 0; for (let i = 0; i < host.length; i++) h = (h * 31 + host.charCodeAt(i)) >>> 0;
      const tx = db.transaction("buckets", "readwrite"); tx.objectStore("buckets").put({ [host]: 1 }, h % 1024);
      tx.oncomplete = () => { db.close(); res(); }; tx.onerror = rej;
    };
    req.onerror = rej;
  });
  // Eski sürümün yarıda kalmış güncelleme durumu (hedef depo bilgisi yok)
  const storage = { kalkanCount: 1, kalkanLastComplete: Date.now(),
    kalkanUpdateState: { running: true, step: "usom", feedIdx: 0, usomPage: 5, status: [], baseCount: 1, newAdds: 0 } };
  const bg = startBackground({ storage, idb, fetchImpl: feeds() });
  assert.equal((await bg.send({ type: "checkHost", host: "eski-liste-sitesi.com" })).blocked, true, "yükseltmeden sonra eski liste çalışmalı");
  bg.listeners.alarm[0]({ name: "kalkanResume" });
  assert.ok(await waitUntil(isDone(storage), 30000), "yarım kalan eski tur yeni yöntemle baştan tamamlanmalı");
  assert.equal(storage.kalkanCount, 130402);
  assert.equal((await bg.send({ type: "checkHost", host: "usom-p25-7.tr" })).blocked, true);
});

test("tarayıcı yeniden açılınca 6 saatlik otomatik güncelleme alarmı geri kurulur", async () => {
  // Chrome, tarayıcı kapanıp açılınca alarmları silebiliyor; açılışta yeniden kurulmalı
  const storage = { kalkanLastComplete: Date.now() };
  const bg = startBackground({ storage, idb: newIDB(), fetchImpl: feeds() });
  bg.env.alarms = {};
  await bg.listeners.startup[0]();
  await sleep(50);
  assert.equal(bg.env.alarms.kalkanListUpdate && bg.env.alarms.kalkanListUpdate.periodInMinutes, 360, "otomatik güncelleme alarmı olmalı");
  assert.equal(bg.env.alarms.kalkanResume && bg.env.alarms.kalkanResume.periodInMinutes, 1);
});

test("otomatik güncelleme alarmı çalınca liste yenilenir", async () => {
  const storage = {}; const idb = newIDB();
  const bg = startBackground({ storage, idb, fetchImpl: feeds() });
  await bg.listeners.installed[0]({ reason: "install" });
  assert.ok(await waitUntil(isDone(storage), 30000));
  const first = storage.kalkanLastComplete;
  await sleep(20);
  bg.listeners.alarm[0]({ name: "kalkanListUpdate" });
  assert.ok(await waitUntil(async () => storage.kalkanLastComplete > first && !storage.kalkanUpdateState.running, 30000), "alarmla yeni tur tamamlanmalı");
  assert.equal(storage.kalkanCount, 130402);
});
