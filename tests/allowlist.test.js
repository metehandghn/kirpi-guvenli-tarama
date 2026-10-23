"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { startBackground, sleep, newIDB } = require("./helpers");

const BAD = "http://kirpi-test.example/giris";          // her zaman engelli test adresi

async function ready() {
  const storage = { kalkanLastComplete: Date.now() };
  const bg = startBackground({ storage, idb: newIDB(), fetchImpl: () => ({ ok: true, status: 200, text: async () => "" }) });
  await bg.listeners.installed[0]({ reason: "update" });
  const nav = async (url) => { bg.env.redirects.length = 0; await bg.listeners.beforeNavigate[0]({ frameId: 0, tabId: 1, url }); return bg.env.redirects.slice(); };
  return { bg, storage, nav };
}

test("engellenen siteye 'yine de devam et' denince site açılır (döngü yok)", async () => {
  const { bg, nav } = await ready();
  assert.equal((await nav(BAD)).length, 1, "ilk girişte uyarı gösterilmeli");
  await bg.send({ type: "allowHost", url: BAD, permanent: false });   // uyarı ekranındaki düğme
  assert.deepEqual(await nav(BAD), [], "izin verilen site tekrar engellenmemeli");
});

test("geçici izin kalıcı listeye yazılmaz", async () => {
  const { bg, storage } = await ready();
  await bg.send({ type: "allowHost", url: BAD, permanent: false });
  assert.deepEqual([...(await bg.send({ type: "listAllowed" })).hosts], []);
  assert.equal("kirpiAllowlist" in storage, false);
});

test("beyaz listeye eklenen site kalıcı olarak engellenmez, kaldırılınca tekrar engellenir", async () => {
  const { bg, nav } = await ready();
  await bg.send({ type: "allowHost", url: BAD, permanent: true });
  assert.deepEqual([...(await bg.send({ type: "listAllowed" })).hosts], ["kirpi-test.example"]);
  assert.deepEqual(await nav(BAD), []);
  assert.deepEqual(await nav("http://alt.kirpi-test.example/"), [], "alt alan adları da güvenilir sayılmalı");
  await bg.send({ type: "removeAllowed", host: "kirpi-test.example" });
  assert.equal((await nav(BAD)).length, 1, "listeden çıkarılınca tekrar engellenmeli");
});

test("beyaz listedeki sitede sayfa içi denetimler kapanır", async () => {
  const { bg } = await ready();
  await bg.send({ type: "allowHost", url: "https://benim-sitem.com/", permanent: true });
  const s = await bg.send({ type: "getSettings", host: "benim-sitem.com" });
  assert.equal(s.allowed, true);
  const other = await bg.send({ type: "getSettings", host: "baska-site.com" });
  assert.equal(other.allowed, false);
});
