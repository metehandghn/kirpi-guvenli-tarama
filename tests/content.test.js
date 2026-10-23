"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { runContent, waitUntil, sleep } = require("./helpers");

const LOGIN_PAGE = (brandText) => `<html><head><title>Giriş</title></head><body>
  <script>var analytics = ${JSON.stringify("x".repeat(50000))};</script>
  <p>${brandText}</p><input name="tckn" maxlength="11"><input type="password"></body></html>`;

const kinds = (reports) => reports.map((r) => r.kind);
// Madenci imzaları parçalardan oluşturulur: antivirüsler düz metni görünce test dosyasını madenci sanabiliyor
const SIG = ["Coin", "Hive", ".Anonymous"].join("");
const MINER_HOST = ["coin", "hive", ".com"].join("");

test("sahte e-Devlet ve banka sayfaları yakalanır", async () => {
  for (const url of ["https://edevlet-giris-sorgula.com/", "https://garanti-giris-dogrula.com/"]) {
    const page = runContent(LOGIN_PAGE("e-Devlet Kapısı · Garanti BBVA internet şubesi"), url);
    assert.ok(await waitUntil(async () => page.reports.length > 0, 3000), url + " yakalanmalı");
    assert.equal(page.reports[0].kind, "phishing");
  }
});

test("gerçek siteler oltalama sayılmaz", async () => {
  const legit = [
    "https://giris.turkiye.gov.tr/Giris/",   // resmi e-Devlet
    "https://ais.osym.gov.tr/",              // gov.tr
    "https://www.garantibbva.com.tr/",       // gerçek banka, sayfada "e-Devlet ile giriş" yazıyor
    "https://www.sahibinden.com/giris"       // "e-Devlet onaylı" ifadesi kullanan büyük site
  ];
  for (const url of legit) {
    const page = runContent(LOGIN_PAGE("e-Devlet ile giriş · Garanti BBVA"), url);
    await sleep(800);
    assert.deepEqual(kinds(page.reports), [], url + " uyarı vermemeli");
  }
});

test("yalnızca zararlı adrese ait gizli çerçeve kaldırılır", async () => {
  const page = runContent(`<html><body>
    <iframe src="https://accounts.youtube.com/CheckConnection" style="display:none"></iframe>
    <iframe src="https://www.google.com/recaptcha/api2/anchor" style="display:none"></iframe>
    <iframe src="http://kirpi-test.example/" style="display:none"></iframe></body></html>`,
    "https://www.youtube.com/watch?v=x", ["kirpi-test.example"]);
  assert.ok(await waitUntil(async () => page.reports.length > 0, 3000));
  const left = [...page.document.querySelectorAll("iframe")].map((f) => new URL(f.src).hostname);
  assert.deepEqual(left, ["accounts.youtube.com", "www.google.com"]);
  assert.deepEqual(kinds(page.reports), ["iframe"]);
});

test("madencilik scripti kaldırılır, sonradan eklenen de yakalanır", async () => {
  const page = runContent(`<html><body><script>var a = "${SIG}";</script></body></html>`, "https://ornek-site.com/");
  assert.ok(await waitUntil(async () => page.reports.length === 1, 3000), "sayfadaki script yakalanmalı");
  const s = page.document.createElement("script");
  s.src = `https://cdn.${MINER_HOST}/lib/miner.min.js`;
  page.document.body.appendChild(s);
  assert.ok(await waitUntil(async () => page.reports.length === 2, 3000), "sonradan eklenen script yakalanmalı");
  assert.deepEqual(kinds(page.reports), ["miner", "miner"]);
});

test("meta refresh yalnızca zararlı hedefe giderse durdurulur", async () => {
  const bad = runContent(`<html><head><meta http-equiv="refresh" content="0; url=http://kirpi-test.example/"></head><body></body></html>`,
    "https://ornek-site.com/", ["kirpi-test.example"]);
  assert.ok(await waitUntil(async () => bad.reports.length > 0, 3000));
  assert.equal(bad.reports[0].kind, "redirect");

  const good = runContent(`<html><head><meta http-equiv="refresh" content="0; url=https://example.com/"></head><body></body></html>`,
    "https://ornek-site.com/", ["kirpi-test.example"]);
  await sleep(500);
  assert.deepEqual(kinds(good.reports), [], "zararsız hedefe yönlendirmeye dokunulmamalı");
});

test("yazarken eklenen öneriler sayfayı baştan taratmaz", async () => {
  const big = `<script>var x = ${JSON.stringify("a".repeat(400000))};</script>`;
  const page = runContent(`<html><body>${big.repeat(40)}</body></html>`, "https://www.google.com/");
  await sleep(500);
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < 30; i++) {
    for (let k = 0; k < 3; k++) {
      const s = page.document.createElement("script");
      s.textContent = `suggest(${i}, ${k})`;
      page.document.body.appendChild(s);
    }
    await sleep(5);
  }
  await sleep(400);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  // 30 x 5 ms bekleme + 400 ms = ~550 ms taban; eski sürüm bunun üzerine ~600 ms iş yapıyordu
  assert.ok(ms < 800, `yazma simülasyonu ${ms.toFixed(0)} ms sürdü`);
});
