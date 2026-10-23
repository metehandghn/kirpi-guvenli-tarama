"use strict";
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { runContent, sleep } = require("./helpers");

async function kinds(html, url) {
  const page = runContent(html, url);
  await sleep(700);
  return page.reports.map((r) => r.kind);
}
const loginForm = (inner = "") => `<form><label>T.C. Kimlik No</label><input name="tckn" maxlength="11">
  <input type="password" name="sifre">${inner}<button>Giriş</button></form>`;
const cardForm = `<form><input name="kartno" placeholder="Kart Numarası"><input name="skt" placeholder="Son Kullanma">
  <input name="cvv" placeholder="CVV"><button>Öde</button></form>`;

test("büyük harfle yazılmış Türkçe marka da yakalanır (İ harfi sorunu)", async () => {
  const html = `<html><head><title>İŞ BANKASI İNTERNET ŞUBESİ</title></head><body><h1>İŞCEP GİRİŞ</h1>${loginForm()}</body></html>`;
  assert.deepEqual(await kinds(html, "https://isbank-guvenli-giris.com/"), ["phishing"]);
});

test("yeni eklenen markaların sahteleri yakalanır", async () => {
  for (const [title, url] of [
    ["Kuveyt Türk Bireysel İnternet Şubesi", "https://kuveyt-turk-bireysel.net/"],
    ["Papara | Hesabına Giriş Yap", "https://papara-destek.org/"],
    ["Gelir İdaresi Başkanlığı - İnteraktif Vergi Dairesi", "https://ivd-gib-iade.com/"],
    ["Netflix", "https://netflix-hesap-dogrula.com/"]
  ]) {
    const html = `<html><head><title>${title}</title></head><body>${loginForm()}</body></html>`;
    assert.deepEqual(await kinds(html, url), ["phishing"], title);
  }
});

test("altbilgide ya da sosyal giriş düğmesinde geçen marka yanlış alarm vermez", async () => {
  const html = `<html><head><title>Kitapçım - Üye Girişi</title></head><body>
    <h1>Kitapçım</h1>${loginForm('<button type="button">Apple ile giriş yap</button><button type="button">Google ile devam et</button>')}
    <footer>Bizi Instagram'da takip edin · Ürünlerimiz Trendyol ve Hepsiburada mağazalarımızda · Netflix dizileri</footer>
  </body></html>`;
  assert.deepEqual(await kinds(html, "https://www.kitapcim.com.tr/giris"), []);
});

test("yeni markaların gerçek siteleri uyarı vermez", async () => {
  for (const url of ["https://www.kuveytturk.com.tr/", "https://www.papara.com/login", "https://www.hepsiburada.com/uyelik/giris", "https://www.netflix.com/tr/login"]) {
    const html = `<html><head><title>Giriş · Kuveyt Türk · Papara · Hepsiburada · Netflix</title></head><body>${loginForm()}</body></html>`;
    assert.deepEqual(await kinds(html, url), [], url);
  }
});

test("marka olmadan da dolandırıcılık kalıbı + kart alanı yakalanır", async () => {
  const cases = [
    "Kargonuz teslim edilemedi. Adres güncelleme ücreti 4,90 TL'yi ödeyerek yeniden gönderim talep edin.",
    "VERGİ İADENİZ hazırdır! İade tutarınızın hesabınıza yatması için kart bilgilerinizi girin.",
    "HGS ihlal kaydınız bulunmaktadır. Cezanın katlanmaması için hemen ödeyin.",
    "Tebrikler! Çekilişi kazandınız. Hediyenizin kargo ücretini ödeyin."
  ];
  for (const text of cases) {
    const html = `<html><head><title>Bilgilendirme</title></head><body><p>${text}</p>${cardForm}</body></html>`;
    assert.deepEqual(await kinds(html, "https://bilgi-guncelle-tr.com/"), ["scam"], text.slice(0, 30));
  }
});

test("normal ödeme sayfası ve resmi kurum sayfası dolandırıcılık sayılmaz", async () => {
  const checkout = `<html><head><title>Sepetim - Ödeme</title></head><body><h1>Ödeme</h1><p>Siparişiniz 3 iş günü içinde kargoya verilir.</p>${cardForm}</body></html>`;
  assert.deepEqual(await kinds(checkout, "https://www.ornek-magaza.com/odeme"), []);
  const gib = `<html><head><title>Vergi iadesi başvurusu</title></head><body><p>Vergi iadesi başvurunuzu buradan yapabilirsiniz.</p>${loginForm()}</body></html>`;
  assert.deepEqual(await kinds(gib, "https://ivd.gib.gov.tr/"), []);
});
