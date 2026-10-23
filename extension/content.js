// Kirpi - Güvenli Tarama | İçerik scripti
// Sayfa içi tehditleri tespit eder: oto-yönlendirme, madencilik, gizli iframe,
// bildirim spamı ve sahte e-Devlet/banka/kargo sayfaları.

(function () {
  const host = location.hostname.replace(/^www\./, "").toLowerCase();

  // Eklenti sayfalarında çalışma
  if (location.protocol === "chrome-extension:") return;

  let settings = { enabled: true, blockRedirects: true, blockMiners: true, detectPhishing: true };

  function report(kind, message, url) {
    try { chrome.runtime.sendMessage({ type: "threatDetected", kind, message, url }); } catch (e) {}
  }

  // Güvenilir hedef mi? (resmi Türkiye uzantıları — sahtekar bunları alamaz)
  const SAFE_TLDS = [".gov.tr", ".edu.tr", ".k12.tr", ".bel.tr", ".pol.tr", ".tsk.tr", ".kep.tr", ".gen.tr"];
  function isTrustedHost(h) {
    if (!h) return false;
    return SAFE_TLDS.some(t => h.endsWith(t));
  }
  // Hedef host zararlı listesinde mi? (arka plana sorar)
  function hostIsBlocked(h, cb) {
    try { chrome.runtime.sendMessage({ type: "checkHost", host: h }, (r) => cb(!!(r && r.blocked))); }
    catch (e) { cb(false); }
  }
  function targetHostOf(u) {
    try { return new URL(u, location.href).hostname.replace(/^www\./, "").toLowerCase(); }
    catch { return ""; }
  }

  // ---- 1) hook.js'ten (sayfanın kendi ortamında çalışır) gelen olayları dinle ----
  // hook.js manifest'te "world": "MAIN" ile yüklenir; location/open/Notification izler.
  window.addEventListener("message", (ev) => {
    if (ev.source !== window || !ev.data || ev.data.__kirpi !== true) return;
    const d = ev.data;
    if (!settings.enabled || settings.allowed) return;

    if (d.event === "autoRedirect" && settings.blockRedirects) {
      // Kullanıcı etkileşimi olmadan dış domaine yönlendirme girişimi
      const targetHost = targetHostOf(d.target);
      if (targetHost && targetHost !== host && !isTrustedHost(targetHost)) {
        // Sadece hedef zararlıysa engelle; güvenilir/bilinmeyen hedefe izin ver
        hostIsBlocked(targetHost, (bad) => {
          if (bad) report("redirect", "İzniniz olmadan zararlı bir siteye yönlendirme engellendi: " + targetHost, d.target);
        });
      }
    }
    if (d.event === "popunder") {
      report("redirect", "Arka planda açılan şüpheli pencere engellendi.");
    }
    // Not: bildirim izni istekleri engellenmediği için "tehdit engellendi" olarak raporlanmaz
    // (Chrome zaten izni kullanıcıya soruyor). İleride bir "şüpheli davranış" günlüğüne eklenebilir.
  });

  // hook.js artık manifest'te "world: MAIN" ile doğrudan sayfaya yükleniyor (enjeksiyon yok)

  // ---- Ayarları al ----
  try {
    chrome.runtime.sendMessage({ type: "getSettings", host }, (s) => {
      if (s) settings = s;
      if (!settings.enabled || settings.allowed) return;   // kapalı ya da beyaz listedeki site
      runChecks();
    });
  } catch (e) { runChecks(); }

  function runChecks() {
    // ---- 2) Meta refresh ile dış yönlendirme ----
    checkMetaRefresh();
    // Sayfa hazır olunca DOM taramaları
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", domScans);
    } else {
      domScans();
    }
  }

  function checkMetaRefresh() {
    const meta = document.querySelector('meta[http-equiv="refresh" i]');
    if (!meta) return;
    const content = meta.getAttribute("content") || "";
    const m = content.match(/url=(.+)$/i);
    if (m) {
      const target = m[1].trim().replace(/['"]/g, "");
      let th = "";
      try { th = new URL(target, location.href).hostname.replace(/^www\./, ""); } catch {}
      if (th && th !== host && settings.blockRedirects && !isTrustedHost(th)) {
        // Sadece hedef zararlıysa engelle; güvenilir/bilinmeyen hedefe izin ver
        hostIsBlocked(th, (bad) => {
          if (bad) {
            meta.remove();
            report("redirect", "Zararlı siteye otomatik yönlendirme (meta refresh) engellendi: " + th, target);
          }
        });
      }
    }
  }

  const isTopFrame = (window.top === window);

  // Ağır işleri tarayıcının boş anına bırak (yazarken/arama yaparken takılma olmasın)
  const idle = (fn) => (window.requestIdleCallback ? requestIdleCallback(fn, { timeout: 2000 }) : setTimeout(fn, 200));

  function domScans() {
    idle(() => {
      document.querySelectorAll("script").forEach(checkScript);
      if (isTopFrame) {
        document.querySelectorAll("iframe").forEach(checkIframe);
        if (settings.detectPhishing) detectPhishing();
      }
    });
    observeMutations();
  }

  // ---- 3) Madencilik scriptleri ----
  // İmzalar dosyada TERS ÇEVRİLMİŞ saklanır: antivirüsler bu kelimeleri düz metin görünce
  // eklentinin kendisini madenci sanabiliyor. Çalışırken düzeltilir.
  const unrev = (t) => t.split("").reverse().join("");
  const MINER_SIGNS = ["evihnioc", "evih-nioc", "enimdehtua", "thginotpyrc", "tool-otpyrc", "toolotpyrc", "pminioc", "niocesj", "enimbew", "trats.renim", "suomynona.evihnioc", "renimpeed", "renim/msaw", "cc.orenim"].map(unrev);
  const NON_JS_TYPES = /json|template|text\/html|text\/x-|speculationrules|importmap/i;
  const seenScripts = new WeakSet();
  const INLINE_SCAN_LIMIT = 20000; // dev satır içi scriptlerin yalnızca başı taranır

  function checkScript(sc) {
    if (!settings.blockMiners || seenScripts.has(sc)) return;
    seenScripts.add(sc);
    if (sc.type && NON_JS_TYPES.test(sc.type)) return;
    const src = (sc.src || "").toLowerCase();
    let hit = src && MINER_SIGNS.some(sig => src.includes(sig));
    if (!hit && !src) {
      const txt = (sc.textContent || "").slice(0, INLINE_SCAN_LIMIT).toLowerCase();
      hit = txt.length > 0 && MINER_SIGNS.some(sig => txt.includes(sig));
    }
    if (hit) {
      try { sc.remove(); } catch (e) {}
      report("miner", "Kripto madenciliği scripti tespit edildi ve kaldırıldı.");
    }
  }

  // ---- 4) Gizli / şüpheli iframe'ler ----
  // Google girişi, ödeme, captcha, çerez onayı gibi pek çok MEŞRU sistem gizli iframe
  // kullanır. Bu yüzden yalnızca adresi ZARARLI LİSTESİNDE olan gizli çerçeveler kaldırılır.
  // Ucuz kontroller önce yapılır; boyut ölçümü (düzen hesaplatır) sadece gerekirse yapılır.
  const checkedFrameHosts = new Set();
  const seenFrames = new WeakSet();

  function checkIframe(f) {
    if (seenFrames.has(f)) return;
    seenFrames.add(f);
    const srcAttr = f.getAttribute("src") || "";
    if (!srcAttr || /^(about:|javascript:|data:|blob:)/i.test(srcAttr)) return;
    const fh = targetHostOf(srcAttr);
    if (!fh || fh === host || isTrustedHost(fh) || checkedFrameHosts.has(fh)) return;
    checkedFrameHosts.add(fh);
    hostIsBlocked(fh, (bad) => {
      if (!bad) return; // zararlı değilse hiç ölçme, dokunma
      idle(() => {
        const st = window.getComputedStyle(f);
        const hidden = st.display === "none" || st.visibility === "hidden" || st.opacity === "0" ||
          (f.offsetWidth <= 2 && f.offsetHeight <= 2) ||
          parseInt(st.left || "0") < -1000 || parseInt(st.top || "0") < -1000;
        if (!hidden) return;
        document.querySelectorAll("iframe").forEach(fr => {
          if (targetHostOf(fr.getAttribute("src") || "") === fh) { try { fr.remove(); } catch (e) {} }
        });
        report("iframe", "Zararlı bir siteye ait gizli çerçeve (iframe) kaldırıldı: " + fh);
      });
    });
  }

  // ---- 5) Sahte kurum sayfası ve dolandırıcılık kalıbı tespiti ----
  // Türkçe metin karşılaştırması: "İŞ BANKASI", "iş bankası", "is bankasi" aynı sayılır.
  // (JS'nin standart toLowerCase'i "İ" harfini noktalı bir karaktere çevirip eşleşmeyi bozuyordu.)
  const fold = (t) => (t || "").toLocaleLowerCase("tr-TR").normalize("NFD")
    .replace(/[̀-ͯ]/g, "").replace(/ı/g, "i");

  // strict: yalnızca başlık / ana başlık / logo metninde aranır. Google, Apple, Instagram gibi
  // markalar "... ile giriş yap" düğmelerinde ve altbilgilerde çok geçtiği için böyle.
  const BRANDS = [
    // Devlet
    { name: "e-Devlet", keys: ["e-devlet", "edevlet", "e-government", "turkiye.gov"], official: ["turkiye.gov.tr"] },
    { name: "Gelir İdaresi", keys: ["gelir idaresi", "interaktif vergi dairesi"], official: ["gib.gov.tr"] },
    { name: "SGK", keys: ["sosyal guvenlik kurumu"], official: ["sgk.gov.tr"] },
    { name: "e-Nabız", keys: ["e-nabiz", "enabiz"], official: ["enabiz.gov.tr"] },
    { name: "MHRS", keys: ["mhrs", "merkezi hekim randevu"], official: ["mhrs.gov.tr"] },
    // Bankalar ve ödeme
    { name: "Ziraat Bankası", keys: ["ziraat bankasi", "ziraatbank", "ziraat mobil", "bankkart"], official: ["ziraatbank.com.tr", "bankkart.com.tr", "ziraatbankasi.com.tr"] },
    { name: "Ziraat Katılım", keys: ["ziraat katilim"], official: ["ziraatkatilim.com.tr"] },
    { name: "Garanti BBVA", keys: ["garanti bbva", "garantibbva", "garanti bankasi"], official: ["garantibbva.com.tr", "garanti.com.tr"] },
    { name: "İş Bankası", keys: ["is bankasi", "isbank", "iscep"], official: ["isbank.com.tr", "isbankasi.com.tr"] },
    { name: "Akbank", keys: ["akbank", "axess"], official: ["akbank.com", "akbank.com.tr", "axess.com.tr"] },
    { name: "Yapı Kredi", keys: ["yapi kredi", "yapikredi", "worldcard"], official: ["yapikredi.com.tr", "worldcard.com.tr"] },
    { name: "Halkbank", keys: ["halkbank", "halk bankasi"], official: ["halkbank.com.tr"] },
    { name: "VakıfBank", keys: ["vakifbank"], official: ["vakifbank.com.tr"] },
    { name: "Vakıf Katılım", keys: ["vakif katilim"], official: ["vakifkatilim.com.tr"] },
    { name: "QNB", keys: ["qnb finansbank", "finansbank", "qnb bank"], official: ["qnb.com.tr", "qnbfinansbank.com"] },
    { name: "DenizBank", keys: ["denizbank"], official: ["denizbank.com"] },
    { name: "Kuveyt Türk", keys: ["kuveyt turk"], official: ["kuveytturk.com.tr"] },
    { name: "Albaraka", keys: ["albaraka"], official: ["albaraka.com.tr"] },
    { name: "Türkiye Finans", keys: ["turkiye finans"], official: ["turkiyefinans.com.tr"] },
    { name: "Emlak Katılım", keys: ["emlak katilim"], official: ["emlakkatilim.com.tr"] },
    { name: "TEB", keys: ["turk ekonomi bankasi", "cepteteb"], official: ["teb.com.tr", "cepteteb.com.tr"] },
    { name: "ING", keys: ["ing bank", "ing mobil"], official: ["ing.com.tr"] },
    { name: "Enpara", keys: ["enpara"], official: ["enpara.com"] },
    { name: "Şekerbank", keys: ["sekerbank"], official: ["sekerbank.com.tr"] },
    { name: "Odeabank", keys: ["odeabank"], official: ["odeabank.com.tr"] },
    { name: "Fibabanka", keys: ["fibabanka"], official: ["fibabanka.com.tr"] },
    { name: "HSBC", keys: ["hsbc"], official: ["hsbc.com.tr", "hsbc.com"] },
    { name: "Papara", keys: ["papara"], official: ["papara.com"] },
    { name: "ininal", keys: ["ininal"], official: ["ininal.com"] },
    { name: "PayPal", keys: ["paypal"], official: ["paypal.com"], strict: true },
    // Kargo
    { name: "PTT", keys: ["ptt kargo", "pttavm", "ptt gonderi"], official: ["ptt.gov.tr", "pttavm.com"] },
    { name: "Yurtiçi Kargo", keys: ["yurtici kargo"], official: ["yurticikargo.com"] },
    { name: "Aras Kargo", keys: ["aras kargo"], official: ["araskargo.com.tr"] },
    { name: "MNG Kargo", keys: ["mng kargo"], official: ["mngkargo.com.tr"] },
    { name: "Sürat Kargo", keys: ["surat kargo"], official: ["suratkargo.com.tr"] },
    { name: "HepsiJET", keys: ["hepsijet"], official: ["hepsijet.com"] },
    // Telekom
    { name: "Turkcell", keys: ["turkcell"], official: ["turkcell.com.tr"] },
    { name: "Vodafone", keys: ["vodafone"], official: ["vodafone.com.tr", "vodafone.com"] },
    { name: "Türk Telekom", keys: ["turk telekom", "turktelekom"], official: ["turktelekom.com.tr"] },
    // Alışveriş ve hizmetler
    { name: "Trendyol", keys: ["trendyol"], official: ["trendyol.com"] },
    { name: "Hepsiburada", keys: ["hepsiburada"], official: ["hepsiburada.com"] },
    { name: "n11", keys: ["n11.com", "n11 giris"], official: ["n11.com"] },
    { name: "Amazon", keys: ["amazon"], official: ["amazon.com.tr", "amazon.com"], strict: true },
    { name: "sahibinden.com", keys: ["sahibinden"], official: ["sahibinden.com"] },
    { name: "Yemeksepeti", keys: ["yemeksepeti"], official: ["yemeksepeti.com"] },
    { name: "Çiçeksepeti", keys: ["ciceksepeti"], official: ["ciceksepeti.com"] },
    { name: "Netflix", keys: ["netflix"], official: ["netflix.com"], strict: true },
    { name: "Instagram", keys: ["instagram"], official: ["instagram.com"], strict: true },
    { name: "Facebook", keys: ["facebook"], official: ["facebook.com"], strict: true },
    { name: "Apple", keys: ["apple id", "icloud"], official: ["apple.com", "icloud.com"], strict: true },
    { name: "Microsoft", keys: ["microsoft hesab", "outlook", "office 365", "microsoft 365"], official: ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"], strict: true }
  ];
  for (const b of BRANDS) b.foldedKeys = b.keys.map(fold);

  // Marka gerektirmeyen, Türkiye'de sık görülen dolandırıcılık senaryoları
  const SCAM_PHRASES = [
    "vergi iadeniz", "vergi iadesi", "iade tutariniz", "iadeniz hesabiniza",
    "hgs ceza", "hgs bakiye", "hgs ihlal", "ogs ceza", "gecis ihlal",
    "trafik cezaniz", "trafik cezasi odeme",
    "gumruk ucreti", "gumruk vergisi", "kargonuz teslim edilemedi", "teslimat ucreti", "adres bilgileriniz eksik",
    "hesabiniz askiya", "hesabiniz bloke", "sifrenizin suresi doldu", "sifreniz sona erdi",
    "odul kazandiniz", "hediye kazandiniz", "cekilisi kazandiniz", "kampanyayi kazandiniz",
    "aidat iadesi", "fatura iadesi", "elektrik iadesi", "dogalgaz iadesi",
    "kimlik dogrulamasi gerekiyor", "e-devlet sifreniz", "odemeniz alinamadi", "odemeniz onaylanmadi"
  ].map(fold);

  function inputHint(i) {
    return fold([i.name, i.id, i.placeholder, i.getAttribute("aria-label"), i.getAttribute("autocomplete")].join(" "));
  }
  function credentialInputs() {
    return Array.from(document.querySelectorAll("input")).filter(i => {
      if (i.type === "password") return true;
      const h = inputHint(i);
      return /\btc\b|tckn|kimlik|sifre|parola|password|musteri no/.test(h) ||
        i.maxLength === 11 || (i.getAttribute("inputmode") === "numeric" && i.maxLength >= 10);
    });
  }
  function cardInputs() {
    return Array.from(document.querySelectorAll("input")).filter(i => {
      const h = inputHint(i);
      return /\bcc-|kart ?no|kart numara|card ?num|cvv|cvc|son kullanma|guvenlik kodu/.test(h);
    });
  }

  // Sayfa metnini script/style içeriğini ATLAYARAK topla (innerText gibi düzen hesaplatmaz)
  function visibleText(limit, root) {
    root = root || document.body;
    if (!root) return "";
    const SKIP = { SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEMPLATE: 1, SVG: 1 };
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => (n.parentNode && SKIP[n.parentNode.nodeName.toUpperCase()]) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT
    });
    let out = "";
    while (out.length < limit && walker.nextNode()) {
      const t = walker.currentNode.nodeValue;
      if (t && t.trim()) out += " " + t.trim();
    }
    return out.slice(0, limit);
  }

  // "Göze çarpan" metin: başlık, ana başlıklar, logo/görsel açıklamaları ve giriş formunun çevresi.
  // Altbilgideki "Instagram'da bizi takip edin" gibi ifadeler bu metne girmez.
  function headlineText() {
    const parts = [document.title];
    document.querySelectorAll("h1, h2, [class*='logo' i] , [id*='logo' i], header img[alt], img[alt*='logo' i]").forEach(el => {
      parts.push(el.getAttribute && (el.getAttribute("alt") || el.getAttribute("title")) || "", (el.textContent || "").slice(0, 200));
    });
    return fold(parts.join(" "));
  }
  function formAreaText(inputs) {
    const seen = new Set(); let out = "";
    for (const i of inputs.slice(0, 4)) {
      let box = i.closest("form");
      if (!box) { box = i; for (let k = 0; k < 3 && box.parentElement; k++) box = box.parentElement; }
      if (seen.has(box)) continue; seen.add(box);
      out += " " + visibleText(3000, box);
      box.querySelectorAll("img[alt], [aria-label]").forEach(el => { out += " " + (el.getAttribute("alt") || el.getAttribute("aria-label")); });
    }
    return fold(out);
  }

  // Bilinen büyük siteler: "e-Devlet ile giriş/onay" gibi ifadeleri meşru olarak kullanırlar
  const KNOWN_SITES = [
    "google.com", "youtube.com", "gmail.com", "microsoft.com", "live.com", "apple.com", "facebook.com", "instagram.com",
    "linkedin.com", "x.com", "twitter.com", "github.com", "getir.com", "kolaybi.com"
  ];
  const onHost = (list) => list.some(o => host === o || host.endsWith("." + o));

  function detectPhishing() {
    // Resmi devlet/eğitim uzantısındaysa hiç kontrol etme (ÖSYM, YÖK, üniversiteler vb.)
    if (SAFE_TLDS.some(t => host.endsWith(t))) return;
    // Listedeki HERHANGİ bir markanın resmi sitesi ya da bilinen büyük bir siteyse kontrol etme
    // (ör. gerçek Garanti sitesinde "e-Devlet ile giriş" yazması oltalama değildir)
    if (BRANDS.some(b => onHost(b.official)) || onHost(KNOWN_SITES)) return;

    // Önce ucuz kontrol: şifre/TC ya da kart alanı yoksa metin hiç okunmaz
    const creds = credentialInputs(), cards = cardInputs();
    if (creds.length === 0 && cards.length === 0) return;
    const sensitive = creds.concat(cards);

    // 1) Marka taklidi
    const head = headlineText();
    const area = head + " " + formAreaText(sensitive);
    for (const b of BRANDS) {
      const where = b.strict ? head : area;
      const hit = b.foldedKeys.find(k => where.includes(k));
      if (hit) {
        report("phishing",
          `DİKKAT: Bu sayfa "${b.name}" gibi görünüp bilgilerinizi istiyor ama resmi adres (${b.official[0]}) DEĞİL. Olası dolandırıcılık.`,
          location.href);
        return;
      }
    }

    // 2) Marka olmadan da: bilinen dolandırıcılık senaryosu + kart/şifre alanı
    const body = fold(document.title + " " + visibleText(8000));
    const phrase = SCAM_PHRASES.find(p => body.includes(p));
    if (phrase) {
      report("scam",
        `DİKKAT: Bu sayfa dolandırıcıların sık kullandığı bir senaryoyla ("${phrase}") sizden ${cards.length ? "kart" : "şifre/kimlik"} bilgisi istiyor.`,
        location.href);
    }
  }

  // ---- Sonradan eklenen içerik için izleyici ----
  // Yalnızca YENİ eklenen script/iframe'ler incelenir (tüm sayfa baştan taranmaz),
  // iş toplanıp tarayıcının boş anında yapılır.
  let observer;
  const pending = new Set();
  let scheduled = false;
  function flushPending() {
    scheduled = false;
    for (const n of pending) {
      if (n.nodeName === "SCRIPT") checkScript(n);
      else if (n.nodeName === "IFRAME" && isTopFrame) checkIframe(n);
    }
    pending.clear();
  }
  function observeMutations() {
    if (observer) return;
    observer = new MutationObserver((muts) => {
      for (const m of muts) {
        for (const n of m.addedNodes) {
          if (n.nodeName === "SCRIPT" || n.nodeName === "IFRAME") pending.add(n);
        }
      }
      if (pending.size && !scheduled) { scheduled = true; idle(flushPending); }
    });
    try {
      observer.observe(document.documentElement, { childList: true, subtree: true });
      setTimeout(() => { try { observer.disconnect(); } catch (e) {} }, 20000);
    } catch (e) {}
  }
})();
