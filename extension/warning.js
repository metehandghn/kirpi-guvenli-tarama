// Kirpi | Uyarı sayfası mantığı
const params = new URLSearchParams(location.search);
const blockedUrl = params.get("url") || "";
const reason = params.get("reason") || "blocklist";

const REASONS = {
  blocklist: {
    tag: "Bilinen zararlı site",
    desc: "Bu adres bilinen zararlı siteler listesinde yer alıyor. Virüs bulaştırma, dolandırıcılık veya bilgi çalma amacı taşıyabilir."
  },
  phishing: {
    tag: "Sahte / oltalama sayfası",
    desc: "Bu sayfa resmi bir kurum (banka, e-Devlet veya kargo) gibi görünüp bilgilerinizi çalmaya çalışıyor olabilir. Resmi adres bu değil."
  },
  scam: {
    tag: "Dolandırıcılık kalıbı",
    desc: "Bu sayfa vergi iadesi, kargo ücreti, HGS cezası veya ödül gibi dolandırıcıların sık kullandığı bir senaryoyla sizden kart ya da şifre bilgisi istiyor. Resmi kurumlar bu tür ödemeleri SMS bağlantısıyla istemez."
  },
  redirect: {
    tag: "Şüpheli yönlendirme",
    desc: "Siz istemeden sizi başka bir siteye göndermeye çalışan bir yönlendirme engellendi."
  },
  miner: {
    tag: "Kripto madenciliği",
    desc: "Bu sayfa cihazınızın işlemcisini gizlice kullanarak kripto para kazmaya çalışıyordu."
  }
};

const info = REASONS[reason] || REASONS.blocklist;
document.getElementById("reason").textContent = info.tag;
document.getElementById("desc").textContent = info.desc;
document.getElementById("url").textContent = blockedUrl || "(adres bilinmiyor)";

document.getElementById("back").addEventListener("click", () => {
  const here = location.href;
  // Önce geri gitmeyi dene
  if (history.length > 1) {
    history.back();
    // Geri gidiş işe yaramadıysa (hâlâ uyarı sayfasındaysak) güvenli yere git
    setTimeout(() => {
      if (location.href === here) location.href = "https://www.google.com";
    }, 500);
  } else {
    location.href = "https://www.google.com";
  }
});

// "Yine de git": ilk basışta onay ister, ikinci basışta siteye izin verip açar.
// İzin arka plana kaydedilir; aksi halde site açılır açılmaz yeniden engellenirdi.
const proceedBtn = document.getElementById("proceed");
let armed = false;
const safeTarget = /^https?:\/\//i.test(blockedUrl) ? blockedUrl : "";   // javascript: vb. adreslere gitme
if (!safeTarget) proceedBtn.style.display = "none";

proceedBtn.addEventListener("click", async () => {
  if (!safeTarget) return;
  if (!armed) {
    armed = true;
    proceedBtn.textContent = "Evet, devam et";
    proceedBtn.classList.add("confirm");
    document.getElementById("hint").classList.add("show");
    document.getElementById("trust").classList.add("show");
    return;
  }
  proceedBtn.disabled = true;
  const permanent = document.getElementById("trustBox").checked;
  try { await chrome.runtime.sendMessage({ type: "allowHost", url: safeTarget, permanent }); } catch (e) {}
  location.replace(safeTarget);
});
