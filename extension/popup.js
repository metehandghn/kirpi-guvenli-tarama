// Kirpi | Popup arayüz mantığı
const TOGGLES = ["enabled", "blockRedirects", "blockDownloads", "blockMiners", "detectPhishing"];

// Anahtarlara dinleyiciyi yalnızca BİR kez bağla
for (const t of TOGGLES) {
  const el = document.getElementById(t);
  el.addEventListener("change", () => save(t, el.checked));
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

async function load() {
  const data = await chrome.storage.local.get([...TOGGLES, "stats", "kalkanCount", "kalkanLastUpdate", "kalkanFeedStatus"]);
  for (const t of TOGGLES) document.getElementById(t).checked = data[t] !== false; // varsayılan açık

  const s = data.stats || {};
  document.getElementById("s_sites").textContent = s.blockedSites || 0;
  document.getElementById("s_phish").textContent = s.blockedPhishing || 0;
  document.getElementById("s_redir").textContent = s.blockedRedirects || 0;
  document.getElementById("s_down").textContent = s.blockedDownloads || 0;
  document.getElementById("s_mine").textContent = s.blockedMiners || 0;

  const count = data.kalkanCount || 0;
  const when = data.kalkanLastUpdate ? new Date(data.kalkanLastUpdate).toLocaleString("tr-TR") : "henüz yok";
  document.getElementById("listMeta").textContent = count.toLocaleString("tr-TR") + " kayıt · " + when;

  // Kaynak durumunu göster
  const fs = data.kalkanFeedStatus || [];
  const fsEl = document.getElementById("feedStatus");
  if (fsEl) {
    fsEl.innerHTML = fs.map(f => {
      const detail = f.ok
        ? " (" + (f.added || 0).toLocaleString("tr-TR") + ")" + (f.info ? " — " + escapeHtml(f.info) : "")
        : " — " + escapeHtml(f.info || "");
      return `<span style="color:${f.ok ? "#4ade80" : "#f87171"}">${f.ok ? "✓" : "✕"} ${escapeHtml(f.id)}${detail}</span>`;
    }).join("<br>");
  }

  updateStatus();
}

async function save(key, val) {
  await chrome.storage.local.set({ [key]: val });
  updateStatus();
}

async function updateStatus() {
  const { enabled } = await chrome.storage.local.get("enabled");
  const txt = document.getElementById("statusText");
  if (enabled === false) { txt.textContent = "Koruma kapalı"; txt.style.color = "#fca5a5"; }
  else { txt.textContent = "Koruma aktif"; txt.style.color = "#93c5fd"; }
}

async function isUpdating() {
  try { const r = await chrome.runtime.sendMessage({ type: "updateStatus" }); return !!(r && r.updating); }
  catch (e) { return false; }
}

// Güncelleme arka planda sürerken paneli tazele
const btn = document.getElementById("updateBtn");
let pollTimer = null;
function startPolling() {
  btn.textContent = "Güncelleniyor…";
  btn.disabled = true;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    await load();
    if (!(await isUpdating())) {
      clearInterval(pollTimer); pollTimer = null;
      await load();
      btn.textContent = "Listeyi Güncelle";
      btn.disabled = false;
    }
  }, 2000);
}

btn.addEventListener("click", async () => {
  try { await chrome.runtime.sendMessage({ type: "forceUpdate" }); } catch (err) {}
  startPolling();
});

// ---------- Güvenilir siteler ----------
// Kullanıcının bir şey seçmesi gerekmez: liste yalnızca uyarı ekranında
// "Bu siteye her zaman güven" denince dolar. Boşsa bölüm hiç görünmez.
const send = (msg) => chrome.runtime.sendMessage(msg).catch(() => null);

async function renderTrust() {
  const hosts = ((await send({ type: "listAllowed" })) || {}).hosts || [];
  const box = document.getElementById("trustBox");
  const list = document.getElementById("allowList");
  list.textContent = "";
  box.hidden = hosts.length === 0;
  for (const h of hosts) {
    const row = document.createElement("div"); row.className = "allow-item";
    const t = document.createElement("span"); t.textContent = h;
    const x = document.createElement("button"); x.textContent = "×"; x.title = "Listeden çıkar";
    x.addEventListener("click", async () => { await send({ type: "removeAllowed", host: h }); renderTrust(); });
    row.append(t, x); list.appendChild(row);
  }
}

(async () => {
  await load();
  renderTrust();
  if (await isUpdating()) startPolling(); // panel açıldığında süren güncellemeyi göster
})();
