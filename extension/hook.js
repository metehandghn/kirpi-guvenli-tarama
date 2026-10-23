// Kirpi - Güvenli Tarama | Sayfa ana dünyası hook'u
// location/open/Notification davranışlarını izleyip içerik scriptine haber verir.
// Not: Bu dosya manifest'te "world": "MAIN" ile sayfanın kendi ortamında çalışır.
// Yalnızca kullanıcı etkileşimi olmadan açılan pencereleri engeller; diğer
// davranışları (yönlendirme, bildirim izni) sadece raporlar.

(function () {
  function post(event, data) {
    window.postMessage(Object.assign({ __kirpi: true, event }, data || {}), "*");
  }

  // Son kullanıcı etkileşimi zamanı
  let lastInteraction = 0;
  ["click", "keydown", "mousedown", "touchstart", "submit"].forEach(ev =>
    window.addEventListener(ev, () => { lastInteraction = Date.now(); }, true)
  );
  // Chrome'un kendi açılır pencere kuralıyla aynı süre (5 sn): meşru giriş/ödeme pencereleri bozulmasın
  function userActedRecently() { return Date.now() - lastInteraction < 5000; }

  // window.open popunder tespiti (etkileşimsiz açılan pencereler)
  const origOpen = window.open;
  window.open = function (url, name, feats) {
    if (!userActedRecently()) {
      post("popunder", { target: url || "" });
      return null; // etkileşimsiz pop-up'ı engelle
    }
    return origOpen.apply(this, arguments);
  };

  // location.assign / replace izleme (etkileşimsiz dış yönlendirme)
  try {
    const origAssign = Location.prototype.assign;
    const origReplace = Location.prototype.replace;
    Location.prototype.assign = function (u) {
      if (!userActedRecently()) post("autoRedirect", { target: String(u) });
      return origAssign.apply(this, arguments);
    };
    Location.prototype.replace = function (u) {
      if (!userActedRecently()) post("autoRedirect", { target: String(u) });
      return origReplace.apply(this, arguments);
    };
  } catch (e) {}

  // Notification izin spamı (sayfa açılır açılmaz izin istenmesi)
  try {
    if (window.Notification && Notification.requestPermission) {
      const origReq = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = function () {
        if (Date.now() < (window.performance?.timing?.navigationStart || 0) + 3000 || !userActedRecently()) {
          post("notificationSpam", {});
        }
        return origReq.apply(this, arguments);
      };
    }
  } catch (e) {}
})();
