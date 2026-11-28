const EP = {
  getSession() {
    return {
      token: localStorage.getItem("ep_token") || "",
      role: localStorage.getItem("ep_role") || "",
      tenantId: localStorage.getItem("ep_tenant_id") || "",
      slug: localStorage.getItem("ep_tenant_slug") || "",
    };
  },

  saveSession(token, role, tenantId, slug = "") {
    localStorage.setItem("ep_token", token);
    localStorage.setItem("ep_role", role);
    localStorage.setItem("ep_tenant_id", tenantId);
    if (slug) localStorage.setItem("ep_tenant_slug", slug);
  },

  clearSession() {
    localStorage.removeItem("ep_token");
    localStorage.removeItem("ep_role");
    localStorage.removeItem("ep_tenant_id");
    localStorage.removeItem("ep_tenant_slug");
  },

  logoutAndRedirect() {
    this.clearSession();
    window.location.href = "/";
  },

  escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, m => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[m]));
  },

  uuid() {
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
      return window.crypto.randomUUID();
    }
    if (window.crypto && typeof window.crypto.getRandomValues === "function") {
      const b = new Uint8Array(16);
      window.crypto.getRandomValues(b);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      const h = [...b].map(x => x.toString(16).padStart(2, "0")).join("");
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    }
    return `${Date.now().toString(16)}-${Math.random().toString(16).slice(2, 10)}-${Math.random().toString(16).slice(2, 10)}`;
  },

  async copyText(text, okMsg = "Copiado al portapapeles.") {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
      }
      this.toast(okMsg);
    } catch {
      this.toast("No se pudo copiar automáticamente.", "warn");
    }
  },

  showMsg(elId, kind, text) {
    const el = document.getElementById(elId);
    if (!el) return;
    const cls = kind === "ok" ? "alert-success" : kind === "warn" ? "alert-warning" : "alert-danger";
    el.innerHTML = `<div class="alert ${cls} py-2 px-3 small mb-0 mt-2">${this.escapeHtml(text)}</div>`;
  },

  formatDateTime(isoStr, timeZone) {
    if (!isoStr) return "-";
    try {
      const d = new Date(isoStr);
      if (isNaN(d.getTime())) return String(isoStr);
      const tz = timeZone || window.currentEventTimezone || "America/Lima";
      return new Intl.DateTimeFormat("es-PE", {
        timeZone: tz,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: true,
      }).format(d);
    } catch (_) {
      return new Date(isoStr).toLocaleString();
    }
  },

  toast(text, kind = "ok") {
    let container = document.getElementById("epToastContainer");
    if (!container) {
      container = document.createElement("div");
      container.id = "epToastContainer";
      container.className = "toast-container position-fixed bottom-0 end-0 p-3";
      container.style.zIndex = "1080";
      document.body.appendChild(container);
    }
    const bg = kind === "ok" ? "text-bg-success" : kind === "warn" ? "text-bg-warning" : "text-bg-danger";
    const el = document.createElement("div");
    el.className = `toast align-items-center ${bg} border-0`;
    el.innerHTML = `<div class="d-flex"><div class="toast-body small fw-semibold">${this.escapeHtml(text)}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div>`;
    container.appendChild(el);
    if (window.bootstrap && window.bootstrap.Toast) {
      const t = new window.bootstrap.Toast(el, { delay: 3200 });
      t.show();
      el.addEventListener("hidden.bs.toast", () => el.remove());
    } else {
      el.classList.add("show");
      setTimeout(() => el.remove(), 3200);
    }
  },

  renderNavbar(activeKey, extraRightHtml = "") {
    const header = document.getElementById("epNavbarHost");
    if (!header) return;
    const s = this.getSession();
    const role = (s.role || "").toUpperCase();
    const isAuth = !!s.token;

    const links = [];
    // Visibles para todo público (invitado y autenticado)
    links.push({ key: "home", href: "/", icon: "bi-grid-1x2", label: "Eventos" });
    links.push({ key: "comprar", href: "/comprar", icon: "bi-ticket-perforated", label: "Taquilla" });

    // Opciones con privilegios según rol autenticado
    if (role === "SUPERADMIN") {
      links.push({ key: "superadmin", href: "/superadmin", icon: "bi-shield-lock", label: "SuperAdmin" });
      links.push({ key: "admin", href: "/admin", icon: "bi-speedometer2", label: "Dashboard" });
      links.push({ key: "validar", href: "/validar", icon: "bi-upc-scan", label: "Puerta" });
      links.push({ key: "acreditacion", href: "/acreditacion", icon: "bi-building-check", label: "Staff" });
      links.push({ key: "reclamos", href: "/reclamos", icon: "bi-journal-bookmark", label: "Reclamos" });
    } else if (role === "ADMIN" || role === "SUPERVISOR") {
      links.push({ key: "admin", href: "/admin", icon: "bi-speedometer2", label: "Dashboard" });
      links.push({ key: "acreditacion", href: "/acreditacion", icon: "bi-building-check", label: "Staff" });
      links.push({ key: "validar", href: "/validar", icon: "bi-upc-scan", label: "Puerta" });
      links.push({ key: "reclamos", href: "/reclamos", icon: "bi-journal-bookmark", label: "Reclamos" });
    } else if (role === "VALIDATOR") {
      links.push({ key: "validar", href: "/validar", icon: "bi-upc-scan", label: "Puerta" });
      links.push({ key: "reclamos", href: "/reclamos", icon: "bi-journal-bookmark", label: "Reclamos" });
    } else {
      // Público / Invitado: Libro de Reclamaciones
      links.push({ key: "reclamos", href: "/reclamos", icon: "bi-journal-bookmark", label: "Reclamos" });
    }

    const navItems = links.map(l => `
      <li class="nav-item">
        <a class="nav-link ${l.key === activeKey ? "active" : ""}" href="${l.href}">
          <i class="bi ${l.icon} me-1"></i>${l.label}
        </a>
      </li>`).join("");

    const sessionHtml = isAuth
      ? `<div class="d-flex align-items-center gap-2">
           ${(role === "ADMIN" || role === "SUPERADMIN") ? `<button type="button" class="btn btn-outline-warning btn-sm py-1 px-2 fw-semibold d-flex align-items-center gap-1" onclick="EP.toggleCopilot()" title="Abrir Copilot Asistente"><i class="bi bi-robot"></i> Copilot</button>` : ""}
           <span class="badge text-bg-success py-2 px-3"><i class="bi bi-person-badge me-1"></i>${this.escapeHtml(s.slug || "tenant")} · ${this.escapeHtml(s.role)}</span>
           <button class="btn btn-outline-danger btn-sm py-1 px-2" onclick="EP.logoutAndRedirect()" title="Cerrar Sesión"><i class="bi bi-box-arrow-right"></i> Salir</button>
         </div>`
      : `<a class="btn btn-outline-info btn-sm py-1 px-3" href="/admin"><i class="bi bi-box-arrow-in-right me-1"></i>Acceso Organizador</a>`;

    header.innerHTML = `
      <nav class="navbar navbar-expand-lg ep-navbar px-3 py-2">
        <div class="container-fluid">
          <a class="navbar-brand fw-bold d-flex align-items-center gap-2 text-white" href="/">
            <span class="ep-brand-mark"><i class="bi bi-lightning-charge-fill"></i></span>
            <span>EVENTPASS <span class="text-info fw-normal fs-6">SaaS</span></span>
          </a>
          <button class="navbar-toggler border-secondary" type="button" data-bs-toggle="collapse" data-bs-target="#epTopNav">
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse" id="epTopNav">
            <ul class="navbar-nav me-auto mb-2 mb-lg-0 gap-1 ms-lg-3">${navItems}</ul>
            <div class="d-flex align-items-center gap-2 flex-wrap">
              ${extraRightHtml}
              ${sessionHtml}
            </div>
          </div>
        </div>
      </nav>`;
    if (role === "ADMIN" || role === "SUPERADMIN") {
      setTimeout(() => this.initCopilot(), 150);
    }
  },

  async api(url, opts = {}) {
    const sess = this.getSession();
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (sess.token && !headers.Authorization && opts.auth !== false) {
      headers.Authorization = `Bearer ${sess.token}`;
    }
    const res = await fetch(url, { ...opts, headers });
    const txt = await res.text();
    let data = null;
    try {
      data = JSON.parse(txt);
    } catch {
      const isHtml = /<[a-z][\s\S]*>/i.test(txt);
      data = { detail: isHtml ? (res.statusText || "Servicio no disponible") : txt.slice(0, 160) };
    }
    let detailMsg = "";
    if (data && Array.isArray(data.detail)) {
      detailMsg = data.detail.map(d => {
        const loc = Array.isArray(d.loc) ? d.loc.filter(k => k !== "body").join(".") : "";
        let m = d.msg || "Valor no válido";
        if (m.includes("String should have at least")) {
          const match = m.match(/\d+/);
          m = `Debe tener al menos ${match ? match[0] : 8} caracteres`;
        } else if (m.includes("valid email") || m.includes("value is not a valid email")) {
          m = "Correo electrónico no válido";
        } else if (m.includes("pattern") || m.includes("String should match pattern")) {
          m = "Formato no válido (solo minúsculas, números y guiones)";
        }
        return loc ? `${loc}: ${m}` : m;
      }).join(" | ");
    } else if (data && typeof data.detail === "object" && data.detail !== null) {
      detailMsg = JSON.stringify(data.detail);
    } else {
      detailMsg = (data && data.detail) || res.statusText || 'Error';
    }
    if (!res.ok) throw new Error(`${res.status}: ${detailMsg}`);
    return data;
  },

  async renderQrDataUrl(qrToken) {
    const res = await this.api("/bff/qr-data-url", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ qr_token: qrToken }),
    });
    return res.data_url;
  },

  b64UrlToBytes(b64u) {
    const b64 = b64u.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - b64u.length % 4) % 4);
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
  },

  pemToSpkiBytes(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
    const bin = atob(b64);
    return Uint8Array.from(bin, c => c.charCodeAt(0));
  },

  async verifyEd25519Jws(jws, publicKeyPem) {
    const parts = jws.split(".");
    if (parts.length !== 3) throw new Error("Formato de QR inválido");
    const key = await crypto.subtle.importKey(
      "spki",
      this.pemToSpkiBytes(publicKeyPem),
      { name: "Ed25519" },
      false,
      ["verify"]
    );
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
    const sig = this.b64UrlToBytes(parts[2]);
    const ok = await crypto.subtle.verify("Ed25519", key, sig, data);
    if (!ok) throw new Error("Firma criptográfica Ed25519 inválida");
    const claims = JSON.parse(new TextDecoder().decode(this.b64UrlToBytes(parts[1])));
    if (claims.exp && claims.exp * 1000 < Date.now()) {
      throw new Error("Credencial QR expirada");
    }
    return claims;
  },

  initCopilot() {
    const s = this.getSession();
    const role = (s.role || "").toUpperCase();
    if (role !== "ADMIN" && role !== "SUPERADMIN") return;
    if (document.getElementById("epCopilotDrawer")) return;

    const drawerHtml = `
      <!-- BOTÓN FLOTANTE COPILOT -->
      <div id="epCopilotLauncher" class="position-fixed bottom-0 end-0 m-3 z-3">
        <button class="btn btn-primary rounded-pill shadow-lg py-2 px-3 d-flex align-items-center gap-2 fw-semibold" onclick="EP.toggleCopilot()" style="background: linear-gradient(135deg, #7c3aed, #2563eb); border: none;">
          <i class="bi bi-robot fs-5"></i>
          <span class="d-none d-sm-inline">Copilot SaaS</span>
          <span class="badge text-bg-warning rounded-pill small">Local</span>
        </button>
      </div>

      <!-- DRAWER LATERAL OFFCANVAS -->
      <div class="offcanvas offcanvas-end bg-dark text-white border-start border-secondary" tabindex="-1" id="epCopilotDrawer" style="width: 440px; max-width: 95vw;">
        <div class="offcanvas-header border-bottom border-secondary py-2" style="background: rgba(124, 58, 237, 0.15);">
          <div class="d-flex align-items-center gap-2">
            <span class="fs-4">🤖</span>
            <div>
              <h5 class="offcanvas-title h6 fw-bold mb-0">EventPass Copilot</h5>
              <small class="text-secondary small">Asistente Operativo Local · Plataforma SaaS</small>
            </div>
          </div>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="offcanvas"></button>
        </div>
        <div class="offcanvas-body d-flex flex-column p-3" style="background: #0f172a;">
          <div class="alert alert-info py-2 px-3 small mb-2 d-flex align-items-center gap-2">
            <i class="bi bi-shield-lock-fill text-info fs-5"></i>
            <div>
              <strong>Seguridad Multi-Tenant:</strong> Solo ejecuta acciones autorizadas para tu empresa en la base de datos local.
            </div>
          </div>

          <!-- SUGGESTION PILLS -->
          <div class="mb-2">
            <small class="text-secondary fw-semibold d-block mb-1">Acciones sugeridas:</small>
            <div class="d-flex flex-wrap gap-1">
              <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 small text-light" onclick="EP.sendCopilotMessage('Crear una entrada VIP a 120 soles con 50 cupos')">➕ VIP S/ 120 (50 cupos)</button>
              <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 small text-light" onclick="EP.sendCopilotMessage('Cambiar el precio de la entrada GENERAL a 65 soles')">💲 General a S/ 65</button>
              <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 small text-light" onclick="EP.sendCopilotMessage('¿Cuánto hemos vendido hoy?')">📊 Ventas y métricas</button>
              <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 small text-light" onclick="EP.sendCopilotMessage('Listar entradas')">📋 Listar entradas</button>
              <button type="button" class="btn btn-outline-secondary btn-sm py-0 px-2 small text-light" onclick="EP.sendCopilotMessage('Crear código PROMO15 con 15% de descuento')">🏷️ Código PROMO15 (15%)</button>
            </div>
          </div>

          <hr class="border-secondary my-2" />

          <!-- CHAT MESSAGES FEED -->
          <div id="epCopilotFeed" class="flex-grow-1 overflow-y-auto mb-3 pe-1" style="max-height: 55vh; min-height: 250px;">
            <div class="d-flex gap-2 mb-3">
              <span class="fs-5">🤖</span>
              <div class="p-2 rounded bg-secondary-subtle text-light small" style="max-width: 90%;">
                ¡Hola! Soy el <strong>Copilot Operativo</strong> de EventPass. Puedo crear tipos de entrada, modificar precios o cupos, consultar ventas en vivo y crear descuentos para tu evento. ¿Qué deseas hacer?
              </div>
            </div>
          </div>

          <!-- INPUT FORM -->
          <form onsubmit="event.preventDefault(); EP.submitCopilotInput();" class="mt-auto">
            <div class="input-group">
              <input id="epCopilotInput" class="form-control form-control-sm bg-dark text-white border-secondary" placeholder="Escribe tu orden (ej: 'Crea entrada VIP S/ 120 50 cupos')..." autocomplete="off" />
              <button type="submit" id="epCopilotSendBtn" class="btn btn-primary btn-sm px-3" style="background: #7c3aed; border-color: #7c3aed;">
                <i class="bi bi-send-fill"></i>
              </button>
            </div>
          </form>
        </div>
      </div>
    `;

    const div = document.createElement("div");
    div.id = "epCopilotRoot";
    div.innerHTML = drawerHtml;
    document.body.appendChild(div);
  },

  toggleCopilot() {
    this.initCopilot();
    const el = document.getElementById("epCopilotDrawer");
    if (!el || typeof bootstrap === "undefined") return;
    const inst = bootstrap.Offcanvas.getOrCreateInstance(el);
    inst.toggle();
    setTimeout(() => document.getElementById("epCopilotInput")?.focus(), 300);
  },

  async sendCopilotMessage(msg) {
    this.initCopilot();
    const el = document.getElementById("epCopilotDrawer");
    if (el && typeof bootstrap !== "undefined") bootstrap.Offcanvas.getOrCreateInstance(el).show();
    const input = document.getElementById("epCopilotInput");
    if (input) input.value = msg;
    await this.submitCopilotInput();
  },

  async submitCopilotInput() {
    const input = document.getElementById("epCopilotInput");
    const sendBtn = document.getElementById("epCopilotSendBtn");
    const feed = document.getElementById("epCopilotFeed");
    const text = (input?.value || "").trim();
    if (!text) return;

    input.value = "";
    if (sendBtn) sendBtn.disabled = true;

    // Append user message
    const userBubble = document.createElement("div");
    userBubble.className = "d-flex justify-content-end mb-2";
    userBubble.innerHTML = `<div class="p-2 rounded bg-primary text-white small" style="max-width: 85%;">${this.escapeHtml(text)}</div>`;
    feed.appendChild(userBubble);
    feed.scrollTop = feed.scrollHeight;

    // Append typing indicator
    const typingBubble = document.createElement("div");
    typingBubble.className = "d-flex gap-2 mb-2";
    typingBubble.innerHTML = `<span class="fs-5">🤖</span><div class="p-2 rounded bg-secondary-subtle text-light small"><span class="spinner-border spinner-border-sm me-1"></span>Ejecutando en la plataforma...</div>`;
    feed.appendChild(typingBubble);
    feed.scrollTop = feed.scrollHeight;

    // Get current event id if available on the page
    const eventSelect = document.getElementById("globalEventSelect") || document.getElementById("valEventSelect");
    const currentEventId = eventSelect ? eventSelect.value : null;

    try {
      const res = await this.api("/bff/assistant/command", {
        method: "POST",
        body: JSON.stringify({ message: text, event_id: currentEventId }),
      });

      typingBubble.remove();

      let formattedReply = this.escapeHtml(res.reply || "")
        .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
        .replace(/\*(.*?)\*/g, "<em>$1</em>")
        .replace(/`([^`]+)`/g, "<code>$1</code>")
        .replace(/\n/g, "<br>");

      const botBubble = document.createElement("div");
      botBubble.className = "d-flex gap-2 mb-3";
      botBubble.innerHTML = `<span class="fs-5">🤖</span><div class="p-2 rounded ${res.ok ? "bg-dark border border-secondary" : "bg-danger-subtle text-danger"} small" style="max-width: 90%; line-height: 1.4;">${formattedReply}</div>`;
      feed.appendChild(botBubble);
      feed.scrollTop = feed.scrollHeight;

      if (res.refresh_needed) {
        if (typeof window.loadEventsAndItemsTable === "function") window.loadEventsAndItemsTable();
        if (typeof window.loadDashboardMetrics === "function") window.loadDashboardMetrics();
        if (typeof window.loadPlatformData === "function") window.loadPlatformData();
        this.toast("Datos actualizados en pantalla.");
      }
    } catch (err) {
      typingBubble.remove();
      const errBubble = document.createElement("div");
      errBubble.className = "d-flex gap-2 mb-3";
      errBubble.innerHTML = `<span class="fs-5">🤖</span><div class="p-2 rounded bg-danger text-white small">${this.escapeHtml(err.message)}</div>`;
      feed.appendChild(errBubble);
      feed.scrollTop = feed.scrollHeight;
    } finally {
      if (sendBtn) sendBtn.disabled = false;
      input.focus();
    }
  },

  openModal(id) {
    const el = document.getElementById(id);
    if (!el) return;
    if (typeof bootstrap !== "undefined" && bootstrap.Modal) {
      try {
        const inst = bootstrap.Modal.getInstance(el) || new bootstrap.Modal(el);
        inst.show();
        return;
      } catch (_) {}
    }
    el.classList.add("show");
    el.style.display = "block";
    document.body.classList.add("modal-open");
    if (!document.querySelector(`.modal-backdrop[data-modal="${id}"]`)) {
      const backdrop = document.createElement("div");
      backdrop.className = "modal-backdrop fade show";
      backdrop.dataset.modal = id;
      document.body.appendChild(backdrop);
    }
  },

  closeModal(id) {
    const el = document.getElementById(id);
    if (!el) return;
    if (typeof bootstrap !== "undefined" && bootstrap.Modal) {
      try {
        const inst = bootstrap.Modal.getInstance(el);
        if (inst) inst.hide();
      } catch (_) {}
    }
    el.classList.remove("show");
    el.style.display = "none";
    document.body.classList.remove("modal-open");
    const backdrop = document.querySelector(`.modal-backdrop[data-modal="${id}"]`) || document.querySelector(".modal-backdrop");
    if (backdrop) backdrop.remove();
  }
};

window.openModal = function(id) { EP.openModal(id); };
window.closeModal = function(id) { EP.closeModal(id); };

document.addEventListener("click", function(e) {
  const dismissBtn = e.target.closest('[data-bs-dismiss="modal"]');
  if (dismissBtn) {
    const modal = dismissBtn.closest(".modal");
    if (modal) EP.closeModal(modal.id);
  }
});
