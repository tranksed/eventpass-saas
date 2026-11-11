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

  escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, m => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[m]));
  },

  showMsg(elId, kind, text) {
    const el = document.getElementById(elId);
    if (!el) return;
    const cls = kind === "ok" ? "alert-success" : kind === "warn" ? "alert-warning" : "alert-danger";
    el.innerHTML = `<div class="alert ${cls} py-2 px-3 small mb-0 mt-2">${this.escapeHtml(text)}</div>`;
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
    const links = [
      { key: "home", href: "/", icon: "bi-grid-1x2", label: "Eventos" },
      { key: "comprar", href: "/comprar", icon: "bi-ticket-perforated", label: "Taquilla" },
      { key: "validar", href: "/validar", icon: "bi-upc-scan", label: "Puerta" },
      { key: "acreditacion", href: "/acreditacion", icon: "bi-building-check", label: "Staff" },
      { key: "admin", href: "/admin", icon: "bi-speedometer2", label: "Dashboard" },
      { key: "reclamos", href: "/reclamos", icon: "bi-journal-bookmark", label: "Reclamos" },
    ];
    const navItems = links.map(l => `
      <li class="nav-item">
        <a class="nav-link ${l.key === activeKey ? "active" : ""}" href="${l.href}">
          <i class="bi ${l.icon} me-1"></i>${l.label}
        </a>
      </li>`).join("");

    const sessionHtml = s.token
      ? `<span class="badge text-bg-success py-2 px-3"><i class="bi bi-person-badge me-1"></i>${this.escapeHtml(s.slug || "tenant")} · ${this.escapeHtml(s.role)}</span>`
      : `<span class="badge text-bg-secondary py-2 px-3">Invitado</span>`;

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
    try { data = JSON.parse(txt); } catch { data = { detail: txt }; }
    if (!res.ok) throw new Error(`${res.status}: ${data.detail || txt}`);
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
  }
};
