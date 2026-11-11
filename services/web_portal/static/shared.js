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
    if (el) el.innerHTML = `<div class="alert ${kind}">${this.escapeHtml(text)}</div>`;
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
