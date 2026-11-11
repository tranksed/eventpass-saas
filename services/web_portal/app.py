"""BFF / API Gateway + Interactive Web Portal for EventPass SaaS.

Serves dedicated clean views:
- /             -> Portal launcher
- /comprar      -> Public ticket & interaction buyer portal (DNI + payment + QR)
- /validar      -> Private door validator portal (Online + Offline contingency)
- /acreditacion -> Private company staff registration link portal
- /admin        -> General SaaS organizer panel (Admin / Supervisor)
"""

from __future__ import annotations

import base64
import io
import json
from pathlib import Path

import httpx
import qrcode
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from shared_kernel.config import get_base_settings
from shared_kernel.crypto import sign_webhook_payload

STATIC_DIR = Path(__file__).parent / "static"


class SimulatePaymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order_id: str = Field(min_length=1, max_length=36)
    payment_reference: str = Field(default="GW_SIM_001", min_length=3, max_length=120)
    status: str = Field(default="PAID", pattern=r"^(PAID|FAILED)$")


class QRRenderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    qr_token: str = Field(min_length=10, max_length=4096)


def _html_page(filename: str) -> HTMLResponse:
    return HTMLResponse(content=(STATIC_DIR / filename).read_text(encoding="utf-8"))


def create_portal_app() -> FastAPI:
    cfg = get_base_settings()
    app = FastAPI(title="EventPass SaaS Web Portal & BFF", version="1.0.0")
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    routes_map = {
        "/api/v1/auth/": cfg.auth_service_url.rstrip("/"),
        "/api/v1/registration/": cfg.registration_service_url.rstrip("/"),
        "/api/v1/accreditation/": cfg.accreditation_service_url.rstrip("/"),
        "/api/v1/audit/": cfg.audit_service_url.rstrip("/"),
    }

    @app.get("/", response_class=HTMLResponse)
    async def home() -> HTMLResponse:
        return _html_page("home.html")

    @app.get("/comprar", response_class=HTMLResponse)
    async def comprar() -> HTMLResponse:
        return _html_page("comprar.html")

    @app.get("/validar", response_class=HTMLResponse)
    async def validar() -> HTMLResponse:
        return _html_page("validar.html")

    @app.get("/admin", response_class=HTMLResponse)
    async def admin() -> HTMLResponse:
        return _html_page("admin.html")

    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard() -> HTMLResponse:
        return _html_page("admin.html")

    @app.get("/acreditacion", response_class=HTMLResponse)
    async def acreditacion() -> HTMLResponse:
        return _html_page("acreditacion.html")

    @app.get("/reclamos", response_class=HTMLResponse)
    async def reclamos() -> HTMLResponse:
        return _html_page("reclamos.html")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "web-portal"}

    @app.post("/bff/qr-data-url")
    async def render_qr_data_url(payload: QRRenderRequest) -> dict[str, str]:
        """Render a real scannable PNG QR code as a base64 data URL."""
        img = qrcode.make(payload.qr_token)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        b64 = base64.b64encode(buf.getvalue()).decode("ascii")
        return {"data_url": f"data:image/png;base64,{b64}"}

    @app.post("/bff/simulate-payment")
    async def simulate_gateway_webhook(payload: SimulatePaymentRequest) -> dict:
        """Simulate an external payment gateway sending an HMAC-SHA256 signed webhook."""
        body_bytes = json.dumps(
            {
                "order_id": payload.order_id,
                "payment_reference": payload.payment_reference,
                "status": payload.status,
            }
        ).encode("utf-8")
        signature = sign_webhook_payload(body_bytes, cfg.payment_webhook_secret)
        reg_url = cfg.registration_service_url.rstrip("/")
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{reg_url}/api/v1/registration/webhooks/payment",
                content=body_bytes,
                headers={"X-Webhook-Signature": signature, "Content-Type": "application/json"},
            )
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()

    @app.api_route("/api/v1/{full_path:path}", methods=["GET", "POST", "PATCH", "PUT", "DELETE"])
    async def proxy_to_microservice(request: Request, full_path: str) -> Response:
        req_path = f"/api/v1/{full_path}"
        target_base = None
        for prefix, base_url in routes_map.items():
            if req_path.startswith(prefix):
                target_base = base_url
                break
        if target_base is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown API route.")

        query = f"?{request.url.query}" if request.url.query else ""
        target_url = f"{target_base}{req_path}{query}"
        fwd_headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in {"host", "content-length"}
        }
        body = await request.body()

        async with httpx.AsyncClient(timeout=15.0) as client:
            upstream = await client.request(
                method=request.method,
                url=target_url,
                headers=fwd_headers,
                content=body,
            )

        excluded = {"content-encoding", "transfer-encoding", "content-length"}
        resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}
        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type=upstream.headers.get("content-type"),
        )

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_portal_app(), host="127.0.0.1", port=8000)
