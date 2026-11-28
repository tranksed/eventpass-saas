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
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
import qrcode
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from shared_kernel.config import get_base_settings
from shared_kernel.crypto import load_ed25519_public_key, sign_webhook_payload
from shared_kernel.security import CurrentActor, Role, make_role_dependency
from services.web_portal.assistant import EventPassAssistant

STATIC_DIR = Path(__file__).parent / "static"


class SimulatePaymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order_id: str = Field(min_length=1, max_length=36)
    payment_reference: str = Field(default="GW_SIM_001", min_length=3, max_length=120)
    status: str = Field(default="PAID", pattern=r"^(PAID|FAILED)$")


class QRRenderRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    qr_token: str = Field(min_length=10, max_length=4096)


class AssistantCommandRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    message: str = Field(min_length=1, max_length=1000)
    event_id: str | None = Field(default=None, max_length=36)


def _html_page(filename: str) -> HTMLResponse:
    return HTMLResponse(
        content=(STATIC_DIR / filename).read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
    )


def create_portal_app() -> FastAPI:
    cfg = get_base_settings()
    shared_client: httpx.AsyncClient | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal shared_client
        shared_client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=5.0),
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=200),
        )
        yield
        if shared_client and not shared_client.is_closed:
            await shared_client.aclose()

    app = FastAPI(title="EventPass SaaS Web Portal & BFF", version="1.0.0", lifespan=lifespan)

    def _get_jwt_pub_key():
        return load_ed25519_public_key(cfg.keys_dir, "jwt")

    require_admin_or_superadmin = make_role_dependency(
        _get_jwt_pub_key, Role.ADMIN, Role.SUPERADMIN
    )

    assistant = EventPassAssistant(
        registration_service_url=cfg.registration_service_url,
        auth_service_url=cfg.auth_service_url,
        accreditation_service_url=cfg.accreditation_service_url,
        audit_service_url=cfg.audit_service_url,
    )

    @app.middleware("http")
    async def no_stale_static_cache(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache, must-revalidate"
        return response

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

    @app.get("/superadmin", response_class=HTMLResponse)
    async def superadmin() -> HTMLResponse:
        return _html_page("superadmin.html")

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "web-portal"}

    @app.post("/bff/assistant/command")
    async def assistant_command(
        payload: AssistantCommandRequest,
        request: Request,
        actor: CurrentActor = Depends(require_admin_or_superadmin),
    ) -> dict[str, Any]:
        """Execute a natural language operational command within the platform boundary."""
        auth_header = request.headers.get("authorization", "")
        token = auth_header.replace("Bearer ", "").strip() if "Bearer " in auth_header else auth_header
        return await assistant.execute_command(
            raw_message=payload.message,
            actor=actor,
            raw_token=token,
            event_id=payload.event_id,
            client=shared_client,
        )

    @app.post("/bff/qr-data-url")
    async def render_qr_data_url(payload: QRRenderRequest) -> dict[str, str]:
        """Render a high-resolution, pixel-crisp PNG QR code as a base64 data URL."""
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=12,
            border=4,
        )
        qr.add_data(payload.qr_token)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
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

        client = shared_client
        if client is None or client.is_closed:
            client = httpx.AsyncClient(timeout=15.0)

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
