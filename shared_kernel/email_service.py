"""Email notification and styled QR generator service for EventPass SaaS.

Generates tickets and credentials with embedded high-resolution QR codes featuring
the event branding / logo, and dispatches them via SMTP or local simulation.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import io
import logging
from pathlib import Path
import smtplib
from typing import Any

import httpx
from PIL import Image, ImageDraw
import qrcode
from qrcode.constants import ERROR_CORRECT_H

from shared_kernel.config import BaseServiceSettings

logger = logging.getLogger("eventpass.email")


def generate_qr_with_logo(
    qr_token: str,
    logo_bytes: bytes | None = None,
    logo_url: str | None = None,
    brand_color: str = "#8b5cf6",
) -> bytes:
    """Generate a high-res scannable QR code PNG with the event logo or badge centered."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_H,  # 30% error correction enables center logo
        box_size=10,
        border=4,
    )
    qr.add_data(qr_token)
    qr.make(fit=True)

    qr_img = qr.make_image(fill_color="black", back_color="white").convert("RGBA")
    qr_w, qr_h = qr_img.size

    # Try loading logo from provided bytes
    logo_img: Image.Image | None = None
    if logo_bytes:
        try:
            logo_img = Image.open(io.BytesIO(logo_bytes)).convert("RGBA")
        except Exception:
            logo_img = None

    # Center box dimensions (~22% of QR dimensions)
    box_size = int(qr_w * 0.22)
    center_x = qr_w // 2
    center_y = qr_h // 2
    box_x0 = center_x - box_size // 2
    box_y0 = center_y - box_size // 2
    box_x1 = box_x0 + box_size
    box_y1 = box_y0 + box_size

    # Draw a clean circular or rounded badge background
    badge_bg = Image.new("RGBA", (box_size, box_size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(badge_bg)
    draw.rounded_rectangle(
        [(0, 0), (box_size - 1, box_size - 1)],
        radius=int(box_size * 0.25),
        fill=(255, 255, 255, 255),
        outline=(220, 226, 235, 255),
        width=2,
    )

    if logo_img:
        # Resize logo keeping aspect ratio to fit inside badge with margin
        margin = int(box_size * 0.15)
        avail = box_size - (margin * 2)
        logo_img.thumbnail((avail, avail), Image.Resampling.LANCZOS)
        lw, lh = logo_img.size
        lx = (box_size - lw) // 2
        ly = (box_size - lh) // 2
        badge_bg.paste(logo_img, (lx, ly), logo_img)
    else:
        # Draw clean ticket monogram if no logo image
        # Inner decorative colored circle
        inner_r = int(box_size * 0.35)
        draw.ellipse(
            [(box_size // 2 - inner_r, box_size // 2 - inner_r),
             (box_size // 2 + inner_r, box_size // 2 + inner_r)],
            fill=(139, 92, 246, 255),  # EventPass purple
        )

    # Paste badge onto QR image
    qr_img.paste(badge_bg, (box_x0, box_y0), badge_bg)

    output = io.BytesIO()
    qr_img.convert("RGB").save(output, format="PNG", quality=95)
    return output.getvalue()


def render_ticket_email_html(
    *,
    event_name: str,
    buyer_name: str,
    dni_last4: str,
    order_id: str,
    items_summary: str,
    total_soles: str,
    venue: str,
    venue_address: str = "",
    starts_at_str: str = "",
    brand_color: str = "#8b5cf6",
    portal_url: str = "",
) -> str:
    """Generate modern, responsive HTML email for ticket confirmation."""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Tus Entradas — {event_name}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #0f172a; padding: 24px 12px;">
    <tr>
      <td align="center">
        <!-- Main Container Card -->
        <table role="presentation" width="100%" style="max-width: 580px; background-color: #1e293b; border-radius: 16px; overflow: hidden; border: 1px solid #334155; box-shadow: 0 10px 25px rgba(0,0,0,0.4);">
          <!-- Header Banner -->
          <tr>
            <td style="background: linear-gradient(135deg, {brand_color}, #4f46e5); padding: 32px 24px; text-align: center;">
              <span style="display: inline-block; background-color: rgba(255,255,255,0.2); color: #ffffff; font-size: 11px; font-weight: 700; letter-spacing: 1.5px; text-transform: uppercase; padding: 4px 12px; border-radius: 9999px; margin-bottom: 12px;">Entrada Oficial Confirmada</span>
              <h1 style="margin: 0 0 8px 0; font-size: 24px; font-weight: 800; color: #ffffff; line-height: 1.2;">{event_name}</h1>
              <p style="margin: 0; font-size: 14px; color: rgba(255,255,255,0.9);">{venue} {f'— {venue_address}' if venue_address else ''}</p>
            </td>
          </tr>

          <!-- Greeting & Details -->
          <tr>
            <td style="padding: 24px 24px 12px 24px;">
              <p style="margin: 0 0 16px 0; font-size: 16px; color: #e2e8f0;">¡Hola <strong>{buyer_name}</strong>! Tu compra ha sido procesada con éxito. Aquí tienes tus entradas oficiales:</p>
              
              <!-- Event & Order Details Box -->
              <table role="presentation" width="100%" style="background-color: #0f172a; border-radius: 12px; padding: 16px; border: 1px solid #334155; margin-bottom: 24px;">
                <tr>
                  <td style="padding: 6px 12px; font-size: 13px; color: #94a3b8; width: 35%;">Fecha y Hora:</td>
                  <td style="padding: 6px 12px; font-size: 14px; color: #f8fafc; font-weight: 600;">{starts_at_str or 'Consultar cartelera'}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 12px; font-size: 13px; color: #94a3b8;">Titular / DNI:</td>
                  <td style="padding: 6px 12px; font-size: 14px; color: #f8fafc; font-weight: 600;">{buyer_name} (DNI •••• {dni_last4})</td>
                </tr>
                <tr>
                  <td style="padding: 6px 12px; font-size: 13px; color: #94a3b8;">Entradas / Ítems:</td>
                  <td style="padding: 6px 12px; font-size: 14px; color: #38bdf8; font-weight: 600;">{items_summary}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 12px; font-size: 13px; color: #94a3b8;">Total Pagado:</td>
                  <td style="padding: 6px 12px; font-size: 14px; color: #4ade80; font-weight: 700;">S/ {total_soles}</td>
                </tr>
                <tr>
                  <td style="padding: 6px 12px; font-size: 13px; color: #94a3b8;">Nº de Orden:</td>
                  <td style="padding: 6px 12px; font-size: 12px; font-family: monospace; color: #94a3b8;">{order_id}</td>
                </tr>
              </table>

              <!-- QR Presentation Box -->
              <table role="presentation" width="100%" style="background: linear-gradient(180deg, #1e293b, #0f172a); border-radius: 16px; border: 2px dashed #475569; padding: 24px; text-align: center; margin-bottom: 24px;">
                <tr>
                  <td align="center">
                    <p style="margin: 0 0 16px 0; font-size: 14px; font-weight: 600; color: #e2e8f0;">🎟️ TU CÓDIGO QR DE ACCESO EN PUERTA</p>
                    <div style="background-color: #ffffff; padding: 12px; border-radius: 12px; display: inline-block; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">
                      <img src="cid:ticket_qr" alt="Código QR de Acceso" width="220" height="220" style="display: block; border-radius: 8px;" />
                    </div>
                    <p style="margin: 16px 0 0 0; font-size: 12px; color: #94a3b8;">Presenta este código en tu teléfono o impreso directamente en los puntos de control del evento.</p>
                  </td>
                </tr>
              </table>

              <!-- Security Warning -->
              <p style="font-size: 12px; color: #64748b; line-height: 1.5; margin: 0 0 20px 0;">
                ⚠️ <strong>Importante:</strong> Este código QR es único y personal. No compartas capturas de pantalla en redes sociales para evitar duplicados en puerta.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background-color: #0f172a; padding: 16px 24px; text-align: center; border-top: 1px solid #334155;">
              <p style="margin: 0; font-size: 12px; color: #64748b;">Emitido por <strong>EventPass SaaS</strong> — Plataforma Segura de Entradas y Acreditación.</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def render_staff_credential_email_html(
    *,
    event_name: str,
    company_name: str,
    staff_name: str,
    role_title: str,
    dni_last4: str,
    venue: str = "",
    starts_at_str: str = "",
    brand_color: str = "#8b5cf6",
) -> str:
    """Generate HTML email for staff / sponsor accreditation credential."""
    return f"""<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Acreditación Staff — {event_name}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f8fafc;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #0f172a; padding: 24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width: 580px; background-color: #1e293b; border-radius: 16px; overflow: hidden; border: 1px solid #334155;">
          <tr>
            <td style="background: linear-gradient(135deg, #0ea5e9, #6366f1); padding: 28px 24px; text-align: center;">
              <span style="display: inline-block; background-color: rgba(255,255,255,0.2); color: #ffffff; font-size: 11px; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; padding: 4px 12px; border-radius: 9999px; margin-bottom: 8px;">Credencial de Acreditación</span>
              <h1 style="margin: 0 0 6px 0; font-size: 22px; font-weight: 800; color: #ffffff;">{event_name}</h1>
              <p style="margin: 0; font-size: 14px; color: rgba(255,255,255,0.9);">{company_name}</p>
            </td>
          </tr>
          <tr>
            <td style="padding: 24px;">
              <p style="margin: 0 0 16px 0; font-size: 15px; color: #e2e8f0;">Hola <strong>{staff_name}</strong>, tu acreditación como staff ha sido registrada con éxito:</p>
              
              <table role="presentation" width="100%" style="background-color: #0f172a; border-radius: 12px; padding: 14px; border: 1px solid #334155; margin-bottom: 20px;">
                <tr><td style="padding: 4px 8px; font-size: 13px; color: #94a3b8;">Empresa / Stand:</td><td style="padding: 4px 8px; font-size: 13px; font-weight: 600; color: #f8fafc;">{company_name}</td></tr>
                <tr><td style="padding: 4px 8px; font-size: 13px; color: #94a3b8;">Rol Asignado:</td><td style="padding: 4px 8px; font-size: 13px; font-weight: 600; color: #38bdf8;">{role_title}</td></tr>
                <tr><td style="padding: 4px 8px; font-size: 13px; color: #94a3b8;">Documento DNI:</td><td style="padding: 4px 8px; font-size: 13px; color: #f8fafc;">•••• {dni_last4}</td></tr>
                <tr><td style="padding: 4px 8px; font-size: 13px; color: #94a3b8;">Lugar:</td><td style="padding: 4px 8px; font-size: 13px; color: #f8fafc;">{venue}</td></tr>
              </table>

              <table role="presentation" width="100%" style="background: #0f172a; border-radius: 16px; border: 2px dashed #475569; padding: 20px; text-align: center; margin-bottom: 20px;">
                <tr>
                  <td align="center">
                    <p style="margin: 0 0 12px 0; font-size: 13px; font-weight: 600; color: #e2e8f0;">QR DE ACCESO PERSONAL STAFF</p>
                    <div style="background-color: #ffffff; padding: 10px; border-radius: 12px; display: inline-block;">
                      <img src="cid:ticket_qr" alt="QR Staff" width="200" height="200" style="display: block; border-radius: 6px;" />
                    </div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


def _send_smtp_sync(
    settings: BaseServiceSettings,
    to_email: str,
    subject: str,
    html_body: str,
    qr_png_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Synchronous SMTP worker execution."""
    msg = MIMEMultipart("related")
    msg["Subject"] = subject
    from_header = f"{settings.smtp_from_name} <{settings.smtp_from_email}>" if settings.smtp_from_name else settings.smtp_from_email
    msg["From"] = from_header
    msg["To"] = to_email

    # Attach alternative/html
    html_part = MIMEText(html_body, "html", "utf-8")
    msg.attach(html_part)

    # Attach embedded QR image
    if qr_png_bytes:
        img_part = MIMEImage(qr_png_bytes, _subtype="png")
        img_part.add_header("Content-ID", "<ticket_qr>")
        img_part.add_header("Content-Disposition", "inline", filename="ticket-qr.png")
        msg.attach(img_part)

    if settings.smtp_use_ssl or settings.smtp_port == 465:
        server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=10.0)
    else:
        server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10.0)

    try:
        if settings.smtp_use_tls and not settings.smtp_use_ssl and settings.smtp_port != 465:
            server.starttls()
        if settings.smtp_user and settings.smtp_password:
            server.login(settings.smtp_user, settings.smtp_password)
        server.send_message(msg)
        return {"status": "delivered", "recipient": to_email, "provider": "smtp"}
    finally:
        try:
            server.quit()
        except Exception:
            pass


async def send_email_async(
    settings: BaseServiceSettings,
    to_email: str,
    subject: str,
    html_body: str,
    qr_png_bytes: bytes | None = None,
) -> dict[str, Any]:
    """Dispatch email via SMTP (if configured) or simulation file log."""
    if not settings.smtp_host or settings.smtp_host.strip() == "":
        # Simulation mode: log and save copy for development/testing
        logger.info("[EMAIL SIMULATION] To: %s | Subject: %s", to_email, subject)
        try:
            sent_dir = settings.data_dir / "sent_emails"
            sent_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            safe_email = to_email.replace("@", "_at_").replace(".", "_")
            out_file = sent_dir / f"{ts}_{safe_email}.html"
            out_file.write_text(html_body, encoding="utf-8")
        except Exception:
            pass
        return {
            "status": "simulated",
            "recipient": to_email,
            "provider": "simulation",
            "message": "Email encolado y simulado localmente (sin servidor SMTP externo configurado).",
        }

    try:
        return await asyncio.to_thread(
            _send_smtp_sync,
            settings,
            to_email,
            subject,
            html_body,
            qr_png_bytes,
        )
    except Exception as exc:
        logger.error("Error sending email via SMTP to %s: %s", to_email, exc)
        return {
            "status": "failed",
            "recipient": to_email,
            "error": str(exc),
        }
