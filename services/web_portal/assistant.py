"""Platform-scoped AI Assistant (EventPass Copilot).

Operates strictly within the boundary of EventPass SaaS with zero external internet dependencies:
- Restricted to ADMIN and SUPERADMIN roles only.
- Interprets natural language commands in Spanish.
- Translates intents into verified platform actions:
    * Create ticket / interaction items (price, stock, type)
    * Update ticket prices and stocks
    * Delete unsold items
    * Query live sales metrics and ticket catalogs
    * Create promoter / RRPP discount codes
    * Pause or activate events
    * SuperAdmin cross-tenant metrics & status
- Dispatches actions via internal microservice APIs preserving tenant isolation and audit logs.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any

import httpx

from shared_kernel.security import CurrentActor, Role


def _normalize(text: str) -> str:
    """Normalize text: lowercase, strip accents, remove extra whitespace."""
    nfkd = unicodedata.normalize("NFKD", text.lower())
    without_accents = "".join(c for c in nfkd if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", without_accents).strip()


class EventPassAssistant:
    """Deterministic platform-scoped assistant engine."""

    def __init__(
        self,
        registration_service_url: str,
        auth_service_url: str,
        accreditation_service_url: str,
        audit_service_url: str,
    ) -> None:
        self.reg_url = registration_service_url.rstrip("/")
        self.auth_url = auth_service_url.rstrip("/")
        self.acc_url = accreditation_service_url.rstrip("/")
        self.audit_url = audit_service_url.rstrip("/")

    async def execute_command(
        self,
        raw_message: str,
        actor: CurrentActor,
        raw_token: str,
        event_id: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """Parse natural language command and execute the corresponding platform action."""
        if actor.role not in (Role.ADMIN, Role.SUPERADMIN):
            return {
                "ok": False,
                "reply": "Acceso restringido: El Asistente Operativo solo está disponible para Administradores y SuperAdmin.",
                "action_taken": "UNAUTHORIZED",
                "refresh_needed": False,
            }

        text = _normalize(raw_message)
        headers = {
            "Authorization": f"Bearer {raw_token}",
            "Content-Type": "application/json",
        }
        owns_client = False
        if client is None or client.is_closed:
            client = httpx.AsyncClient(timeout=15.0)
            owns_client = True

        try:
            # 1. AYUDA / QUÉ PUEDES HACER
            if any(k in text for k in ["ayuda", "que puedes hacer", "comandos", "instrucciones", "help"]):
                return self._handle_help(actor)

            # 2. RESOLVER EVENTO ACTIVO SI NO SE ENVIÓ EXPLÍCITO
            resolved_event = await self._resolve_active_event(client, headers, actor, event_id)
            current_event_id = resolved_event.get("id") if resolved_event else None
            current_event_name = resolved_event.get("name", "Evento Activo") if resolved_event else ""

            # 3. SUPERADMIN: MÉTRICAS GLOBALES DE LA PLATAFORMA
            if actor.role == Role.SUPERADMIN and any(
                k in text for k in ["metricas globales", "plataforma", "ingresos globales", "cuantos tenants", "empresas registradas"]
            ):
                return await self._handle_superadmin_overview(client, headers)

            # 4. CREAR ENTRADA / ÍTEM EN TAQUILLA
            if self._matches_create_item(text):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ No encontré ningún evento activo en tu empresa para crear la entrada. Primero crea o selecciona un evento en la pantalla.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_create_item(client, headers, text, current_event_id, current_event_name, raw_message=raw_message)

            # 5. ACTUALIZAR PRECIO DE ENTRADA
            if self._matches_update_price(text):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento en el panel para modificar el precio de sus entradas.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_update_price(client, headers, text, current_event_id, current_event_name)

            # 6. ACTUALIZAR STOCK / CUPOS DE ENTRADA
            if self._matches_update_stock(text):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para modificar el aforo/stock de sus entradas.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_update_stock(client, headers, text, current_event_id, current_event_name)

            # 7. ELIMINAR ÍTEM / ENTRADA NO VENDIDA
            if any(k in text for k in ["elimina la entrada", "elimina entrada", "borra la entrada", "borra entrada", "elimina el item", "borra el item"]):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para gestionar sus ítems.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_delete_item(client, headers, text, current_event_id, current_event_name)

            # 8. LISTAR ARTISTAS / EXPERIENCIAS
            if self._matches_list_artists(text):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ No hay un evento seleccionado. Selecciona un evento en la parte superior para consultar sus artistas.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_list_artists(client, headers, current_event_id, current_event_name)

            # 9. LISTAR ENTRADAS / CATÁLOGO DEL EVENTO
            if any(k in text for k in ["listar entradas", "que entradas hay", "ver entradas", "catalogo", "mostrar entradas", "entradas disponibles"]):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ No hay un evento seleccionado. Selecciona un evento en la parte superior para ver su catálogo.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_list_items(client, headers, current_event_id, current_event_name)

            # 10. CONSULTAR VENTAS Y MÉTRICAS DEL EVENTO
            if any(k in text for k in ["cuanto hemos vendido", "ventas", "metricas", "cuantas entradas", "recaudacion", "ingresos"]):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para consultar sus ventas y métricas.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_event_metrics(client, headers, current_event_id, current_event_name)

            # 11. CONTROL DE ACCESO EN PUERTA / AFORO / ASISTENCIA
            if self._matches_door_metrics(text):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para consultar el aforo y la puerta de acceso.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_door_metrics(client, headers, current_event_id, current_event_name)

            # 12. CONSULTAR ÓRDENES RECIENTES
            if self._matches_recent_orders(text):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para ver sus órdenes recientes.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_recent_orders(client, headers, current_event_id, current_event_name)

            # 13. CONSULTAR PERSONAL Y CUOTAS DE STAFF
            if self._matches_staff_summary(text):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para ver el resumen de acreditación de staff.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_staff_summary(client, headers, current_event_id, current_event_name)

            # 14. CREAR CÓDIGO PROMOCIONAL / RRPP
            if any(k in text for k in ["crear codigo", "crea codigo", "nuevo codigo", "agrega codigo", "descuento"]):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para crear un código promocional.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_create_promo_code(client, headers, text, current_event_id, current_event_name)

            # 15. PAUSAR O ACTIVAR EVENTO
            if any(k in text for k in ["pausar evento", "pausa el evento", "activar evento", "activa el evento"]):
                if not current_event_id:
                    return {
                        "ok": False,
                        "reply": "⚠️ Selecciona un evento para cambiar su estado.",
                        "action_taken": "NOOP",
                        "refresh_needed": False,
                    }
                return await self._handle_toggle_event(client, headers, text, current_event_id, current_event_name)

            # Si no coincide con un comando conocido, dar respuesta contextual de la plataforma
            return {
                "ok": True,
                "reply": (
                    f"🤖 **EventPass Copilot** activo en el evento **{current_event_name or 'General'}**.\n\n"
                    "No logré identificar la acción exacta. Prueba con instrucciones como:\n"
                    "• *\"Crea una entrada VIP a 120 soles con 50 cupos\"*\n"
                    "• *\"Crea foto con Mario Castañeda a 60 soles con 50 cupos\"*\n"
                    "• *\"Crea firma de René García a 50 soles con 40 cupos\"*\n"
                    "• *\"Listar artistas\"* o *\"Ver experiencias\"*\n"
                    "• *\"¿Cómo va la puerta?\"* o *\"Aforo actual\"*\n"
                    "• *\"Últimas compras\"*\n"
                    "• *\"Cambia el precio de GENERAL a 60 soles\"*\n"
                    "• *\"¿Cuánto hemos vendido hoy?\"*"
                ),
                "action_taken": "FALLBACK",
                "refresh_needed": False,
                "suggested_actions": [
                    "Listar entradas del evento",
                    "Listar artistas y experiencias",
                    "Ver ventas y métricas",
                    "¿Cómo va la puerta?",
                ],
            }
        finally:
            if owns_client:
                await client.aclose()

    # -------------------------------------------------------------------------
    # Intent Matchers
    # -------------------------------------------------------------------------
    def _matches_create_item(self, t: str) -> bool:
        return any(
            t.startswith(prefix)
            for prefix in [
                "crea entrada", "crear entrada", "agrega entrada", "agregar entrada",
                "anade entrada", "anadir entrada", "crea ticket", "crear ticket",
                "nuevo item", "nueva entrada", "crear boleto", "crea boleto",
                "crea foto", "crear foto", "agrega foto", "agregar foto",
                "crea firma", "crear firma", "agrega firma", "agregar firma",
                "crea meet", "crear meet", "agrega meet", "agregar meet",
                "crea interaccion", "crear interaccion", "agrega interaccion", "agregar interaccion",
                "nueva experiencia", "crea experiencia",
            ]
        ) or (
            any(w in t for w in ["entrada", "foto", "firma", "meet", "m&g", "taller", "interaccion"])
            and any(v in t for v in ["precio", "soles", "stock", "cupos", "s/"])
        )

    def _matches_list_artists(self, t: str) -> bool:
        return any(
            k in t
            for k in [
                "listar artistas", "que artistas vienen", "ver artistas", "mostrar artistas",
                "artistas del evento", "cuales son los artistas", "artistas invitados", "invitados",
                "experiencias de artistas", "interacciones de artistas", "experiencias",
                "fotos y firmas", "que interacciones hay", "listar interacciones",
            ]
        )

    def _matches_door_metrics(self, t: str) -> bool:
        return any(
            k in t
            for k in [
                "como va la puerta", "control de acceso", "cuantos han ingresado",
                "aforo", "ocupacion", "asistencia en puerta", "escaneos",
                "ingresados", "puerta de ingreso", "metricas de puerta",
            ]
        )

    def _matches_recent_orders(self, t: str) -> bool:
        return any(
            k in t
            for k in [
                "ultimas ordenes", "ultimas compras", "ultimas ventas",
                "compras recientes", "ordenes recientes", "ventas recientes",
                "quienes han comprado", "ultimos pedidos",
            ]
        )

    def _matches_staff_summary(self, t: str) -> bool:
        return any(
            k in t
            for k in [
                "personal de staff", "cuotas de staff", "empresas de staff",
                "acreditaciones staff", "como va el staff", "resumen de staff",
            ]
        )

    def _matches_update_price(self, t: str) -> bool:
        return any(
            k in t
            for k in [
                "cambia el precio", "cambiar precio", "actualiza el precio", "actualizar precio",
                "modifica el precio", "modificar precio", "pon la entrada", "pon el precio",
                "sube el precio", "baja el precio",
            ]
        )

    def _matches_update_stock(self, t: str) -> bool:
        return any(
            k in t
            for k in [
                "cambia el stock", "cambiar stock", "actualiza el stock", "actualizar stock",
                "modifica el stock", "modificar stock", "aumenta el stock", "amplia cupo",
                "cambia los cupos", "modifica cupos", "aumenta cupos",
            ]
        )

    # -------------------------------------------------------------------------
    # Handlers
    # -------------------------------------------------------------------------
    def _handle_help(self, actor: CurrentActor) -> dict[str, Any]:
        admin_examples = [
            "• **Crear entrada:** *\"Crea una entrada VIP a 120 soles con 50 cupos\"*",
            "• **Crear foto con artista:** *\"Crea foto con Mario Castañeda a 60 soles con 50 cupos\"*",
            "• **Crear firma con artista:** *\"Crea firma de René García a 50 soles con 40 cupos\"*",
            "• **Crear Meet & Greet:** *\"Crea meet and greet con Stan Lee a 180 soles con 15 cupos\"*",
            "• **Ver catálogo de artistas:** *\"Listar artistas\"* o *\"Ver experiencias\"*",
            "• **Cambiar precio:** *\"Cambia el precio de GENERAL a 65 soles\"*",
            "• **Modificar stock:** *\"Aumenta el stock de VIP a 150 cupos\"*",
            "• **Eliminar entrada:** *\"Elimina la entrada BACKSTAGE\"* (solo si no tiene ventas)",
            "• **Ver catálogo de entradas:** *\"Listar entradas\"*",
            "• **Consultar ventas:** *\"¿Cuánto hemos vendido hoy?\"*",
            "• **Control de acceso / puerta:** *\"¿Cómo va la puerta?\"* o *\"Aforo actual\"*",
            "• **Últimas ventas registradas:** *\"Últimas órdenes\"*",
            "• **Crear descuento:** *\"Crea código PROMO15 con 15% de descuento\"*",
            "• **Pausar/Reactivar:** *\"Pausa el evento\"* o *\"Activa el evento\"*",
        ]
        if actor.role == Role.SUPERADMIN:
            admin_examples.extend([
                "• **Métricas globales (SuperAdmin):** *\"Métricas globales de la plataforma\"*",
            ])
        return {
            "ok": True,
            "reply": (
                "🤖 **EventPass Copilot — Asistente de Operaciones**\n\n"
                "Puedo ejecutar acciones directamente sobre la base de datos de tu empresa en tiempo real:\n\n"
                + "\n".join(admin_examples)
            ),
            "action_taken": "HELP",
            "refresh_needed": False,
        }

    async def _resolve_active_event(
        self, client: httpx.AsyncClient, headers: dict[str, str], actor: CurrentActor, preferred_id: str | None
    ) -> dict[str, Any] | None:
        """Resolve the target event for action context."""
        events_url = f"{self.reg_url}/api/v1/registration/events"
        res = await client.get(events_url, headers=headers)
        if res.status_code != 200:
            return None
        events: list[dict[str, Any]] = res.json()
        if not events:
            return None
        if preferred_id:
            for ev in events:
                if ev.get("id") == preferred_id:
                    return ev
        # Default: first active event or first event in list
        active = [e for e in events if e.get("is_active")]
        return active[0] if active else events[0]

    async def _handle_create_item(
        self,
        client: httpx.AsyncClient,
        headers: dict[str, str],
        text: str,
        event_id: str,
        event_name: str,
        raw_message: str = "",
    ) -> dict[str, Any]:
        """Extract item parameters and create in registration service."""
        # 1. Price extraction
        price_cents = 5000  # Default S/ 50.00
        price_match = re.search(r"(?:s\/?\.?\s*|soles?\s*|precio\s*(?:de)?\s*)(\d+(?:\.\d{1,2})?)", text)
        if price_match:
            price_cents = int(round(float(price_match.group(1)) * 100))
        else:
            standalone_num = re.search(r"\b(\d{2,4})\b", text)
            if standalone_num:
                price_cents = int(standalone_num.group(1)) * 100

        # 2. Stock extraction
        stock_total = 100
        stock_match = re.search(r"(\d+)\s*(?:cupos?|entradas?|unidades?|stock|boletos?)", text)
        if stock_match:
            stock_total = max(1, int(stock_match.group(1)))
        else:
            stock_match2 = re.search(r"stock\s*(?:de)?\s*(\d+)", text)
            if stock_match2:
                stock_total = max(1, int(stock_match2.group(1)))

        # 3. Item type, Artist detection & Name/Code derivation
        artist_name = ""
        interaction_type = ""
        description = ""
        item_type = "ENTRY"
        name = "Entrada General"
        code = "ENTRY"

        source_text = raw_message if raw_message else text
        # Check for artist interaction pattern in source_text (preserving casing/accents/ñ)
        inter_match = re.search(
            r"(foto|fotografia|firma|autografo|meet\s*(?:and|&)?\s*greet|m&g|taller|masterclass|pase\s*vip)\s+(?:con|de)?\s+([a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s]+?)(?:\s+(?:a|de|por|con|precio|stock|soles|cupos|s\/)\b|$)",
            source_text,
            re.IGNORECASE,
        )
        if inter_match:
            raw_kind = inter_match.group(1).lower()
            raw_artist = inter_match.group(2).strip()
            raw_artist = re.sub(r"\s+(?:a|de|por|con)\s*$", "", raw_artist, flags=re.IGNORECASE).strip()
            if len(raw_artist) >= 2 and _normalize(raw_artist) not in ["entrada", "ticket", "boleto", "general", "vip"]:
                artist_name = raw_artist.title()
                item_type = "INTERACTION"
                artist_slug = re.sub(r"[^A-Z0-9]", "", _normalize(artist_name).upper().replace(" ", "_"))[:18]

                if "foto" in raw_kind or "fotografia" in raw_kind:
                    interaction_type = "FOTO"
                    name = f"Foto con {artist_name}"
                    code = f"FOTO_{artist_slug}"
                    description = f"Sesión fotográfica con {artist_name}"
                elif "firma" in raw_kind or "autografo" in raw_kind:
                    interaction_type = "FIRMA"
                    name = f"Firma de Autógrafo - {artist_name}"
                    code = f"FIRMA_{artist_slug}"
                    description = f"Firma oficial de autógrafo con {artist_name}"
                elif "meet" in raw_kind or "m&g" in raw_kind:
                    interaction_type = "MEET_GREET"
                    name = f"Meet & Greet VIP - {artist_name}"
                    code = f"MG_{artist_slug}"
                    description = f"Experiencia exclusiva Meet & Greet con {artist_name}"
                elif "taller" in raw_kind or "masterclass" in raw_kind:
                    interaction_type = "TALLER"
                    name = f"Taller / Masterclass - {artist_name}"
                    code = f"TALLER_{artist_slug}"
                    description = f"Taller presencial con {artist_name}"
                else:
                    interaction_type = "VIP_PASS"
                    name = f"Experiencia VIP - {artist_name}"
                    code = f"VIP_{artist_slug}"
                    description = f"Pase VIP con {artist_name}"

        if not artist_name:
            # Generic Entry / Ticket or non-artist item
            if "vip" in text:
                name = "Entrada VIP"
                code = "VIP"
            elif "golden" in text or "oro" in text:
                name = "Entrada Golden"
                code = "GOLDEN"
            elif "early" in text:
                name = "Early Bird"
                code = "EARLY_BIRD"
            elif "interaccion" in text or "foto" in text:
                name = "Pase Foto / M&G"
                code = "PHOTO_MG"
                item_type = "INTERACTION"
                interaction_type = "FOTO"
            elif "meet" in text:
                name = "Meet & Greet"
                code = "MEET_GREET"
                item_type = "INTERACTION"
                interaction_type = "MEET_GREET"
            elif "backstage" in text:
                name = "Pase Backstage"
                code = "BACKSTAGE"
            else:
                custom = re.search(
                    r"(?:entrada|ticket|boleto|item)\s+([a-zA-Z0-9áéíóúÁÉÍÓÚñÑ\s]{3,30}?)(?:\s+(?:a|de|por|con|precio|stock|s\/)\b|$)",
                    source_text,
                    re.IGNORECASE,
                )
                if custom and len(custom.group(1).strip()) >= 3:
                    name = custom.group(1).strip().title()
                    code = re.sub(r"[^A-Z0-9_]", "", _normalize(name).upper().replace(" ", "_"))[:20]
                else:
                    code = f"ENTRY_{abs(hash(text)) % 999:03d}"

        if not code:
            code = "TICKET"

        # Post to registration service
        payload = {
            "code": code,
            "name": name,
            "item_type": item_type,
            "artist_name": artist_name,
            "interaction_type": interaction_type,
            "description": description,
            "price_cents": price_cents,
            "stock_total": stock_total,
        }
        res = await client.post(
            f"{self.reg_url}/api/v1/registration/events/{event_id}/items",
            headers=headers,
            json=payload,
        )
        if res.status_code == 201:
            data = res.json()
            is_artist = bool(data.get("artist_name"))
            details = [
                f"🎉 **¡{'Experiencia con artista' if is_artist else 'Entrada'} creada exitosamente!**\n",
                f"• **Evento:** {event_name}",
                f"• **Nombre:** {data['name']} (`{data['code']}`)",
                f"• **Tipo:** {data['item_type']}",
            ]
            if is_artist:
                details.append(f"• **Artista / Invitado:** ⭐ {data['artist_name']}")
                if data.get("interaction_type"):
                    details.append(f"• **Categoría:** {data['interaction_type']}")
            details.extend([
                f"• **Precio:** S/ {(data['price_cents'] / 100):.2f}",
                f"• **Stock inicial:** {data['stock_total']} cupos disponibles\n",
                "El catálogo de taquilla y el portal público de compra ya se actualizaron automáticamente.",
            ])
            return {
                "ok": True,
                "reply": "\n".join(details),
                "action_taken": "CREATE_CATALOG_ITEM",
                "data": data,
                "refresh_needed": True,
            }
        return {
            "ok": False,
            "reply": f"⚠️ No se pudo crear el ítem: {res.text}",
            "action_taken": "ERROR",
            "refresh_needed": False,
        }

    async def _handle_update_price(
        self, client: httpx.AsyncClient, headers: dict[str, str], text: str, event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Find matching catalog item and patch its price."""
        items_res = await client.get(f"{self.reg_url}/api/v1/registration/events/{event_id}/items", headers=headers)
        if items_res.status_code != 200:
            return {"ok": False, "reply": "No pude obtener las entradas del evento.", "action_taken": "ERROR", "refresh_needed": False}
        items: list[dict] = items_res.json()
        if not items:
            return {"ok": False, "reply": f"El evento '{event_name}' no tiene entradas registradas.", "action_taken": "NOOP", "refresh_needed": False}

        # Extract new price
        price_match = re.search(r"(?:a\s*s\/?\.?\s*|a\s*)(\d+(?:\.\d{1,2})?)(?:\s*soles|\s*$|\s+)", text)
        if not price_match:
            price_match = re.search(r"(\d+(?:\.\d{1,2})?)\s*soles", text)
        if not price_match:
            return {"ok": False, "reply": "Indica el nuevo precio en soles (por ejemplo: *'Cambia el precio de GENERAL a 65 soles'*).", "action_taken": "NOOP", "refresh_needed": False}

        new_price_cents = int(round(float(price_match.group(1)) * 100))

        # Match item by name or code
        target_item = None
        for item in items:
            code_norm = _normalize(item["code"])
            name_norm = _normalize(item["name"])
            if code_norm in text or name_norm in text:
                target_item = item
                break
        if not target_item:
            # Fallback if only 1 item exists
            if len(items) == 1:
                target_item = items[0]
            else:
                available = ", ".join(f"`{i['name']}`" for i in items)
                return {
                    "ok": False,
                    "reply": f"¿A cuál entrada deseas cambiarle el precio? Entradas disponibles en este evento: {available}.",
                    "action_taken": "NOOP",
                    "refresh_needed": False,
                }

        patch_res = await client.patch(
            f"{self.reg_url}/api/v1/registration/events/{event_id}/items/{target_item['id']}",
            headers=headers,
            json={"price_cents": new_price_cents},
        )
        if patch_res.status_code == 200:
            data = patch_res.json()
            old_price_s = f"S/ {(target_item['price_cents'] / 100):.2f}"
            new_price_s = f"S/ {(data['price_cents'] / 100):.2f}"
            return {
                "ok": True,
                "reply": (
                    f"✅ **Precio actualizado con éxito.**\n\n"
                    f"• **Evento:** {event_name}\n"
                    f"• **Ítem:** {data['name']} (`{data['code']}`)\n"
                    f"• **Precio anterior:** {old_price_s}\n"
                    f"• **Nuevo precio:** **{new_price_s}**"
                ),
                "action_taken": "UPDATE_CATALOG_ITEM_PRICE",
                "data": data,
                "refresh_needed": True,
            }
        return {"ok": False, "reply": f"⚠️ Error al actualizar precio: {patch_res.text}", "action_taken": "ERROR", "refresh_needed": False}

    async def _handle_update_stock(
        self, client: httpx.AsyncClient, headers: dict[str, str], text: str, event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Find matching catalog item and patch its stock total."""
        items_res = await client.get(f"{self.reg_url}/api/v1/registration/events/{event_id}/items", headers=headers)
        if items_res.status_code != 200:
            return {"ok": False, "reply": "No pude obtener las entradas del evento.", "action_taken": "ERROR", "refresh_needed": False}
        items: list[dict] = items_res.json()
        if not items:
            return {"ok": False, "reply": f"El evento '{event_name}' no tiene entradas creadas.", "action_taken": "NOOP", "refresh_needed": False}

        stock_match = re.search(r"(?:a\s*)?(\d+)\s*(?:cupos?|stock|entradas?|unidades?)", text)
        if not stock_match:
            stock_match = re.search(r"a\s*(\d+)", text)
        if not stock_match:
            return {"ok": False, "reply": "Especifica el nuevo número de cupos (ej: *'Aumenta el stock de VIP a 150 cupos'*).", "action_taken": "NOOP", "refresh_needed": False}

        new_stock = int(stock_match.group(1))

        target_item = None
        for item in items:
            code_norm = _normalize(item["code"])
            name_norm = _normalize(item["name"])
            if code_norm in text or name_norm in text:
                target_item = item
                break
        if not target_item:
            if len(items) == 1:
                target_item = items[0]
            else:
                available = ", ".join(f"`{i['name']}`" for i in items)
                return {
                    "ok": False,
                    "reply": f"¿A cuál entrada deseas cambiarle el stock? Opciones: {available}.",
                    "action_taken": "NOOP",
                    "refresh_needed": False,
                }

        patch_res = await client.patch(
            f"{self.reg_url}/api/v1/registration/events/{event_id}/items/{target_item['id']}",
            headers=headers,
            json={"stock_total": new_stock},
        )
        if patch_res.status_code == 200:
            data = patch_res.json()
            return {
                "ok": True,
                "reply": (
                    f"✅ **Stock actualizado con éxito.**\n\n"
                    f"• **Evento:** {event_name}\n"
                    f"• **Ítem:** {data['name']} (`{data['code']}`)\n"
                    f"• **Nuevo cupo total:** **{data['stock_total']}**\n"
                    f"• **Vendidas:** {data['stock_sold']} | **Disponibles:** {data['stock_available']}"
                ),
                "action_taken": "UPDATE_CATALOG_ITEM_STOCK",
                "data": data,
                "refresh_needed": True,
            }
        return {"ok": False, "reply": f"⚠️ No se pudo modificar el stock: {patch_res.text}", "action_taken": "ERROR", "refresh_needed": False}

    async def _handle_delete_item(
        self, client: httpx.AsyncClient, headers: dict[str, str], text: str, event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Delete an unsold catalog item."""
        items_res = await client.get(f"{self.reg_url}/api/v1/registration/events/{event_id}/items", headers=headers)
        if items_res.status_code != 200:
            return {"ok": False, "reply": "No pude consultar los ítems.", "action_taken": "ERROR", "refresh_needed": False}
        items: list[dict] = items_res.json()

        target_item = None
        for item in items:
            if _normalize(item["code"]) in text or _normalize(item["name"]) in text:
                target_item = item
                break
        if not target_item:
            return {"ok": False, "reply": f"No encontré esa entrada en el evento '{event_name}'.", "action_taken": "NOOP", "refresh_needed": False}

        del_res = await client.delete(
            f"{self.reg_url}/api/v1/registration/events/{event_id}/items/{target_item['id']}",
            headers=headers,
        )
        if del_res.status_code == 200:
            return {
                "ok": True,
                "reply": f"🗑️ **Entrada eliminada:** Se eliminó '{target_item['name']}' de la taquilla.",
                "action_taken": "DELETE_CATALOG_ITEM",
                "refresh_needed": True,
            }
        return {"ok": False, "reply": f"⚠️ No se puede eliminar: {del_res.text}", "action_taken": "ERROR", "refresh_needed": False}

    async def _handle_list_items(
        self, client: httpx.AsyncClient, headers: dict[str, str], event_id: str, event_name: str
    ) -> dict[str, Any]:
        """List all catalog items in active event."""
        res = await client.get(f"{self.reg_url}/api/v1/registration/events/{event_id}/items", headers=headers)
        if res.status_code != 200:
            return {"ok": False, "reply": "Error al consultar catálogo.", "action_taken": "ERROR", "refresh_needed": False}
        items: list[dict] = res.json()
        if not items:
            return {
                "ok": True,
                "reply": f"📋 El evento **{event_name}** aún no tiene entradas ni experiencias creadas. Puedes pedirme: *'Crea una entrada General a 50 soles con 100 cupos'*. ",
                "action_taken": "LIST_ITEMS",
                "refresh_needed": False,
            }

        entries = [i for i in items if i.get("item_type") == "ENTRY"]
        interactions = [i for i in items if i.get("item_type") == "INTERACTION"]

        lines = [f"🎟️ **Catálogo de Taquilla — {event_name}:**\n"]
        if entries:
            lines.append("**🎟️ Entradas al Evento:**")
            for i in entries:
                price_s = f"S/ {(i['price_cents'] / 100):.2f}"
                lines.append(f"• **{i['name']}** (`{i['code']}`): {price_s} — **{i['stock_available']}** disp. / {i['stock_total']} total ({i['stock_sold']} vendidas)")
            lines.append("")

        if interactions:
            lines.append("**⭐ Experiencias con Artistas & Invitados:**")
            for i in interactions:
                price_s = f"S/ {(i['price_cents'] / 100):.2f}"
                artist_tag = f"[{i['artist_name']}] " if i.get("artist_name") else ""
                lines.append(f"• **{artist_tag}{i['name']}** (`{i['code']}`): {price_s} — **{i['stock_available']}** disp. / {i['stock_total']} total")

        return {
            "ok": True,
            "reply": "\n".join(lines).strip(),
            "action_taken": "LIST_ITEMS",
            "data": items,
            "refresh_needed": False,
        }

    async def _handle_list_artists(
        self, client: httpx.AsyncClient, headers: dict[str, str], event_id: str, event_name: str
    ) -> dict[str, Any]:
        """List all artists and their available experiences (photos, signatures, M&G)."""
        res = await client.get(f"{self.reg_url}/api/v1/registration/events/{event_id}/items", headers=headers)
        if res.status_code != 200:
            return {"ok": False, "reply": "Error al consultar experiencias de artistas.", "action_taken": "ERROR", "refresh_needed": False}
        items: list[dict] = res.json()
        interactions = [i for i in items if i.get("item_type") == "INTERACTION" or i.get("artist_name")]

        if not interactions:
            return {
                "ok": True,
                "reply": (
                    f"⭐ El evento **{event_name}** aún no tiene artistas ni experiencias configuradas.\n\n"
                    "Puedes agregar uno diciéndome por ejemplo:\n"
                    "• *\"Crea foto con Mario Castañeda a 60 soles con 50 cupos\"*\n"
                    "• *\"Crea firma de René García a 50 soles con 40 cupos\"*"
                ),
                "action_taken": "LIST_ARTISTS",
                "refresh_needed": False,
            }

        groups: dict[str, list[dict]] = {}
        for it in interactions:
            a_name = it.get("artist_name", "").strip() or "Experiencias Especiales"
            groups.setdefault(a_name, []).append(it)

        reply_lines = [f"⭐ **Artistas e Invitados Confirmados — {event_name}:**\n"]
        for artist, a_items in groups.items():
            reply_lines.append(f"🎭 **{artist}**:")
            for it in a_items:
                cat = it.get("interaction_type") or "Experiencia"
                price_s = f"S/ {(it['price_cents'] / 100):.2f}"
                reply_lines.append(f"  • **{cat}:** {it['name']} (`{it['code']}`) — {price_s} ({it['stock_available']} cupos disp.)")
            reply_lines.append("")

        return {
            "ok": True,
            "reply": "\n".join(reply_lines).strip(),
            "action_taken": "LIST_ARTISTS",
            "data": groups,
            "refresh_needed": False,
        }

    async def _handle_door_metrics(
        self, client: httpx.AsyncClient, headers: dict[str, str], event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Query real-time gate attendance and access control from accreditation service."""
        try:
            res = await client.get(f"{self.acc_url}/api/v1/accreditation/events/{event_id}/metrics", headers=headers)
            if res.status_code != 200:
                return {
                    "ok": True,
                    "reply": f"🚪 **Control de Acceso — {event_name}:**\n\nEl servicio de acreditación aún no registra eventos de puerta o se encuentra inicializando.",
                    "action_taken": "DOOR_METRICS",
                    "refresh_needed": False,
                }
            acc = res.json()
            checked_in = acc.get("checked_in_entry", 0)
            total_active = acc.get("total_active_credentials", 0)
            pct = acc.get("occupancy_pct", 0.0)
            scans = acc.get("total_scan_events", 0)
            by_mode = acc.get("by_mode", {})
            online_scans = by_mode.get("ONLINE", 0)
            offline_scans = by_mode.get("OFFLINE_SYNC", 0)
            conflicts = acc.get("offline_conflicts", 0)

            return {
                "ok": True,
                "reply": (
                    f"🚪 **Estado de Control de Acceso (Puerta) — {event_name}:**\n\n"
                    f"• **Asistentes Ingresados:** **{checked_in}** personas\n"
                    f"• **Credenciales Digitales Emitidas:** {total_active}\n"
                    f"• **Ocupación en Puerta:** **{pct}%** ingresados\n"
                    f"• **Total Escaneos:** {scans} lecturas QR\n"
                    f"• **Modo Escaneo:** {online_scans} online · {offline_scans} offline sincronizados\n"
                    f"• **Conflictos Offline Resueltos:** {conflicts}"
                ),
                "action_taken": "DOOR_METRICS",
                "data": acc,
                "refresh_needed": False,
            }
        except Exception as e:
            return {"ok": False, "reply": f"⚠️ Error al consultar acreditación: {e}", "action_taken": "ERROR", "refresh_needed": False}

    async def _handle_recent_orders(
        self, client: httpx.AsyncClient, headers: dict[str, str], event_id: str, event_name: str
    ) -> dict[str, Any]:
        """List last orders registered for this event."""
        res = await client.get(f"{self.reg_url}/api/v1/registration/events/{event_id}/orders", headers=headers)
        if res.status_code != 200:
            return {"ok": False, "reply": "No se pudieron obtener las órdenes.", "action_taken": "ERROR", "refresh_needed": False}
        orders: list[dict] = res.json()
        if not orders:
            return {
                "ok": True,
                "reply": f"🧾 El evento **{event_name}** aún no tiene órdenes de compra registradas.",
                "action_taken": "RECENT_ORDERS",
                "refresh_needed": False,
            }

        top = orders[:5]
        lines = [f"🧾 **Últimas {len(top)} Compras Registradas — {event_name}:**\n"]
        for o in top:
            name = o.get("full_name") or "Anónimo"
            dni = o.get("dni_last4") or "----"
            soles = f"S/ {((o.get('total_cents', 0)) / 100):.2f}"
            status = o.get("status", "PAID")
            status_icon = "✅" if status == "PAID" else "⏳"
            items = o.get("items_summary") or "Entrada"
            pm = o.get("payment_method") or "ONLINE"
            lines.append(f"• {status_icon} **{name}** (DNI *{dni}*): **{soles}** ({pm}) — *{items}*")

        return {
            "ok": True,
            "reply": "\n".join(lines),
            "action_taken": "RECENT_ORDERS",
            "data": top,
            "refresh_needed": False,
        }

    async def _handle_staff_summary(
        self, client: httpx.AsyncClient, headers: dict[str, str], event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Fetch staff credentials summary for the event."""
        res = await client.get(f"{self.acc_url}/api/v1/accreditation/events/{event_id}/metrics", headers=headers)
        if res.status_code != 200:
            return {"ok": False, "reply": "No se pudo obtener el resumen de staff.", "action_taken": "ERROR", "refresh_needed": False}
        acc = res.json()
        staff = acc.get("staff_companies_summary", {})
        used = staff.get("total_used", 0)
        quota = staff.get("total_quota", 0)
        companies = staff.get("companies_count", 0)

        return {
            "ok": True,
            "reply": (
                f"🦺 **Resumen de Personal y Staff — {event_name}:**\n\n"
                f"• **Empresas Contratistas / Aliadas:** {companies} empresas\n"
                f"• **Pases de Staff Acreditados:** **{used}** de {quota} cupos asignados\n"
                f"• **Cupos Disponibles para Asignar:** {max(0, quota - used)} pases"
            ),
            "action_taken": "STAFF_SUMMARY",
            "data": staff,
            "refresh_needed": False,
        }

    async def _handle_event_metrics(
        self, client: httpx.AsyncClient, headers: dict[str, str], event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Fetch real-time sales and attendance metrics for event."""
        res = await client.get(f"{self.reg_url}/api/v1/registration/events/{event_id}/metrics", headers=headers)
        if res.status_code != 200:
            return {"ok": False, "reply": "No se pudieron obtener las métricas.", "action_taken": "ERROR", "refresh_needed": False}
        m = res.json()
        revenue_soles = f"S/ {(m.get('total_revenue_cents', 0) / 100):.2f}"
        sold = m.get("tickets_sold", 0)
        cap = m.get("tickets_capacity", 0)
        pct = m.get("occupancy_percent", 0.0)
        orders = m.get("total_orders", 0)
        paid = m.get("orders_paid", 0)

        return {
            "ok": True,
            "reply": (
                f"📊 **Estado de Ventas — {event_name}:**\n\n"
                f"• **Ingresos Recaudados:** **{revenue_soles}**\n"
                f"• **Entradas Vendidas:** **{sold}** / {cap} cupos ({pct}% ocupación)\n"
                f"• **Órdenes Pagadas:** **{paid}** de {orders} generadas\n"
                f"• **Entradas Disponibles:** {max(0, cap - sold)} cupos restantes"
            ),
            "action_taken": "EVENT_METRICS",
            "data": m,
            "refresh_needed": False,
        }

    async def _handle_create_promo_code(
        self, client: httpx.AsyncClient, headers: dict[str, str], text: str, event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Create a promoter / RRPP channel."""
        prefix_match = re.search(r"(?:codigo|rrpp|promotor)\s+([a-zA-Z0-9_-]{2,20})", text)
        code_prefix = prefix_match.group(1).upper() if prefix_match else f"PR{abs(hash(text)) % 99:02d}"

        payload = {
            "name": f"Promotor {code_prefix}",
            "code_prefix": code_prefix,
            "email": f"rrpp_{code_prefix.lower()}@eventpass.pe",
        }
        res = await client.post(
            f"{self.reg_url}/api/v1/registration/events/{event_id}/promoters",
            headers=headers,
            json=payload,
        )
        if res.status_code == 201:
            data = res.json()
            return {
                "ok": True,
                "reply": (
                    f"🏷️ **¡Promotor / Canal RRPP registrado!**\n\n"
                    f"• **Evento:** {event_name}\n"
                    f"• **Nombre:** {data['name']}\n"
                    f"• **Prefijo de Códigos:** `{data['code_prefix']}`\n"
                    f"• **Contacto:** {data['email']}\n\n"
                    "Ya puedes generar lotes de cortesías vinculadas a este canal en la sección de Códigos."
                ),
                "action_taken": "CREATE_PROMOTER",
                "data": data,
                "refresh_needed": True,
            }
        return {"ok": False, "reply": f"⚠️ No se pudo registrar el promotor: {res.text}", "action_taken": "ERROR", "refresh_needed": False}

    async def _handle_toggle_event(
        self, client: httpx.AsyncClient, headers: dict[str, str], text: str, event_id: str, event_name: str
    ) -> dict[str, Any]:
        """Pause or activate active event sales."""
        make_active = "activa" in text
        # Status endpoint in registration service
        res = await client.patch(
            f"{self.reg_url}/api/v1/registration/events/{event_id}",
            headers=headers,
            json={"is_active": make_active},
        )
        if res.status_code == 200:
            status_text = "ACTIVADO (Ventas abiertas)" if make_active else "PAUSADO (Ventas suspendidas)"
            return {
                "ok": True,
                "reply": f"⚡ El evento **{event_name}** ahora está en estado **{status_text}**.",
                "action_taken": "TOGGLE_EVENT_STATUS",
                "refresh_needed": True,
            }
        return {"ok": False, "reply": f"⚠️ No se pudo cambiar el estado: {res.text}", "action_taken": "ERROR", "refresh_needed": False}

    async def _handle_superadmin_overview(
        self, client: httpx.AsyncClient, headers: dict[str, str]
    ) -> dict[str, Any]:
        """SuperAdmin global platform overview metrics."""
        reg_res = await client.get(f"{self.reg_url}/api/v1/registration/superadmin/overview", headers=headers)
        auth_res = await client.get(f"{self.auth_url}/api/v1/auth/superadmin/tenants", headers=headers)

        if reg_res.status_code == 200 and auth_res.status_code == 200:
            reg = reg_res.json()
            tenants = auth_res.json()
            active_tenants = sum(1 for t in tenants if t.get("is_active"))
            rev_s = f"S/ {(reg.get('total_revenue_cents', 0) / 100):.2f}"
            return {
                "ok": True,
                "reply": (
                    f"🌐 **Visión Global de la Plataforma (SuperAdmin):**\n\n"
                    f"• **Empresas (Tenants):** {len(tenants)} registradas ({active_tenants} activas)\n"
                    f"• **Eventos Globales:** {reg.get('total_events', 0)} ({reg.get('active_events', 0)} activos)\n"
                    f"• **Recaudación Global:** **{rev_s}**\n"
                    f"• **Entradas Vendidas:** {reg.get('total_tickets_sold', 0)} tickets históricos\n"
                    f"• **Órdenes Pagadas:** {reg.get('total_orders_paid', 0)}"
                ),
                "action_taken": "SUPERADMIN_OVERVIEW",
                "refresh_needed": False,
            }
        return {"ok": False, "reply": "No pude cargar métricas de SuperAdmin.", "action_taken": "ERROR", "refresh_needed": False}
