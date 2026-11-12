# EventPass SaaS — Plataforma Multi-Tenant de Eventos, Taquilla y Acreditación

Plataforma SaaS en Python (**FastAPI + SQLAlchemy 2.0 Async + Ed25519 + AES-256-GCM + Bootstrap 5.3**) con arquitectura de **microservicios y bases de datos independientes (*Database-per-Service*)** diseñada para ráfagas de **10,000+ usuarios en 48 horas**, acreditación privada corporativa, validación **online + contingencia offline** y analítica avanzada.

---

## Arquitectura de Microservicios y Bases de Datos

| Servicio | Puerto Interno | Base de Datos | Responsabilidad |
| :--- | :---: | :--- | :--- |
| **`web-portal`** | `8000` | — | Aplicativo Web unificado (Bootstrap 5.3 + Chart.js), BFF de QR PNG y simulador HMAC de pasarela. |
| **`auth-service`** | `8001` | `auth_db` | Multi-tenant por empresa, RBAC (`SUPERADMIN`, `ADMIN`, `SUPERVISOR`, `VALIDATOR`), impersonación SuperAdmin, MFA TOTP y JWT Ed25519 (`EdDSA`). |
| **`registration-service`** | `8002` | `registration_db` (vía PgBouncer) | Eventos (`America/Lima`), catálogo (`ENTRY`, `INTERACTION`), límite configurable por DNI (`1..10`), códigos RR.PP., Guest List, envíos masivos Excel/CSV, Libro de Reclamaciones y exportación `.xlsx`. |
| **`accreditation-service`** | `8003` | `accreditation_db` | Empresas acreditadas con link privado de staff (cupo default `6`, Supervisor hasta `10`, Admin personalizado), QR Ed25519, check-in atómico, **contingencia offline + sync** y métricas de puerta. |
| **`audit-service`** | `8004` | `audit_db` | Bitácora inmutable (*append-only*) con **encadenamiento criptográfico SHA-256** (`verify-chain`). |
| **`api-gateway`** | Público configurable (`8088`, `80`, etc.) | — | NGINX con rate limiting por zonas y enrutamiento unificado hacia los microservicios y portal web. |

---

## Vistas del Aplicativo Web

| Ruta | Módulo | Descripción |
| :--- | :--- | :--- |
| `/` | **Portal de Eventos** | Buscador de eventos publicados, flujo operativo en 3 pasos y acceso directo a todos los módulos. |
| `/comprar` | **Taquilla, Códigos y Guest List** | Compra con control por DNI (Yape/Plin, MercadoPago/Tarjeta, PayPal), canje de códigos RR.PP./cortesías nominativas y solicitud pública de Guest List. |
| `/validar` | **Consola de Puerta (Online / Offline)** | Acceso privado por rol, lector de QR (cámara o USB/pegado), historial de sesión, descarga de paquete Ed25519 y sincronización offline anti-duplicados. |
| `/acreditacion` | **Portal Corporativo de Staff** | Registro mediante enlace privado por empresa expositora con control de cupo en tiempo real y descarga de credencial QR. |
| `/admin` (`/dashboard`) | **Dashboard Organizador (Bootstrap 5)** | 8 KPIs en vivo, 4 gráficos Chart.js, exportación `.xlsx`, gestión de eventos/catálogo, códigos RR.PP., Guest List en 1 clic, carga masiva Excel/CSV, **Acreditaciones Staff**, usuarios RBAC, auditoría SHA-256 y Reclamos. |
| `/superadmin` | **Consola SuperAdmin Global** | Acceso maestro de plataforma (`SUPERADMIN`): KPIs globales multi-tenant, alta/suspensión de empresas, impersonación 1-click hacia `/admin`, pausa de eventos globales y auditoría global. |
| `/reclamos` | **Libro de Reclamaciones Virtual** | Registro público conforme a Perú (INDECOPI) con código de seguimiento `LR-...`. |

---

## Instalación Rápida en VPS (Ubuntu 22.04/24.04 o Debian 12)

El instalador configura Docker Engine, Compose v2, Firewall UFW, genera secretos criptográficos únicos en `infra/.env`, permite elegir el puerto público y verifica todas las rutas HTTP automáticamente:

```bash
git clone https://github.com/tranksed/eventpass-saas.git
cd eventpass-saas
sudo bash deploy/install-vps.sh
```

También puedes pasar el puerto directamente sin modo interactivo (ideal para automatización o cambiar de puerto luego):

```bash
sudo bash deploy/install-vps.sh --port 8088
```

### Actualizar una instalación existente en el VPS

El instalador registra el comando global `eventpass-update` (que ejecuta `deploy/update-vps.sh`), el cual descarga los cambios desde GitHub, reconstruye los contenedores sin perder tus secretos (`infra/.env`) ni base de datos, y verifica HTTP `200` en todas las rutas:

```bash
sudo eventpass-update
```

O manualmente dentro del repositorio:

```bash
cd eventpass-saas
sudo bash deploy/update-vps.sh
```

> Si ya habías instalado antes de existir `eventpass-update`, ejecuta `cd eventpass-saas && git pull origin main && sudo bash deploy/update-vps.sh` una sola vez; luego ya podrás usar `sudo eventpass-update` desde cualquier directorio. También puedes configurar `SUPERADMIN_PASSWORD` en `infra/.env` o inicializar la primera cuenta directamente ingresando a `/superadmin`.

---

## Desarrollo Local y Pruebas

### Pruebas automatizadas (`pytest`)

```powershell
# Windows (PowerShell)
.\.venv\Scripts\python.exe -m pytest -v
```

La suite valida:
- Normalización, enmascaramiento y *blind index* HMAC-SHA256 por tenant/evento de DNI.
- Hashing `scrypt`, firmas Ed25519 de QR y expiración.
- Aislamiento multi-tenant, jerarquía de cupos Staff (`6` / `<=10` / personalizado), concurrencia sin sobreventa y modo contingencia offline con detección de duplicados.
- Promotores RR.PP., canje de cortesías, Guest List en 1 clic, envíos masivos CSV/Excel, métricas + exportación `.xlsx` y Libro de Reclamaciones.

### Levantar en local (Windows)

```powershell
.\scripts\start_local.ps1
```

Abrir en el navegador: `http://127.0.0.1:8000/` (y Dashboard en `http://127.0.0.1:8000/admin`).
