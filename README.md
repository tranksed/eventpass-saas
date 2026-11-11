# EventPass SaaS — Plataforma Multi-Tenant de Registro, Compras y Acreditación Privada

Plataforma SaaS en Python (**FastAPI + SQLAlchemy 2.0 Async + Ed25519 + AES-256-GCM**) diseñada con arquitectura de **microservicios y bases de datos independientes (*Database-per-Service*)** para soportar ráfagas de **10,000+ usuarios en 48 horas**, acreditación privada de staff por empresa y operación **online + contingencia offline**.

## Microservicios y Bases de Datos Independientes

| Servicio | Puerto | Base de Datos | Responsabilidad |
| :--- | :--- | :--- | :--- |
| **`auth-service`** | `8001` | `auth_db` | Multi-tenant, 3 niveles RBAC (`ADMIN`, `SUPERVISOR`, `VALIDATOR`), MFA (TOTP), JWT Ed25519 (`EdDSA`), refresh rotation con detección de reuso. |
| **`registration-service`** | `8002` | `registration_db` | Eventos, catálogo (entradas, fotos, firmas), límite configurable por DNI (`1..10`), reserva atómica de stock, idempotencia y webhooks HMAC-SHA256. |
| **`accreditation-service`** | `8003` | `accreditation_db` | Empresas acreditadas con link privado (cupo default `6`, Supervisor hasta `10`, Admin personalizado), QR firmados Ed25519, check-in online y **contingencia offline + sync**. |
| **`audit-service`** | `8004` | `audit_db` | Registro inmutable (*append-only*) con **hash-chaining SHA-256**. |

## Ejecución Local (Desarrollo / Pruebas)

```powershell
# Ejecutar suite completa de pruebas E2E, seguridad, concurrencia y modo offline
.\.venv\Scripts\python.exe -m pytest -v

# Levantar cada microservicio con su propia BD aislada + Portal Web (http://127.0.0.1:8000)
.\.venv\Scripts\python.exe -m uvicorn services.auth_service.app:create_auth_app --factory --port 8001
.\.venv\Scripts\python.exe -m uvicorn services.registration_service.app:create_registration_app --factory --port 8002
.\.venv\Scripts\python.exe -m uvicorn services.accreditation_service.app:create_accreditation_app --factory --port 8003
.\.venv\Scripts\python.exe -m uvicorn services.audit_service.app:create_audit_app --factory --port 8004
.\.venv\Scripts\python.exe -m uvicorn services.web_portal.app:create_portal_app --factory --port 8000
```

## Despliegue en Producción (Docker Compose + 4 PostgreSQL + PgBouncer + NGINX)

```bash
cd infra
docker compose up --build -d
```
