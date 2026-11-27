# EventPass SaaS — Plataforma Multi-Tenant de Eventos, Taquilla y Acreditación

Plataforma SaaS en Python (**FastAPI + SQLAlchemy 2.0 Async + Ed25519 + AES-256-GCM + Bootstrap 5.3 + Chart.js**) con arquitectura de **microservicios y bases de datos independientes (*Database-per-Service*)** diseñada para ráfagas de **10,000+ usuarios concurrentes**, venta de entradas e interacciones por artistas, acreditación corporativa de staff, pasarelas de pago peruanas e internacionales (Mercado Pago, Izipay, Yape), validación **online + contingencia offline** con QR firmado y asistente chatbot operativo local.

---

## 🏗️ Arquitectura de Microservicios y Bases de Datos

```text
[ Cliente Web / Móvil / Taquilla ]
               │
               ▼
   [ API Gateway (NGINX Modern TLS) ]  <─── Let's Encrypt SSL / Puertos 80 & 443
               │
  ┌────────────┼──────────────────────────┬────────────────────────┐
  ▼            ▼                          ▼                        ▼
web-portal  auth-service          registration-service   accreditation-service
 (UI & BFF) (Ed25519 / Tenants)     (PgBouncer Pool)       (Offline QR & Sync)
               │                          │                        │
            auth_db                registration_db          accreditation_db
                                          │
                                          ▼
                                    audit-service  (Encadenamiento SHA-256)
                                          │
                                       audit_db
```

| Microservicio | Puerto Interno | Base de Datos | Responsabilidad Principal |
| :--- | :---: | :--- | :--- |
| **`web-portal`** | `8000` | — | Interfaz unificada responsiva (Bootstrap 5.3 + Chart.js), BFF de credenciales QR y orquestador web. |
| **`auth-service`** | `8001` | `auth_db` | Identidad multi-tenant por empresa, RBAC (`SUPERADMIN`, `ADMIN`, `SUPERVISOR`, `VALIDATOR`), impersonación SuperAdmin, MFA TOTP, JWT Ed25519 (`EdDSA`), y gestión de dominios/SSL. |
| **`registration-service`** | `8002` | `registration_db` (vía PgBouncer) | Eventos en zona horaria local (`America/Lima`), catálogo de entradas (`ENTRY`) e interacciones con artistas (`INTERACTION`), control de compra por DNI, pasarelas (Mercado Pago, Izipay, Yape), códigos RR.PP., Guest List, carga masiva Excel/CSV y Libro de Reclamaciones. |
| **`accreditation-service`** | `8003` | `accreditation_db` | Enlaces privados por empresa expositora para staff con cupo en tiempo real, credenciales con firma QR Ed25519, check-in atómico y sincronización offline anti-duplicados. |
| **`audit-service`** | `8004` | `audit_db` | Bitácora de auditoría inmutable (*append-only*) con **encadenamiento criptográfico SHA-256** (`verify-chain`). |
| **`api-gateway`** | `80` & `443` | — | NGINX con terminación TLS moderna, rate-limiting de protección anti-DDoS y enrutamiento perimetral. |

---

## 🌐 Módulos y Vistas del Sistema

| Ruta | Módulo | Descripción |
| :--- | :--- | :--- |
| `/` | **Portal Público de Eventos** | Catálogo de eventos activos, buscador por fecha y accesos directos. |
| `/comprar` | **Taquilla y Venta por Artista** | Compra con control por DNI, selección de entradas generales o interacciones específicas por artista/personaje (fotos, firmas, Meet & Greet), medios de pago (Mercado Pago, Izipay, Yape/Plin) y canje de códigos promocionales. |
| `/validar` | **Consola de Puerta (Online / Offline)** | Validación de QR en puerta mediante cámara o pistola USB con soporte de contingencia offline sin internet mediante claves públicas Ed25519. |
| `/acreditacion` | **Acreditación Corporativa Staff** | Registro de personal de stands/empresas patrocinadoras con control estricto de cupos en tiempo real. |
| `/admin` | **Panel de Organizador (Tenant)** | 8 KPIs en tiempo real, 4 gráficos analíticos, métricas de ventas, gestión de catálogo, Guest List, carga masiva Excel y Chatbot Operativo interno. |
| `/superadmin` | **Consola SuperAdmin Global** | Control maestro de la plataforma: provisión y suspensión de empresas (tenants), dominios personalizados, verificación DNS en tiempo real y activación de certificados SSL. |
| `/reclamos` | **Libro de Reclamaciones Virtual** | Formulario de reclamos conforme a normativa peruana (INDECOPI) con código de seguimiento único `LR-...`. |

---

## 🚀 Instalación en Cualquier Servidor VPS

La instalación se realiza en un servidor VPS limpio (Ubuntu 22.04 / 24.04 o Debian 12). El instalador detecta automáticamente la IP pública del servidor, genera claves criptográficas seguras y únicas, configura el firewall y levanta la plataforma con Docker:

```bash
# 1. Clonar el repositorio en el VPS
git clone https://github.com/tranksed/eventpass-saas.git /opt/eventpass-saas
cd /opt/eventpass-saas

# 2. Ejecutar el instalador automático
sudo bash deploy/install-vps.sh
```

El script configura automáticamente los puertos estándar **80 (HTTP)** y **443 (HTTPS)** para que el dominio funcione directamente sin números de puerto en la URL (si el puerto 80 estuviese ocupado, te permite elegir uno alternativo):
* Instalación de Docker Engine y Docker Compose v2.
* Generación de secretos en `infra/.env` con permisos `600` (AES-256-GCM, blind index de DNI, contraseñas de las 4 BDs, Redis y RabbitMQ).
* Configuración del firewall UFW (puertos 22, 80, 443).
* Creación de los comandos globales en el sistema: `eventpass-update` y `eventpass-ssl`.

---

## 🔒 Dominio Universal y Certificados SSL HTTPS (Let's Encrypt)

Cada servidor VPS puede configurarse con su propio dominio o subdominio (ej. `tickets.tuempresa.pe`, `entradas.midominio.com`).

### Paso 1: Configurar el Registro DNS en tu proveedor
En tu panel de DNS (Cloudflare, GoDaddy, Namecheap, Hostinger, etc.):
* **Tipo**: `A`
* **Nombre / Host**: `tickets` (o `@` si es el dominio raíz)
* **Valor / Destino**: `IP_PUBLICA_DE_TU_VPS`
* *(En Cloudflare, se recomienda inicialmente dejar el proxy en **DNS Only / Nube Gris** durante la validación inicial).*

### Paso 2: Activar SSL (2 métodos disponibles)

#### Método A: Desde la Consola SuperAdmin Web (Recomendado)
1. Ingresa a `http://IP_DE_TU_VPS:PUERTO/superadmin`.
2. Dirígete a la sección **Dominio Universal y Certificados SSL (HTTPS)**.
3. El sistema valida en tiempo real tu registro DNS mediante resolución autoritativa global **DoH (DNS-over-HTTPS)**.
4. Ingresa tu dominio y tu correo de contacto y haz clic en **"Guardar y Activar SSL HTTPS"**.

#### Método B: Desde la Terminal SSH (Emisión instantánea)
Ejecuta el asistente CLI de certificados:
```bash
sudo eventpass-ssl setup tickets.tuempresa.com admin@tuempresa.com
```

Este comando:
1. Solicita y valida el certificado oficial con Let's Encrypt vía ACME Challenge webroot en el puerto 80.
2. Reemplaza automáticamente el certificado provisional autofirmado de fábrica por el certificado oficial en `gateway/ssl/active_cert.pem`.
3. Reinicia Nginx en los puertos estándar **80 (HTTP)** y **443 (HTTPS)** con redirección automática HTTP -> HTTPS.
4. Instala un cronjob de auto-renovación diaria en `/etc/cron.d/eventpass-ssl-renew`.

> **¿Por qué el navegador muestra "No seguro" al inicio?**
> En una instalación limpia, el sistema genera inicialmente un certificado SSL autofirmado de contingencia (`CN=eventpass.local`) para que el contenedor Nginx pueda arrancar y responder sin fallar antes de tener un dominio apuntado. Los navegadores muestran "No seguro" ante certificados autofirmados. En cuanto ejecutas `sudo eventpass-ssl setup midominio.com tu@correo.com`, se instala el certificado oficial de Let's Encrypt y el navegador muestra de inmediato el candado de conexión segura.

---

## 💳 Configuración de Pasarelas de Pago

EventPass SaaS soporta pagos con tarjeta, billeteras digitales y pasarelas peruanas e internacionales:

1. Edita el archivo de configuración del entorno:
```bash
nano /opt/eventpass-saas/infra/.env
```

2. Añade las credenciales de tu pasarela:

### Mercado Pago (Tarjetas + QR Yape / Plin)
```env
MERCADOPAGO_ACCESS_TOKEN=APP_USR-xxxxxxxxxxxxxxxxxxxx
MERCADOPAGO_PUBLIC_KEY=APP_USR-xxxxxxxxxxxxxxxxxxxx
MERCADOPAGO_WEBHOOK_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx
```

### Izipay (Tarjetas + Yape Directo)
```env
IZIPAY_CLIENT_ID=xxxxxxxx
IZIPAY_CLIENT_KEY=xxxxxxxx
IZIPAY_PUBLIC_KEY=xxxxxxxx
IZIPAY_SHA256_KEY=xxxxxxxx
```

3. Aplica los cambios reiniciando los contenedores:
```bash
cd /opt/eventpass-saas/infra && docker compose --env-file .env up -d
```

---

## 🎭 Entradas e Interacciones con Artistas / Personajes

El sistema permite segmentar y vender tanto entradas tradicionales como experiencias e interacciones nominadas por artista:

* **Entradas Generales (`ENTRY`)**: General, VIP, Platinum, Preferencial.
* **Interacciones por Artista (`INTERACTION`)**: Meet & Greet, Fotografía profesional, Firma de autógrafos, Backstage pass. Cada interacción se asocia a un artista o personaje específico, con stock independiente y precios diferenciados.
* **En el Home de Compra (`/comprar`)**: El comprador visualiza claramente las entradas del evento y puede filtrar o seleccionar la interacción deseada con su artista favorito.

---

## 🤖 Chatbot Operativo Interno (IA Administrativa)

La plataforma integra un asistente chatbot en el panel de administración (`/admin` y `/superadmin`) con las siguientes características:
* **Privado y Restringido**: Exclusivo para usuarios autenticados con rol `SUPERADMIN` o `ADMIN`.
* **Conocimiento de Base de Datos Propia**: Consulta y opera exclusivamente con el esquema y los datos reales de la plataforma (no genera información externa de internet).
* **Operaciones Soportadas**:
  * Consultas de ventas, recaudación y estados de stock.
  * Creación y modificación de precios de entradas e interacciones.
  * Búsqueda y verificación de compradores por DNI.
  * Análisis de tasa de asistencia y check-in en puerta.

---

## 🏢 Arquitectura Multi-Tenant y Dominios Propios

EventPass soporta múltiples empresas organizadoras sobre una misma infraestructura:
* **Ruta Universal**: `https://tudominio.com/{slug-empresa}/...`
* **Dominio Propio por Tenant**: Cada empresa puede tener asignado un dominio personalizado (ej. `entradas.festivalnorte.pe`). El SuperAdmin puede vincular y verificar el estado DNS de cada empresa con un solo clic.

---

## 🔄 Actualizaciones y Mantenimiento del VPS

Para actualizar la plataforma a la última versión disponible en GitHub **sin perder tus datos ni tus claves secretas en `.env`**:

```bash
sudo eventpass-update
```

### Comandos de diagnóstico útiles:
```bash
# Ver estado de los contenedores
cd /opt/eventpass-saas/infra && docker compose --env-file .env ps

# Ver logs en vivo de todos los microservicios
cd /opt/eventpass-saas/infra && docker compose --env-file .env logs -f

# Verificar estado de certificados SSL
sudo eventpass-ssl status
```

---

## 🧪 Pruebas Automatizadas y Desarrollo Local

```bash
# Crear entorno virtual e instalar dependencias
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\Scripts\activate
pip install -e .[dev]

# Ejecutar suite de pruebas con pytest
pytest -v
```

---

## 📄 Licencia

Desarrollado para despliegue empresarial de alta concurrencia. Todos los derechos reservados.
