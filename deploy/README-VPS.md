# Guía de Despliegue y Administración en Servidores VPS

Esta guía describe el procedimiento de instalación, configuración de dominio/SSL, pasarelas de pago y mantenimiento de **EventPass SaaS** en cualquier servidor VPS limpio (Ubuntu 22.04 / 24.04 LTS o Debian 12).

---

## 1. Requisitos Mínimos del Servidor VPS

* **CPU**: 2 vCPU (recomendado 4 vCPU para ráfagas de 10,000+ usuarios).
* **RAM**: 2 GB mínimo (recomendado 4 GB a 8 GB).
* **Disco**: 20 GB SSD / NVMe.
* **Sistema Operativo**: Ubuntu 22.04 LTS, Ubuntu 24.04 LTS o Debian 12.
* **Acceso**: Usuario `root` o usuario con privilegios `sudo`.

---

## 2. Instalación Paso a Paso

1. Conéctate a tu VPS vía SSH:
   ```bash
   ssh root@IP_DE_TU_VPS
   ```

2. Clona el repositorio e inicia el instalador:
   ```bash
   git clone https://github.com/tranksed/eventpass-saas.git /opt/eventpass-saas
   cd /opt/eventpass-saas
   sudo bash deploy/install-vps.sh
   ```

3. Durante la instalación:
   * El instalador detecta automáticamente la **IP pública real de tu servidor**.
   * Por defecto se configuran los puertos estándar **80 (HTTP)** y **443 (HTTPS)** para que tu dominio funcione de forma limpia y directa sin requerir números de puerto en la URL (ej. `https://midominio.com`). Si el puerto 80 estuviese ocupado por otro servicio previo, el instalador te avisará y te permitirá elegir uno alternativo.
   * Se generan automáticamente claves criptográficas únicas de 256 bits y contraseñas independientes para las 4 bases de datos PostgreSQL, Redis y RabbitMQ en `/opt/eventpass-saas/infra/.env`.
   * Se habilitan los comandos globales `eventpass-update` y `eventpass-ssl`.

---

## 3. Configuración de Dominio y Certificados SSL HTTPS (Let's Encrypt)

Cada nuevo proyecto o VPS tiene su propia IP y su propio dominio.

### A. Configuración de Registros DNS
En tu panel de DNS (Cloudflare, GoDaddy, Namecheap, Hostinger, etc.):
* **Tipo**: `A`
* **Nombre / Host**: `tickets` (o `@` si es el dominio raíz)
* **Valor / IP**: `IP_PUBLICA_DE_TU_VPS`
* **TTL**: Automático o 300 segundos.

> **Nota para usuarios de Cloudflare**: Durante la emisión inicial del certificado, mantén el proxy en modo **DNS Only (Nube Gris)** para que los servidores de validación de Let's Encrypt puedan verificar tu servidor directamente por el puerto 80.

### B. Emisión del Certificado SSL

#### Opción 1: Desde la Consola Web SuperAdmin
1. Ingresa a `http://IP_DE_TU_VPS:PUERTO/superadmin`.
2. Dirígete a la sección **Dominio Universal y Certificados SSL (HTTPS)**.
3. El panel verificará en tiempo real tu registro DNS mediante resolución DoH (DNS-over-HTTPS).
4. Escribe tu dominio (ej. `tickets.tuempresa.pe`), tu correo y presiona **"Guardar y Activar SSL HTTPS"**.

#### Opción 2: Desde la Terminal SSH (Recomendado para producción)
Ejecuta el asistente oficial de certificados:
```bash
sudo eventpass-ssl setup tickets.tuempresa.pe contacto@tuempresa.pe
```
Este comando:
1. Valida el dominio mediante el desafío ACME de Let's Encrypt por el puerto 80.
2. Reemplaza el certificado autofirmado temporal (`CN=eventpass.local`) por el certificado oficial en `gateway/ssl/active_cert.pem`.
3. Reinicia NGINX en los puertos estándar **80 (HTTP)** y **443 (HTTPS)** con redirección automática a HTTPS.
4. Programa la auto-renovación desatendida en el cron del sistema (`/etc/cron.d/eventpass-ssl-renew`).

> **💡 ¿Por qué el navegador muestra "No seguro" tras la instalación inicial?**  
> Al instalar el sistema por primera vez, Nginx arranca con un certificado autofirmado de contingencia (`eventpass.local`) para que el contenedor pueda responder de inmediato. Dado que las autoridades públicas no reconocen certificados autofirmados, el navegador muestra la advertencia roja de "No seguro". En cuanto ejecutas `sudo eventpass-ssl setup`, se instala el certificado oficial de Let's Encrypt y el navegador muestra el candado seguro de inmediato.

---

## 4. Configuración de Pasarelas de Pago (Mercado Pago, Izipay y Yape)

Edita el archivo de entorno del VPS:
```bash
nano /opt/eventpass-saas/infra/.env
```

Agrega las credenciales de tu proyecto:
```env
# Mercado Pago (Tarjetas de crédito/débito y código QR Yape/Plin)
MERCADOPAGO_ACCESS_TOKEN=APP_USR-xxxxxxxxxxxxxxxxxxxx
MERCADOPAGO_PUBLIC_KEY=APP_USR-xxxxxxxxxxxxxxxxxxxx
MERCADOPAGO_WEBHOOK_SECRET=xxxxxxxxxxxxxxxxxxxxxxxx

# Izipay (Tarjetas de crédito/débito y Yape directo)
IZIPAY_CLIENT_ID=xxxxxxxx
IZIPAY_CLIENT_KEY=xxxxxxxx
IZIPAY_PUBLIC_KEY=xxxxxxxx
IZIPAY_SHA256_KEY=xxxxxxxx
```

Reinicia los contenedores para aplicar las credenciales:
```bash
cd /opt/eventpass-saas/infra && docker compose --env-file .env up -d
```

---

## 5. Actualización del Sistema (Zero-Secret-Loss)

Para descargar e implementar nuevas mejoras desde GitHub **sin perder tus claves secretas ni las bases de datos**:

```bash
sudo eventpass-update
```

El script de actualización realiza las siguientes operaciones automáticas:
1. Sincroniza la última versión estable desde `main` en GitHub (resolviendo automáticamente cambios de archivos rastreados sin requerir banderas manuales).
2. **Preserva el archivo `infra/.env`**, tus claves secretas AES/Ed25519 y todos los volúmenes de datos persistentes de PostgreSQL, Redis y RabbitMQ.
3. Asegura la estandarización de puertos (`APP_HTTP_PORT=80` y `APP_HTTPS_PORT=443`).
4. Reconstruye las imágenes Docker de los microservicios y ejecuta las migraciones de base de datos.
5. Valida la salud de todos los endpoints (`/health`) confirmando que devuelvan código HTTP `200`.

---

## 6. Comandos de Diagnóstico y Monitoreo

```bash
# Ver estado de los contenedores Docker
cd /opt/eventpass-saas/infra && docker compose --env-file .env ps

# Ver logs en tiempo real
cd /opt/eventpass-saas/infra && docker compose --env-file .env logs -f

# Ver estado y fecha de expiración del certificado SSL
sudo eventpass-ssl status

# Probar resolución DNS de un dominio
sudo eventpass-ssl check-dns midominio.com

# Forzar renovación de certificados SSL
sudo eventpass-ssl renew
```
