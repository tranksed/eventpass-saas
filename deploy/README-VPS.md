# Despliegue en VPS (Ubuntu 22.04 / 24.04 o Debian 12)

1. Clona el repositorio en tu VPS:

```bash
git clone https://github.com/tranksed/eventpass-saas.git /opt/eventpass-saas
cd /opt/eventpass-saas
```

2. Ejecuta el instalador automático eligiendo el puerto que quieras (modo interactivo o con `--port`):

```bash
# Modo interactivo (te preguntará qué puerto usar y validará si está libre)
sudo bash deploy/install-vps.sh

# O indicando el puerto directamente (ej. 8088, 9000, 80):
sudo bash deploy/install-vps.sh --port 8088
```

### Qué hace `install-vps.sh` automáticamente:
- Verifica que el puerto elegido esté libre y lo guarda en `infra/.env` (`APP_HTTP_PORT`).
- Instala **Docker Engine** y **Docker Compose v2**.
- Genera claves criptográficas aleatorias (`openssl rand`) para cifrado **AES-256-GCM**, **HMAC-SHA256**, tokens internos S2S y contraseñas únicas para las **4 bases de datos PostgreSQL** (`auth-db`, `registration-db`, `accreditation-db`, `audit-db`), **Redis** y **RabbitMQ**.
- Configura **UFW Firewall** abriendo solo `22` y el puerto elegido (las 4 BDs quedan aisladas en red Docker `internal: true`).
- Levanta todos los contenedores con `restart: unless-stopped`, incluyendo **PgBouncer** y **NGINX**.
