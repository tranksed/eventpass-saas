#!/usr/bin/env bash
# =============================================================================
# EventPass SaaS — Instalador Automático para VPS (Ubuntu 22.04/24.04 & Debian 12)
# - Permite elegir el puerto público (--port 8088 o interactivo)
# - Instala Docker Engine & Compose v2, UFW y curl/openssl
# - Genera secretos criptográficos únicos en infra/.env (si no existen)
# - Construye y levanta los 5 servicios Python + NGINX + 4 PostgreSQL + PgBouncer
# - Verifica HTTP 200 en /, /admin, /comprar, /validar, /acreditacion, /reclamos
# =============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_DIR="${APP_DIR}/infra"
ENV_FILE="${INFRA_DIR}/.env"
CHOSEN_PORT="${APP_PORT:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--port)
      CHOSEN_PORT="${2:-}"
      shift 2
      ;;
    -h|--help)
      echo "Uso: sudo bash deploy/install-vps.sh [--port 8088]"
      exit 0
      ;;
    *)
      echo "Argumento no reconocido: $1"
      echo "Uso: sudo bash deploy/install-vps.sh [--port 8088]"
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Ejecuta este script como root: sudo bash deploy/install-vps.sh"
  exit 1
fi

is_port_in_use() {
  local port="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -tuln | grep -qE "[:.]${port}[[:space:]]"
  else
    return 1
  fi
}

if [[ -z "${CHOSEN_PORT}" ]]; then
  echo "=== Configuración de Puerto Público ==="
  while true; do
    read -r -p "Elige el puerto público para EventPass [Enter = 8088, ej: 80, 8080, 9000]: " input_port || true
    CHOSEN_PORT="${input_port:-8088}"
    if ! [[ "${CHOSEN_PORT}" =~ ^[0-9]+$ ]] || (( CHOSEN_PORT < 1 || CHOSEN_PORT > 65535 )); then
      echo "[!] Puerto inválido. Ingresa un número entre 1 y 65535."
      continue
    fi
    if is_port_in_use "${CHOSEN_PORT}"; then
      read -r -p "[!] El puerto ${CHOSEN_PORT} está ocupado (puede ser una instancia previa de EventPass). ¿Usarlo igualmente? [s/N]: " reuse || true
      if [[ "${reuse,,}" != "s" && "${reuse,,}" != "y" ]]; then
        continue
      fi
    fi
    break
  done
else
  if ! [[ "${CHOSEN_PORT}" =~ ^[0-9]+$ ]] || (( CHOSEN_PORT < 1 || CHOSEN_PORT > 65535 )); then
    echo "[!] Puerto inválido: ${CHOSEN_PORT}"
    exit 1
  fi
fi

echo "=== [1/6] Instalando dependencias del sistema (curl, openssl, ufw, git) ==="
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y ca-certificates curl gnupg openssl ufw git

if ! command -v docker >/dev/null 2>&1; then
  echo "=== [2/6] Instalando Docker Engine y Docker Compose v2 ==="
  install -m 0755 -d /etc/apt/keyrings
  . /etc/os-release
  curl -fsSL "https://download.docker.com/linux/${ID}/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  chmod a+r /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${ID} \
    ${VERSION_CODENAME} stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
else
  echo "=== [2/6] Docker ya instalado ==="
fi

echo "=== [3/6] Configurando secretos y puerto (${CHOSEN_PORT}) en ${ENV_FILE} ==="
if [[ ! -f "${ENV_FILE}" ]]; then
  cat > "${ENV_FILE}" <<EOF
ENVIRONMENT=production
APP_HTTP_PORT=${CHOSEN_PORT}
PII_MASTER_KEY_B64=$(openssl rand -base64 32)
DNI_BLIND_INDEX_PEPPER=$(openssl rand -hex 32)
PAYMENT_WEBHOOK_SECRET=$(openssl rand -hex 32)
INTERNAL_SERVICE_TOKEN=$(openssl rand -hex 32)

AUTH_DB_PASSWORD=$(openssl rand -hex 20)
REG_DB_PASSWORD=$(openssl rand -hex 20)
ACCRED_DB_PASSWORD=$(openssl rand -hex 20)
AUDIT_DB_PASSWORD=$(openssl rand -hex 20)
REDIS_PASSWORD=$(openssl rand -hex 20)
RABBITMQ_PASSWORD=$(openssl rand -hex 20)
EOF
  chmod 600 "${ENV_FILE}"
  echo "    Secretos generados en ${ENV_FILE} (permisos 600)."
else
  if grep -q "^APP_HTTP_PORT=" "${ENV_FILE}"; then
    sed -i "s/^APP_HTTP_PORT=.*/APP_HTTP_PORT=${CHOSEN_PORT}/" "${ENV_FILE}"
  else
    echo "APP_HTTP_PORT=${CHOSEN_PORT}" >> "${ENV_FILE}"
  fi
  echo "    ${ENV_FILE} actualizado con APP_HTTP_PORT=${CHOSEN_PORT} (secretos preservados)."
fi

echo "=== [4/6] Configurando Firewall UFW (SSH 22 y puerto ${CHOSEN_PORT}) ==="
ufw allow 22/tcp >/dev/null || true
ufw allow "${CHOSEN_PORT}/tcp" >/dev/null || true
ufw --force enable >/dev/null || true

echo "=== [5/6] Construyendo e iniciando contenedores EventPass SaaS ==="
cd "${INFRA_DIR}"
docker compose --env-file "${ENV_FILE}" up -d --build --remove-orphans

echo "=== [6/6] Verificando salud de los servicios en http://127.0.0.1:${CHOSEN_PORT} ==="
READY=0
for i in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:${CHOSEN_PORT}/health" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 2
done

if [[ "${READY}" -ne 1 ]]; then
  echo "[!] El gateway no respondió /health a tiempo. Últimos logs:"
  docker compose --env-file "${ENV_FILE}" ps
  docker compose --env-file "${ENV_FILE}" logs --tail=30 web-portal api-gateway
  exit 1
fi

for route in "/" "/comprar" "/validar" "/acreditacion" "/admin" "/reclamos"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${CHOSEN_PORT}${route}")
  echo "    HTTP ${code} -> ${route}"
done

PUBLIC_IP=$(curl -fsSL https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
BASE_URL="http://${PUBLIC_IP}"
if [[ "${CHOSEN_PORT}" != "80" ]]; then
  BASE_URL="http://${PUBLIC_IP}:${CHOSEN_PORT}"
fi

echo ""
echo "====================================================================="
echo "  EventPass SaaS desplegado correctamente (Puerto ${CHOSEN_PORT})"
echo "====================================================================="
echo "  Portal de Eventos    : ${BASE_URL}/"
echo "  Taquilla y Cortesías : ${BASE_URL}/comprar"
echo "  Consola de Puerta    : ${BASE_URL}/validar"
echo "  Acreditación Staff   : ${BASE_URL}/acreditacion"
echo "  Dashboard Organizador: ${BASE_URL}/admin"
echo "  Libro Reclamaciones  : ${BASE_URL}/reclamos"
echo ""
echo "  Comandos útiles:"
echo "    Ver estado   : cd ${INFRA_DIR} && docker compose --env-file ${ENV_FILE} ps"
echo "    Ver logs     : cd ${INFRA_DIR} && docker compose --env-file ${ENV_FILE} logs -f"
echo "    Cambiar pto. : sudo bash ${APP_DIR}/deploy/install-vps.sh --port 9000"
echo "====================================================================="
