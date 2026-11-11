#!/usr/bin/env bash
# =============================================================================
# EventPass SaaS — Instalador Automático para VPS (Ubuntu 22.04/24.04 & Debian 12)
# Permite elegir el puerto público (ej. --port 8088 o interactivo), instala Docker,
# genera secretos únicos, configura UFW y levanta los 4 microservicios + 4 BDs.
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
    *)
      echo "Uso: sudo bash deploy/install-vps.sh [--port 8088]"
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Por favor ejecuta como root: sudo bash deploy/install-vps.sh"
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
    read -r -p "Elige el puerto público para EventPass [Enter = 8088, o ej: 80, 9000]: " input_port || true
    CHOSEN_PORT="${input_port:-8088}"
    if ! [[ "${CHOSEN_PORT}" =~ ^[0-9]+$ ]] || (( CHOSEN_PORT < 1 || CHOSEN_PORT > 65535 )); then
      echo "[!] Puerto inválido. Ingresa un número entre 1 y 65535."
      continue
    fi
    if is_port_in_use "${CHOSEN_PORT}"; then
      echo "[!] El puerto ${CHOSEN_PORT} ya está en uso en este VPS. Elige otro puerto."
      continue
    fi
    break
  done
else
  if ! [[ "${CHOSEN_PORT}" =~ ^[0-9]+$ ]] || (( CHOSEN_PORT < 1 || CHOSEN_PORT > 65535 )); then
    echo "[!] Puerto inválido: ${CHOSEN_PORT}"
    exit 1
  fi
fi

echo "=== [1/5] Instalando dependencias del sistema (curl, openssl, ufw) ==="
apt-get update -y
apt-get install -y ca-certificates curl gnupg openssl ufw

if ! command -v docker >/dev/null 2>&1; then
  echo "=== [2/5] Instalando Docker Engine y Docker Compose v2 ==="
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
  echo "=== [2/5] Docker ya instalado ==="
fi

echo "=== [3/5] Generando secretos y puerto (${CHOSEN_PORT}) en ${ENV_FILE} ==="
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

echo "=== [4/5] Configurando Firewall UFW (SSH 22 y puerto ${CHOSEN_PORT}) ==="
ufw allow 22/tcp >/dev/null || true
ufw allow "${CHOSEN_PORT}/tcp" >/dev/null || true
ufw --force enable >/dev/null || true

echo "=== [5/5] Construyendo y levantando clúster EventPass SaaS ==="
cd "${INFRA_DIR}"
docker compose --env-file "${ENV_FILE}" up -d --build

echo "Esperando a que los servicios inicien..."
sleep 8
PUBLIC_IP=$(curl -fsSL https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
BASE_URL="http://${PUBLIC_IP}"
if [[ "${CHOSEN_PORT}" != "80" ]]; then
  BASE_URL="http://${PUBLIC_IP}:${CHOSEN_PORT}"
fi

echo ""
echo "====================================================================="
echo "  EventPass SaaS instalado y corriendo en el puerto ${CHOSEN_PORT}"
echo "====================================================================="
echo "  Portal Principal : ${BASE_URL}/"
echo "  Taquilla Compras : ${BASE_URL}/comprar"
echo "  Validación Puerta: ${BASE_URL}/validar"
echo "  Acreditación     : ${BASE_URL}/acreditacion"
echo "  Panel General    : ${BASE_URL}/admin"
echo ""
echo "  Para cambiar de puerto luego, vuelve a ejecutar:"
echo "  sudo bash deploy/install-vps.sh --port 9000"
echo "====================================================================="
