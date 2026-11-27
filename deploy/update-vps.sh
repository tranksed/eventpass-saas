#!/usr/bin/env bash
# =============================================================================
# EventPass SaaS — Actualizador Zero-Secret-Loss para VPS
# Uso:
#   sudo eventpass-update
#   sudo bash deploy/update-vps.sh [--branch main] [--reset]
# =============================================================================
set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
APP_DIR="$(cd "$(dirname "${SCRIPT_PATH}")/.." && pwd)"
INFRA_DIR="${APP_DIR}/infra"
ENV_FILE="${INFRA_DIR}/.env"
BRANCH="main"
HARD_RESET=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b|--branch)
      BRANCH="${2:-main}"
      shift 2
      ;;
    --reset)
      HARD_RESET=1
      shift
      ;;
    -h|--help)
      echo "Uso: sudo eventpass-update [--branch main] [--reset]"
      exit 0
      ;;
    *)
      echo "[!] Argumento no reconocido: $1"
      exit 1
      ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Ejecuta este comando como root: sudo eventpass-update"
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[!] No se encontró ${ENV_FILE}. Ejecuta primero: sudo bash ${APP_DIR}/deploy/install-vps.sh"
  exit 1
fi

echo "=== [1/4] Descargando últimos cambios desde GitHub (${BRANCH}) ==="
cd "${APP_DIR}"
git fetch origin "${BRANCH}"
if [[ "${HARD_RESET}" -eq 1 ]]; then
  git reset --hard "origin/${BRANCH}"
else
  if ! git pull --ff-only origin "${BRANCH}"; then
    echo "[!] git pull --ff-only falló por cambios locales. Si deseas sobrescribir archivos locales (sin tocar infra/.env), usa:"
    echo "    sudo eventpass-update --reset"
    exit 1
  fi
fi
chmod +x "${APP_DIR}/deploy/install-vps.sh" "${APP_DIR}/deploy/update-vps.sh" "${APP_DIR}/deploy/setup-ssl.sh"
ln -sf "${APP_DIR}/deploy/setup-ssl.sh" /usr/local/bin/eventpass-ssl

CHOSEN_PORT="$(grep -E '^APP_HTTP_PORT=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- || echo "80")"
CHOSEN_PORT="${CHOSEN_PORT:-80}"

# Si se ha configurado un dominio o SSL, migrar automáticamente a puertos estándar 80 y 443
HAS_DOMAIN="$(grep -E '^PLATFORM_DOMAIN=' "${ENV_FILE}" | cut -d= -f2- | tr -d ' ' || true)"
IS_SSL="$(grep -E '^SSL_ENABLED=' "${ENV_FILE}" | cut -d= -f2- | tr -d ' ' || true)"
if [[ -n "${HAS_DOMAIN}" || "${IS_SSL}" == "true" ]]; then
  if [[ "${CHOSEN_PORT}" != "80" ]]; then
    echo "    [i] Dominio o SSL detectado (${HAS_DOMAIN:-activo}). Migrando puerto público de ${CHOSEN_PORT} a los puertos estándar 80 (HTTP) y 443 (HTTPS)..."
    sed -i "s|^APP_HTTP_PORT=.*|APP_HTTP_PORT=80|" "${ENV_FILE}"
    CHOSEN_PORT=80
  fi
  if grep -q "^APP_HTTPS_PORT=" "${ENV_FILE}"; then
    sed -i "s|^APP_HTTPS_PORT=.*|APP_HTTPS_PORT=443|" "${ENV_FILE}"
  else
    echo "APP_HTTPS_PORT=443" >> "${ENV_FILE}"
  fi
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
  fi
fi

grep -q '^SUPERADMIN_EMAIL=' "${ENV_FILE}" || echo 'SUPERADMIN_EMAIL=superadmin@eventpass.pe' >> "${ENV_FILE}"
grep -q '^SUPERADMIN_PASSWORD=' "${ENV_FILE}" || echo 'SUPERADMIN_PASSWORD=' >> "${ENV_FILE}"
grep -q '^UVICORN_WORKERS=' "${ENV_FILE}" || echo 'UVICORN_WORKERS=1' >> "${ENV_FILE}"

# Auto-detectar IP pública del VPS en el host (donde sí hay salida directa a internet)
PUBLIC_IP=$(curl -fsSL --max-time 4 https://api.ipify.org 2>/dev/null || curl -fsSL --max-time 4 https://icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
if [[ -n "${PUBLIC_IP}" ]]; then
  if grep -q '^SERVER_PUBLIC_IP=' "${ENV_FILE}"; then
    sed -i "s|^SERVER_PUBLIC_IP=.*|SERVER_PUBLIC_IP=${PUBLIC_IP}|" "${ENV_FILE}"
  else
    echo "SERVER_PUBLIC_IP=${PUBLIC_IP}" >> "${ENV_FILE}"
  fi
fi

# Asegurar certificados SSL iniciales para arranque seguro de Nginx
mkdir -p "${APP_DIR}/gateway/ssl"
if [[ ! -f "${APP_DIR}/gateway/ssl/active_cert.pem" || ! -f "${APP_DIR}/gateway/ssl/active_key.pem" ]]; then
  echo "    Generando certificado TLS base para Nginx..."
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout "${APP_DIR}/gateway/ssl/active_key.pem" \
    -out "${APP_DIR}/gateway/ssl/active_cert.pem" \
    -subj "/CN=eventpass-local" >/dev/null 2>&1 || true
fi

echo "=== [2/4] Reconstruyendo e iniciando contenedores (puerto ${CHOSEN_PORT}, uvicorn workers: 1) ==="
cd "${INFRA_DIR}"
docker compose --env-file "${ENV_FILE}" up -d --build --remove-orphans
docker image prune -f >/dev/null 2>&1 || true

echo "=== [3/4] Esperando que todos los microservicios estén HEALTHY (puerto ${CHOSEN_PORT}) ==="
READY=0
for i in $(seq 1 45); do
  if curl -fsS "http://127.0.0.1:${CHOSEN_PORT}/health" >/dev/null 2>&1 \
    && curl -fsS "http://127.0.0.1:${CHOSEN_PORT}/api/v1/auth/superadmin/status" >/dev/null 2>&1 \
    && curl -fsS "http://127.0.0.1:${CHOSEN_PORT}/api/v1/registration/public/events" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 2
done

if [[ "${READY}" -ne 1 ]]; then
  echo "[!] Los servicios o sus bases de datos no respondieron a tiempo tras la actualización."
  docker compose --env-file "${ENV_FILE}" ps
  docker compose --env-file "${ENV_FILE}" logs --tail=50 web-portal auth-service registration-service accreditation-service audit-service api-gateway
  exit 1
fi

echo "=== [4/4] Verificando rutas HTTP y API del Aplicativo Web ==="
FAILED=0
for route in "/" "/comprar" "/validar" "/acreditacion" "/admin" "/superadmin" "/reclamos" "/api/v1/auth/superadmin/status" "/api/v1/registration/public/events"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${CHOSEN_PORT}${route}")
  echo "    HTTP ${code} -> ${route}"
  if [[ "${code}" != "200" ]]; then
    FAILED=1
  fi
done

if [[ "${FAILED}" -ne 0 ]]; then
  echo "[!] Alguna ruta no devolvió HTTP 200. Revisa: docker compose --env-file ${ENV_FILE} logs -f"
  exit 1
fi

COMMIT_SHA="$(git -C "${APP_DIR}" rev-parse --short HEAD)"
echo ""
echo "====================================================================="
echo "  EventPass SaaS actualizado correctamente al commit ${COMMIT_SHA}"
echo "  Puerto activo: ${CHOSEN_PORT} (infra/.env y BD preservados)"
echo "====================================================================="
