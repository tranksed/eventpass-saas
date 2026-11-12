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
chmod +x "${APP_DIR}/deploy/install-vps.sh" "${APP_DIR}/deploy/update-vps.sh"

CHOSEN_PORT="$(grep -E '^APP_HTTP_PORT=' "${ENV_FILE}" | tail -n1 | cut -d= -f2- || echo "8088")"
CHOSEN_PORT="${CHOSEN_PORT:-8088}"

grep -q '^SUPERADMIN_EMAIL=' "${ENV_FILE}" || echo 'SUPERADMIN_EMAIL=superadmin@eventpass.pe' >> "${ENV_FILE}"
grep -q '^SUPERADMIN_PASSWORD=' "${ENV_FILE}" || echo 'SUPERADMIN_PASSWORD=' >> "${ENV_FILE}"

echo "=== [2/4] Reconstruyendo e iniciando contenedores (puerto ${CHOSEN_PORT}) ==="
cd "${INFRA_DIR}"
docker compose --env-file "${ENV_FILE}" up -d --build --remove-orphans

echo "=== [3/4] Esperando /health y DB de microservicios en http://127.0.0.1:${CHOSEN_PORT} ==="
READY=0
for i in $(seq 1 40); do
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
