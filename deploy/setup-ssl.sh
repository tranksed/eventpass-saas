#!/usr/bin/env bash
# =============================================================================
# EventPass SaaS — Herramienta de Dominio y Certificados SSL HTTPS (Let's Encrypt)
# Comandos:
#   sudo eventpass-ssl setup <dominio.pe> <email@dominio.pe>
#   sudo eventpass-ssl check-dns <dominio.pe>
#   sudo eventpass-ssl renew
#   sudo eventpass-ssl status
# =============================================================================
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INFRA_DIR="${APP_DIR}/infra"
ENV_FILE="${INFRA_DIR}/.env"
SSL_DIR="${APP_DIR}/gateway/ssl"
CERTBOT_DIR="${APP_DIR}/gateway/certbot_www"

mkdir -p "${SSL_DIR}" "${CERTBOT_DIR}"

get_public_ip() {
  curl -fsSL https://api.ipify.org 2>/dev/null || curl -fsSL https://icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}'
}

resolve_dns() {
  local domain="$1"
  local res
  res=$(python3 -c "import socket; print('\n'.join(sorted(list({i[4][0] for i in socket.getaddrinfo('${domain}', None, socket.AF_INET)}))))" 2>/dev/null || true)
  if [[ -z "${res}" ]]; then
    res=$(curl -fsSL -H "accept: application/dns-json" "https://cloudflare-dns.com/dns-query?name=${domain}&type=A" 2>/dev/null | grep -oE '"data":"[0-9.]+"' | cut -d'"' -f4 || true)
  fi
  echo "${res}"
}

cmd_check_dns() {
  local domain="${1:-}"
  if [[ -z "${domain}" ]]; then
    echo "Uso: sudo eventpass-ssl check-dns <midominio.com>"
    exit 1
  fi
  local pub_ip
  pub_ip=$(get_public_ip)
  echo "=== Verificación DNS para: ${domain} ==="
  echo "IP Pública de este VPS : ${pub_ip}"

  local resolved
  resolved=$(resolve_dns "${domain}")
  if [[ -z "${resolved}" ]]; then
    echo "Estado DNS             : ❌ NO RESUELVE"
    echo ""
    echo "Acción requerida: Ve a tu proveedor de dominio (Cloudflare, GoDaddy, Hostinger, etc.)"
    echo "y crea un Registro DNS:"
    echo "   Tipo : A"
    echo "   Nombre : ${domain} (o @)"
    echo "   Valor : ${pub_ip}"
    return 1
  fi

  echo "IPs a las que apunta   : $(echo ${resolved} | tr '\n' ' ')"
  if echo "${resolved}" | grep -q "^${pub_ip}$"; then
    echo "Estado DNS             : ✅ CORRECTO (Apunta a este servidor VPS)"
    return 0
  else
    echo "Estado DNS             : ⚠️ DISCREPANCIA (No apunta a este servidor)"
    echo "El dominio resuelve a otra IP. Cambia el Registro A hacia: ${pub_ip}"
    return 2
  fi
}

cmd_status() {
  echo "=== Estado de Dominio y Certificado SSL ==="
  local pub_ip
  pub_ip=$(get_public_ip)
  echo "IP Servidor VPS : ${pub_ip}"

  if [[ -f "${SSL_DIR}/active_cert.pem" ]]; then
    echo "Certificado     : ${SSL_DIR}/active_cert.pem presente"
    if command -v openssl >/dev/null 2>&1; then
      local subject issuer not_after
      subject=$(openssl x509 -in "${SSL_DIR}/active_cert.pem" -noout -subject 2>/dev/null || true)
      issuer=$(openssl x509 -in "${SSL_DIR}/active_cert.pem" -noout -issuer 2>/dev/null || true)
      not_after=$(openssl x509 -in "${SSL_DIR}/active_cert.pem" -noout -enddate 2>/dev/null || true)
      echo "  Sujeto        : ${subject}"
      echo "  Emisor        : ${issuer}"
      echo "  Expira        : ${not_after}"
      if openssl x509 -checkend 0 -noout -in "${SSL_DIR}/active_cert.pem" 2>/dev/null; then
        echo "  Vigencia      : ✅ Certificado Vigente"
      else
        echo "  Vigencia      : ❌ Certificado EXPIRADO"
      fi
    fi
  else
    echo "Certificado     : ❌ No hay certificado configurado en ${SSL_DIR}/active_cert.pem"
  fi

  if [[ -f "${ENV_FILE}" ]]; then
    local dom ssl_en
    dom=$(grep "^PLATFORM_DOMAIN=" "${ENV_FILE}" | cut -d'=' -f2 || true)
    ssl_en=$(grep "^SSL_ENABLED=" "${ENV_FILE}" | cut -d'=' -f2 || true)
    echo "Dominio en .env : ${dom:-Sin configurar}"
    echo "SSL Habilitado  : ${ssl_en:-false}"
  fi
}

cmd_setup() {
  local domain="${1:-}"
  local email="${2:-}"

  if [[ -z "${domain}" || -z "${email}" ]]; then
    echo "Uso: sudo eventpass-ssl setup <dominio.pe> <email@dominio.pe>"
    exit 1
  fi

  echo "=== Configurando SSL Let's Encrypt para: ${domain} (${email}) ==="

  # 1. Verificar DNS antes de proceder
  if ! cmd_check_dns "${domain}"; then
    echo ""
    read -r -p "¿Deseas forzar la solicitud de certificado a pesar de la advertencia de DNS? [s/N]: " force_dns || true
    if [[ "${force_dns,,}" != "s" && "${force_dns,,}" != "y" ]]; then
      echo "[!] Operación cancelada. Configura el registro A primero para evitar bloqueos de Let's Encrypt."
      exit 1
    fi
  fi

  # 2. Instalar Certbot si no está presente
  if ! command -v certbot >/dev/null 2>&1; then
    echo "--> Instalando Certbot..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y && apt-get install -y certbot
  fi

  # 3. Abrir firewall UFW para puerto 80 y 443
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp >/dev/null 2>&1 || true
    ufw allow 443/tcp >/dev/null 2>&1 || true
  fi

  # 4. Solicitar certificado Let's Encrypt usando webroot
  echo "--> Solicitando certificado a Let's Encrypt..."
  mkdir -p "${CERTBOT_DIR}"
  if certbot certonly --webroot -w "${CERTBOT_DIR}" \
      -d "${domain}" \
      --email "${email}" \
      --agree-tos \
      --no-eff-email \
      --non-interactive \
      --keep-until-expiring; then
    echo "✅ Certificado Let's Encrypt obtenido con éxito."
  else
    echo "--> Intentando método alternativo standalone..."
    docker compose -f "${INFRA_DIR}/docker-compose.yml" stop api-gateway 2>/dev/null || true
    certbot certonly --standalone \
      -d "${domain}" \
      --email "${email}" \
      --agree-tos \
      --no-eff-email \
      --non-interactive \
      --keep-until-expiring
    docker compose -f "${INFRA_DIR}/docker-compose.yml" start api-gateway 2>/dev/null || true
  fi

  # 5. Enlazar certificados al Nginx de EventPass
  if [[ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]]; then
    echo "--> Enlazando certificados a ${SSL_DIR}..."
    cp -L "/etc/letsencrypt/live/${domain}/fullchain.pem" "${SSL_DIR}/active_cert.pem"
    cp -L "/etc/letsencrypt/live/${domain}/privkey.pem" "${SSL_DIR}/active_key.pem"
    chmod 600 "${SSL_DIR}/active_key.pem"
    chmod 644 "${SSL_DIR}/active_cert.pem"

    # Actualizar .env para puertos estándar web (80 y 443) y dominio SSL
    if grep -q "^PLATFORM_DOMAIN=" "${ENV_FILE}"; then
      sed -i "s/^PLATFORM_DOMAIN=.*/PLATFORM_DOMAIN=${domain}/" "${ENV_FILE}"
    else
      echo "PLATFORM_DOMAIN=${domain}" >> "${ENV_FILE}"
    fi

    if grep -q "^SSL_ENABLED=" "${ENV_FILE}"; then
      sed -i "s/^SSL_ENABLED=.*/SSL_ENABLED=true/" "${ENV_FILE}"
    else
      echo "SSL_ENABLED=true" >> "${ENV_FILE}"
    fi

    sed -i "s/^APP_HTTP_PORT=.*/APP_HTTP_PORT=80/" "${ENV_FILE}"
    if grep -q "^APP_HTTPS_PORT=" "${ENV_FILE}"; then
      sed -i "s/^APP_HTTPS_PORT=.*/APP_HTTPS_PORT=443/" "${ENV_FILE}"
    else
      echo "APP_HTTPS_PORT=443" >> "${ENV_FILE}"
    fi

    # Recargar o reiniciar Nginx para vincular puertos 80 y 443 con SSL
    echo "--> Recargando e iniciando NGINX en puertos 80 y 443..."
    docker compose -f "${INFRA_DIR}/docker-compose.yml" --env-file "${ENV_FILE}" up -d api-gateway 2>/dev/null || \
      docker compose -f "${INFRA_DIR}/docker-compose.yml" exec -T api-gateway nginx -s reload 2>/dev/null || true

    echo ""
    echo "====================================================================="
    echo "  🎉 ¡HTTPS SSL Activado con éxito para ${domain}!"
    echo "====================================================================="
    echo "  Accede ahora de forma segura:"
    echo "    Portal de Eventos    : https://${domain}/"
    echo "    Taquilla & Compra    : https://${domain}/comprar"
    echo "    Consola SuperAdmin   : https://${domain}/superadmin"
    echo "    Panel Organizador    : https://${domain}/admin"
    echo "====================================================================="
  else
    echo "[!] No se encontró el certificado en /etc/letsencrypt/live/${domain}/"
    exit 1
  fi
}

cmd_renew() {
  echo "=== Renovando certificados SSL Let's Encrypt ==="
  certbot renew --webroot -w "${CERTBOT_DIR}"
  local dom
  dom=$(grep "^PLATFORM_DOMAIN=" "${ENV_FILE}" 2>/dev/null | cut -d'=' -f2 || true)
  if [[ -n "${dom}" && -f "/etc/letsencrypt/live/${dom}/fullchain.pem" ]]; then
    cp -L "/etc/letsencrypt/live/${dom}/fullchain.pem" "${SSL_DIR}/active_cert.pem"
    cp -L "/etc/letsencrypt/live/${dom}/privkey.pem" "${SSL_DIR}/active_key.pem"
    docker compose -f "${INFRA_DIR}/docker-compose.yml" exec -T api-gateway nginx -s reload 2>/dev/null || true
    echo "✅ Certificados renovados y NGINX recargado."
  fi
}

# Cronjob diario de auto-renovación
setup_cron() {
  local cron_file="/etc/cron.d/eventpass-ssl-renew"
  if [[ ! -f "${cron_file}" ]]; then
    echo "0 3 * * * root /usr/local/bin/eventpass-ssl renew >/dev/null 2>&1" > "${cron_file}"
    chmod 644 "${cron_file}"
  fi
}

ACTION="${1:-}"
shift || true

case "${ACTION}" in
  setup)
    cmd_setup "$@"
    setup_cron
    ;;
  check-dns)
    cmd_check_dns "$@"
    ;;
  status)
    cmd_status
    ;;
  renew)
    cmd_renew
    ;;
  *)
    echo "Uso: sudo eventpass-ssl {setup|check-dns|status|renew}"
    echo ""
    echo "Ejemplos:"
    echo "  sudo eventpass-ssl check-dns midominio.com"
    echo "  sudo eventpass-ssl setup midominio.com admin@midominio.com"
    echo "  sudo eventpass-ssl status"
    echo "  sudo eventpass-ssl renew"
    exit 1
    ;;
esac
