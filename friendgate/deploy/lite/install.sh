#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${FRIENDGATE_INSTALL_DIR:-/opt/friendgate}"
REPO_URL="${FRIENDGATE_REPO_URL:-}"
RELEASE_IMAGE="${FRIENDGATE_IMAGE:-}"
PUBLIC_HOST="${FRIENDGATE_PUBLIC_HOST:-}"
PUBLIC_IPV4_HOST="${FRIENDGATE_PUBLIC_IPV4_HOST:-}"
PUBLIC_IPV6_HOST="${FRIENDGATE_PUBLIC_IPV6_HOST:-}"
API_PUBLISHED_PORT="${API_PORT:-8080}"
ADMIN_PUBLISHED_PORT="${ADMIN_PORT:-8081}"
INVITE_PUBLISHED_PORT="${INVITE_PORT:-8082}"
GUIDE_PUBLISHED_PORT="${GUIDE_PORT:-8083}"
PORTAL_PUBLISHED_PORT="${PORTAL_PORT:-8084}"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 运行：sudo bash deploy/lite/install.sh" >&2
  exit 1
fi

validate_port() {
  local name="$1" value="$2"
  if [[ ! "${value}" =~ ^[0-9]+$ ]] || (( 10#${value} < 1 || 10#${value} > 65535 )); then
    echo "${name} 必须是 1–65535 之间的端口号" >&2
    exit 1
  fi
}
validate_port API_PORT "${API_PUBLISHED_PORT}"
validate_port ADMIN_PORT "${ADMIN_PUBLISHED_PORT}"
validate_port INVITE_PORT "${INVITE_PUBLISHED_PORT}"
validate_port GUIDE_PORT "${GUIDE_PUBLISHED_PORT}"
validate_port PORTAL_PORT "${PORTAL_PUBLISHED_PORT}"
if [ "$(printf '%s\n' "${API_PUBLISHED_PORT}" "${ADMIN_PUBLISHED_PORT}" "${INVITE_PUBLISHED_PORT}" "${GUIDE_PUBLISHED_PORT}" "${PORTAL_PUBLISHED_PORT}" | sort -u | wc -l)" -ne 5 ]; then
  echo "API_PORT、ADMIN_PORT、INVITE_PORT、GUIDE_PORT 和 PORTAL_PORT 必须使用五个不同端口" >&2
  exit 1
fi

# Resolve local-vs-piped execution before installing anything. A malformed
# pipe invocation must fail without changing an otherwise empty server.
SCRIPT_PATH="${BASH_SOURCE[0]:-}"
SCRIPT_DIR=""
SOURCE_ROOT=""
if [ -n "${SCRIPT_PATH}" ] && [ -f "${SCRIPT_PATH}" ]; then
  SCRIPT_DIR="$(cd -- "$(dirname -- "${SCRIPT_PATH}")" 2>/dev/null && pwd || true)"
  SOURCE_ROOT="$(cd -- "${SCRIPT_DIR}/../.." 2>/dev/null && pwd || true)"
fi
if { [ -z "${SOURCE_ROOT}" ] || [ ! -f "${SOURCE_ROOT}/Dockerfile.lite" ]; } && [ -z "${REPO_URL}" ]; then
  echo "管道安装时必须指定仓库：FRIENDGATE_REPO_URL=https://github.com/你的账号/你的仓库.git" >&2
  exit 1
fi

install_base_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl git openssl docker.io
    DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-v2 || \
      DEBIAN_FRONTEND=noninteractive apt-get install -y docker-compose-plugin || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y ca-certificates curl git openssl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y ca-certificates curl git openssl
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache ca-certificates curl git openssl docker docker-cli-compose
  else
    echo "不支持的 Linux 发行版；请先安装 Docker Engine、Compose v2、curl、git、openssl。" >&2
    exit 1
  fi
}

if ! command -v docker >/dev/null 2>&1 || ! command -v git >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
  install_base_packages
fi

if ! command -v docker >/dev/null 2>&1; then
  DOCKER_INSTALLER="/tmp/friendgate-get-docker.sh"
  curl -fsSL https://get.docker.com -o "${DOCKER_INSTALLER}"
  sh "${DOCKER_INSTALLER}"
fi

if command -v rc-update >/dev/null 2>&1 && command -v rc-service >/dev/null 2>&1; then
  rc-update add docker default
  rc-service docker start
elif command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now docker
elif command -v service >/dev/null 2>&1; then
  service docker start || true
fi

if ! docker compose version >/dev/null 2>&1; then
  MACHINE_ARCH="$(uname -m)"
  case "${MACHINE_ARCH}" in
    x86_64|amd64) COMPOSE_ARCH=x86_64 ;;
    aarch64|arm64) COMPOSE_ARCH=aarch64 ;;
    *) echo "不支持的 CPU 架构：${MACHINE_ARCH}" >&2; exit 1 ;;
  esac
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fL "https://github.com/docker/compose/releases/download/v2.39.1/docker-compose-linux-${COMPOSE_ARCH}" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod 0755 /usr/local/lib/docker/cli-plugins/docker-compose
fi

if [ -n "${SOURCE_ROOT}" ] && [ -f "${SOURCE_ROOT}/Dockerfile.lite" ]; then
  INSTALL_DIR="${SOURCE_ROOT}"
else
  if [ -e "${INSTALL_DIR}" ] && [ -n "$(ls -A "${INSTALL_DIR}" 2>/dev/null || true)" ]; then
    echo "安装目录非空，为避免覆盖已停止：${INSTALL_DIR}" >&2
    exit 1
  fi
  mkdir -p "$(dirname "${INSTALL_DIR}")"
  git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
fi

# Direct-IP HTTP installs can probe both public families without DNS. For an
# HTTPS deployment, replace these values with IPv4-only/IPv6-only DNS names.
if [ -z "${PUBLIC_IPV4_HOST}" ]; then
  PUBLIC_IPV4_HOST="$(curl -4fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
fi
if [ -z "${PUBLIC_IPV6_HOST}" ]; then
  PUBLIC_IPV6_HOST="$(curl -6fsS --max-time 5 https://api64.ipify.org 2>/dev/null || true)"
fi
# Accept either a bare IPv6 literal or the bracketed form commonly copied from
# a URL; the generated URL below adds exactly one bracket pair.
PUBLIC_IPV6_HOST="${PUBLIC_IPV6_HOST#\[}"
PUBLIC_IPV6_HOST="${PUBLIC_IPV6_HOST%\]}"
if [ -z "${PUBLIC_HOST}" ]; then
  PUBLIC_HOST="${PUBLIC_IPV4_HOST:-${PUBLIC_IPV6_HOST:-}}"
fi
if [ -z "${PUBLIC_HOST}" ]; then
  PUBLIC_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
if [ -z "${PUBLIC_HOST}" ]; then
  PUBLIC_HOST="127.0.0.1"
fi

format_url_host() {
  local value="$1"
  if [[ "${value}" == \[*\] ]]; then
    printf '%s' "${value}"
  elif [[ "${value}" == *:* ]]; then
    printf '[%s]' "${value}"
  else
    printf '%s' "${value}"
  fi
}
PUBLIC_URL_HOST="$(format_url_host "${PUBLIC_HOST}")"
PUBLIC_API_URL="${LITE_PUBLIC_API_URL:-http://${PUBLIC_URL_HOST}:${API_PUBLISHED_PORT}/v1}"
PUBLIC_INVITE_URL="${LITE_PUBLIC_INVITE_URL:-http://${PUBLIC_URL_HOST}:${INVITE_PUBLISHED_PORT}}"
PUBLIC_GUIDE_URL="${LITE_PUBLIC_GUIDE_URL:-http://${PUBLIC_URL_HOST}:${GUIDE_PUBLISHED_PORT}}"
PUBLIC_PORTAL_URL="${LITE_PUBLIC_PORTAL_URL:-http://${PUBLIC_URL_HOST}:${PORTAL_PUBLISHED_PORT}}"

ENV_FILE="${INSTALL_DIR}/deploy/lite/.env"
HOST_NGINX_AVAILABLE=false
if [ -d /etc/nginx ] && [ -r /etc/nginx ]; then
  HOST_NGINX_AVAILABLE=true
fi
if [ ! -f "${ENV_FILE}" ]; then
  ADMIN_PASSWORD="${LITE_ADMIN_PASSWORD:-$(openssl rand -base64 24 | tr -d '\n')}"
  MASTER_KEY="${LITE_MASTER_KEY:-$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')}"
  umask 077
  {
    printf 'LITE_ADMIN_USERNAME=%s\n' "${LITE_ADMIN_USERNAME:-admin}"
    printf 'LITE_ADMIN_PASSWORD=%s\n' "${ADMIN_PASSWORD}"
    printf 'LITE_MASTER_KEY=%s\n' "${MASTER_KEY}"
    printf 'LITE_PUBLIC_API_URL=%s\n' "${PUBLIC_API_URL}"
    printf 'LITE_PUBLIC_INVITE_URL=%s\n' "${PUBLIC_INVITE_URL}"
    printf 'LITE_PUBLIC_GUIDE_URL=%s\n' "${PUBLIC_GUIDE_URL}"
    printf 'LITE_PUBLIC_PORTAL_URL=%s\n' "${PUBLIC_PORTAL_URL}"
    printf 'LITE_UPSTREAM_BASE_URL=%s\n' "${LITE_UPSTREAM_BASE_URL:-https://chatgpt.com/backend-api/codex}"
    if [ -n "${PUBLIC_IPV4_HOST}" ]; then
      printf 'LITE_PUBLIC_IPV4_PROBE_URL=http://%s:%s\n' "${PUBLIC_IPV4_HOST}" "${INVITE_PUBLISHED_PORT}"
    else
      printf 'LITE_PUBLIC_IPV4_PROBE_URL=\n'
    fi
    if [ -n "${PUBLIC_IPV6_HOST}" ]; then
      printf 'LITE_PUBLIC_IPV6_PROBE_URL=http://[%s]:%s\n' "${PUBLIC_IPV6_HOST}" "${INVITE_PUBLISHED_PORT}"
    else
      printf 'LITE_PUBLIC_IPV6_PROBE_URL=\n'
    fi
    printf 'LITE_SECURE_COOKIES=%s\n' "${LITE_SECURE_COOKIES:-true}"
    printf 'LITE_BAN_THRESHOLD=%s\n' "${LITE_BAN_THRESHOLD:-20}"
    printf 'LITE_BAN_WINDOW=%s\n' "${LITE_BAN_WINDOW:-1m}"
    printf 'LITE_BAN_DURATION=%s\n' "${LITE_BAN_DURATION:-24h}"
    printf 'LITE_INVITE_TTL=%s\n' "${LITE_INVITE_TTL:-168h}"
    printf 'LITE_ADMIN_SESSION_TTL=%s\n' "${LITE_ADMIN_SESSION_TTL:-12h}"
    printf 'LITE_USER_SESSION_TTL=%s\n' "${LITE_USER_SESSION_TTL:-168h}"
    printf 'LITE_DESKTOP_FLOW_TTL=%s\n' "${LITE_DESKTOP_FLOW_TTL:-10m}"
    printf 'LITE_DESKTOP_ACCESS_TTL=%s\n' "${LITE_DESKTOP_ACCESS_TTL:-15m}"
    printf 'LITE_DESKTOP_REFRESH_TTL=%s\n' "${LITE_DESKTOP_REFRESH_TTL:-720h}"
    printf 'LITE_STICKY_SESSION_TTL=%s\n' "${LITE_STICKY_SESSION_TTL:-1h}"
    printf 'LITE_ACCOUNT_COOLDOWN=%s\n' "${LITE_ACCOUNT_COOLDOWN:-5m}"
    printf 'LITE_QUOTA_BASE_URL=%s\n' "${LITE_QUOTA_BASE_URL:-https://chatgpt.com/backend-api/wham}"
    printf 'LITE_QUOTA_SYNC_INTERVAL=%s\n' "${LITE_QUOTA_SYNC_INTERVAL:-5m}"
    printf 'LITE_MAX_BODY_MIB=%s\n' "${LITE_MAX_BODY_MIB:-64}"
    printf 'API_PORT=%s\n' "${API_PUBLISHED_PORT}"
    printf 'ADMIN_PORT=%s\n' "${ADMIN_PUBLISHED_PORT}"
    printf 'INVITE_PORT=%s\n' "${INVITE_PUBLISHED_PORT}"
    printf 'GUIDE_PORT=%s\n' "${GUIDE_PUBLISHED_PORT}"
    printf 'PORTAL_PORT=%s\n' "${PORTAL_PUBLISHED_PORT}"
    if [ -n "${RELEASE_IMAGE}" ]; then
      printf 'FRIENDGATE_IMAGE=%s\n' "${RELEASE_IMAGE}"
    fi
    printf 'LITE_TRUSTED_PROXIES=%s\n' "${LITE_TRUSTED_PROXIES:-}"
    printf 'LITE_NGINX_MONITOR_PATHS=/host-nginx/nginx.conf,/host-nginx/conf.d,/host-nginx/sites-enabled\n'
    if [ "${HOST_NGINX_AVAILABLE}" = true ]; then
      printf 'LITE_NGINX_HOST_PATH=/etc/nginx\n'
    fi
    printf 'TMPFS_SIZE=%s\n' "${TMPFS_SIZE:-128m}"
    printf 'MEMORY_LIMIT=%s\n' "${MEMORY_LIMIT:-512m}"
    printf 'CPU_LIMIT=%s\n' "${CPU_LIMIT:-1.0}"
    printf 'STOP_GRACE_PERIOD=%s\n' "${STOP_GRACE_PERIOD:-30s}"
    printf 'LOG_MAX_SIZE=%s\n' "${LOG_MAX_SIZE:-10m}"
    printf 'LOG_MAX_FILES=%s\n' "${LOG_MAX_FILES:-3}"
    printf 'TZ=%s\n' "${TZ:-Asia/Shanghai}"
  } > "${ENV_FILE}"
fi

cd "${INSTALL_DIR}/deploy/lite"
COMPOSE_ARGS=(-f docker-compose.yml)
if [ "${HOST_NGINX_AVAILABLE}" = true ]; then
  COMPOSE_ARGS+=(-f docker-compose.nginx.yml)
fi
if [ -z "${RELEASE_IMAGE}" ]; then
  RELEASE_IMAGE="$(sed -n 's/^FRIENDGATE_IMAGE=//p' .env)"
fi
if [ -n "${RELEASE_IMAGE}" ]; then
  FRIENDGATE_IMAGE="${RELEASE_IMAGE}" docker compose --env-file .env "${COMPOSE_ARGS[@]}" pull friendgate
  FRIENDGATE_IMAGE="${RELEASE_IMAGE}" docker compose --env-file .env "${COMPOSE_ARGS[@]}" up -d --no-build
else
  docker compose --env-file .env "${COMPOSE_ARGS[@]}" up -d --build
fi

ADMIN_PASSWORD_VALUE="$(sed -n 's/^LITE_ADMIN_PASSWORD=//p' .env)"
ADMIN_PORT_VALUE="$(sed -n 's/^ADMIN_PORT=//p' .env)"
ADMIN_PORT_VALUE="${ADMIN_PORT_VALUE:-8081}"
echo
echo "FriendGate 已启动"
echo "API:    $(sed -n 's/^LITE_PUBLIC_API_URL=//p' .env)"
echo "后台:   http://${PUBLIC_URL_HOST}:${ADMIN_PORT_VALUE}"
echo "邀请端: $(sed -n 's/^LITE_PUBLIC_INVITE_URL=//p' .env)"
echo "配置指南: $(sed -n 's/^LITE_PUBLIC_GUIDE_URL=//p' .env)"
echo "用户登录: $(sed -n 's/^LITE_PUBLIC_PORTAL_URL=//p' .env)"
if [ "${HOST_NGINX_AVAILABLE}" = true ]; then
  echo "Nginx:  已从 /etc/nginx 只读挂载，可在后台确认基线"
else
  echo "Nginx:  宿主机未安装，后台将如实显示不适用（N/A）"
fi
echo "初始化账号: $(sed -n 's/^LITE_ADMIN_USERNAME=//p' .env)"
echo "初始化口令: ${ADMIN_PASSWORD_VALUE}"
echo
echo "首次打开后台后，请创建最终管理员密码并扫描 Microsoft Authenticator 二维码。"
echo "初始化完成后创建入口会永久关闭。请同时配置防火墙，并在正式使用前为五个入口配置 HTTPS。"
