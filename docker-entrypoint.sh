#!/bin/sh
# docker-entrypoint.sh — 容器启动时自动修复数据目录权限，无需用户手动 mkdir/chown
set -eu

APP_UID="65532"
APP_GID="65532"
DATA_DIR="${DATA_DIR:-/data}"

case "${DATA_DIR}" in
    /data|/data/*) ;;
    *)
        echo "[entrypoint] refusing unsafe DATA_DIR=${DATA_DIR}; must be /data or a subdirectory under /data" >&2
        exit 1
        ;;
esac

case "${DATA_DIR}" in
    *..*|*" "*)
        echo "[entrypoint] refusing unsafe DATA_DIR=${DATA_DIR}" >&2
        exit 1
        ;;
esac

# 确保数据目录存在（拒绝软链接）
mkdir -p "${DATA_DIR}"
if [ -L "${DATA_DIR}" ]; then
    echo "[entrypoint] refusing symlink DATA_DIR=${DATA_DIR}" >&2
    exit 1
fi

# 如果当前是 root，修复属主后降权执行
if [ "$(id -u)" = "0" ]; then
    current=$(stat -c '%u:%g' "${DATA_DIR}" 2>/dev/null || echo "unknown")
    if [ "$current" != "${APP_UID}:${APP_GID}" ]; then
        echo "[entrypoint] fixing ownership of ${DATA_DIR} -> ${APP_UID}:${APP_GID}"
        chown -Rh "${APP_UID}:${APP_GID}" "${DATA_DIR}"
    fi
    exec su-exec "${APP_UID}:${APP_GID}" /usr/local/bin/veilink "$@"
fi

# 非 root 启动（如 k8s securityContext），直接跑
exec /usr/local/bin/veilink "$@"
