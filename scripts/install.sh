#!/bin/sh
# install.sh — Docker 统一镜像部署引导脚本
# 用法: sh scripts/install.sh [version]
set -eu

IMAGE_REPO="${IMAGE_REPO:-ghcr.io/aurorax-neo/veilink}"
VERSION="${1:-latest}"
DATA_HOST_DIR="${DATA_HOST_DIR:-/opt/docker/veilink-master/data}"

if ! command -v docker >/dev/null 2>&1; then
  echo "未检测到 docker，请先安装 Docker Engine 后再运行。" >&2
  exit 1
fi

echo "-> 拉取统一镜像 ${IMAGE_REPO}:${VERSION}..."
docker pull "${IMAGE_REPO}:${VERSION}"

cat <<EOF

镜像已就绪。使用以下命令启动 Master（数据持久化到 ${DATA_HOST_DIR}）：

  docker run -itd --restart unless-stopped --name veilink-master \
    -e TZ=Asia/Shanghai \
    --network host \
    -v "${DATA_HOST_DIR}:/data" \
    "${IMAGE_REPO}:${VERSION}" master

首次启动不会自动生成管理员 API Key，请手动创建（明文仅显示一次）：

  docker exec veilink-master /usr/local/bin/veilink keys create admin
EOF
