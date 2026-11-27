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

首次启动会自动启用防访客抢注安装锁（Install Lock）并生成一次性初始化令牌：

  docker exec veilink-master /usr/local/bin/veilink admin show-install-secret

打开 Web 控制台输入该安全令牌，手工注册唯一管理员邮箱与密码后，安装入口将自动销毁并永久锁定。
EOF
