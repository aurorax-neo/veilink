#!/bin/sh
# install.sh — 全平台一键安装脚本
# 用法: curl -fsSL https://raw.githubusercontent.com/aurorax-neo/veilink/main/scripts/install.sh | sh
#   或: curl -fsSL https://raw.githubusercontent.com/aurorax-neo/veilink/main/scripts/install.sh | sh -s -- --no-service
set -eu

REPO="aurorax-neo/veilink"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
NO_SERVICE=0

for arg in "$@"; do
  case "$arg" in
    --no-service) NO_SERVICE=1 ;;
  esac
done

# 1. 检测平台
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
  linux)  GOOS="linux" ;;
  darwin) GOOS="darwin" ;;
  *) echo "不支持的系统: $OS" >&2; exit 1 ;;
esac
case "$ARCH" in
  x86_64|amd64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *) echo "不支持的架构: $ARCH" >&2; exit 1 ;;
esac

# 2. 拿最新版本
echo "→ 获取最新版本..."
VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
echo "  版本: $VERSION"

# 3. 下载二进制
echo "→ 下载 veilink-${VERSION}-${GOOS}-${GOARCH}..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
curl -fsSL -o "$TMP/veilink" \
  "https://github.com/${REPO}/releases/download/${VERSION}/veilink-${VERSION}-${GOOS}-${GOARCH}"
chmod +x "$TMP/veilink"

# 4. 安装
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP/veilink" "$INSTALL_DIR/veilink"
else
  echo "→ 需要 sudo 安装到 $INSTALL_DIR"
  sudo mv "$TMP/veilink" "$INSTALL_DIR/veilink"
fi
echo "  已安装到 $INSTALL_DIR/veilink"

# 5. 系统服务（可选）
if [ "$NO_SERVICE" = "0" ] && [ "$OS" = "linux" ] && [ -d /etc/systemd/system ]; then
  echo "→ 安装 systemd 服务..."
  cat | sudo tee /etc/systemd/system/veilink.service > /dev/null <<'EOF'
[Unit]
Description=Veilink Tunnel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/veilink master
Restart=always
RestartSec=5
# 数据目录用用户缓存，无需预建
Environment=DATA_DIR=

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now veilink
  echo "  服务已启动: systemctl status veilink"
fi

echo ""
echo "✅ 安装完成！运行以下命令启动："
echo "   veilink master"
echo ""
echo "首次启动会自动生成 API Key 并拉取前端，无需任何配置。"
