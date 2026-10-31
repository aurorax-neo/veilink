# install.ps1 — Docker 统一镜像部署引导脚本
# 用法: .\scripts\install.ps1 [-Version latest]

param(
    [string]$Version = "latest",
    [string]$ImageRepo = "ghcr.io/aurorax-neo/veilink"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "未检测到 docker，请先安装 Docker Desktop 或 Docker Engine。"
    exit 1
}

$Image = "${ImageRepo}:${Version}"
Write-Host "-> 拉取统一镜像 $Image..." -ForegroundColor Cyan
docker pull $Image

Write-Host ""
Write-Host "镜像已就绪。在 Linux 宿主机启动 Master：" -ForegroundColor Green
Write-Host "  docker run -itd --restart unless-stopped --name veilink-master -e TZ=Asia/Shanghai --network host -v /opt/docker/veilink-master/data:/data $Image master" -ForegroundColor Yellow
Write-Host ""
Write-Host "首次启动不会自动生成管理员 API Key，请手动创建（明文仅显示一次）：" -ForegroundColor Cyan
Write-Host "  docker exec veilink-master /usr/local/bin/veilink keys create admin" -ForegroundColor Yellow
