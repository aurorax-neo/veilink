# install.ps1 — Windows 一键安装脚本
# 用法: irm https://get.veilink.dev/install.ps1 | iex

$ErrorActionPreference = "Stop"
$Repo = "aurorax-neo/veilink"
$InstallDir = "$env:ProgramFiles\veilink"

# 检测架构
$Arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { $Arch = "arm64" }

# 获取最新版本
Write-Host "→ 获取最新版本..." -ForegroundColor Cyan
$Latest = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
$Version = $Latest.tag_name
Write-Host "  版本: $Version" -ForegroundColor Green

# 下载
$FileName = "veilink-$Version-windows-$Arch.exe"
$Url = "https://github.com/$Repo/releases/download/$Version/$FileName"
$Tmp = Join-Path $env:TEMP $FileName
Write-Host "→ 下载 $FileName..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $Url -OutFile $Tmp

# 安装
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
}
Copy-Item $Tmp "$InstallDir\veilink.exe" -Force
Write-Host "  已安装到 $InstallDir\veilink.exe" -ForegroundColor Green

# 加入 PATH
$Path = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($Path -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$Path;$InstallDir", "Machine")
    $env:Path += ";$InstallDir"
    Write-Host "  已加入系统 PATH" -ForegroundColor Green
}

Write-Host ""
Write-Host "✅ 安装完成！运行以下命令启动：" -ForegroundColor Green
Write-Host "   veilink master" -ForegroundColor Yellow
Write-Host ""
Write-Host "首次启动会自动生成 API Key 并拉取前端，无需任何配置。"
