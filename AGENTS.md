# Veilink 项目约束

适用范围：整个仓库。此文件是唯一项目开发约束文件；面向使用者的部署与接口说明在 `README.md`。维护时先读实际代码，不把未执行的检查写成已通过。

更新记录：2026-10-04 按新需求修订——前后端独立发布、API Key 认证、前后端解耦。旧约束中与新需求冲突的部分以本版为准。

- **角色与发布**：一个原生 Go 源码项目，以 `master|server|client` 子命令选择角色；只有 Master 启用 Web/API。发布采用前后端独立版本线：后端打 `v*` 标签走 `release-backend.yml`（Go 二进制 + `veilink-backend` 镜像），前端打 `web-v*` 标签走 `release-web.yml`（静态资源 tar.gz + `veilink-web` 镜像），统一镜像由 `release-image.yml` 手动触发组装（指定后端版本 + 前端版本）。Tag 命名空间物理隔离（`v*` vs `web-v*`），版本号独立演进，唯一耦合点是 API 契约版本（`/api/v1`）。Veilink 生产使用 `docker run`；命令必须有 `-itd`、`--restart unless-stopped`、`--name`、`TZ=Asia/Shanghai`。数据目录零配置自动解析（`$DATA_DIR` → `/data` → OS 标准缓存目录 → `./data`），无需用户预建。
- **HTTP 默认与可选 TLS**：Master 开箱默认 `http://127.0.0.1:2545`，不强制 TLS；内置 HTTPS 是可选功能。常见生产形态为 nginx（或同类）终止 HTTPS 后转发到 Veilink 本机/内网 HTTP。反代须同时正确处理 Web/API 与 gRPC h2c；HTTPS 证书由终止 TLS 的组件管理。
- **认证模型**：API Key 认证，无用户名、无密码、无 session、无 CSRF。Key 存数据库 `api_keys` 表（仅存 sha256 hash + 8 位前缀 + role，不存明文）。首次启动无 admin key 时自动生成 `default-admin` 并打印到日志（仅显示一次）。支持 `admin` / `readonly` 两种 role。请求头优先级：`Authorization: Bearer <key>` > `X-API-Key` > `?api_key=`（query 方式默认关闭，需显式开启）。公开路径免认证：`/api/version`、`/healthz`、`/api/health`。CLI 提供 `keys list/create/revoke` 子命令；`revoke` 保护最后一个 admin key 不可删。
- **API 版本化**：所有 API 路由带 `/api/v1` 前缀。老 `/api/*` 路径 301 重定向到 `/api/v1/*`（保留至少 2 个大版本）。`GET /api/version` 返回 `{api_version, backend_version, web_version, web_mode}` 契约信息，前端启动时检查，不匹配弹全屏警告。Breaking change 必须走 `/api/v2`，CI 用 oasdiff 卡点。
- **前端托管模式**：`WEB_MODE` 环境变量控制，仅两种值：`off`（纯 API，不托管前端） / `pull`（默认，从 GitHub Release 拉取前端 tar.gz 并托管）。`pull` 模式支持 `WEB_VERSION`（空=latest）、`WEB_CACHE_DIR`（默认 `/data/web`）、`WEB_GITHUB_MIRROR`（加速地址，支持代理网关式和镜像站式两种写法）。拉取原子切换（tmp 解压 → `.ok` 标记 → rename），`POST /api/v1/web/update` 可热更新前端版本。CORS 默认开启（`WEB_CORS=true`），分离部署时前端可跨域调用。
- **实时推送**：单向推送（日志、节点状态、统计）用 SSE（`GET /api/v1/stream`），替代 WebSocket。EventSource 不能带 Header，用 `POST /api/v1/stream/token` 换一次性 token（60 秒有效）。如 `ConsoleView` 需双向交互则该接口保留 WebSocket，其余全部 SSE。
- **启动参数与目录**：所有角色用专属命令行 flags；不接受 YAML 配置文件。容器内数据默认 `/data`，宿主机零配置（entrypoint 自动修复权限，无需用户 mkdir/chown）。Master 的 SQLite 配置可持久化，显式 flags 覆盖已存设置。Docker entrypoint 以 root 启动修复 `/data` 属主后 `su-exec` 降权到 65532 执行；非 root 启动时跳过 chown。
- **职责与安全**：`internal/tunnel` 实现原生私有 VLESS/mux/XUDP，不嵌入 Xray。`internal/store` 校验并持久化配置；`internal/httpapi` 保持严格 JSON、API Key 认证、登录限速（按 key 限速）；`frontend/` 是唯一 Web 界面。Server 只接受授权反向连接，Client 只拨允许的目标，不做开放代理。不能为兼容旧版本放宽认证或配置校验。
- **密钥与配置**：仅 Master HTTPS 身份证书来自只读文件挂载；隧道证书与密钥在 Web 保存为 PEM。Client 不上传、不保存隧道设置；快照不得包含私钥材料。注册令牌在有效期内可重复使用，撤销或过期后失效。
- **映射与 Vision**：映射直接选 Server/Client，Pool 只属于映射（1–32），无公开绑定管理。TCP/XUDP 授权隔离；Vision 仅 TCP+TLS/REALITY。协议修改须覆盖往返、恶意输入、并发、取消和 race。
- **配置同步**：期望修订与已应用修订分开；心跳不是目标可达性。Apply 失败不报成功，重复修订不同配置或旧修订必须拒绝；保留最后成功快照。
- **前端**：Vue 3 + TypeScript + Vite。页面只呈现任务相关信息，业务规则通过控件约束/字段校验/提交确认/失败反馈体现，不堆说明文字。骨架屏代替白屏（布局尺寸与真实界面一致），顶栏等静态部分不等数据先渲染，`scrollbar-gutter: stable` 防布局抖动。支持浅色/深色，响应式、键盘操作。API 调用统一走 `src/api.ts` 封装（自动带 Key、401 跳登录）。
- **升级迁移**：旧版用户名密码用户升级时，首次启动检测到旧 `admin` 表有数据，自动生成 API Key 并在日志中明确提示迁移（旧账号已失效，请用新 Key 登录）。旧 `/api/*` 路径 301 重定向保证老前端可用。遇到已有用户数据先备份。
- **验收**：至少运行 `go test ./...`、`go vet ./...`、相关 race 测试、前端测试与生产构建、带 `integration` 标签的端到端测试、统一镜像的一次构建及 master/server/client 三种启动模式的内容和健康检查（若当前环境无 Docker 则如实说明）；校验 `git diff --check`。不得声称远端部署、镜像构建或 Git 提交已完成，除非确实执行。
