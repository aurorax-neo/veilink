# Veilink

Veilink 是原生 Go 实现的私有 VLESS 反向隧道。Master 管理 Server、Client 与 TCP/UDP 映射；业务数据由 Server 和 Client 直接传输，除非 Master 自身启用了内置 Server。Web 控制台由 Vue 3 + TypeScript 构建。不运行 Xray 外部内核二进制，也不承诺与其客户端互通；第三方源码组件及 HY2 BBR 来源见下方法律声明。

> **唯一支持的生产运行方式是 Docker Run。** 只发布一个统一镜像 `veilink:latest`（版本发布使用同一版本 tag），以 `master`、`server`、`client` 子命令选择角色，不维护角色镜像或发布包矩阵。项目开发约束见 [AGENTS.md](AGENTS.md)；许可证和法律声明分别见 [LICENSE](LICENSE)、[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 许可证与第三方来源

Veilink 原创代码及文档（另有声明者除外）以 **GPL-3.0-or-later** 发布，即 GNU GPL 第 3 版或由您选择的 FSF 后续版本；完整正文见 [LICENSE](LICENSE)，授权及版权声明见 [NOTICE](NOTICE)。软件按许可证约定不提供担保。第三方组件继续适用各自许可证，不因根许可证变更而被统一改为 GPL。

HY2 默认使用 Xray `standard` BBR：Client/Server 均在认证成功后、业务流建立前挂载，不使用 Brutal，也不继续使用默认 Cubic。通过 Go 模块引用 `ref/Xray-core` 对应 commit `d562d8947d3175db86b4fa849742433a9876cb63` 的 `congestion/bbr` 和 `congestion/common`（MPL-2.0），配合 `github.com/apernet/quic-go`（MIT）；本地适配文件 `internal/tunnel/hysteria_bbr.go` 保留 MPL-2.0、来源与修改说明。未引入 mihomo 实现代码，仅从其本地 `LICENSE` 取得标准 GPLv3 正文。

分发源码、二进制、镜像或前端产物时，须保留适用的第三方版权、许可和 NOTICE，并按 GPL/MPL 等适用条款提供对应源码与获取说明；本段不表示发布物已经完成合规审计。直接依赖许可核查、REALITY 标准 MPL Exhibit B 的说明及分发义务见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)，不构成法律意见或保证。

## 发布与目录

统一镜像包含一个原生 Go 可执行文件、系统信任证书、`/usr/local/html/` 管理页面及健康检查依赖。只有 Master 启用 Web，Server/Client 不启动 Web 服务。Go/UI 多阶段构建只是构建实现，不是多个发布产品；一次构建生成一个镜像：

```sh
docker build -t veilink:latest .
```

国内网络默认使用 USTC Alpine 镜像源、npmmirror 和 goproxy.cn，采用 linuxmirrors.cn 的替换软件源思路，不执行远程安装脚本。可用 `--build-arg APK_MIRROR=https://dl-cdn.alpinelinux.org/alpine` 覆盖 APK 源（地址不带末尾斜线），也可覆盖 `NPM_REGISTRY` 和 `GOPROXY`。

若使用已发布的统一镜像，无需在宿主机编译。镜像入口是 `/usr/local/bin/veilink`，必须在镜像名后指定 **`master|server|client` 子命令，再跟角色 flags**；不指定角色会退出，不接受 `-config`。所有持久化内容位于容器内 `/data/`，宿主机挂载根目录统一为 `/opt/docker/<app_name>/`；不在项目目录创建 `.local`。镜像用户是 UID/GID `65532:65532`。日志从 `docker logs <app_name>` 读取，不创建未被程序使用的 `logs` 目录。

所有命令包含 `-itd`、`--restart unless-stopped`、`--name` 和 `TZ=Asia/Shanghai`。Master（允许内置网关与动态映射）和独立 Server 使用 `--net host`，**不加 `-p`**；仅出站的 Client 使用 Docker 默认 Bridge 网络，**不写 `--net` 或 `-p`**。Host 网络直接使用宿主机端口，应检查端口冲突、防火墙和访问控制；Client 容器中的 `127.0.0.1` 不代表宿主机。

**执行顺序注意：** 下文按“Docker Run 命令 → 挂载准备 → 参数说明”展示以便复制，但在全新宿主机上，务必先执行该角色的“挂载准备”，放好证书并设置权限，最后才运行上方的 Docker Run 命令；否则 Docker 自动创建的目录可能归 root，非 root 容器无法写入 `/data`。

### Master（可含内置 Server）

准备 Master HTTPS 的 `cert.pem`、`key.pem`，证书须包含控制台域名并允许 UID 65532 读取。Master 首次启动不创建管理员，也不生成默认账号密码；不再支持 `VEILINK_INIT_ADMIN_*` 环境变量或 `init-admin` 命令。访问控制台后按首次注册引导创建唯一管理员（用户名最多 128 字节，密码 12–72 字节）。

**首次注册必须在可信网络完成**：先通过防火墙限制控制台访问，否则任何能访问面板的人都可能抢先注册。公开 `GET /api/setup` 返回 `registration_required`；`POST /api/register` 仅在无管理员时开放，创建成功后关闭，竞争注册返回 409。无账号时登录失败，管理 API 始终需要认证。

**Docker Run 命令**（替换域名占位值）：

```sh
docker run -itd \
  --name veilink-master --restart unless-stopped --net host \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-master/config:/config:ro \
  -v /opt/docker/veilink-master/data:/data \
  veilink:latest master \
  -database /data/veilink.db -deployment-key /data/veilink.key \
  -state-dir /data/state -listen-addr 0.0.0.0:8443 \
  -scheme https -cert-file /config/cert.pem -key-file /config/key.pem \
  -html-dir /usr/local/html \
  -control-server-name panel.example.com \
  -embedded-server-enabled=true \
  -embedded-server-address gateway.example.com \
  -embedded-server-server-name gateway.example.com -embedded-server-port 8444
```

**挂载准备：**

```sh
mkdir -p /opt/docker/veilink-master/config /opt/docker/veilink-master/data && chown -R 65532:65532 /opt/docker/veilink-master/config /opt/docker/veilink-master/data && chmod 700 /opt/docker/veilink-master/config /opt/docker/veilink-master/data
```

**关键参数：** `/config` 只读，仅保存 Master HTTPS 证书、私钥及可选私有 CA；`/data` 保存 SQLite、deployment key、内置节点状态。Web、REST API 和 gRPC 共用 Master 的 `8443` 监听器。内置 Server 默认显示名为 `default`；已有节点身份和自定义名保持不变，可用 `-embedded-server-name` 指定首次名称。`-embedded-server-address/-port/-server-name` 初始化默认客户端接入候选；首次创建时本地隧道监听端口也初始化为该 port，之后可在 Web 分别修改。动态映射端口直接监听宿主机。`-control-server-name` 用于内置节点验证 Master 证书域名，不要省略。私有 CA 时放入 `config/master-ca.pem` 并追加 `-control-ca /config/master-ca.pem`；该 CA 仅验证 Master HTTPS。无需内置网关时改为 `-embedded-server-enabled=false`。

### 重置已有管理员

在管理容器内分别重置已有唯一管理员的用户名或密码；两条命令均不能创建首个用户，旧的合并命令 `reset-admin` 已移除。

仅修改用户名（必须提供 `-username`，密码及其存储 hash 严格不变；同名请求明确拒绝）：

```sh
docker exec -i veilink-master /usr/local/bin/veilink reset-admin-username -username new-admin
```

仅修改密码（必须提供 `-password-stdin`，保留用户名，拒绝 `-username`）：

```sh
docker exec -i veilink-master /usr/local/bin/veilink reset-admin-password -password-stdin < /opt/docker/veilink-master/config/admin-password.txt
```

密码文件须预先通过安全方式创建、权限设为 `0600`，内容为 12–72 字节密码（可带末尾 LF 或 CRLF），完成后安全移除；密码仅经 stdin 读取，不放入 argv、环境变量或日志。用户名命令不读取密码且拒绝 `-password-stdin`。两条命令的数据库及 key 默认 `/data/veilink.db`、`/data/veilink.key`，可用 `-database`、`-deployment-key` 指定已有文件；缺失或数据库无管理员时拒绝，不创建数据库/key/用户。任一操作成功后所有旧 Cookie 会话即时失效，无需重启 Master；改名后用新用户名和原密码登录，改密后用原用户名和新密码登录。

### 独立 Server

先在 Web 创建 Server 节点并配置可访问地址及隧道参数，再获取节点 ID 与一次性接入令牌。Server 监听的隧道与 TCP/UDP 映射端口可能动态变化，因此只用 Host 网络。

**Docker Run 命令**（替换节点 ID、令牌与 Master 域名）：

```sh
docker run -itd \
  --name veilink-server --restart unless-stopped --net host \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-server/config:/config:ro \
  -v /opt/docker/veilink-server/data:/data \
  veilink:latest server \
  -master-addr panel.example.com:8443 \
  -control-server-name panel.example.com \
  -node-id '<Server 节点 ID>' -enroll-token '<一次性令牌>' \
  -state-dir /data/state
```

**挂载准备：**

```sh
mkdir -p /opt/docker/veilink-server/config /opt/docker/veilink-server/data && chown -R 65532:65532 /opt/docker/veilink-server/config /opt/docker/veilink-server/data && chmod 700 /opt/docker/veilink-server/config /opt/docker/veilink-server/data
```

**关键参数：** `-control-server-name` 开启并验证到 Master 的 HTTPS，`-master-addr` 是 `host:port`；只有 Master 使用私有 CA 时，才将 CA 放在 `config/master-ca.pem`，并在角色子命令后的 flags 中添加 `-control-ca /config/master-ca.pem`。`/data/state` 保留已获取的节点凭据与最后成功快照；后续重建容器无需再次提供 `-enroll-token`。令牌在启动命令、Shell 历史和 `docker inspect` 中可见；首次接入成功后，**保留 `/data`，删除原容器并以不含令牌的命令重建**。绝不把服务端隧道私钥或证书路径放在节点启动参数中。

### Client

先在 Web 创建 Client 节点，选择 Server/Client 创建映射，并获取 ID 与一次性接入令牌。Client 只发起出站连接，无需发布端口，因此使用默认 Bridge 网络。

**Docker Run 命令**（替换节点 ID、令牌与 Master 域名）：

```sh
docker run -itd \
  --name veilink-client --restart unless-stopped \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-client/config:/config:ro \
  -v /opt/docker/veilink-client/data:/data \
  veilink:latest client \
  -master-addr panel.example.com:8443 \
  -control-server-name panel.example.com \
  -node-id '<Client 节点 ID>' -enroll-token '<一次性令牌>' \
  -state-dir /data/state
```

**挂载准备：**

```sh
mkdir -p /opt/docker/veilink-client/config /opt/docker/veilink-client/data && chown -R 65532:65532 /opt/docker/veilink-client/config /opt/docker/veilink-client/data && chmod 700 /opt/docker/veilink-client/config /opt/docker/veilink-client/data
```

**关键参数：** `/config` 只在私有 Master CA 时放置 `master-ca.pem`，并通过 `-control-ca /config/master-ca.pem` 指定；`/data/state` 保存凭据和缓存。首次接入后按 Server 的方式重建不含令牌的容器。Client 的映射目标须从**容器网络**可达；宿主机上的服务不能填容器内的 `127.0.0.1`。

## 配置与运维边界

- **仅通过角色 flags 配置运行参数**：不接受 YAML 配置文件、`-config` 或 `VEILINK_CONFIG`；Master 的持久化设置优先级是首次默认值 → SQLite 已存设置 → 显式传入的 flags。`-database`、`-deployment-key` 是 Master 存储位置，数据库与 key 必须一起备份。容器默认绝对路径为 `/data/veilink.db`、`/data/veilink.key` 与 `/data/state`，不会在源码目录创建 `.local`。管理员仅通过首次 Web 注册创建，不接受初始化环境变量。
- **所有隧道参数均从 Web 管理**：Master 数据库保存 Server 私有 `tunnel` 及配对 `client_tunnel`，授权快照只把所需公共参数/共享认证发给 Client；Client 不允许用启动参数或本地文件覆写。Master 身份证书来自只读 `/config`，与隧道 TLS/Hysteria2 的 Web PEM 不同。映射直接选择 Server、Client 与 Pool（1–32）。
- **客户端连接地址与监听分离**：Server 私有 `tunnel.listen_host/listen_port` 是实际本地监听地址；`connect_endpoints` 的 Host/Port 是 Client 拨号使用的公网可达地址，可与监听 IP/端口不同（例如端口转发）。SNI（`server_name`）独立于拨号地址，须匹配 TLS 证书或 REALITY 域名。保留多个具名候选、优先级和启用状态，Client 按优先级失败切换；不再提供 direct/nat/cdn 分类，旧 `kind` 字段不受支持。Client 永不接收或覆盖本地监听字段。中间代理须保持原始 TCP 或 UDP/QUIC 的 L4 透传；HTTP-only 或终止、改写协议的 CDN 不支持。
- **Hysteria2 安全边界**：Hysteria2 基于 QUIC/UDP 且使用 TLS；当前上游和本实现不支持 REALITY，配置会被拒绝。
- **认证**：管理员使用密码会话、CSRF；节点一次性接入令牌最长 24 小时，凭据有效期 30 天。内置 Server 身份持久且不可通过外部令牌接管。Web 的“快捷接入”生成统一镜像加角色子命令的 Docker Run 命令和挂载准备步骤；令牌可能暴露于 Shell 历史及 Docker inspect，关闭弹窗会从页面内存移除。
- **TCP mux 可选**：Web「映射 → 新建/编辑 → TCP mux」对应映射 JSON 字段 `mux`，默认 `false`（省略也是关闭），不是节点或全局设置。关闭时每条 TCP 流使用独立认证反向连接；开启时多条 TCP 流共享 mux 会话。同一 Server/Client 的不同映射可独立选择。Pool（1–32）控制该节点对的共享会话或独立连接预备数量，取启用映射的最大值，不限制业务并发。保存开关或类型后授权快照触发相关节点重建，现有连接会断开；以已应用修订确认生效。控制连接仍保留，UDP 始终使用 XUDP/共享帧通道，不受 TCP mux 开关影响。
- **mux 类型**：Mapping 保留布尔 `mux` 和字符串 `mux_type`。仅 TCP 映射开启 mux 时显示类型下拉，支持 sing-mux 的 `smux`、`yamux`、`h2mux`，开启默认 `smux`；省略/留空类型采用此默认值，保存和授权快照携带明确类型。关闭时保存清空类型且不参与连接模式协商，未知非空类型拒绝，不静默回退。切换 UDP 立即关闭 mux、清空类型并隐藏下拉；API 拒绝 UDP + mux=true。不提供额外 padding 或流数配置。反向隧道仍是 Veilink 协议，使用这些 mux 类型不代表兼容 mihomo 节点直连，也不宣称 Xray 通用互通。
- **mux 实现边界**：smux/yamux 使用 sing-mux 客户端与服务端；h2mux 使用标准 HTTP/2 CONNECT 发起端及 sing-mux 编解码/服务端，以避开当前依赖的空 Header 兼容问题。每条真实 mux 流内另有 Veilink 有界 payload/FIN 记录，保留 TCP 半关闭语义；该记录不承担多路复用。连接池按节点绑定及 mux 类型隔离，每池最多 64 条活动/等待流，超过上限拒绝新流；Pool 不等于该并发上限。h2mux 单流 deadline API 不受支持，关闭和取消由上下文、受跟踪连接及目标 socket 驱动。旧 `private-session` 类型即使在关闭状态也明确拒绝。
- **传输边界**：业务只转发已授权目标。REALITY、Hysteria2、VLESS Encryption 与 Vision 可按其各自约束配置；Vision 仅在关闭 TCP mux 的 TLS/REALITY 独立认证连接下，对可识别的内层 TLS 1.3 切换底层 socket 复制。mux/控制/UDP、TLS 1.2、明文及叠加 Encryption 的流不切换为裸传输。这不是内核零拷贝，也不声称 Xray 通用互通。
- **查看状态**：使用 `docker logs veilink-master` 等读取日志。Master 的 Docker 健康检查实际请求 `/healthz`；节点健康检查仅检查进程，不表示目标端口可达。生产环境必须使用 HTTPS，打开防火墙时仅放行必需的控制、隧道与映射端口。项目尚未发布，旧数据库 schema 明确报错，不自动迁移或清除。

项目的持续开发约束与验收要求单独保存在 [AGENTS.md](AGENTS.md)，不与本部署说明混写。
