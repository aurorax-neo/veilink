# Veilink

用 Web 管理的私有反向隧道系统，将 Server 的 TCP/UDP 入口转发到 Client 可访问的目标服务。

Veilink 使用 Go 实现节点与隧道，Vue 3 提供管理界面。**一个 Docker 镜像，三种运行角色**，不需要额外安装代理内核。

[发布版本](https://github.com/aurorax-neo/veilink/releases) · [问题反馈](https://github.com/aurorax-neo/veilink/issues) · [许可证](LICENSE)

## 目录

- [功能与架构](#功能与架构)
- [部署准备](#部署准备)
- [启动 Master](#启动-master)
- [配置管理入口](#配置管理入口)
- [首次注册与配置映射](#首次注册与配置映射)
- [接入独立 Server](#接入独立-server)
- [接入 Client](#接入-client)
- [协议与配置参考](#协议与配置参考)
- [日常运维](#日常运维)
- [故障排查](#故障排查)
- [开发与验证](#开发与验证)
- [许可证与第三方组件](#许可证与第三方组件)

## 功能与架构

- **集中管理**：在 Web 中管理节点、连接入口、映射和配置修订。
- **反向连接**：Client 主动连接 Server，将业务转发到授权目标，无需为 Client 开放入站端口。
- **TCP/UDP 映射**：映射直接选择 Server 和 Client，连接池大小 Pool 为 `1–32`。
- **多种传输**：支持私有 VLESS、Hysteria2、TCP mux、XUDP 和 XHTTP，具体组合见[协议参考](#协议与配置参考)。
- **统一部署**：同一镜像包含二进制与 Web 静态资源，用 `master`、`server`、`client` 子命令选择角色。

| 角色 | 职责 | 容器网络 |
| --- | --- | --- |
| Master | 提供 Web/API、管理授权配置，可运行内置 Server | Host |
| Server | 提供隧道接入和业务映射监听 | Host |
| Client | 主动建立反向隧道，访问授权目标 | 默认 Bridge |

```text
控制面：浏览器 ── Web/API ── Master ←── gRPC ── Server / Client

业务面：访问者 ── Server 映射入口 ══ 反向隧道 ══ Client ── 目标服务
                                  ↑
                         隧道连接由 Client 发起
```

只有 Master 提供 Web。Master 内置 Server 与独立 Server 职责相同，可先使用内置节点，再按需增加独立节点。

> Veilink 是双端私有隧道，不是开放代理，也不承诺与 Xray、mihomo 或原生 Hysteria2 对端互通。项目不嵌入 Xray 代理内核；第三方源码依赖及其许可单独列在[第三方声明](THIRD_PARTY_NOTICES.md)。

## 部署准备

### 快速启动（零配置）

```sh
# Docker 一行启动（数据持久化可选）
docker run -itd --restart unless-stopped --name veilink \
  -e TZ=Asia/Shanghai \
  --network host \
  -v veilink-data:/data \
  ghcr.io/aurorax-neo/veilink:latest master
```

首次启动自动完成：
- 生成管理员 API Key（日志中显示一次，请保存）
- 拉取最新前端（`WEB_MODE=pull` 默认）
- 数据目录自动初始化，无需手动 `mkdir`/`chown`

查看 API Key：
```sh
docker logs veilink 2>&1 | grep "API Key"
```

### 镜像与版本

前后端独立发布：
- 后端：`ghcr.io/aurorax-neo/veilink-backend:v1.2.0`（tag `v*` 触发）
- 前端：`ghcr.io/aurorax-neo/veilink-web:web-v1.0.0`（tag `web-v*` 触发）
- 统一：`ghcr.io/aurorax-neo/veilink:latest`（手动组装，含预置前端）

原生二进制（Linux/macOS/Windows）：
```sh
# Linux/macOS
curl -fsSL https://get.veilink.dev | sh

# Windows (PowerShell)
irm https://get.veilink.dev/install.ps1 | iex
```

### 目录与网络

- 容器 entrypoint 自动修复 `/data` 权限，无需手动 `mkdir`/`chown`
- Master、Server 使用 Host 网络承载动态入站端口，**不要添加 `-p`**；Client 使用默认 Bridge
- 命名卷（`veilink-data`）推荐用于持久化，权限自动处理

| 端口示例 | 用途 | 放行范围 |
| --- | --- | --- |
| `127.0.0.1:2545/TCP` | Master 默认 HTTP/h2c | 默认仅本机 |
| `8843/TCP` | 本文 nginx 外部 HTTPS 示例 | 管理员和节点来源 |
| `8444` | 内置 Server 首次默认隧道监听 | 按传输放行 TCP 或 UDP |
| Web 中设置的映射端口 | 业务访问入口 | 实际业务访问来源 |

首次注册前必须限制管理入口来源。HTTPS 加密不能防止管理员被抢注。

## 启动 Master

### 1. 准备目录

```sh
mkdir -p /opt/docker/veilink-master/config /opt/docker/veilink-master/data
chown 65532:65532 /opt/docker/veilink-master/config /opt/docker/veilink-master/data
chmod 700 /opt/docker/veilink-master/config /opt/docker/veilink-master/data
```

### 2. 启动容器

默认 HTTP 不需要证书：

```sh
docker run -itd \
  --name veilink-master --restart unless-stopped --net host \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-master/config:/config:ro \
  -v /opt/docker/veilink-master/data:/data \
  ghcr.io/aurorax-neo/veilink:latest master \
  -database /data/veilink.db -deployment-key /data/veilink.key \
  -state-dir /data/state -listen-addr 127.0.0.1:2545 \
  -scheme http -html-dir /usr/local/html \
  -embedded-server-enabled=true
```

镜像名后必须先写 `master`，再写 flags。内置 Server 首次默认显示名为 `default`，端口为 `8444`；已有稳定身份和自定义名称保持不变。无需内置节点时，将 `-embedded-server-enabled` 改为 `false`。

Master 会保留 SQLite 已存设置：显式 flags 覆盖已存值，缺省 flags 不清空旧设置。已有 HTTPS 配置切回 HTTP 时，除 `-scheme http` 外还应显式清空 `-control-server-name= -control-ca=`，不要删库。

### 3. 确认启动

```sh
docker ps -a --filter name=veilink-master
docker logs --tail=200 veilink-master
curl -fsS http://127.0.0.1:2545/healthz
```

返回容器 ID 不代表启动成功。默认监听只同机可达；远程浏览器和节点需使用下一节的 HTTPS 入口，或受访问控制的可信内网地址。

## 配置管理入口

选择一种方式即可，不要求首次注册必须使用 HTTPS。

### 方式一：nginx 终止 HTTPS

适合跨不可信网络访问。示例拓扑为同机 nginx `https://panel.example.com:8843` → Master `http://127.0.0.1:2545`。

下面的 `server` 段放入 nginx 的 `http {}` 中，需要 nginx ≥ 1.25.1 及 SSL、HTTP/2、gRPC 模块。替换域名和实际证书路径；证书文件路径不能用 `*`。首次开放入口前，用防火墙或反代访问控制限制来源。

```nginx
server {
    listen 8843 ssl;
    listen [::]:8843 ssl;
    http2 on;
    server_name panel.example.com;
    ssl_certificate /etc/nginx/ssl/panel.example.com/fullchain.cer;
    ssl_certificate_key /etc/nginx/ssl/panel.example.com/private.key;

    if ($host != $server_name) {
        return 404;
    }

    # 只转换本站的精确 Origin，其它 Origin 原样交给 Master 校验。
    set $veilink_origin $http_origin;
    if ($http_origin = "https://$http_host") {
        set $veilink_origin "http://$http_host";
    }

    location /veilink.control.v1.Control/ {
        grpc_pass grpc://127.0.0.1:2545;
        grpc_set_header Host $host:$server_port;
        grpc_read_timeout 3600s;
        grpc_send_timeout 3600s;
    }

    location / {
        proxy_pass http://127.0.0.1:2545;
        client_max_body_size 1m;
        proxy_http_version 1.1;
        proxy_set_header Host $host:$server_port;
        proxy_set_header Origin $veilink_origin;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_cookie_flags veilink_session secure httponly samesite=strict;
    }
}
```

```sh
nginx -t && nginx -s reload
curl -fsS https://panel.example.com:8843/api/setup
openssl s_client -connect panel.example.com:8843 \
  -servername panel.example.com -alpn h2 </dev/null 2>&1 \
  | grep -i 'ALPN protocol'
```

预期 ALPN 为 `h2`。部署时注意：

- Web/API 用 `proxy_pass`，节点 gRPC 用 `grpc_pass`，两者不能互换。
- nginx 如果运行在独立 Bridge 容器，`127.0.0.1` 是 nginx 自己，必须换成能到达的受限回源地址。
- 本例监听端口就是外部端口，所以 Host 使用 `$host:$server_port`。前置代理若改写端口，两处 Host 应填写真实外部域名和端口，并与 Origin 转换一致。
- 不关闭 CSRF，不把所有 Origin 改成本域，不盲目信任客户端转发头。nginx 为会话 Cookie 添加 Secure；Master 不靠 `X-Forwarded-Proto` 放宽认证。
- 此反代仅处理管理面和控制面；业务隧道端口需按传输直达或 L4 透传。它不是 XHTTP 业务反代配置。

### 方式二：可信内网直接 HTTP

将 Master 的 `-listen-addr` 改为节点可达的可信内网地址，例如 `192.168.10.2:2545`，并限制来源。Web「快捷接入」填写 `http://192.168.10.2:2545`。

手工节点命令使用 `-master-addr 192.168.10.2:2545`，省略 `-control-server-name` 与 `-control-ca`。HTTP/h2c 会明文传输凭据，不适合跨不可信网络。

### 方式三：Master 内置 HTTPS

将证书与私钥放入已挂载的只读 `/config`，确保 UID `65532` 可读取；在 Master 启动命令中替换或补充以下参数：

```text
-listen-addr 0.0.0.0:2545
-scheme https
-cert-file /config/cert.pem
-key-file /config/key.pem
-control-server-name panel.example.com
```

限制该监听地址的访问来源。内置 Server 也会验证 Master 证书；私有 CA 额外设置 `-control-ca /config/master-ca.pem`。外部 Server、Client 同样配置控制面证书名称和 CA。

证书由实际终止 TLS 的组件管理。nginx 证书续期后先检查新证书，再执行 `nginx -t && nginx -s reload`。

## 首次注册与配置映射

1. **注册管理员**：从可信或已限制来源的入口打开 Web。Master 不自动创建账号；`GET /api/setup` 返回是否需要注册，`POST /api/register` 仅允许无管理员时原子创建唯一账号。
2. **配置 Server**：使用内置 `default` 或创建独立 Server。在 Web 保存隧道、连接入口和本地监听配置；客户端模板由 Server 配置自动派生。
3. **创建 Client**：获取节点 ID 和接入令牌，按下文或 Web「快捷接入」生成的命令启动。生成命令和手工命令二选一。
4. **创建映射**：选择 Server、Client、TCP/UDP、Server 监听地址与端口、Client 可达的目标地址与端口，以及 Pool（`1–32`）。没有独立的公开绑定管理。
5. **选择连接入口**：固定入口只用所选启用入口；“自动”按启用入口顺序尝试。NAT 对外连接端口可以与 Server 本地隧道监听端口不同。
6. **验证业务**：等待节点应用配置，从 Server 映射监听地址发起符合目标协议的实际请求。

例如，Client 能访问 `192.168.10.20:8080` 的 HTTP 服务时，可建立 TCP 映射到 Server 的空闲业务端口。验证该映射应发送 HTTP 请求，而不是只确认 TCP 握手成功。目标必须从 Client 容器网络可达；容器内的 `127.0.0.1` 不是宿主机。

### 如何理解状态

| 信号 | 能说明什么 | 不能说明什么 |
| --- | --- | --- |
| Master `/healthz` | 管理进程健康接口可响应 | 隧道或目标服务可用 |
| Server/Client Docker `healthy` | PID 1 存活 | 节点已认证或配置已应用 |
| 节点上报时间 | 控制面近期收到上报 | 目标服务可达 |
| 配置“最新” | 节点已应用期望修订 | 业务请求必然成功 |
| 映射“待业务验证” | 节点近期上报且配置已应用 | 已完成业务探针 |
| 上行/下行流量 | Server 公网侧有实际载荷 | 应用认证和请求成功 |

期望修订与已应用修订分开记录；Apply 失败不会报成功，旧修订或相同修订对应不同配置会被拒绝，节点保留最后成功快照。刷新按钮只是请求节点刷新，以实际上报为准。流量计数在进程重启后重新开始。

## 接入独立 Server

使用内置 Server 可跳过。先在 Web 创建 Server，获取节点 ID 和接入令牌；在 Server 主机准备镜像与目录：

```sh
mkdir -p /opt/docker/veilink-server/config /opt/docker/veilink-server/data
chown 65532:65532 /opt/docker/veilink-server/config /opt/docker/veilink-server/data
chmod 700 /opt/docker/veilink-server/config /opt/docker/veilink-server/data
```

以下连接到前述 nginx HTTPS 入口：

```sh
docker run -itd \
  --name veilink-server --restart unless-stopped --net host \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-server/config:/config:ro \
  -v /opt/docker/veilink-server/data:/data \
  ghcr.io/aurorax-neo/veilink:latest server \
  -master-addr panel.example.com:8843 \
  -control-server-name panel.example.com \
  -node-id '<Server 节点 ID>' -enroll-token '<接入令牌>' \
  -state-dir /data/state
```

## 接入 Client

先在 Web 创建 Client，获取节点 ID 和接入令牌；在 Client 主机准备镜像与目录：

```sh
mkdir -p /opt/docker/veilink-client/config /opt/docker/veilink-client/data
chown 65532:65532 /opt/docker/veilink-client/config /opt/docker/veilink-client/data
chmod 700 /opt/docker/veilink-client/config /opt/docker/veilink-client/data
```

Client 保持默认 Bridge，不添加 `--net host` 或 `-p`：

```sh
docker run -itd \
  --name veilink-client --restart unless-stopped \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-client/config:/config:ro \
  -v /opt/docker/veilink-client/data:/data \
  ghcr.io/aurorax-neo/veilink:latest client \
  -master-addr panel.example.com:8843 \
  -control-server-name panel.example.com \
  -node-id '<Client 节点 ID>' -enroll-token '<接入令牌>' \
  -state-dir /data/state
```

两种节点若连接私有 CA 签发的 Master，将 CA 放到只读 `/config`，追加 `-control-ca /config/master-ca.pem`。该参数只影响 Master 控制面信任，不影响业务隧道证书。

### 首次接入后的令牌清理

令牌在有效期内可重复使用，撤销或过期后失效；它可能留在 shell 历史和 `docker inspect` 中。

确认首次接入成功且 `/data/state` 已保存凭据后，停止并删除原节点容器，**保留数据目录**，用去掉 `-enroll-token` 的相同命令重建，再撤销不再需要的令牌。撤销令牌不会清除 inspect 或历史中的文本残留，不要公开完整启动命令。

## 协议与配置参考

### 配置归属

| 设置 | 配置位置 |
| --- | --- |
| Master 监听、数据库、deployment key、内置 HTTPS | Master 角色 flags；部分设置持久化于 SQLite |
| 节点 Master 地址、ID、首次令牌、状态目录、控制面 TLS 信任 | Server/Client 角色 flags |
| 隧道协议、证书 PEM、密钥、入口和映射 | Master Web |
| Client 公共隧道模板 | 从 Server 私有配置自动派生，Client 不本地覆盖 |

不接受 YAML 配置文件、`-config` 或 `VEILINK_CONFIG`。Server 证书私钥、REALITY 私钥和 VLESS decryption 材料不会进入 Client 快照。

### 传输组合

| 传输 | 安全要求与边界 |
| --- | --- |
| VLESS TCP + TLS | 校验证书及名称；可选 Encryption、Vision |
| VLESS TCP + REALITY | 公私钥、Short ID、Server Name 匹配；可选 Encryption、Vision |
| VLESS TCP + plain | 必须启用 Encryption；禁止 Vision |
| Hysteria2 | 独立 UDP/QUIC + TLS；需要证书、私钥和密码；不叠加 VLESS Encryption、REALITY、XHTTP、Vision |
| XHTTP | Veilink 双端业务通道；HTTP 版本与模式须符合下表和能力矩阵 |

TCP 映射可选择关闭 mux 或使用 `smux`、`yamux`、`h2mux`；UDP 业务使用授权 XUDP，不启用 TCP mux，也不代表原生 Hysteria2 datagram 互通。

Vision 只用于 TCP + TLS/REALITY。只有独立已认证连接上的内层 TLS 1.3 满足结构和记录边界条件才可能直拷；mux、控制和 UDP 不裸传，Encryption 或无法安全识别的流保留加密回退。不宣称内核零拷贝。

### XHTTP

| 模式 | 行为 |
| --- | --- |
| `packet-up`（默认） | 分片上行，GET 流式下行 |
| `stream-up` | 同会话流式上行与 GET 下行 |
| `stream-one` | 单条双向请求，不使用会话 ID |
| `auto` | 当前在非 REALITY 和 REALITY 下均选择 `packet-up`，不是完整参考实现的自动协商 |

- 显式 HTTP/1.1 仅支持 `packet-up`。HTTP/2、HTTP/3 流模式仅支持直连 HTTPS 与 TLS 回源。
- h2c 仅限直连 HTTP、plain 回源且启用 VLESS Encryption 的 `packet-up`；显式版本不降级。普通 HTTP 链路或回源段必须启用 Encryption；REALITY 外层保护的 XHTTP 按独立安全组合校验。
- HTTP/3 需要 UDP 直连和端到端 QUIC/TLS。上行默认 POST，可选 PUT，前置代理须放行并禁用请求缓冲。不承诺通用 CDN 支持。
- `host` 仅覆写业务 HTTP Host，限小写 DNS 名或 IPv4、无端口；不改变授权拨号地址或证书校验名称。反代须保留 Host。
- 默认分片为 32768 字节、无额外间隔、逐片确认背压。随机分片、并发缓冲、padding、xmux、元数据位置和独立下行入口等高级参数见[XHTTP 能力边界](tests/deployment/xhttp-capability-matrix.md)，避免在两处重复维护字段范围。
- 半关闭与上传确认是 Veilink 私有扩展；业务 Cookie 元数据不是 Master 的登录 Cookie。

## 日常运维

### 备份

从源码仓库根目录执行 [备份工具](tools/backup-master.sh)，需要宿主机 Python 3，以及读取源目录、保留数字 UID/GID 的权限。该工具只支持离线备份，目标必须是**尚不存在的新目录**，父目录须存在。

Master 数据库、deployment key 和内置节点状态须成套保存：

```sh
docker stop veilink-master
mkdir -p /opt/docker/veilink-master/backups
tools/backup-master.sh backup master \
  /opt/docker/veilink-master/data \
  /opt/docker/veilink-master/backups/$(date +%Y%m%d-%H%M%S)
docker start veilink-master
```

检查工具退出状态与 `backup complete` 输出；失败的目录不可作为有效备份。备份含凭据，限制读取权限并加密存放。修改过数据库文件名或将状态放到 `/data` 外时，先确认工具要求与完整备份范围，不能直接套用默认示例。

独立节点同样先停机，在对应节点主机执行：

```sh
docker stop veilink-server
mkdir -p /opt/docker/veilink-server/backups
tools/backup-master.sh backup node \
  /opt/docker/veilink-server/data \
  /opt/docker/veilink-server/backups/$(date +%Y%m%d-%H%M%S)
docker start veilink-server
```

Client 备份将路径及容器名中的 `veilink-server` 替换为 `veilink-client`。

### 恢复

工具会校验 `manifest.json` 与备份文件内容。恢复到尚不存在的新目录，**不要覆盖生产目录**；将示例时间戳替换为实际备份目录名：

```sh
tools/backup-master.sh restore master \
  /opt/docker/veilink-master/backups/20260930-120000 \
  /opt/docker/veilink-master/recovery-data
```

先在隔离环境验证登录、节点身份、上报和业务探针，再切换正式挂载。保留原数据副本，禁止旧、新 Master 同时提供写服务。旧 schema 不自动迁移或删库，任何数据删除都须先备份并得到明确授权。

### 管理员维护

仅修改已有唯一管理员，不创建数据库、key 或用户；成功后旧会话即时失效。

改名只改用户名，密码 hash 不变，同名请求会被拒绝：

```sh
docker exec -i veilink-master /usr/local/bin/veilink reset-admin-username -username new-admin
```

改密保留用户名。先用安全方式准备权限 `0600`、包含 12–72 字节新密码的文件，再从 stdin 读取；不要在 shell 命令中直接写密码：

```sh
docker exec -i veilink-master /usr/local/bin/veilink reset-admin-password -password-stdin < /opt/docker/veilink-master/config/admin-password.txt
```

使用自定义数据库或 key 路径时，两种命令均需补充对应的 `-database`、`-deployment-key`。改名命令拒绝密码 flags；改密命令拒绝 `-username`。密码更新并验证登录后，妥善清理临时密码文件。无管理员时只能通过受限 Web 首次注册。

### 升级与回滚

1. 记录当前镜像版本和运行参数，敏感令牌不要写入公开日志。
2. 停机备份 Master 数据和独立节点状态，确认备份有效。
3. 拉取目标版本镜像，保留数据挂载，以原有角色和 flags 重建容器。
4. 检查日志、健康接口、节点应用状态及实际业务请求。
5. 回滚前备份当前状态，确认旧版本兼容性；不兼容时用匹配旧版本的成套备份在新目录验证，不直接覆盖数据库。

## 故障排查

按“容器 → 控制面 → 配置应用 → 业务目标”的顺序检查，不以删库或关闭校验代替排障。

| 现象 | 优先检查 |
| --- | --- |
| 镜像拉取 `DENIED: invalid token` | GHCR 或镜像代理的鉴权、路径；这不是 Veilink 启动错误 |
| 容器返回 ID 后退出 | `docker ps -a` 和容器日志；角色是否写在 flags 前、目录权限、端口占用 |
| 内置 Server 与 Master 端口冲突 | 用另一个 Master 端口启动，再到 Web 调整内置节点；不要删库 |
| `flag provided but not defined` | 使用当前角色 `--help`；没有 `-embedded-server-server-name` 或 `-config` |
| 远端无法访问 `127.0.0.1:2545` | 该地址仅本机可达；使用反代或受限内网监听 |
| `tls: no application protocol` | 外部 HTTPS 是否协商 ALPN `h2`、nginx HTTP/2 模块和 `grpc_pass` |
| 注册/登录直接 403 | Host、Origin 和非标准外部端口是否匹配 |
| 登录后写操作 403 | 会话 Cookie、`X-CSRF-Token`、`Sec-Fetch-Site`；不要关闭 CSRF |
| 节点未上报 | 节点日志、Master 地址、证书名称/CA、端口、节点 ID、令牌和状态目录 |
| 配置待应用或应用失败 | 对比期望/已应用修订，查看节点错误；刷新请求不是成功确认 |
| 配置已应用但业务失败 | Server 业务端口、Client 容器目标可达性、TCP/UDP 协议、防火墙/NAT、目标认证 |

常用诊断命令（按角色选择已存在的容器）：

```sh
docker logs --tail=200 veilink-master
docker logs --tail=200 veilink-server
docker logs --tail=200 veilink-client
docker exec veilink-master /usr/local/bin/veilink version
docker exec veilink-master /usr/local/bin/veilink master --help
```

反馈问题时提供版本、角色、传输方式、脱敏配置、复现步骤与相关日志。不要附上接入令牌、会话 Cookie、私钥或数据库。

## 开发与验证

### 项目结构

| 路径 | 内容 |
| --- | --- |
| `cmd/veilink`、`internal/cli`、`internal/config` | 统一命令入口与角色参数 |
| `internal/master`、`internal/control`、`internal/node` | 管理服务、控制面与节点配置应用 |
| `internal/store`、`internal/httpapi` | 配置持久化与 Web API |
| `internal/tunnel` | 隧道、复用与数据传输 |
| `frontend` | 唯一 Web 界面，Vue 3 + TypeScript + Vite |
| `tests/integration`、`tests/deployment` | 集成与部署测试 |
| `tests/web` | 历史 Web 验收记录和截图 |
| `tools` | 离线备份及节点验证工具 |

Go 版本以 [go.mod](go.mod) 为准，当前为 `1.27.0`；前端发布构建使用 Node.js 22 和 npm 锁文件。前端 `npm run build` 输出到仓库根目录 `html/`，统一镜像将其放入 `/usr/local/html`，仅 Master 加载。

### 检查命令

以下是维护者验收命令，不代表本次文档更新已执行这些检查：

```sh
go test ./...
go vet ./...
go test -race ./internal/store ./internal/control ./internal/httpapi ./internal/master ./internal/node ./internal/tunnel ./tests/deployment
go test -tags=integration ./tests/integration -count=1
(
  cd frontend &&
  npm ci &&
  node --test tests/*.mjs &&
  npm run typecheck &&
  npm run build
)
git diff --check
```

此外需构建一次统一镜像，分别检查 Master、Server、Client 的镜像内容、启动和健康状态；节点 `healthy` 只表示进程存活，业务验收仍需授权节点和实际目标请求。不要提交生成的 `bin/`、`html/`、密钥、数据库或部署 env 文件。

### 能力与验证材料

- [协议矩阵](tests/deployment/protocol-matrix.md)：组合、授权和往返覆盖范围。
- [XHTTP 能力边界](tests/deployment/xhttp-capability-matrix.md)：字段、模式与限制。
- [XHTTP 验证记录](tests/deployment/xhttp.md)：对应阶段的执行证据。
- [统一镜像验收记录](tests/web/unified-image-acceptance.md)：历史镜像与三角色验证。

`tests/` 下的执行结果只对应记录中的版本和环境，不是当前版本的生产认证。真实多主机 WAN/NAT、24–72 小时长稳、生产 CA 生命周期和供应链签名仍需目标环境验收。开发约束集中在 [AGENTS.md](AGENTS.md)。

## 许可证与第三方组件

Veilink 原创代码和文档（另有声明者除外）采用 [GPL-3.0-or-later](LICENSE)，授权声明见 [NOTICE](NOTICE)。

第三方组件保留各自许可。依赖版本、MPL-2.0 覆盖文件、上游来源、对应源码获取及分发义务见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
