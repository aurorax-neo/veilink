# Veilink

用 Web 管理的私有反向隧道系统，将 Server 的 TCP/UDP 入口转发到 Client 可访问的目标服务。

Veilink 使用 Rust (Tokio 异步运行时) 实现高性能节点与反向多路复用隧道，Vue 3 提供现代化单页管理界面。**单二进制打包内嵌 Web，一个 Docker 镜像承载三种运行角色**，控制面全 HTTP REST/长轮询架构，对 Nginx 等标准反代友好，无需 gRPC。

[发布版本](https://github.com/aurorax-neo/veilink/releases) · [问题反馈](https://github.com/aurorax-neo/veilink/issues) · [许可证](LICENSE)

## 目录

- [功能与架构](#功能与架构)
- [部署准备](#部署准备)
- [启动 Master](#启动-master)
- [配置管理入口](#配置管理入口)
- [首次配置与映射](#首次配置与映射)
- [接入独立 Server](#接入独立-server)
- [接入 Client](#接入-client)
- [协议与配置参考](#协议与配置参考)
- [性能实测与基准](#性能实测与基准)
- [日常运维](#日常运维)
- [故障排查](#故障排查)
- [开发与验证](#开发与验证)
- [许可证与第三方组件](#许可证与第三方组件)

## 功能与架构

- **集中管理**：在 Web 中管理节点、连接入口、映射和配置修订。
- **实时推送**：管理面内置 HTTP SSE（`/api/v1/events`）实时事件流，节点控制面采用长轮询即时唤醒，前后端统一 `UTC+8` 时区并自动校准服务端时钟偏移。
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
控制面：浏览器 ── Web/API ── Master ←── HTTP ── Server / Client

业务面：访问者 ── Server 映射入口 ══ 反向隧道 ══ Client ── 目标服务
                                  ↑
                         隧道连接由 Client 发起
```

只有 Master 提供 Web。Master 内置 Server 与独立 Server 职责相同，可先使用内置节点，再按需增加独立节点。

> Veilink 是双端私有隧道，不是开放代理，也不承诺与 Xray、mihomo 或原生 Hysteria2 对端互通。项目不嵌入 Xray 代理内核；第三方源码依赖及其许可单独列在[第三方声明](THIRD_PARTY_NOTICES.md)。

## 部署准备

### 快速启动（零配置）

```sh
# 拉取统一镜像
docker pull ghcr.io/aurorax-neo/veilink:latest

# Docker 一行启动
docker run -itd --restart unless-stopped --name veilink-master \
  -e TZ=Asia/Shanghai \
  --network host \
  -v /opt/docker/veilink-master/data:/data \
  ghcr.io/aurorax-neo/veilink:latest master
```

首次启动自动完成：
- 使用镜像内置前端界面，前后端随统一镜像一起更新
- 数据目录自动初始化，无需手动 `mkdir`/`chown`
- 不自动创建管理员。启动后执行一次 `veilink keys create`，明文只在该命令输出里出现一次

创建管理员 API Key：
```sh
docker exec veilink-master /usr/local/bin/veilink keys create admin
```

### 镜像与版本

- **统一 Docker 镜像**：`ghcr.io/aurorax-neo/veilink:latest`（包含全功能二进制与预置 Web 前端，通过 `master|server|client` 子命令选择角色）
- **Web 前端**：直接通过 `rust-embed` 内嵌在单个 `veilink` 可执行文件中，不再单独发布 `html/` 目录或运行时拉取

### 目录与网络

- 容器 entrypoint 自动修复 `/data` 及其子目录权限，无需手动 `mkdir`/`chown`
- Master、Server 使用 Host 网络承载动态入站端口，**不要添加 `-p`**；Client 使用默认 Bridge
- 宿主机挂载统一以 `/opt/docker/<app_name>/data:/data` 为持久化根目录

| 端口示例 | 用途 | 放行范围 |
| --- | --- | --- |
| `127.0.0.1:2545/TCP` | Master 默认 HTTP/h2c | 默认仅本机 |
| `8843/TCP` | 本文 nginx 外部 HTTPS 示例 | 管理员和节点来源 |
| `8444` | 内置 Server 首次默认隧道监听 | 按传输放行 TCP 或 UDP |
| Web 中设置的映射端口 | 业务访问入口 | 实际业务访问来源 |

首次启动前建议限制管理入口来源。管理员 API Key 由 `veilink keys create` 生成，明文只出现在该命令输出中，不会写入日志。

## 启动 Master

### 1. 启动容器（零配置）

```sh
docker run -itd \
  --name veilink-master --restart unless-stopped --network host \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-master/data:/data \
  ghcr.io/aurorax-neo/veilink:latest master
```

entrypoint 自动处理 `/data` 权限，无需手动 `mkdir`/`chown`。宿主机映射目录 `/opt/docker/veilink-master/data` 保存 SQLite 数据库与凭据（`veilink.db`）。Web 直接从 `veilink` 二进制内嵌资源提供服务，不读取或创建 `/data/web`，也不支持前端跳转地址、pull 模式、在线拉取版本或 GitHub 加速。旧 Web 文件不会覆盖新内嵌资源，升级不会自动删除旧文件或数据库。已发布的 schema 5 数据库自动升级：先备份数据库与部署密钥，再事务化清理已知旧 Web 字段、修复旧版缺失的 ML-DSA 验证公钥；未知结构或损坏配置仍拒绝启动，不删库。

### 2. 获取 API Key

```sh
docker exec veilink-master /usr/local/bin/veilink keys create admin
```

命令输出里的 `vlk_` 明文只出现这一次。在浏览器打开 `http://服务器IP:2545`，输入 Key 进入控制台。Master 不会把 Key 写入日志。

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

选择一种方式即可。

### 方式一：nginx 终止 HTTPS

适合跨不可信网络访问。示例拓扑为同机 nginx `https://panel.example.com:8843` → Master `http://127.0.0.1:2545`。

Master 与节点之间的控制面（`/api/control/*`）及管理面（`/api/v1/*`）均采用纯 HTTP JSON 接口，直接使用标准 `proxy_pass` 即可，无需 `grpc_pass`。下面的 `server` 段放入 nginx 的 `http {}` 中，替换域名和实际证书路径；证书文件路径不能用 `*`。首次开放入口前，用防火墙或反代访问控制限制来源。

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

    location / {
        proxy_pass http://127.0.0.1:2545;
        client_max_body_size 1m;
        proxy_http_version 1.1;
        proxy_set_header Host $host:$server_port;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        # API Key 通过 Authorization 头传递，无需 cookie/CSRF 特殊处理
        proxy_buffering off;
    }
}
```

```sh
nginx -t && nginx -s reload
curl -fsS https://panel.example.com:8843/api/version
```

部署时注意：

- Web/API 与节点控制面（`/api/control/*`）统一走 HTTP `proxy_pass`，兼容 HTTP/1.1 与 HTTP/2，无需配置 `grpc_pass`。
- `proxy_buffering off;` 同时保障 `/api/v1/events`（SSE 实时事件流，每 25 秒发送保活心跳）与 `/api/control/events`（节点长轮询）即时透传，不产生反代缓冲延迟。
- nginx 如果运行在独立 Bridge 容器，`127.0.0.1` 是 nginx 自己，必须换成能到达的受限回源地址；若需让 Master 信任非回环反代转发的 `X-Forwarded-For` 最后一跳以精确按客户端 IP 限流，可在 Master 容器设置环境变量 `VEILINK_TRUSTED_PROXIES=<nginx容器IP>`。
- API Key 通过 `Authorization` 头传递，nginx 无需特殊处理；不要盲目信任客户端转发的头。
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

## 首次配置与映射

1. **获取 API Key**：Master 不自动创建管理员。执行 `docker exec veilink-master /usr/local/bin/veilink keys create admin`，明文只在命令输出中显示一次。在 Web 登录页输入该 Key。
2. **配置 Server**：使用内置 `default` 或创建独立 Server。在 Web 保存隧道、连接入口和本地监听配置；客户端模板由 Server 配置自动派生。
3. **创建 Client**：获取节点 ID 和接入令牌，按下文或 Web「快捷接入」生成的命令启动。生成命令和手工命令二选一。
4. **创建映射**：选择 Server、Client、TCP/UDP、Server 监听地址与端口、Client 可达的目标地址与端口，以及 Pool（`1–32`）。没有独立的公开绑定管理。
5. **选择连接入口**：固定入口只用所选启用入口；“自动”按启用入口顺序尝试。NAT 对外连接端口可以与 Server 本地隧道监听端口不同。
6. **验证业务**：等待节点应用配置，从 Server 映射监听地址发起符合目标协议的实际请求。

Pool 是同一 Server/Client 授权下共享连接池的目标大小，启用映射取最大值；不同 Mux 类型分别维护连接池。普通 TCP 使用独立业务连接，Pool 控制备用连接数；Mux 优先使用空闲的已授权底层连接，再按活动流数量分配，不对单条 TCP 流做带宽聚合，也不提供断线无损续传。smux 的同一底层连接内仍可能因慢读者耗尽共享接收缓冲而阻塞；Pool 为 1 或所有底层连接都繁忙时不能保证慢流隔离。调整 Pool 会增量扩缩容：缩容停止为退休连接分配新业务，已有业务排空后再关闭。目标、协议或授权变更仍会关闭对应的受影响连接；一条 Mux 底层连接故障会中断其承载的流，其他底层连接不因此重建。

例如，Client 能访问 `192.168.10.20:8080` 的 HTTP 服务时，可建立 TCP 映射到 Server 的空闲业务端口。验证该映射应发送 HTTP 请求，而不是只确认 TCP 握手成功。目标必须从 Client 容器网络可达；容器内的 `127.0.0.1` 不是宿主机。

### API Key 管理

Web 控制台「设置」页可直接管理（列表/新建/撤销），或用 CLI：

```sh
# 查看现有 Key（仅显示前缀，不显示明文）
docker exec veilink-master /usr/local/bin/veilink keys list

# 创建新 Key（明文仅显示一次）
docker exec veilink-master /usr/local/bin/veilink keys create my-key

# 吊销 Key
docker exec veilink-master /usr/local/bin/veilink keys revoke <id>
```

旧版用户名密码用户升级：执行 `veilink keys list`。若旧 `admin` 表还没有 API Key，命令会生成 `migrated-admin` 并把明文只打印一次，然后才列出前缀。旧用户名密码即刻失效。

### 设置页

Web 控制台「设置」页集中管理：

- **Web 版本**：只读显示统一镜像内置版本，随镜像更新；Web/API 固定同源
- **服务配置**：监听地址、协议、证书（修改后需重启）
- **API Key**：列表/新建/撤销（明文仅显示一次）

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

使用内置 Server 可跳过。先在 Web 创建 Server，获取节点 ID 和接入令牌。

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

先在 Web 创建 Client，获取节点 ID 和接入令牌。

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
| VLESS TCP + REALITY | 公私钥、Short ID、Server Name 匹配；可选 Encryption、Vision、ML-DSA-65 后量子验证、SpiderX/Y 伪装 |
| VLESS TCP + plain | 必须启用 Encryption；禁止 Vision |
| Hysteria2 | 独立 UDP/QUIC + TLS；需要证书、私钥和密码；不叠加 VLESS Encryption、REALITY、XHTTP、Vision |
| XHTTP | Veilink 双端业务通道；HTTP 版本与模式须符合下表和能力矩阵 |

ML-DSA-65 新配置使用独立的 32 字节种子（Base64）生成签名密钥，不能复用 REALITY 的 X25519 私钥。v0.4.2 生成的 4032 字节展开私钥经严格校验后兼容读取，升级保留原密钥身份，无需重新生成。只填写私有材料时自动派生验证公钥；同时填写公钥时必须配对。回落目标须支持 TLS 1.3，且其证书握手记录需要容纳额外的 3309 字节签名，过短的证书链可能导致握手失败。私有材料只保存在服务端，不下发客户端。关闭时清空种子和验证公钥，或使用“关闭 ML-DSA-65”后保存。TLS / REALITY 下可清空可选 VLESS Encryption；无 TLS 的 plain / HTTP 仍须保留 Encryption，不能关闭全部传输保护。

TCP 映射可选择关闭 mux 或使用 `smux`、`yamux`、`h2mux`；UDP 业务使用授权 XUDP，不启用 TCP mux，也不代表原生 Hysteria2 datagram 互通。

Vision 只用于 TCP + TLS/REALITY。只有独立已认证连接上的内层 TLS 1.3 满足结构和记录边界条件才可能直拷；mux、控制和 UDP 不裸传，Encryption 或无法安全识别的流保留加密回退。不宣称内核零拷贝。

### XHTTP

| 模式 | 行为 |
| --- | --- |
| `packet-up`（默认） | 分片上行，GET 流式下行 |
| `stream-up` | 同会话流式上行与 GET 下行 |
| `stream-one` | 单条双向请求，不使用会话 ID |
| `auto` | 自动协商（对齐 Xray-core）：无 REALITY 时选 `packet-up`；有 REALITY 时选 `stream-one`；有 REALITY 且配置下载端点时选 `stream-up` |

- 显式 HTTP/1.1 仅支持 `packet-up`。HTTP/2、HTTP/3 流模式仅支持直连 HTTPS 与 TLS 回源。
- h2c 仅限直连 HTTP、plain 回源且启用 VLESS Encryption 的 `packet-up`；显式版本不降级。普通 HTTP 链路或回源段必须启用 Encryption；REALITY 外层保护的 XHTTP 按独立安全组合校验。
- HTTP/3 需要 UDP 直连和端到端 QUIC/TLS。上行默认 POST，可选 PUT，前置代理须放行并禁用请求缓冲。不承诺通用 CDN 支持。
- `host` 仅覆写业务 HTTP Host，限小写 DNS 名或 IPv4、无端口；不改变授权拨号地址或证书校验名称。反代须保留 Host。
- 默认分片为 32768 字节、无额外间隔、逐片确认背压。随机分片、并发缓冲、padding、xmux、元数据位置和独立下行入口等高级参数见[XHTTP 能力边界](tests/deployment/xhttp-capability-matrix.md)，避免在两处重复维护字段范围。
- 半关闭与上传确认是 Veilink 私有扩展；业务 Cookie 元数据不是 Master 的登录 Cookie。

## 性能实测与基准

Veilink 后端全量重构为基于 Rust Tokio 的全异步架构，以下为 Linux x86_64（Ubuntu 7.0 内核）实机真实部署与三端压测数据：

### 1. 延迟与往返开销（RTT）

在真实代理链路中，数据面套接字开启 `TCP_NODELAY` 并优化多路复用帧头与载荷的内存紧凑拼接（单缓冲网络下发），彻底消除 Nagle 算法与 Delayed ACK 导致的 80ms 延迟陷阱：

- **直接 TCP 回环基准（直连 Target）**：平均 0.072ms（p50: 0.069ms，p99: 0.087ms）
- **Veilink 反向隧道穿透（通过 Proxy）**：平均 0.264ms（p50: 0.256ms，p99: 0.520ms）
- **纯隧道协议引入处理开销**：仅 **0.19ms**

### 2. 吞吐能力与带宽（iperf3 测量）

- **单连接吞吐**：**2.80 Gbits/sec**（~350 MB/s，5秒传输 1.63 GB）
- **4 并发流吞吐**：**3.44 Gbits/sec**（~430 MB/s，5秒传输 2.00 GB）
- **8 并发流吞吐**：**4.89 Gbits/sec**（~611 MB/s，5秒传输 2.85 GB）
- **短连接性能**：50 次连续短连接仅 0.74s（平均 14.8ms/次）；10 线程并发 30 次请求仅 0.06s（60ms）
- **大数据流完整性**：5 MB 随机二进制流 POST 上传回显，SHA-256 毫秒级完全一致

### 3. 全协议矩阵三端实机性能（120 项组合 100% 通过）

涵盖 24 种外层传输/安全/加密/流控组合 × 5 种映射模式（`off` / `smux` / `yamux` / `h2mux` / `udp` XUDP）共 **120 项组合**全部通过实机三端（`master` + `server` + `client`）往返校验（优化后总耗时由 31.83s 降至 **15.30s ~ 18.96s**）。单流 32 MiB 双向回显吞吐与短连接 RTT 实测如下：

| 协议与传输配置 | 映射模式 | 32 MiB 单流吞吐 | 折合带宽 | 短连接 Avg RTT |
| --- | --- | ---: | ---: | ---: |
| `vless-tcp-tls` | `off` / `smux` / `yamux` / `h2mux` | 151.0 - 194.7 MiB/s | 1.27 - 1.63 Gbps | 0.71 - 0.90 ms |
| `vless-tcp-tls-vision` | `off` | 157.5 - 182.0 MiB/s | 1.32 - 1.53 Gbps | 0.75 - 0.91 ms |
| `vless-tcp-tls-pq` (ML-KEM-768) | `off` | 156.7 - 183.3 MiB/s | 1.31 - 1.54 Gbps | 0.80 - 1.01 ms |
| `vless-tcp-reality` / `vision` / `mldsa65` | `off` | 118.5 - 164.9 MiB/s | 0.99 - 1.38 Gbps | 0.72 - 0.98 ms |
| `vless-tcp-plain-enc` (X25519) | `off` | 154.1 - 216.8 MiB/s | 1.29 - 1.82 Gbps | 0.76 - 0.90 ms |
| `hysteria2` (QUIC) | `off` / `smux` | 75.2 - 87.8 MiB/s | 0.63 - 0.74 Gbps | 0.79 - 0.94 ms |
| `xhttp-https` (`packet-up` / `stream-one` / `stream-up` / `auto`) | `off` | 130.5 - 177.3 MiB/s | 1.09 - 1.49 Gbps | 0.78 - 0.97 ms |
| `xhttp-reality-auto` | `off` | 117.7 - 138.0 MiB/s | 0.99 - 1.16 Gbps | 0.77 - 0.94 ms |
| `xhttp-http-auto` | `off` | 167.1 - 199.3 MiB/s | 1.40 - 1.67 Gbps | 0.81 - 0.96 ms |

### 4. 内存与资源消耗（高并发与 4.89 Gbps 压测下）

- **Master 控制面进程常驻内存（RSS）**：约 11.9 MB
- **Server 隧道接入节点进程常驻内存（RSS）**：约 12.6 MB
- **Client 隧道反向客户端进程常驻内存（RSS）**：约 10.6 MB
- **长稳表现**：高带宽传输数十 GB 数据流后，内存始终稳定在 10~13 MB 区间，无句柄或流对象泄漏。

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

先在隔离环境验证登录、节点身份、上报和业务探针，再切换正式挂载。保留原数据副本，禁止旧、新 Master 同时提供写服务。已知已发布 schema 自动备份后迁移；未知 schema 不自动迁移或删库，任何数据删除都须先备份并得到明确授权。

### API Key 维护

Web 控制台「设置」页可直接管理，或用 CLI：

```sh
# 列出所有 Key（仅显示前缀）
docker exec veilink-master /usr/local/bin/veilink keys list

# 创建新 Key（明文仅显示一次，请保存）
docker exec veilink-master /usr/local/bin/veilink keys create my-key

# 吊销 Key（最后一个 admin Key 受保护，不可删除）
docker exec veilink-master /usr/local/bin/veilink keys revoke <id>
```

使用自定义数据库路径时补充 `-database`、`-deployment-key` 参数。Key 吊销即时生效。

### 升级与回滚

1. 记录当前镜像版本和运行参数，敏感令牌不要写入公开日志。
2. 停机备份 Master 数据和独立节点状态，确认备份有效。
3. 拉取目标版本镜像，保留数据挂载，以原有角色和 flags 重建容器。
4. 检查日志、健康接口、节点应用状态及实际业务请求。
5. 回滚前备份当前状态，确认旧版本兼容性；不兼容时用匹配旧版本的成套备份在新目录验证，不直接覆盖数据库。

**从 `v0.4.13` 及更早 Go 版本无痛升级至 Rust 版（`v0.4.14+`）**：

- **数据与永久凭证 100% 兼容**：Master 的 `veilink.db`（Schema v1~v6 自动迁移）、`master.key`（AES-256-GCM 密文格式一致）、各 Server/Client 的 `state.json`（永久节点凭证与快照）、CLI 启动参数及 Docker `/data` 挂载目录均无需改动，升级后节点直接复用既有永久凭证自动重连，无需重新签发令牌或重建映射。
- **三端同步更新**：因控制面已从 gRPC 升级为纯 HTTP（`/api/control/*`），升级时请将 **Master、Server、Client 三端镜像或单二进制一并替换**。若只升级一端，未升级节点会因协议差异进入退避重试（不会误删本地永久凭证），待三端全部更新后即刻恢复。
- **Nginx 反代无需额外改动**：新版控制面直接复用现有的 `location / { proxy_pass ...; }`；旧 Nginx 配置中针对 `/veilink.control.v1.Control/` 的 `grpc_pass` 段落不再需要，可在升级后移除。

**从更早期（用户名密码）版本升级**：执行 `docker exec veilink-master /usr/local/bin/veilink keys list`。存在旧 `admin` 表且还没有 API Key 时，命令生成 `migrated-admin` 并只在这次输出里显示明文；输出失败则回滚，不会留下无人知道的 Key。旧用户名密码即刻失效。老 `/api/*` 路径自动重定向到 `/api/v1/*`（`GET/HEAD` 为 301，其余方法为 308 保留方法与请求体）。数据（节点、映射、配置）完整保留。

## 故障排查

按“容器 → 控制面 → 配置应用 → 业务目标”的顺序检查，不以删库或关闭校验代替排障。

| 现象 | 优先检查 |
| --- | --- |
| 镜像拉取 `DENIED: invalid token` | GHCR 或镜像代理的鉴权、路径；这不是 Veilink 启动错误 |
| 容器返回 ID 后退出 | `docker ps -a` 和容器日志；角色是否写在 flags 前、目录权限、端口占用 |
| 内置 Server 与 Master 端口冲突 | 用另一个 Master 端口启动，再到 Web 调整内置节点；不要删库 |
| `flag provided but not defined` | 使用当前角色 `--help`；没有 `-embedded-server-server-name` 或 `-config` |
| 远端无法访问 `127.0.0.1:2545` | 该地址仅本机可达；使用反代或受限内网监听 |
| 反代连接超时或长轮询中断 | 检查 nginx `proxy_pass`、`proxy_http_version 1.1` 与 `proxy_read_timeout` |
| API Key 无效 401 | 检查 `Authorization: Bearer` 头是否正确，Key 是否被吊销 |
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
| `backend/src/main.rs`、`backend/src/cli.rs`、`backend/src/config.rs` | 统一命令入口与角色参数 |
| `backend/src/master.rs`、`backend/src/control.rs`、`backend/src/node.rs` | 管理服务、纯 HTTP 控制面与节点配置应用 |
| `backend/src/store.rs`、`backend/src/httpapi.rs` | 配置持久化、控制面路由与 Web API |
| `backend/src/tunnel/mod.rs` | 隧道、协议协商与数据传输 |
| `frontend` | 唯一 Web 界面，Vue 3 + TypeScript + Vite |
| `backend/tests/integration`、`backend/tests/deployment` | 集成与部署测试 |
| `frontend/tests/acceptance` | 历史 Web 验收记录和截图 |
| `tools` | 离线备份及节点验证工具 |

Rust 依赖与版本以 [backend/Cargo.toml](backend/Cargo.toml) 为准；前端构建使用 Node.js 22 和 npm 锁文件。`npm run build` 输出到 `frontend/dist/`，发布与 Docker 构建在编译 Rust 前将其同步到 `backend/internal/webui/dist/` 并通过 `rust-embed` 内嵌进单二进制，仅 Master 提供 Web。

### 映射限速与连接检测

- Web 的“带宽上限（Mbps）”只填数字，例如 `48`；`0` 或留空表示不限速，支持最多六位小数，非零范围为 `0.001` 至 `100000`。API 的 `bandwidth_limit` 保留单位字符串，例如 `48Mbps`；`0`、`0Mbps` 或空字符串表示不限速，非零支持十进制 `Kbps`、`Mbps`、`Gbps`，范围 `1Kbps` 至 `100Gbps`。
- 同一映射的所有连接、Pool 通道共享限额，两个方向各自独立限速。只计算业务负载，不包含 TCP/TLS/mux/XHTTP 等协议开销；50Mbps 链路可先试 48Mbps，若开销或共享流量较大应继续降低。
- TCP 采用令牌桶等待和有界读取，将背压传回源端；UDP 不具备可靠背压，保留有界队列，过载仍可能丢包。限速不能保证消除所有 RST，也不能让持续 60Mbps 的视频在 50Mbps 链路上流畅播放。
- 修改或清空限速实时应用，不主动断开现有业务连接。映射标识纳入私有隧道授权头，Master、Server、Client 必须一起升级，不能混用升级前后的数据面版本。
- TCP 拨号及监听启用 keepalive：空闲 60 秒、探测间隔 60 秒、3 次未响应后由操作系统关闭。它检测空闲半开连接，不替代繁忙连接的 TCP 重传超时；重连不会恢复已断开的业务 TCP 会话。
- 15 秒期限用于握手或单次阻塞写入，不应成为业务连接寿命。XHTTP 在每次写入并刷新后清除响应写期限，空闲时不再因遗留期限被断开；协议心跳、空闲回收和异常写入超时仍保留。

### 检查命令

以下是维护者验收命令，不代表本次文档更新已执行这些检查：

```sh
cd backend && cargo test --locked
cd backend && cargo build --release --locked
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

- [协议矩阵](backend/tests/deployment/protocol-matrix.md)：组合、授权和往返覆盖范围。
- [XHTTP 能力边界](backend/tests/deployment/xhttp-capability-matrix.md)：字段、模式与限制。
- [XHTTP 验证记录](backend/tests/deployment/xhttp.md)：对应阶段的执行证据。
- [统一镜像验收记录](frontend/tests/acceptance/unified-image-acceptance.md)：历史镜像与三角色验证。

`backend/tests/` 与 `frontend/tests/` 下的执行结果只对应记录中的版本和环境，不是当前版本的生产认证。真实多主机 WAN/NAT、24–72 小时长稳、生产 CA 生命周期和供应链签名仍需目标环境验收。

## 许可证与第三方组件

Veilink 原创代码和文档（另有声明者除外）采用 [GPL-3.0-or-later](LICENSE)，授权声明见 [NOTICE](NOTICE)。

第三方组件保留各自许可。依赖版本、MPL-2.0 覆盖文件、上游来源、对应源码获取及分发义务见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
