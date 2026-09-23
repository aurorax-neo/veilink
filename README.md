# Veilink

Go 编写的集中管理 TCP 内网穿透工具：自带的 VLESS 反向通道负责数据面，管理中心负责节点、绑定、映射与配置同步。数据面不经过 master，也不嵌入其他代理内核。

```text
公网访问者 → server 映射端口 → 反向入口 ← VLESS + TLS ← client 出口 → 内网服务
                                ↑                           ↑
                                └──── TLS gRPC / master ────┘
```

## 功能与范围

- 单二进制 `master` / `server` / `client` 三角色，多网关、多内网节点。
- SQLite 集中配置、节点注册/吊销、独立绑定密钥、TCP 映射 CRUD 与启停。
- TLS gRPC 事件流、完整配置拉取、心跳与期望/实际版本回报。
- 内嵌中文管理界面，无 Node.js 构建依赖；会话、CSRF 与登录限速。
- 客户端主动出站；管理中心离线时维持已运行的数据面，节点可恢复本地成功快照。
- TLS 证书验证默认启用；管理 API 不返回 VLESS UUID，数据库中的绑定密钥加密保存。

首版仅支持 TCP。HTTP、HTTPS、SSH 等均按 TCP 透明转发。**不承诺无损热更新**：配置变更会停掉该节点当前隧道并按新快照重新监听，已有连接会被中断。节点在线不等于目标服务健康。暂不含 UDP、REALITY、自动证书、多租户、P2P 打洞或远程终端。

## 构建与验证

需要 **Go 1.27+**（与 `go.mod` 一致）。数据面在 `internal/tunnel` 内实现，构建不依赖 `ref/`。

```sh
go build -o bin/veilink ./cmd/veilink
./bin/veilink version
go test ./...
go vet ./...
go test -race ./...
# 较慢：真实 CLI 三进程 + TLS + 管理 API + 大响应/并发 + 故障恢复
go test -tags integration -v -timeout 10m ./tests/integration
```

测试生成的二进制、证书、数据库和日志保存在临时目录。

## 本机快速启动

以下命令从仓库根目录执行，相对配置路径以**进程工作目录**为准。使用 `.local/` 保存本机证书、数据库和节点状态。这些运行数据以及本地参考目录 `ref/` 已由 `.gitignore` 排除，不要强制加入版本库。

### 1. 生成演示证书、初始化管理员

```sh
go run ./tools/devcert -out .local/certs
# 手工输入强口令，避免将明文写入历史；无默认管理员密码。
read -rs VEILINK_ADMIN_PASSWORD; echo
export VEILINK_ADMIN_PASSWORD
./bin/veilink init-admin -config examples/master.yaml -username admin
unset VEILINK_ADMIN_PASSWORD
./bin/veilink master -config examples/master.yaml
```

打开 **http://127.0.0.1:8080** 登录。该示例显式允许仅回环 HTTP；控制面仍为 TLS。演示证书只有七天有效期，生成器不会覆盖已有文件。生产环境应使用自己的证书，并为管理入口启用 HTTPS。

### 2. 创建节点并注册

管理页面创建：

| 名称 | 角色 | 网关地址 | VLESS 端口 | TLS ServerName |
| --- | --- | --- | --- | --- |
| gateway | server | `127.0.0.1` | `4433` | `localhost` |
| inside | client | 无 | 无 | 无 |

在各节点操作中生成一次性注册令牌，记录节点 ID。在**两个独立终端**启动：

```sh
# 网关终端：替换为页面显示的实际值。
export VEILINK_NODE_ID='<server-id>'
export VEILINK_ENROLL_TOKEN='<server-onetime-token>'
./bin/veilink server -config examples/server.yaml

# 内网客户端终端：替换为其自己的实际值。
export VEILINK_NODE_ID='<client-id>'
export VEILINK_ENROLL_TOKEN='<client-onetime-token>'
./bin/veilink client -config examples/client.yaml
```

首次注册后，节点凭据存于其 `state_dir`。后续启动保留节点 ID 和同一状态目录，移除 `VEILINK_ENROLL_TOKEN` 即可。不要共用两个节点的状态目录，也不要把 client/server 凭据混用。

### 3. 创建绑定和 TCP 映射

页面将 gateway 与 inside 建立绑定，然后创建映射：

```text
名称：web
绑定：gateway → inside
监听地址：127.0.0.1
公网端口：8081
目标地址：127.0.0.1
目标端口：9000
启用：是
```

在客户端所在机器启动任意 HTTP 服务，例如在一个只含公开测试内容的目录运行：

```sh
python3 -m http.server 9000 --bind 127.0.0.1
```

等待两个节点期望/实际版本一致，然后：

```sh
curl --fail http://127.0.0.1:8081/
```

公网部署时，把 server 地址改为**客户端可访问的公网域名/IP**，ServerName 与证书 SAN 匹配；映射监听地址改为需要的地址（如 `0.0.0.0`），仅开放确实需要的端口。目标地址相对于 **client 的网络环境**，不是 master 或 server。

SSH 也可直接映射：目标 `127.0.0.1:22`、网关映射 `2222`，用 `ssh -p 2222 user@gateway.example.com` 访问。SSH 服务自身应使用密钥认证与访问限制。

## Docker Compose 演示

需 Docker Engine 和 Compose v2。本演示的 client 不发布端口，目标 nginx 仅连接 `internal` 网络，网关无法绕过 client 直接访问它。

```sh
docker compose build
docker compose --profile setup run --rm certs
read -rs VEILINK_ADMIN_PASSWORD; echo
export VEILINK_ADMIN_PASSWORD
docker compose --profile setup run --rm init-admin
unset VEILINK_ADMIN_PASSWORD
docker compose up -d master
```

管理地址为 **https://localhost:8444**。将演示 CA 导入仅用于开发的信任库；不要在生产环境禁用证书校验。可导出 CA：

```sh
docker compose run --rm --no-deps --entrypoint cat master /certs/demo/ca.pem > /tmp/veilink-demo-ca.pem
```

页面创建 server 节点时填 **地址 `server`、端口 `4433`、ServerName `server`**（Compose 网络内解析），另建 client 节点并生成各自令牌。然后：

```sh
export SERVER_NODE_ID='<server-id>' SERVER_ENROLL_TOKEN='<server-token>'
export CLIENT_NODE_ID='<client-id>' CLIENT_ENROLL_TOKEN='<client-token>'
docker compose --profile nodes up -d server client target
```

创建绑定；映射监听 `0.0.0.0:8081`，目标 **`target:80`**。等待配置下发完成后，宿主机访问 `http://127.0.0.1:8081/` 可看到 nginx 页面。

命名卷保存数据库、部署密钥及节点状态。`docker compose down` 不删除这些卷；不要随意使用 `down -v`。演示为了简化挂载共享了一套证书，**生产应分别签发 master/server 证书，client 仅挂载 CA，不挂载服务端私钥**。演示端口默认仅发布到宿主机回环。

## 运维要点

- 数据面连接失败：依次检查节点应用错误、client→server 端口、TLS ServerName/CA、映射端口防火墙和 client→目标连通性。
- 管理中心不可达时，已运行映射继续；配置修改和即时吊销不可用。
- 吊销要求网关收到新配置才能移除旧身份；紧急撤销可同时关闭映射入口/网关进程或使用防火墙阻断。
- 备份 SQLite 和对应部署密钥；仅备份数据库无法恢复加密 UUID。维护窗口停止 master 后一起备份是最简单的安全方式。
- 生产使用非 root 专用账户与受限文件权限；不要把节点凭据、一次性令牌或私钥交给不可信人员。

详见 [架构](docs/architecture.md) 和 [第三方组件](THIRD_PARTY_NOTICES.md)。
