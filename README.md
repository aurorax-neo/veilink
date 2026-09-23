# Veilink

Veilink 是一个专注于安全、高性能与易运维的集中管理型 TCP/UDP 内网穿透工具：基于原生 Go 实现的 VLESS 反向通道负责数据面传输，控制中心负责节点纳管、多路复用隧道绑定、映射生命周期以及动态配置下发。数据面不经过 Master 转发，也不依赖任何外部代理内核。

```text
公网访问者 → server 映射端口 → 反向入口 ← VLESS + TLS ← client 出口 → 内网服务
                                ↑                           ↑
                                └──── TLS gRPC / master ────┘
```

---

## 核心特性

- **双部署架构**：
  - **单机一体化模式 (All-in-One)**：Master 内置数据面网关（`embedded_server`），单个二进制进程同时承担控制台与公网穿透入口，免令牌自启动。
  - **分布式多节点模式 (Distributed)**：Master 作为独立控制面，支持跨多台公网服务器连接多个独立 Server 网关与内网 Client。
- **单二进制多角色**：一个二进制支持 `master`、`server`、`client`、`init-admin` 以及辅助诊断工具。
- **原生高性能隧道**：基于 Go 原生 VLESS 协议、Private Mux（单连接多路复用）、XUDP 数据报封装，无外部重量级依赖。
- **全方位传输安全**：数据面支持标准证书 TLS、REALITY（去特征与合规站点伪装）、Hysteria2（基于 QUIC 的弱网加速）及 VLESS Encryption 后量子加密。
- **现代化管理控制台**：基于 Vue 3 + TypeScript 打造的单页面管理后台，Master 端口同源服务静态资源与 REST API。
- **生产级容器化**：官方多阶段构建 Dockerfile，默认使用非 root 用户（`65532:65532`）运行，内置容器级探活健康检查（`HEALTHCHECK`）。
- **完善的环境变量支持**：所有核心配置均可通过 `VEILINK_<SECTION>_<KEY>` 环境变量直接覆盖，支持容器集群的零文件挂载自动化引导。

---

## 快速上手

### 方式一：Docker Compose 生产级部署（推荐）

#### 1. 单机一体化网关 (All-in-One)

适合拥有单台公网 VPS，希望快速部署穿透服务并使用 Web 控制台管理的用户：

```sh
# 进入示例目录
cd examples/compose

# 启动 Master（包含 Web 控制台与内置 Server 网关）
# 首次启动会自动创建初始管理员：admin / ChangeMeToAStrongPassword123!
docker compose -f compose.master.yaml up -d
```

启动后：
- 浏览器访问控制台：**https://<你的公网IP>:8443**
- 登录账号密码：`admin` / `ChangeMeToAStrongPassword123!`（可在 `compose.master.yaml` 中通过 `VEILINK_INIT_ADMIN_PASSWORD` 自定义）。
- 内置网关 `integrated-gateway` 已经就绪，监听 `8444` 端口。

#### 2. 内网客户端 (Client)

在需要穿透内网服务的设备上部署客户端：

```sh
# 获取在控制台中生成的客户端节点 ID 与注册令牌
export VEILINK_NODE_ID='<client-node-id>'
export VEILINK_ENROLL_TOKEN='<client-enroll-token>'
export VEILINK_MASTER_ADDR='<master-ip>:8443'

docker compose -f compose.client.yaml up -d
```

在控制台创建**绑定（Binding）**并添加**映射（Mapping）**（支持 TCP / UDP），即可完成穿透！

---

### 方式二：本地二进制构建与运行

需要 **Go 1.27+** 与 **Node.js** 环境。

#### 1. 编译构建
```sh
# 构建前端
cd frontend && npm install && npm run build && cd ..

# 编译 Veilink 二进制
go build -o bin/veilink ./cmd/veilink
./bin/veilink version
```

#### 2. 生成本地测试证书并初始化管理员
```sh
# 生成演示 TLS 证书
go run ./tools/devcert -out .local/certs

# 初始化管理员账号
export VEILINK_ADMIN_PASSWORD="YourStrongPasswordHere"
./bin/veilink init-admin -config examples/master.yaml -username admin
unset VEILINK_ADMIN_PASSWORD
```

#### 3. 启动一体化 Master
编辑 `examples/master.yaml`，开启内置网关：
```yaml
embedded_server:
  enabled: true
  name: "integrated-gateway"
  port: 8444
  address: "127.0.0.1"
  server_name: "localhost"
```

启动 Master：
```sh
./bin/veilink master -config examples/master.yaml
```
访问 **https://127.0.0.1:8443** 登录控制台。

---

## 环境变量配置规范

Veilink 支持完整的环境变量覆盖机制，优先级高于配置文件：

| 环境变量 | 作用与示例 | 默认值 |
| :--- | :--- | :--- |
| `VEILINK_CONFIG` | 指定加载的配置文件路径 | `veilink.yaml` |
| `VEILINK_INIT_ADMIN_USERNAME` | Master 首次启动自动初始化的管理员用户名 | 无（需配合密码） |
| `VEILINK_INIT_ADMIN_PASSWORD` | Master 首次启动自动初始化的管理员密码 | 无（留空则不自动初始化） |
| `VEILINK_EMBEDDED_SERVER_ENABLED` | 是否在 Master 内置数据面 Server 网关（`true`/`false`） | `false` |
| `VEILINK_EMBEDDED_SERVER_NAME` | 内置网关在控制台登记的节点名称 | `integrated-gateway` |
| `VEILINK_EMBEDDED_SERVER_PORT` | 内置网关数据面反向隧道监听端口 | `8444` |
| `VEILINK_EMBEDDED_SERVER_ADDRESS` | 客户端连接内置网关的公网域名或 IP | `127.0.0.1` |
| `VEILINK_EMBEDDED_SERVER_SERVER_NAME`| 内置网关 TLS ServerName（SNI） | `localhost` |
| `VEILINK_MASTER_ADDR` | 节点连接控制面的 `host:port` | `127.0.0.1:8443` |
| `VEILINK_NODE_ID` | 节点自身唯一标识符（UUID） | 无 |
| `VEILINK_ENROLL_TOKEN` | 节点首次加入时的一次性注册令牌 | 无 |
| `VEILINK_STATE_DIR` | 节点持久化保存凭据与快照的目录 | `state/` |

---

## 生产级 Nginx 反向代理

在生产环境中，推荐使用 Nginx 统一管理公网 80/443 端口与 SSL 证书，并反向代理 Master Web 控制台与 gRPC 控制通道。

Veilink 提供了完整的实战配置指南，涵盖：
- Master Web 控制台与 REST API 的 HTTPS 反向代理与安全标头配置。
- TLS gRPC 长连接与 HTTP/2 的 `grpc_pass` 代理转发。
- 基于 Nginx `stream` 模块的 SNI Preread 四层透传与端口复用。
- 经过语法与实操检验的完整 `nginx.conf` 范例。

详细请阅读：👉 **[docs/nginx-reverse-proxy.md](docs/nginx-reverse-proxy.md)**

---

## 架构与深入指南

- **系统架构与安全边界**：[docs/architecture.md](docs/architecture.md)
- **Nginx 生产反向代理指南**：[docs/nginx-reverse-proxy.md](docs/nginx-reverse-proxy.md)
- **第三方组件与开源合规**：[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
- **开源许可证**：[LICENSE](LICENSE) (Apache License 2.0)
