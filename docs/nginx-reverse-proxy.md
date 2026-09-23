# Veilink 生产级 Nginx 反向代理配置实战指南

本文档提供在生产环境中使用 Nginx 作为前端反向代理与流量分发网关接入 Veilink 的详尽实战指南。涵盖 **HTTPS Web 控制台**、**TLS gRPC 节点控制面**以及**基于 Stream SNI 的四层端口复用与透传分流**。

---

## 1. 架构与协议分流原理

Veilink 的网络通信主要分为三层：

```
                              [ 用户 / 运维浏览器 ]
                                        │ (HTTPS Web Console / REST API)
                                        ▼
   [ 边缘 Nginx 入口 ] ─────────► [ 443 / 8443 ]
   (Stream SNI / TLS 终结)              │
                                        ├─► [ TLS gRPC 控制面 (HTTP/2) ] ───► Veilink Master
                                        │
                                        └─► [ 4层 Stream SNI 透传 ] ──────► Veilink Server / 网关数据面
                                                                               (VLESS / REALITY / Mux)
```

1. **Web 控制台与 REST API**：
   - 协议：HTTP/1.1 或 HTTP/2，承载静态资源与 `/api/*` 请求。
   - 特点：包含会话 Cookie（`Secure`, `HttpOnly`, `SameSite=Strict`）及 CSRF 校验，需传递标准的 `Host`、`X-Real-IP`、`X-Forwarded-For`、`X-Forwarded-Proto` 头。
2. **节点控制面（TLS gRPC）**：
   - 协议：原生 HTTP/2 gRPC。
   - 特点：长周期双向流（Streaming RPC），需要持久连接与适当的超时（`grpc_read_timeout`），使用 Nginx 的 `grpc_pass` 指令。
3. **数据面穿透流量（VLESS / REALITY）**：
   - 协议：TCP / UDP（XUDP）私有多路复用协议，带有自定义 TLS 或 REALITY 伪装层。
   - 最佳实践：使用 Nginx 的 `stream` 模块配合 `ssl_preread` 实现 **SNI 四层透明路由**，无需在 Nginx 解密数据面，性能极高且保留 REALITY 伪装特性。

---

## 2. 方案一：标准七层反代（Web + gRPC 共享域名与端口）

适用于使用公网受信任证书（如 Let's Encrypt），Master 自身使用自签证书，由 Nginx 对外终结标准 HTTPS 并分流 Web 与 gRPC。

### `nginx.conf` 核心配置

```nginx
# /etc/nginx/conf.d/veilink.conf

# 上游 Master 服务
upstream veilink_master {
    server 127.0.0.1:8443;
    keepalive 32;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name panel.example.com;

    # 公网受信任 TLS 证书配置
    ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 1d;

    # 1. gRPC 控制面路由（HTTP/2 原生转发）
    # Veilink 控制面 proto package 为 veilink.control.v1.Control
    location /veilink.control.v1.Control/ {
        # 转发至 Master 的 HTTPS 端口（若 Master 启用 TLS，则用 grpcs://）
        grpc_pass grpcs://veilink_master;

        # 信任 Master 的自签证书
        grpc_ssl_verify off;

        # gRPC 长连接超时配置（防止事件流被 Nginx 中途掐断）
        grpc_read_timeout 300s;
        grpc_send_timeout 300s;
        grpc_buffer_size  64k;

        # 传递客户端真实 IP
        grpc_set_header X-Real-IP $remote_addr;
        grpc_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        grpc_set_header Host $http_host;
    }

    # 2. REST API 接口反向代理
    location /api/ {
        proxy_pass https://veilink_master;
        proxy_ssl_verify off;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 安全与防重放
        proxy_buffering off;
        client_max_body_size 2m;
    }

    # 3. 健康检查接口
    location /healthz {
        proxy_pass https://veilink_master;
        proxy_ssl_verify off;
    }

    # 4. 前端静态单页应用（Web 控制台）
    location / {
        proxy_pass https://veilink_master;
        proxy_ssl_verify off;

        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 3. 方案二：生产高阶架构 —— 443 单端口 Stream SNI 多路复用

如果公网服务器仅开放 443 端口，需要将：
- `panel.example.com`（Web 控制台与 gRPC）
- `gateway.example.com`（Veilink 数据面网关，支持 REALITY 或自定义 TLS）

共用公网 443 端口接入，可使用 Nginx 的 `stream { ssl_preread on; }` 实现四层无感分流。

### `nginx.conf` 完整范例

```nginx
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 10240;
}

# -------------------------------------------------------------
# 四层 Stream SNI 预读分流（核心）
# -------------------------------------------------------------
stream {
    # 读取 ClientHello 中的 SNI 扩展名
    ssl_preread on;

    map $ssl_preread_server_name $veilink_backend {
        # 访问控制台与 gRPC 域名的流量 -> 本机 Nginx 七层 Web 端口
        panel.example.com    127.0.0.1:10443;

        # 访问数据面隧道的流量 -> 直接透传给 Veilink Server / 内置网关数据端口
        gateway.example.com  127.0.0.1:8444;

        # 默认回落
        default              127.0.0.1:10443;
    }

    server {
        listen 443;
        listen [::]:443;
        proxy_pass $veilink_backend;
        proxy_timeout 1d;
        proxy_connect_timeout 5s;
    }
}

# -------------------------------------------------------------
# 七层 HTTP/2 & Web 服务（由上面的 Stream 模块内部转发过来）
# -------------------------------------------------------------
http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;
    sendfile        on;
    keepalive_timeout  65;

    upstream master_backend {
        server 127.0.0.1:8443;
        keepalive 32;
    }

    server {
        # 仅监听本机内部 10443 端口
        listen 127.0.0.1:10443 ssl http2;
        server_name panel.example.com;

        ssl_certificate     /etc/letsencrypt/live/panel.example.com/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/panel.example.com/privkey.pem;

        # gRPC 控制面
        location /veilink.control.v1.Control/ {
            grpc_pass grpcs://master_backend;
            grpc_ssl_verify off;
            grpc_read_timeout 600s;
            grpc_send_timeout 600s;
            grpc_set_header X-Real-IP $remote_addr;
            grpc_set_header Host $http_host;
        }

        # API 与 Web 控制台静态资源
        location / {
            proxy_pass https://master_backend;
            proxy_ssl_verify off;
            proxy_http_version 1.1;
            proxy_set_header Host $http_host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
        }
    }
}
```

---

## 4. 关键配置注意事项与调优

### 4.1 gRPC 超时设置 (`grpc_read_timeout`)
Veilink 节点（`server` 和 `client`）通过双向 gRPC 长连接拉取配置与上报心跳。Nginx 默认的 `grpc_read_timeout`（60s）若过短，可能导致空闲时偶发重连。
- **推荐值**：`grpc_read_timeout 300s` 或 `600s`。
- Veilink 客户端内部具备自动指数退避重连机制，但适当调高超时可避免频繁重连日志。

### 4.2 Cookie 与安全标头
Veilink Web 控制台在登录时使用安全的 `SameSite=Strict; Secure; HttpOnly` 会话 Cookie，并强制校验 `X-CSRF-Token` 请求头。
- 如果 Nginx 终结了 HTTPS（对外提供 HTTPS，对内以 HTTP 转发），必须确保传递了 `proxy_set_header X-Forwarded-Proto https;`。
- 严禁篡改或缓存响应头中的 `Set-Cookie`。

### 4.3 配置文件语法校验与热重载
修改完 Nginx 配置后，执行测试并平滑重载：
```bash
# 测试语法正确性
nginx -t

# 平滑重新加载配置
nginx -s reload
```
