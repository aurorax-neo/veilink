# Veilink

Veilink 是原生 Go 私有反向隧道：Master 管理 Server、Client 和 TCP/UDP 映射。**生产只使用一个统一 Docker 镜像**，以 `master|server|client` 子命令选择角色；只有 Master 提供 Web。默认 Master 使用 HTTP，内置 HTTPS 可选；不承诺与 Xray 协议互通。

[v0.2.0 Release](https://github.com/aurorax-neo/veilink/releases/tag/v0.2.0) 提供统一镜像 `ghcr.io/aurorax-neo/veilink:0.2.0`（linux/amd64、linux/arm64）。下文使用本机镜像别名 `veilink:latest`。**先做准备，再执行 Docker Run**；三种角色使用相同镜像。示例拓扑：nginx 与 Master 同机，外部 `https://vl.vekt.cc.cd:8843` → Master `http://127.0.0.1:2545`；内置 Server 首次默认监听 `8444`。首次注册前须限制面板访问来源。

## 1. 每台运行节点的主机：准备镜像

```sh
docker pull ghcr.io/aurorax-neo/veilink:0.2.0
docker tag ghcr.io/aurorax-neo/veilink:0.2.0 veilink:latest
```

`veilink:latest` 只是本地别名，不会自动升级。v0.2.0 的新安装默认监听 `127.0.0.1:2545`；已有 Master 若已存旧监听地址，仍须按下方命令显式指定 `-listen-addr 127.0.0.1:2545`。第三方镜像代理若提示 `DENIED: invalid token`，先检查代理的鉴权/镜像路径；不要把拉取失败误判成 Veilink 启动失败。也可以从当前源码构建同一个镜像（会覆盖这个本地别名）：

```sh
docker build -t veilink:latest .
```

## 2. Master 主机：先准备目录，再启动

首次创建目录时执行；**已有数据不删除、不覆盖**，数据库与 deployment key 应一起备份。容器使用 UID/GID `65532:65532`：

```sh
mkdir -p /opt/docker/veilink-master/config /opt/docker/veilink-master/data
chown 65532:65532 /opt/docker/veilink-master/config /opt/docker/veilink-master/data
chmod 700 /opt/docker/veilink-master/config /opt/docker/veilink-master/data
```

启动 Master（默认 HTTP，无需 Master 证书）：

```sh
docker run -itd \
  --name veilink-master --restart unless-stopped --net host \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-master/config:/config:ro \
  -v /opt/docker/veilink-master/data:/data \
  veilink:latest master \
  -database /data/veilink.db -deployment-key /data/veilink.key \
  -state-dir /data/state -listen-addr 127.0.0.1:2545 \
  -scheme http -html-dir /usr/local/html \
  -embedded-server-enabled=true
```

**镜像名后必须先写 `master`，再写 `-database` 等 flags**；少写角色会启动失败。`-embedded-server-address`、`-embedded-server-port` 通常不必设置，内置 Server 首次默认名 `default`、监听端口 `8444`；`-embedded-server-server-name` 不是合法 flag。已有内置节点的自定义设置不会被默认值覆盖；如果已存监听端口与新的 Master 端口冲突，选择另一个 Master 端口启动，再到 Web 调整内置节点，不要删库。`-embedded-server-enabled=false` 可显式关闭内置节点。

```sh
docker ps -a --filter name=veilink-master
docker logs veilink-master
curl -fsS http://127.0.0.1:2545/healthz
```

`docker run -itd` 返回容器 ID 不代表启动成功。**新部署的 Master 默认监听** `127.0.0.1:2545`；上例仍显式指定该地址，以便已有数据库保存了旧监听地址时也切换至 2545。它仅同机可达，远端节点必须走下一步的 HTTPS 反代，或者改成受访问控制的可信内网监听。Host 网络不要加 `-p`。Master 会保留 SQLite 已存设置；显式 flags 覆盖已存值，缺省 flags 不会清空旧设置。若从已存 HTTPS 切回 HTTP，另加 `-control-server-name= -control-ca=`，不要删除数据库。

## 3. 同机 nginx：先配 HTTPS 与 gRPC，再接入远端节点

示例放入 nginx 的 `http {}` 中；需要 **nginx ≥ 1.25.1**、SSL/HTTP2/gRPC 模块。与贴出的站点配置一致：外部域名 `vl.vekt.cc.cd`、HTTPS 端口 `8843`，后端 HTTP/h2c 端口 `2545`。`<实际证书目录>` 须替换为证书所在的**具体目录名**（例如实际目录 `*.vekt.cc.cd_vekt.cc.cd_EC384`），`ssl_certificate` 指令不能直接用 `*` 通配符匹配目录。nginx 若在独立 Bridge 容器，`127.0.0.1` 是 nginx 自己，回源地址须改成它能到达的受限地址。

```nginx
server {
    listen 8843 ssl;
    listen [::]:8843 ssl;
    http2 on;
    server_name vl.vekt.cc.cd;
    ssl_certificate /etc/nginx/ssl/<实际证书目录>/fullchain.cer;
    ssl_certificate_key /etc/nginx/ssl/<实际证书目录>/private.key;

    if ($host != $server_name) {
        return 404;
    }

    # 只转换本站 Origin；其它 Origin 原样传递，由 Master 拒绝跨站写入。
    set $veilink_origin $http_origin;
    if ($http_origin = "https://vl.vekt.cc.cd:8843") {
        set $veilink_origin "http://vl.vekt.cc.cd:8843";
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
curl -fsS https://vl.vekt.cc.cd:8843/api/setup
openssl s_client -connect vl.vekt.cc.cd:8843 -servername vl.vekt.cc.cd -alpn h2 </dev/null 2>&1 | grep -i 'ALPN protocol'
```

预期 ALPN 为 `h2`。旧 nginx 不支持 `http2 on;` 时可使用 `listen 8843 ssl http2;`，但仍须有 HTTP/2 模块。**`tls: no application protocol` 是外部 HTTPS 入口未提供 h2，不是 CSRF 错误**；节点控制面必须使用 `grpc_pass`，不能换成普通 `proxy_pass`。本例 nginx 的监听端口就是外部访问端口 `8843`，所以回源 Host 使用 `$host:$server_port`；单独 `$host` 不含非标准端口，会导致同源 Origin 比对失败。若前置负载均衡/CDN 改写了外部端口，不要用 `$server_port` 猜测，应在两个 Host 指令中填写实际外部域名和端口。Web/API 使用同一外部域名及端口，本站 Origin 的精确转换也须与回源 Host 一致。登录/注册就 403 先检查 Origin/Host/端口；登录后操作 403 再检查 `veilink_session` Cookie、`X-CSRF-Token` 与 `Sec-Fetch-Site`。不关闭 CSRF、不信任客户端提供的转发头，也不把所有 Origin 改成本域。nginx 为会话 Cookie 加 `Secure`；Master 不依赖 `X-Forwarded-Proto` 放宽认证。

反代只处理管理 Web/API/gRPC；隧道 TCP/TLS/REALITY 和 HY2 UDP/QUIC 业务端口仍按所选传输直达或 L4 透传。证书续期先验证新证书，再 `nginx -t && nginx -s reload`；不要把 HTTP 管理入口直接暴露不可信网络。若不使用 nginx，也可给 Master 配只读证书并使用 `-scheme https -cert-file /config/cert.pem -key-file /config/key.pem`；内置 Server 验证 Master 身份时根据证书配置 `-control-server-name`，私有 CA 再设置 `-control-ca`。

## 4. 限制访问后完成首次注册、配置节点与映射

Master **不会自动创建账号**；在可信网络或已限制来源的反代入口打开 Web 完成首次注册。`GET /api/setup` 显示是否需要注册，`POST /api/register` 只允许无账号时创建唯一账号。TLS 本身不能防止抢注；不要开放未注册的管理页面给不可信来源。

在 Web 中配置 Server 的隧道、接入候选和本地监听地址/端口；创建 Client，直接选择 Server/Client 建立映射（Pool 1–32）。客户端隧道模板由 Server 自动派生，**Client 不维护本地隧道配置**。映射可指定一个启用的连接入口；选择“自动”才按服务端启用地址顺序切换。NAT 的客户端连接端口可与 Server 本地监听端口不同。只看节点列表的「配置是否最新」状态和最后上报时间，不把 Master 健康或心跳当成业务目标可达性。

## 5. 可选独立 Server：节点主机先准备，再运行

如使用 Master 内置 Server，可跳过本节。先在 Web 创建 Server 并获取节点 ID、接入令牌；节点主机须已完成步骤 1。主机目录先准备：

```sh
mkdir -p /opt/docker/veilink-server/config /opt/docker/veilink-server/data
chown 65532:65532 /opt/docker/veilink-server/config /opt/docker/veilink-server/data
chmod 700 /opt/docker/veilink-server/config /opt/docker/veilink-server/data
```

```sh
docker run -itd \
  --name veilink-server --restart unless-stopped --net host \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-server/config:/config:ro \
  -v /opt/docker/veilink-server/data:/data \
  veilink:latest server \
  -master-addr vl.vekt.cc.cd:8843 \
  -control-server-name vl.vekt.cc.cd \
  -node-id '<Server 节点 ID>' -enroll-token '<接入令牌>' \
  -state-dir /data/state
```

## 6. Client：节点主机先准备，再运行

先在 Web 创建 Client、建立映射并获取节点 ID、接入令牌；节点主机须已完成步骤 1。Client 只出站，保持默认 Bridge，**不加 `--net host` 或 `-p`**：

```sh
mkdir -p /opt/docker/veilink-client/config /opt/docker/veilink-client/data
chown 65532:65532 /opt/docker/veilink-client/config /opt/docker/veilink-client/data
chmod 700 /opt/docker/veilink-client/config /opt/docker/veilink-client/data
```

```sh
docker run -itd \
  --name veilink-client --restart unless-stopped \
  -e TZ=Asia/Shanghai \
  -v /opt/docker/veilink-client/config:/config:ro \
  -v /opt/docker/veilink-client/data:/data \
  veilink:latest client \
  -master-addr vl.vekt.cc.cd:8843 \
  -control-server-name vl.vekt.cc.cd \
  -node-id '<Client 节点 ID>' -enroll-token '<接入令牌>' \
  -state-dir /data/state
```

两种节点均可在 Web「快捷接入」填写 `https://vl.vekt.cc.cd:8843` 生成同类 Docker 命令；**不要同时运行生成命令和手工命令创建重复容器**。私有 Master CA 才将 CA 放入只读 `/config` 并追加 `-control-ca /config/master-ca.pem`，保持证书校验。可信内网也可直接 HTTP/h2c：填写 `http://节点可达地址:2545`，或手工把 `-master-addr` 改成该地址并省略 `-control-server-name` 和 `-control-ca`；HTTP 传输会暴露凭据，不能跨不可信网络。Client 容器里的 `127.0.0.1` 不是宿主机，映射目标须从容器网络可达。

接入令牌会出现在 shell 历史和 `docker inspect`。确认节点首次接入且 `/data/state` 已保存凭据后，**保留数据目录**，删除原节点容器并用不含 `-enroll-token` 的同参数命令重建，以清除 inspect 中的令牌；令牌也可在 Web 撤销。不要为了修复未上报或待应用删除数据库、key 或节点状态。如果节点显示「未上报」，检查节点容器日志、Master 地址、端口与 TLS/ALPN；「最新」只代表认证上报的期望配置已应用，不代表映射目标可达。节点状态列的刷新图标只发出请求，实际结果仍以节点上报为准。

## 7. 运维：备份、恢复、账号

停机备份 Master 的 `/data`（数据库、deployment key、内置节点 state 必须成套保存）；从**源码仓库目录**调用工具，备份目标必须为新目录：

```sh
docker stop veilink-master
mkdir -p /opt/docker/veilink-master/backups
tools/backup-master.sh backup master \
  /opt/docker/veilink-master/data \
  /opt/docker/veilink-master/backups/$(date +%Y%m%d-%H%M%S)
docker start veilink-master
```

恢复前先验证备份 `manifest.json`，并恢复到**新的空目录**，不要覆盖生产目录：

```sh
tools/backup-master.sh restore master \
  /opt/docker/veilink-master/backups/<timestamp> \
  /opt/docker/veilink-master/recovery-data
```

先在隔离环境验证登录、节点身份、心跳和业务探针，再切换正式实例；禁止旧、新 Master 同时提供写服务。备份包含凭据，须限制读取权限并加密存放。独立节点数据可用 `tools/backup-master.sh backup node <节点data目录> <新备份目录>` 备份。

仅重置**已有**账号（不会创建管理员；成功后旧会话失效）：

```sh
docker exec -i veilink-master /usr/local/bin/veilink reset-admin-username -username new-admin
docker exec -i veilink-master /usr/local/bin/veilink reset-admin-password -password-stdin < /opt/docker/veilink-master/config/admin-password.txt
```

改名不改密码；改密须从权限 `0600` 的文件经 stdin 读取 12–72 字节密码，不要把密码放在命令参数或日志里。无管理员时只能通过受限访问的 Web 首次注册。

## 边界与许可证

只转发授权映射，不是开放代理。支持原生私有 VLESS、Hysteria2、TCP mux、XUDP 等；Server 证书/私钥由 Web 保存，不通过节点 flags 下发私钥。XHTTP `packet-up` 是业务通道，和上文 Master 的 gRPC/h2c **不是同一个反代路径**；业务 HTTP 回源须按安全模式启用 VLESS Encryption，不承诺通用 CDN/Xray 互通。旧字段与旧数据库 schema 不自动迁移或删除，处理已有用户数据前先备份并获得删除授权。真实多主机 WAN/NAT、24–72 小时长稳、生产 CA 生命周期和供应链签名仍须目标环境验收。历史实验记录在 `tests/`，不代表当前版本已完成生产认证。

源码与文档适用 [GPL-3.0-or-later](LICENSE)；第三方组件的许可与分发声明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。项目约束见 [AGENTS.md](AGENTS.md)。
