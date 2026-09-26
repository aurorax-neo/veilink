# 自动派生客户端配置与只读弹窗验收

## 当前变更

- 服务端本地绑定使用「监听地址（IP）」「监听端口」；Client 拨号候选使用「主机/域名」「端口」。客户端配置仅从服务端自动派生，不允许独立编辑或提交 `client_tunnel`。
- 客户端列表默认不展开配置 JSON，点击节点名称也只展示轻量详情；必须点击「查看配置」才能打开只读 Modal。弹窗明确区分期望配置与节点实际应用版本。
- 本次提交包含 Modal、回归测试、本记录、15 张新截图及已授权删除的 `mux-address-*.png`。其他历史截图、性能资料、tsbuildinfo 等不纳入本任务。

## 本次实际执行（2026-09-27）

### 隔离浏览器与真实节点

- 当前源码构建统一二进制，在 session scratch 内使用独立 SQLite、deployment key、状态目录和前端产物；没有使用或修改用户数据库。
- Brave + Playwright，无 API mock，HTTP Master `127.0.0.1:19843`。真实浏览器完成首次注册、登录、TLS 服务端创建/证书生成、客户端创建、关联映射创建。
- 服务端本地监听 `127.0.0.1:29443`，客户端连接地址 `localhost:29443`；断言两组标签不同，TLS 保持证书验证。
- 同一二进制以 `master`、外部 `server`、外部 `client` 启动。通过带 Cookie/CSRF 的真实 API 获取一次性接入令牌，节点成功接入；令牌未写入报告或截图。
- TCP 映射 `127.0.0.1:29080 → 127.0.0.1:29081`：关闭、smux、yamux、h2mux 均实际传输并完整回显，分别校验 15360、16384、17408、17408 字节。
- UDP 映射 `127.0.0.1:29083 → 127.0.0.1:29082`：真实 XUDP 回显 `real-udp-echo` 成功。
- 每次映射更新等待外部 Server/Client 应用修订收敛。数据面检查结束时两者均为 `desired_revision=10`、`applied_revision=10`、错误为空；再观察 12 秒，两者 `last_seen` 均推进。后续浏览器 mux 保存继续产生新修订，不应把截图修订号限定为 r10。
- 客户端列表及名称详情没有可见 textarea；点击「查看配置」才打开 Modal。配置含派生 CA，不含服务端证书、私钥或 decryption 材料。
- 浏览器实际切换并保存 TCP 四种 mux，UDP 编辑时 mux 禁用且值为空；查看真实审计事件和日志，完成退出登录。
- 桌面视口 1440×1000、窄屏 390×844，DPR=2；对应 PNG 宽度 2880/780 像素。浏览器 pageerror 为 0。15 张 PNG 仓库与桌面副本逐文件 SHA-256 一致。

### 自动化与镜像

- `go test ./...`、`go vet ./...` 通过。
- `go test -race ./internal/store ./internal/httpapi ./internal/control ./internal/node ./internal/tunnel` 通过。
- `go test -tags integration -count=1 ./tests/integration` 通过（138.509 秒）；该套件使用真实 CLI 子进程。
- `cd frontend && node --test tests/*.mjs`：30/30 通过。`npm run build` 的 TypeScript 检查和 Vite 生产构建通过。
- `docker build -t veilink:modal-check .` 成功；本地镜像 ID 前缀 `cf984b029e54`。
- 同一镜像分别启动 master/server/client；三者 `/usr/local/html/index.html` 存在，健康脚本成功且 Docker 状态均为 `running healthy`。
- 三角色二进制 SHA-256 均为 `c93268636711d59870328e93b6e0c0147df9ce11e54e5a91e912c75683aea061`。
- 容器角色检查使用另一套隔离容器数据库及真实注册/接入；节点共享测试 Master 网络命名空间以规避 Colima 主机路由差异。该 smoke 检查不是生产网络拓扑验收，业务数据面以上述本机独立进程回显为证。
- `git diff --check` 通过。未 push、未远端 Actions、未发布、未部署。

## 心跳语义对照

- Veilink 节点 gRPC 心跳约 **10 秒**；Master 控制流等待超时 **45 秒**；Web/统计近期在线窗口 **90 秒**，吊销节点不计在线。
- 对照 `ref/frp-panel`：同样基于 RPC 更新 `last_seen`，但部分查询约 5 分钟、WireGuard `OfflineThreshold` 约 2 分钟，frp 另有 `heartbeatInterval`/`heartbeatTimeout` 字段。
- 因此不是 frp-panel 逐参数 1:1 对齐。本次真实心跳推进、修订收敛和回显检查未发现相关缺陷；仍必须分开理解“近期在线”“授权配置应用成功”和“业务数据面可达”。本次没有完整计时验证断网后所有 45/90 秒边界，边界自动化测试与实测范围不可混淆。

## 当前截图（全部 DPR=2）

仓库 `tests/web/screenshots/`，桌面 `~/Desktop/veilink-shots/`，同名副本：

1. `modal-4point-01-client-list-no-config.png` — 默认列表无 JSON。
2. `modal-4point-02-client-config-modal.png` — 显式打开只读配置。
3. `modal-4point-03-server-list.png` — 服务端监听/连接地址和在线修订。
4. `modal-4point-04-client-list-narrow.png` — 窄屏客户端列表。
5. `modal-4point-05-server-addresses.png` — 服务端本地监听与主机/域名输入分离。
6. `modal-4point-06-client-modal-narrow.png` — 窄屏只读弹窗。
7. `modal-4point-07-tcp-udp-mappings.png` — TCP/UDP 映射。
8. `modal-4point-08-mux-off.png` — mux 关闭。
9. `modal-4point-09-mux-smux.png` — smux。
10. `modal-4point-10-mux-yamux.png` — yamux。
11. `modal-4point-11-mux-h2mux.png` — h2mux。
12. `modal-4point-12-udp-mux-disabled.png` — UDP 禁用 mux。
13. `modal-4point-13-audit.png` — 真实审计事件。
14. `modal-4point-14-logs.png` — 真实日志。
15. `modal-4point-15-logout.png` — 退出后登录页。

旧 `mux-address-*.png` 已从两目录清理；其他 `auto-derived-*` / `post-*` 是历史证据，不代表当前 Modal。没有无差别清空截图目录或删除无关文件。

## 剩余生产验证缺口

- 本次为本机回环 TLS 数据面，未覆盖公网/NAT/多机网络、丢包、长稳、跨平台原生运行和生产容量。
- 未穷举 TLS、REALITY、VLESS Encryption、Vision、Hysteria2 与 TCP mux/UDP 的所有协议组合及恶意输入/并发/取消/重连场景；相关测试通过不等于全组合实地验证。
- 未实测生产 HTTPS 终止代理、h2c/gRPC 反代和 HTTPS 快捷接入链路；HTTP 首次注册仍必须限制在可信网络防抢占。
- 未验证远端 Actions/GHCR 权限、多架构远端构建、正式发布或部署。未重跑历史性能/HY2 benchmark。
- 截图通过实际浏览器 DOM 断言、像素尺寸和哈希验证，未进行逐像素人工审图。
- 一次性接入令牌可能残留在启动参数或 Docker inspect，生产接入后应保留状态并重建无令牌容器；本次临时进程/容器结束后清理。
