# 缺口 3 / 4 / 7 验收（2026-09-27）

## 3：跨容器稳定性与故障恢复

新增 `tests/deployment/soak.py`。独立内部 Docker 网络、四个独立网络命名空间：Master、Server、Client、HTTP 目标。无生产挂载、无 Compose，不共享主机/容器网络。隔离 Bridge 仅为测试模拟多机，不替代 README 的生产 Host 网络要求。

复跑（Python 3、Docker、已构建统一镜像与 node:alpine；输出目录必须不存在）：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/deployment/soak.py \
  --image veilink:gaps347 --duration 1800 --output "$PI_SCRATCH_DIR/soak-new-run"
```

`--duration` 为故障恢复之后的稳态秒数，默认 1800，可设置 86400。流程：认证注册/接入 → 实际 HTTP 业务 → Client 断网 100 秒 → 心跳超过 90 秒、业务失败 → 离线修改 pool，验证期望/已应用漂移 → 重新联网收敛 → Client/Server/Master 分别重启，等待新心跳而非仅读取旧缓存 → 四种 mux 与 pool 滚动 → 每 5 秒业务/心跳采样 → 三角色内容/健康检查 → 自动清理。SIGTERM/异常进入 finally，不能处理 SIGKILL 或 daemon 不可用时的清理。

本次结果：
- `evidence/gaps347/soak-600s.json`：修复前基线镜像 `veilink:version-ui`，故障注入加稳态总计 **735.22 秒**；稳态请求 600 秒，12 次滚动、72 次业务采样通过。100 秒断网确实导致心跳过期、业务不可用，离线出现期望 r4 / 已应用 r3，恢复约 16.53 秒后收敛。此轮早期重启判据仍可能读到旧心跳，不能单独证明重启后新心跳。
- 随后加强重启判据；`evidence/gaps347/soak-final-image.json` 使用最终镜像 `veilink:gaps347`，总计 **256.78 秒**，包含同样 100 秒断网、三角色重启后新心跳、配置/业务恢复，2 次滚动、12 次稳态业务采样通过。
- 最终三角色均 healthy，Web 产物存在，二进制 SHA-256 均 `3bc3e90ad3445e4ded4c7ba23d6e1df038474423f869c96c0c3cb6a757eaf479`。
- `cancel-cleanup.json` 是预期失败：主动 SIGTERM 返回 interrupted，资源剩余为空。所有成功运行也记录 cleanup_remaining 为空。
- 首轮目标 busybox 没有 httpd，造成业务探测失败；已改用 node:alpine 固定 HTTP 目标。失败不是隧道产品缺陷，原始日志保留 scratch。

限制：单宿主 Docker 隔离网络，不是真实跨主机/WAN；没有模拟随机丢包、延迟、磁盘故障和数天运行。分钟级证据不能替代目标环境 24–72 小时长稳，工具已支持延长运行。

## 4：合法协议矩阵与 nginx TLS/h2c

矩阵详见 [protocol-matrix.md](protocol-matrix.md)，使用现有 TLS、REALITY、plain+Encryption、Hysteria2、smux/yamux/h2mux、XUDP、Vision 名称。新增 **47 个组合**，每组合 3 个并发连接：TCP 64 KiB 并半关闭，UDP 1 KiB；私钥不进入 Client 模板。

矩阵发现并修复 Hysteria2 TCP mux-off 半关闭截断：QUIC 包装器缺少 CloseWrite，正常结束又立即关闭整个 QUIC 连接，响应排队数据被丢弃。增加流级 FIN，正常读 EOF 后等待反向服务端消费响应 FIN 后关连接；等待由运行取消与空闲超时限制，不新增协议确认帧。原失败组合 30 次重复通过；完整矩阵连续两轮通过，附加清理测试覆盖对端结束、取消、超时。

新增 `tests/deployment/proxy_check.py`，实际 nginx TLS 终止 → 后端 HTTP API / grpc_pass h2c。使用独立短期 CA，校验证书，不用 insecure。复跑：

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tests/deployment/proxy_check.py \
  --image veilink:gaps347 --nginx-image nginx:alpine \
  --output "$PI_SCRATCH_DIR/proxy-new-run"
```

`evidence/gaps347/nginx-h2c.json`：最终镜像通过 nginx -t、受信 TLS、不受信 CA 拒绝、Web/API、注册登录、Secure/HttpOnly/SameSite Cookie、外站 Origin 拒绝、无 CSRF 拒绝；实际调用 `/nodes/{id}/join`，从快捷接入结果提取角色 flags 启动独立节点（仅容器名/挂载/网络改为隔离测试设施，私有 CA 按提示追加）。Server/Client 经 nginx 完成注册、Pull、双向 Events 心跳并应用 r2；12 秒后两者心跳均推进。所有资源清理完成。

nginx 配置沿用 README 精确同站 Origin 转换，不清空外站 Origin，不让 Master 盲信 X-Forwarded-Proto。nginx 是 TLS 终止组件，Master 保持 HTTP 默认。初次 CA 为 0600 导致非 root curl 无法读取，仅将公开 CA 改 0644；私钥保持受限。

## 7：版本验真最小方案

参考 frp-panel 的 Version/GitCommit 分离，以及 mihomo 发布 checksums.txt 的常见校验和做法；不自制签名协议。新增 `tools/verify-node.py`：

1. 操作者从**独立可信的发布产物/镜像**提取对应平台二进制，取得 SHA-256、Version、Commit；不能拿待验节点输出充当基准。现有归档 SHA256SUMS 是归档摘要，不能直接当二进制摘要；先校验归档，再对解包二进制求摘要。生产需信任来源、签名或独立校验渠道，本轮不建立签名发布基础设施。
2. 通过可信 Docker 管理通道读取 PID 1 实际 `/proc/1/exe` 字节，在核验机计算摘要；PID 1 node-id/角色绑定管理 API 中的节点。
3. 对账实际文件 `version` 输出、节点认证 API 上报、受信期望值；Master `/api/version` 独立记录，不强迫节点与 Master 同版本。
4. 核验前后检查 PID 启动标识、参数和文件摘要一致。任何不匹配退出 1；无法验证退出 2；通过退出 0。报告不包含 Cookie、接入令牌或完整进程参数。

```sh
# session 文件仅包含已有 veilink_session Cookie 值，权限 0600；不要提交。
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify-node.py \
  --container veilink-client --node-id NODE_ID \
  --expected-sha256 TRUSTED_BINARY_SHA256 --expected-version v1.2.3 \
  --expected-commit TRUSTED_COMMIT --master-url https://panel.example.com \
  --session-file /PRIVATE/session --output /PRIVATE/verification.json
```

私有 CA 可传 `--ca`。外部 API 要求 HTTPS，仅本机 loopback 可 HTTP。若运维机只可通过 Docker context 管理 Master，可加 `--master-container NAME --master-url http://127.0.0.1:8443`，只访问容器内 loopback，Cookie 经 stdin 而非 exec 参数发送。支持现有 DOCKER_HOST/context（如 SSH Docker context），不自动连接未知主机。

本次 `verify-pass.json`：受信基准来自独立本地镜像提取文件，真实 Bridge Client 的运行文件摘要、版本/提交/API/PID 绑定全部通过。`verify-reject.json`：版本/commit 都一致但期望摘要改为全零，明确 verified=false，退出 1。4 项 Python 单元测试覆盖错摘要、错节点、伪报版本/提交、吊销、缺报。

环境限制：Colima 的 host.docker.internal 及 localhost 端口转发无法完成本机/容器互通，改用上述 Docker API 模式测通；未降低 TLS 校验。容器 root 缺少 ptrace capability 无法读取不同 UID 的 /proc/1/exe，使用镜像默认同 UID 即可，不加特权。

信任边界：必须信任 Docker daemon、宿主机和独立基准。这是运维通道的时点文件对账，不是硬件远程证明；不能抵抗已失陷宿主/容器内读取工具被恶意替换、运行内存补丁或事后换包。没有把节点自报哈希升级成“可信”。Web 明确显示“节点上报，未验真”，不持久化易过期的已验真徽标，具体结果以核验报告为证。

## 自动化与截图

- `cd backend && go test ./...`、`cd backend && go vet ./...`、tunnel/node/control/httpapi/store race 通过。
- 47 组合矩阵两轮和清理测试：196.993 秒；integration 无缓存：138.974 秒。
- 前端 32/32、TypeScript/Vite 生产构建通过；Python 4/4 通过。
- 最终统一镜像构建 ID `929bacdeeaaf`，三角色实际启动/健康/内容检查通过。镜像注入的是构建时 HEAD `eb2f241...`，包含本次未提交改动，不冒充最终提交产物。
- 两张 DPR=2 改动详情页：`tests/web/screenshots/gaps347-verification-desktop.png`、`gaps347-verification-narrow.png`；桌面副本在 `~/Desktop/veilink-shots/`，哈希一致。截图仅证明真实页面提示，不证明截图中的离线节点已验真；Docker 核验证据为上述 JSON。未做逐像素人工审图。
- 原始过程日志在本会话 `$PI_SCRATCH_DIR/gaps347/`；仓库 `evidence/gaps347/` 只保留无密钥/令牌的结果摘要。未 push、未部署、未远端 Actions。

## 剩余生产缺口

真实跨机 24–72 小时稳态与网络劣化、全部 Encryption/ML-KEM/票据模式及 8 个 Encryption+Vision 交叉、跨平台原生运行、生产 CA/反代运维、签名发布与供应链基准仍需目标环境验证。三项本轮均有可复跑产出，不将有限本地验收写成无条件生产承诺。
