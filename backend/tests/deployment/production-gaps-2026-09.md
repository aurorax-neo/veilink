# 生产缺口复审与发布构建改进（2026-09）

> 历史审计快照：下文「尚未 push / 正式 release 需另行授权」仅表示当次审计尚未发布；v0.1.0 已发布。多机长稳、生产恢复演练及未关闭的供应链缺口不会因 Release 工作流成功而自动关闭。

基线 `1b366b3`。本轮是定向源码/部署审计，不是完整渗透测试或生产认证。
旧记录 `production-gaps-347.md` 和 `evidence/gaps347/` 保留，不把历史分钟级测试升级成生产承诺。
产品继续全 JSON：SQLite 配置正文、HTTP 对象、节点 Struct 快照及 UI 均未改变。

## 参考与实际检查范围

- frp-panel：`idl/common.proto` 的 Server 地址字段与 `idl/rpc_master.proto` 的身份认证配置拉取。Veilink 连接地址继续表示 Client 拨号候选，与本地监听分离，不引入自创 NAT 协议。
- Xray：`core/core.go` 的 Version/构建身份分离及 dirty 标记。借鉴身份分离，不复制实现，也不把自报身份当签名证明。
- mihomo：`docs/config.yaml:480–488` 的 mux 默认关闭与 smux/yamux/h2mux；`.github/workflows/build.yml` 显式平台/工具链构建。参考命名和发布实践，不采用其 YAML 配置。
- 本项目：Dockerfile、手动开发 workflow、部署契约测试、README Docker/nginx 接入、healthcheck、CLI 帮助、verify-node 工具和现有协议/soak 证据。

## 本轮落地：收窄构建环境漂移并补齐镜像身份元数据

原 Dockerfile 使用 `golang:alpine`、`node:alpine`，可随最新大版本变化。现改为
`golang:1.27-alpine3.23`、`node:22-alpine3.23`，Node 与工作流检查阶段对齐。
最终产物仍是同一个 `alpine:3.23` 统一镜像、同一个角色可选二进制。

新增 OCI title/description/version/revision/source 标签；VERSION/COMMIT 与二进制使用相同构建参数。
SOURCE_URL 表示源码仓库，revision 表示提交。手动 workflow 同步传参，保留默认不推送、仅显式可选草稿行为。
契约测试锁定版本系列、OCI 标签、source 参数、非 root 数据权限及原有健康检查命令。

**关闭范围有限**：这些 tag 仍可变，只限制版本系列漂移，不是 digest 锁定、可复现构建、provenance 证明或签名。
标签由构建者提供；脏工作区加旧 COMMIT 不会自动变成可信的精确提交产物。

## 更新后的开放清单与关闭条件

### P0：目标环境验收门槛

1. **真实多机 24–72h 长稳**：跨机 WAN 丢包/抖动/MTU、断网重连、节点/控制面重启、修订漂移、业务与资源曲线尚无证据。关闭需目标环境连续日志、业务成功率/延迟、资源趋势及恢复记录。Docker Bridge 不能替代。
2. **备份恢复与授权恢复（本机路径已落地，目标环境仍开放）**：新增 `tools/backup-master.sh`，停机收集 SQLite、deployment key 和持久化目录，生成完整文件树 SHA-256 manifest；恢复拒绝异常输入并写入新目录。README 提供停机备份、隔离恢复及恢复验收步骤；部署烟雾验证真实 Master 管理员、节点身份和 credential 可恢复。仍未在生产数据、独立备份介质和真实节点上演练；目标环境须确认加密/保留、RPO/RTO 和节点/管理员授权恢复。
3. **生产 HTTPS/反代运维（本机演练通过，目标 CA 生命周期仍开放）**：README 有 nginx HTTPS→HTTP/h2c 接入、权限、证书更新、`nginx -t`/reload 和验收步骤；本机 `proxy_check.py` 验证错误证书拒绝、候选配置验证失败时旧服务仍工作、更新证书 reload、Cookie/Origin/CSRF 和节点 h2c 重连。尚未验证生产 CA 自动续期/监控、访问控制和首次注册防抢占目标环境演练。首次注册本身仍是“无管理员时一次性开放”，必须先用防火墙/私网/反代访问策略限制可信来源；TLS、Origin 和 CSRF 不提供网络隔离，也不能阻止同一入口上的抢注。
4. **发布供应链**：digest 锁定、SBOM、漏洞扫描、Actions SHA 锁定、签名/provenance、可信摘要来源及发布审批未完成。verify-node 仅受信运维通道的时点对账；OCI 标签也不是签名。正式 release/push 必须另行授权。

### P1：协议、公网和容量覆盖

5. **协议矩阵（部分加密交叉已本机实测，整体仍开放）**：`TestProtocolMatrixRoundTrip` 当前 70 格，其中 TLS/REALITY 的 Encryption+Vision ×（smux/yamux/h2mux+UDP）8 个交叉已实测。另有 `TestEncryptionModesAndResumption` 对 native/xorpub/random × X25519/ML-KEM/chain 共 9 格，逐格验证首连发 ticket、次连实际恢复；普通及 race×10 通过。仍开放 random × chain 语义以外的额外密钥组合、票据过期/并发重放容量与完整映射业务笛卡尔积、padding 边界、IPv6/大 UDP/恶意输入及公网路径；本机握手测试不代表互通认证或公网覆盖。
6. **公网拨号候选/NAT**：本地配置已区分候选地址和监听，但真实公网端口转发、UDP NAT 超时、双栈、候选切换、L4 透传路径尚无证据。关闭需受控公网测试与每种路径证据；不把 Docker Bridge/loopback 当作替代。
7. **性能复测/容量（新增单轮本机冒烟，不足以关闭）**：受限 `TLS-xorpub-mlkem-1rtt` loopback 单轮 smoke 有固定 4 MiB TCP/本地 UDP 样本，记录见本轮验证。不是重复统计、饱和连接、CPU/内存曲线、容量拐点或 WAN 基准。完整项目仍需固定机器/版本/负载、多轮对照、并发和资源上限；不把本机数据外推公网。
8. **监控与审计运维**：已有健康端点、内存日志 ring、认证 API 审计和心跳/修订展示；但没有外部业务探针、告警阈值与投递、审计持久化/留存、磁盘耗尽演练。心跳不是业务可达性。关闭需实际告警/留存演练；HTTP `429` 限速当前是单 Master 共享窗口，尚无按客户端分桶或反代级节流，本轮没有改写认证实现。

### P2：安装与 UX 待办

9. **帮助命令退出码（已修复，CLI help 专项收口）**：原三角色 `--help` 显示帮助却返回 `flag: help requested`、退出 1。现顶层 `--help` / `-h` / `help`，以及 8 个子命令的 `--help` / `-h` / `help` 和 `help <command>` 均正常显示帮助、退出 0；仅实际 `flag.ErrHelp` 视为成功，帮助前的非法参数不被掩盖。`internal/cli/help_test.go` 覆盖 35 种成功形式、13 种非法调用，并构建真实二进制校验退出码；同时检查帮助不读取 stdin、不生成密钥、不创建数据库，非法 reset 密码参数不回显秘密。专项实际执行 `go test ./internal/cli ./internal/config -count=1`、对应两包 `go test -race ... -count=1`、`go vet ./internal/cli ./internal/config` 与 `git diff --check`，均通过。本次只收口 CLI help，不改变 xhttp 或其它生产缺口结论。
10. **跨平台/浏览器矩阵**：交叉编译不等于原生运行；现有窄屏/状态测试不等于生产浏览器完整兼容。关闭需对应系统/浏览器验收。批量操作和更细错误提示按使用场景评估，不冒充安全阻塞。

## 本轮实际验证

- `go test ./internal/tunnel -run '^TestProtocolMatrixRoundTrip$' -count=1 -timeout=10m`：70/70 组合通过，130.158 秒；包含新增 8 个 Encryption+Vision 交叉。
- `tests/deployment/protocol-matrix.md` 已同步 70 组合分组和剩余覆盖边界。
- `cd backend && go test -race ./internal/tunnel -run '^TestEncryptionModesAndResumption$' -count=10 -timeout=5m`：9 格各两次连接的真实 ticket resume 通过，10 次 race 重跑通过。
- `go test ./internal/tunnel -run '^TestEncryptionModesAndResumption$' -count=1 -v -timeout=5m`：native/xorpub/random × X25519/ML-KEM/chain，9/9 通过；首连签发 ticket，次连确认 resumed。
- `VEILINK_PERF=1 VEILINK_PERF_CASE=TLS-xorpub-mlkem-1rtt VEILINK_PERF_ROUNDS=1 VEILINK_PERF_BLOCKS=64 go test ./internal/tunnel -run '^TestLocalPerformance$' -count=1 -v -timeout=5m`：macOS arm64 Go 1.27 loopback 单轮通过；4 MiB TCP 311.790 MiB/s、p50/p95 102/118 us；UDP 73.213 MiB/s、p50/p95 64/74 us。仅 smoke，不是容量或公网指标。
- 首次注册/限速/Origin/CSRF 现有回归见 `internal/httpapi/registration_test.go`、`http_test.go`；本轮未修改认证实现。可信网络/防抢占边界已在 P0-3 说明。
- `cd backend && go test -tags=integration ./tests/integration -count=1`：通过，138.858 秒。
- `cd web && node --test tests/*.mjs && npm run build`：34/34，通过 TypeScript/Vite 构建。
- 统一镜像 `veilink:gaps-audit` 构建通过，ID `de98426df409`；该镜像为历史本机审计产物，不是本次最终提交身份。
- 历史 `veilink:gaps-audit` soak：266.8 秒通过，三角色 healthy、静态资源存在、二进制摘要一致，cleanup_remaining 为空。
- actionlint 不在 PATH，本轮未运行；未运行远端 Actions、未 push、未部署。

### 本轮新增验证

- 备份专项 Go smoke 与 race 通过：真实 Master 管理员、节点稳定 ID/credential、nested state、node-only 和 fail-closed 校验。
- 本机 `proxy_check.py` 证书更新验收通过：坏候选拒绝、证书 reload、新 serial 验证、节点 h2c 重连及 TLS/Origin/CSRF，资源清理完成；使用既有镜像，不代表公网/生产 CA 验证。
- `cd backend && go test ./... -count=1`、`cd backend && go vet ./...`、`git diff --check` 通过；integration 138.793 秒、前端 34/34 和 `veilink:p0-check` 本地镜像构建通过。
结论：本轮完成本机可复跑子项，P0/P1 整体仍开放；不宣称无条件生产就绪。优先继续真实多机长稳、目标环境备份恢复与 CA/反代演练，再补供应链和容量覆盖。
