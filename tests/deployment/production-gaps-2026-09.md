# 生产缺口复审与发布构建改进（2026-09）

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
2. **备份恢复与授权恢复**：已有管理员重置、会话吊销和凭据测试，但未有生产数据/key/节点状态成套备份恢复演练。关闭需隔离恢复副本、管理员/节点授权验证、明确 RPO/RTO；不允许自动删库或迁移旧 schema。
3. **生产 HTTPS/反代运维**：已有 nginx TLS/h2c 自动化证明；生产 CA、续期/reload、私钥权限、访问控制、首次注册防抢占未在目标环境演练。关闭需完整证书生命周期和安全回归。HTTP 在可信网络仍受支持，HTTPS 本身不能防抢占。
4. **发布供应链**：digest 锁定、SBOM、漏洞扫描、Actions SHA 锁定、签名/provenance、可信摘要来源及发布审批未完成。verify-node 仅受信运维通道的时点对账；OCI 标签也不是签名。正式 release/push 必须另行授权。

### P1：协议、公网和容量覆盖

5. **协议矩阵**：47 组合只覆盖有限 X25519/native 配置。8 个 Encryption+Vision 交叉、ML-KEM、xorpub/random、1rtt/0rtt、padding、票据恢复、IPv6、大 UDP、取消/恶意输入组合仍开放。关闭需扩展逐项矩阵与真实往返/race/取消结果；现有 HY2 半关闭修复不等于全部交叉通过。
6. **公网拨号候选/NAT**：本地配置已区分候选地址和监听，但真实公网端口转发、UDP NAT 超时、双栈、候选切换、L4 透传路径尚无证据。关闭需受控公网测试与每种路径证据。HTTP-only CDN 或终止业务 TLS 的代理不是支持路径，不把对称 NAT 打洞视为已实现功能。
7. **性能复测/容量**：未复测不同 mux/pool、TLS/REALITY/HY2、大 UDP、连接数/CPU/内存与 WAN 基准。用户已有 `tests/perf/` 未跟踪材料保持不动，本轮不作为新结论。关闭需固定机器/版本/负载、重复对照与容量上限。
8. **监控与审计运维**：心跳不等于业务可达性；当前日志/状态不替代外部业务探针、告警和审计留存。关闭需指标、阈值、留存/磁盘耗尽与告警演练；不把缺少批量 UI 功能直接列为阻止所有部署的缺陷。

### P2：安装与 UX 待办

9. **帮助命令退出码（已修复，CLI help 专项收口）**：原三角色 `--help` 显示帮助却返回 `flag: help requested`、退出 1。现顶层 `--help` / `-h` / `help`，以及 8 个子命令的 `--help` / `-h` / `help` 和 `help <command>` 均正常显示帮助、退出 0；仅实际 `flag.ErrHelp` 视为成功，帮助前的非法参数不被掩盖。`internal/cli/help_test.go` 覆盖 35 种成功形式、13 种非法调用，并构建真实二进制校验退出码；同时检查帮助不读取 stdin、不生成密钥、不创建数据库，非法 reset 密码参数不回显秘密。专项实际执行 `go test ./internal/cli ./internal/config -count=1`、对应两包 `go test -race ... -count=1`、`go vet ./internal/cli ./internal/config` 与 `git diff --check`，均通过。本次只收口 CLI help，不改变 xhttp 或其它生产缺口结论。
10. **跨平台/浏览器矩阵**：交叉编译不等于原生运行；现有窄屏/状态测试不等于生产浏览器完整兼容。关闭需对应系统/浏览器验收。批量操作和更细错误提示按使用场景评估，不冒充安全阻塞。

## 本轮实际验证

- `go test ./...`、`go vet ./...`：通过（部分使用 Go 缓存）。
- `go test -race ./tests/deployment ./internal/cli`：通过。
- `go test -tags=integration ./tests/integration -count=1`：通过，138.858 秒。
- `cd frontend && node --test tests/*.mjs && npm run build`：32/32，通过 TypeScript/Vite 构建。UI 无变更，不重复截图。
- 统一镜像 `veilink:gaps-audit` 构建通过，ID `de98426df409`；inspect 标签与二进制 version 对齐。
  构建参数为 VERSION=dev-audit、COMMIT=1b366b3 全 SHA、SOURCE_URL=local://veilink/该 SHA；包含本轮未提交构建改动，**不是最终提交的发布身份**。
- `PYTHONDONTWRITEBYTECODE=1 python3 tests/deployment/soak.py --image veilink:gaps-audit --duration 60 --output "$PI_SCRATCH_DIR/gaps-audit-soak"`：266.8 秒通过，100 秒断网、恢复、三角色重启后新心跳、两次 rollout、12 次业务采样；三角色 healthy、静态资源存在、二进制摘要一致：`3faac8b26106b9169651ffa6f819f082cbefb1062e7ec12c7f01ae111611a98c`，cleanup_remaining 为空。
- actionlint 不在 PATH 或已检查的 Go bin 路径，本轮未运行；工作流契约测试通过，未运行远端 Actions。
- 原始日志在会话 scratch 的 `gaps-audit-*`，无生产数据或密钥进入仓库；未 push、未部署、未创建盯梢任务。

结论：本轮关闭一个有限的发布构建缺口，**仍不宣称无条件生产就绪**。优先继续目标环境长稳、备份恢复与 CA/反代演练，然后补供应链与协议/性能覆盖。
