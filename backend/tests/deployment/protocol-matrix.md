# 原生隧道协议矩阵

范围：Veilink 私有 VLESS / Hysteria2 reverse session / mux / XUDP，真实本机 Server → 反向 Client → echo 目标往返；不嵌入 Xray，不是 mihomo/Xray 互通测试，也不是原生 Hysteria2 datagram 互通测试。

## 合法配置

下表每行包含 TCP 的四个独立组合和 UDP 的一个组合，共 **20 个基础组合**。`off` 仅表示 `mux=false`，不是新增协议名称。TCP mux 开启时空 `mux_type` 默认 `smux`；UDP 不能开启 TCP mux。

| 外层传输 / 安全 | TCP 业务 mux | UDP 业务 mux | Encryption | Vision |
| --- | --- | --- | --- | --- |
| TCP + TLS | off / smux / yamux / h2mux | off（XUDP） | 可选 | 可选 |
| TCP + REALITY | off / smux / yamux / h2mux | off（XUDP） | 可选 | 可选 |
| TCP + plain + Encryption | off / smux / yamux / h2mux | off（XUDP） | 必须 | 禁止 |
| Hysteria2（QUIC + TLS，独立协议） | off / smux / yamux / h2mux | off（XUDP） | 禁止 VLESS Encryption | 禁止 |

Hysteria2 的外层使用 UDP/QUIC；表中的 TCP/UDP 指业务映射，不是外层 socket。UDP 业务使用本项目 XUDP，不代表原生 Hysteria2 datagram 互通。Vision 是网关 flow 设置，TLS/REALITY 上可以存在 UDP 映射，但不对 UDP 启用 Vision 直拷。

约束来源：`internal/tunnel/validate.go:52`、`reality.go:34`（CheckBootstrap）、`transport.go:11`、`hysteria.go:24`、`encryption.go:52`、`internal/model/mux.go:13`。

- TLS 需要有效配对证书/私钥，Client 校验证书及名称；REALITY 使用对应公私钥、short ID、server name，不能同时提供数据面证书 PEM 或 Hysteria2。
- Hysteria2 必须有证书/私钥及服务器密码，不能与 plain、VLESS Encryption、REALITY、XHTTP 或 Vision 组合。其标准 HTTP/3 `/auth` 使用授权 Binding UUID 作为每绑定凭据；后续 TCP 请求目标必须匹配同一 binding 域名和会话端口。
- `tunnel.protocol` 明确为 `vless` 或 `hysteria2`；空值仅为旧 JSON 的兼容默认。显式协议与不适用字段组合必须拒绝，不自动迁移或清理。
- VLESS 的 `flow` 使用 `xtls-rprx-vision`（现有校验还将 `xtls-rprx-vision-udp443` 归一化到该 flow）；只允许 TCP+TLS/REALITY 外层。开启 mux 的 TCP 仍可配置 flow，但不会把 mux/控制/UDP 裸传。
- Vision 直拷仅限独立已认证连接、可安全识别的内层 TLS 1.3 和正确记录边界。Encryption + Vision 合法，但保留加密回退；普通 echo 成功不证明发生直拷。
- 映射 pool 仍为 1–32，必须匹配授权 binding/目标/业务网络；本测试不修改或绕过生产校验。

## 名称对照（仅名称，不承诺线协议兼容）

- `ref/mihomo/listener/inbound/mux_test.go:12` 已有 `h2mux`、`smux`、`yamux`；`ref/mihomo/docs/config.yaml:482` 同样列出三者。
- `ref/mihomo/transport/vless/vless.go:15` 使用 `xtls-rprx-vision`；`ref/mihomo/adapter/outbound/vless.go:71` 使用 `encryption`。
- `ref/mihomo/adapter/outbound/hysteria2.go:39` 为 `Hysteria2Option`。这里沿用 Hysteria2、REALITY、TLS、VLESS、XUDP 现有名称，不引入新协议名，不复制 ref 实现。

## 新增实际覆盖

`internal/tunnel/protocol_matrix_test.go:13` 的 `TestProtocolMatrixRoundTrip` 当前共 **75 个往返组合**（原有分组 + XHTTP + XHTTP/REALITY）：

| 配置分组 | 组合数 |
| --- | ---: |
| 四种外层基础配置 ×（TCP 四种 mux + UDP off） | 20 |
| VLESS TLS / REALITY 各增加 Encryption × 五种业务模式 | 10 |
| TLS / REALITY 各增加 Vision、无 Encryption × 五种业务模式 | 10 |
| TLS / REALITY 各增加 Encryption + Vision，仅 TCP off | 2 |
| TLS / REALITY 各增加 Encryption + Vision，补齐 TCP smux/yamux/h2mux 与 UDP off | 8 |
| XHTTP HTTPS / HTTPS+Encryption / HTTP+Encryption × 五种业务模式 | 15 |
| XHTTP + REALITY（关闭 XHTTP TLS）/ Encryption × 五种业务模式 | 10 |

复用 `tlsFiles`、`fixtures`、`run`、`awaitEcho`、`awaitUDPEcho`、`exchange`、`exchangeUDP`、`camouflage`。每个组合在 ready 往返后使用三个并发业务连接：TCP 每连接 64 KiB 二进制内容并 CloseWrite，UDP 每 peer 1 KiB 数据报，逐字节校验。通过 `PublicPeerTunnel` 生成授权模板并检查服务端秘密没有泄漏；实际授权快照同时携带协议模板和 Binding UUID，HY2 仅将 UUID 作为标准 `Hysteria-Auth` password。

XHTTP + REALITY 覆盖 TCP → REALITY → Veilink 原生 XHTTP；`auto` 的模式选择按 Xray 规则：无下行端点为 `stream-one`，配置下行端点为 `stream-up`。XHTTP TLS 关闭，Encryption 作为可选内层 VLESS 保护；当前矩阵仍是 Veilink 双端测试，不是 Xray 对端互通证据。

有限覆盖：Encryption 只使用 `GenerateVLESSEnc` 的 X25519、native、600s 默认配置及派生 Client 模板，不穷举 ML-KEM、xorpub/random、1rtt/0rtt、padding、票据恢复。新增测试不验证内层 TLS 1.3 直拷标志、不穷举 pool/IPv6/大 UDP/故障恢复/恶意输入/取消时序；已有专门测试不能等同于这些维度的完整笛卡尔积。

## 本次执行结果

- 本轮矩阵覆盖 75/75 组合；标准 Hysteria2 认证使用每绑定 UUID 作为 `Hysteria-Auth` password，不经过 VLESS Encryption 或 VLESS 请求头。`TestHysteriaNativeSessionAuthorization` 额外覆盖共享服务器密码、跨绑定凭据、跨绑定目标、错误凭据、非法目标和 forward-proxy 拒绝；`TestHysteriaGracefulCleanupBounded` 继续覆盖对端结束、运行取消、超时释放路径。

## XHTTP 扩展

XHTTP 的 15 个组合使用 HTTP/1.1 packet-up。每组同样执行 3 个并发 peer，TCP 每 peer 64 KiB 加 CloseWrite，UDP 每 peer 1 KiB；保持 off/smux/yamux/h2mux 与授权 XUDP，不新增公开绑定管理。HTTPS 和 HTTP 分别验证对应监听；CDN TLS 终止/HTTP 回源另由 `internal/tunnel/xhttp_test.go` 的反向代理用例覆盖。

XHTTP 不支持 Vision/Hysteria2 叠加；可使用 REALITY + TCP + XHTTP，此时关闭 XHTTP TLS。普通 HTTP XHTTP 仍强制 VLESS Encryption。XHTTP 的 Xray 黑盒互通测试尚未纳入本矩阵。上文执行结果为历史记录，本次执行结果见 [xhttp.md](xhttp.md)。

## 尚未完成的验收

当前 HY2 已完成绑定级身份隔离的本地覆盖：服务端只接受授权 Binding UUID 对应的标准 `Hysteria-Auth` password，并要求后续目标属于同一 Binding；跨绑定凭据复用、跨绑定目标、错误凭据测试已通过。统一镜像构建及三角色实际启动/健康检查、WAN/NAT、恢复、监控和供应链等生产验收仍未完成。

## CI 失败排查记录（2026-10-31）

关联排查记录：`01a1863b-21b0-7d20-8e42-75a8bcec0c95`。GitHub Actions Run `41191422964` 在 `Go checks` 阶段失败，前端阶段未开始。初始冷运行在连续执行协议矩阵后，REALITY/XHTTP 组合出现连接建立或 UDP 回包等待；单独执行同一子用例可以通过，说明问题发生在子测试之间的资源生命周期累积，而不是该协议组合的固定功能错误。

根因是 `realityListener` 包装底层 TCP listener 后，服务停止路径只关闭了内部 listener，没有把包装 listener 纳入 `service.listeners`；在途 REALITY 握手协程也没有等待关闭完成。前一个子测试的握手和 cover 连接因此可能跨越到下一个子测试，最终表现为矩阵测试卡在 `awaitEcho`/`awaitUDPEcho`，并触发 Actions 的 Go 检查超时。

本次修复：

- `backend/internal/tunnel/tunnel.go`：创建 REALITY 包装 listener 后，用包装对象替换服务关闭列表中的内部 listener，确保 `Runtime.Close` 能取消 REALITY 上下文并关闭包装层。
- `backend/internal/tunnel/reality_listener.go`：为 listener 主循环和每个握手协程增加等待组；关闭时取消上下文、关闭底层 listener，并等待所有在途握手退出，避免资源泄漏到后续测试。

复现与修复后的结果：

- `go test ./internal/tunnel -run '^TestProtocolMatrixRoundTrip$' -count=1 -v -timeout=6m`：75/75 组合通过，用时 179.93 秒。
- `go test ./internal/tunnel -run '^TestXHTTPCombinationMatrix$' -count=1 -v -timeout=6m`：350/350 组合通过，用时 104.133 秒。
- `go test -race ./internal/tunnel -run '^TestRealityListener' -count=1 -timeout=2m`：通过，无 race 报告。
- `go test ./... -count=1 -timeout=12m`：全部通过，用时 464.779 秒。

后续提交 `53c1f35` 的复跑 Run `41194907219` 已证明还存在流水线层面的独立限制：完整 `Go checks` 步骤在 4 分 58 秒被 Actions 的 5 分钟步骤上限终止，命令自己的 `-timeout=15m` 无法覆盖平台步骤上限。为此，`.github/workflows/ci.yml` 和 `development-artifacts.yml` 已将普通包、隧道回归、75 项协议矩阵、350 项 XHTTP 矩阵、vet、race、集成测试拆成独立步骤；每个步骤都保留 5 分钟内的明确测试超时，避免长矩阵拖死同一流水线步骤。

该事件包含两个独立修复：产品运行时的 REALITY listener 关闭生命周期，以及 CI 长测试步骤的拆分。后续若新增传输包装 listener，必须同时纳入 `service.listeners` 的关闭路径，并为在途握手或后台协程提供可等待的退出信号。

### 第二次 CI 失败（Run `41195758727`）

提交 `3af0b06` 将长隧道测试拆步后，新的 `Go package tests` 仍失败。GitHub API 只返回退出码 `1`，没有提供公开步骤日志；按相同命令在本地复现后，失败点落在 `internal/master` 的 `TestEmbeddedServerLifecycleAndRegistration`：

- 测试把映射监听端口固定为 `127.0.0.1:10080`，多个 Go 包测试进程并行运行或宿主机已有服务时会发生 `bind: address already in use`。
- 测试原先只 `cancel()`，断言失败时没有等待 `Run` 返回，后台 Master/embedded server 可能继续占用监听端口并污染后续测试。
- 端口冲突后，运行时恢复了旧 revision，但嵌入式服务没有在测试等待窗口内重新监听，最终表现为 `embedded server is not listening`。

本次修复：

- `backend/internal/master/embedded_test.go`：映射端口改为每次动态分配；增加幂等的 `stop` 清理函数，在正常结束和任何断言失败路径都等待 Master 及 embedded server 完整退出；禁用 embedded server 的生命周期测试同步采用该清理方式。
- `.github/workflows/ci.yml`、`.github/workflows/development-artifacts.yml`：普通包测试使用 `go test -p 1 -count=1`，避免端口型包测试并行争用并关闭测试缓存。
- `backend/tests/deployment/workflow_test.go`：更新工作流契约，锁定串行、无缓存的普通包测试命令。

修复后的验证：

- `go test -p 1 -count=1 $(go list ./... | grep -v '^veilink/internal/tunnel$') -timeout=5m`：通过，用时约 35 秒。
- `go test ./internal/master -run '^TestEmbeddedServer(LifecycleAndRegistration|Disabled)$' -count=3 -timeout=3m`：3 次全部通过。
- `go test ./... -count=1 -timeout=12m`：全部通过，隧道包用时 476.748 秒。
- `go vet ./...`、目标包 race 测试、集成测试：全部通过。
- 前端 116 项 Node 测试、`npm run typecheck`、`npm run build`：全部通过。

### 第三次 CI 失败（Run `41197965538`）

逐包诊断后，失败包和错误已由 GitHub 检查注释确认：

```text
veilink/tests/deployment: required project path "ref":
stat /home/runner/work/veilink/veilink/ref: no such file or directory
```

`ref/` 是 `.gitignore` 明确排除的本地参考源码目录，不属于构建或测试所需的版本库制品；本地工作区存在该目录掩盖了契约测试错误，GitHub checkout 没有它才暴露问题。修复为从 `TestProjectLayout` 的 CI 必需路径中移除 `ref`，保留报告和文档中的参考路径说明。普通包工作流继续逐包运行，并在失败时输出包名和错误摘要，后续同类问题可直接定位。
