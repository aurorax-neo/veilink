# 原生隧道协议矩阵

范围：Veilink 私有 VLESS / mux / XUDP，真实本机 Server → 反向 Client → echo 目标往返；不嵌入 Xray，不是 mihomo/Xray 互通测试，也不是 Docker 部署验收。

## 合法配置

下表每行包含 TCP 的四个独立组合和 UDP 的一个组合，共 **20 个基础组合**。`off` 仅表示 `mux=false`，不是新增协议名称。TCP mux 开启时空 `mux_type` 默认 `smux`；UDP 不能开启 TCP mux。

| 外层传输 / 安全 | TCP 业务 mux | UDP 业务 mux | Encryption | Vision |
| --- | --- | --- | --- | --- |
| TCP + TLS | off / smux / yamux / h2mux | off（XUDP） | 可选 | 可选 |
| TCP + REALITY | off / smux / yamux / h2mux | off（XUDP） | 可选 | 可选 |
| TCP + plain + Encryption | off / smux / yamux / h2mux | off（XUDP） | 必须 | 禁止 |
| Hysteria2（QUIC + TLS） | off / smux / yamux / h2mux | off（XUDP） | 可选 | 禁止 |

Hysteria2 的外层使用 UDP/QUIC；表中的 TCP/UDP 指业务映射，不是外层 socket。UDP 业务使用本项目 XUDP，不代表原生 Hysteria2 datagram 互通。Vision 是网关 flow 设置，TLS/REALITY 上可以存在 UDP 映射，但不对 UDP 启用 Vision 直拷。

约束来源：`internal/tunnel/validate.go:52`、`reality.go:34`（CheckBootstrap）、`transport.go:11`、`hysteria.go:24`、`encryption.go:52`、`internal/model/mux.go:13`。

- TLS 需要有效配对证书/私钥，Client 校验证书及名称；REALITY 使用对应公私钥、short ID、server name，不能同时提供数据面证书 PEM 或 Hysteria2。
- Hysteria2 必须有证书/私钥及授权密码，不能与 plain 或 Vision 组合。TCP 非 REALITY 配置必须显式选择 `tls` 或 `plain`。
- plain 必须有有效 VLESS Encryption，不接受服务端 TLS 证书；Server 使用 `decryption`，Client 模板使用 `encryption`，两者不能同时设置。Client 不接受本地隧道覆盖。
- flow 使用 `xtls-rprx-vision`（现有校验还将 `xtls-rprx-vision-udp443` 归一化到该 flow）；只允许 TCP+TLS/REALITY 外层。开启 mux 的 TCP 仍可配置 flow，但不会把 mux/控制/UDP 裸传。
- Vision 直拷仅限独立已认证连接、可安全识别的内层 TLS 1.3 和正确记录边界。Encryption + Vision 合法，但保留加密回退；普通 echo 成功不证明发生直拷。
- 映射 pool 仍为 1–32，必须匹配授权 binding/目标/业务网络；本测试不修改或绕过生产校验。

## 名称对照（仅名称，不承诺线协议兼容）

- `ref/mihomo/listener/inbound/mux_test.go:12` 已有 `h2mux`、`smux`、`yamux`；`ref/mihomo/docs/config.yaml:482` 同样列出三者。
- `ref/mihomo/transport/vless/vless.go:15` 使用 `xtls-rprx-vision`；`ref/mihomo/adapter/outbound/vless.go:71` 使用 `encryption`。
- `ref/mihomo/adapter/outbound/hysteria2.go:39` 为 `Hysteria2Option`。这里沿用 Hysteria2、REALITY、TLS、VLESS、XUDP 现有名称，不引入新协议名，不复制 ref 实现。

## 新增实际覆盖

`internal/tunnel/protocol_matrix_test.go:13` 的 `TestProtocolMatrixRoundTrip` 共 **47 个往返组合**：

| 配置分组 | 组合数 |
| --- | ---: |
| 四种外层基础配置 ×（TCP 四种 mux + UDP off） | 20 |
| TLS / REALITY / Hysteria2 各增加 Encryption × 五种业务模式 | 15 |
| TLS / REALITY 各增加 Vision、无 Encryption × 五种业务模式 | 10 |
| TLS / REALITY 各增加 Encryption + Vision，仅 TCP off | 2 |

复用 `tlsFiles`、`fixtures`、`run`、`awaitEcho`、`awaitUDPEcho`、`exchange`、`exchangeUDP`、`camouflage`。每个组合在 ready 往返后使用三个并发业务连接：TCP 每连接 64 KiB 二进制内容并 CloseWrite，UDP 每 peer 1 KiB 数据报，逐字节校验。通过 `PublicPeerTunnel` 生成授权模板并检查服务端秘密没有泄漏；HY2 密码按现有测试单独注入授权 Client。

原有覆盖包括 `TestOptionalMuxTCPAndRebuild`（TLS、Vision、三种 mux）、`TestUDPReverse`（TLS UDP）、`TestRealityReverse`、`TestHysteriaReverse`（各自 TCP off）、`TestPlainMetadataEncryptionNoCA`（plain TCP off）、`TestVisionApplicationRuntime`（真实内层 TLS 及直拷/回退）。新矩阵主要补充 REALITY/plain/Hysteria2 的各 mux 和 UDP，以及 Encryption/Vision 与这些模式的交叉；基础行保留作为可审计共同基线，不声称 47 个都是此前未测过的组合。

有限覆盖：Encryption 只使用 `GenerateVLESSEnc` 的 X25519、native、600s 默认配置及派生 Client 模板，不穷举 ML-KEM、xorpub/random、1rtt/0rtt、padding、票据恢复。未覆盖 TLS/REALITY 的 Encryption+Vision ×（三种 TCP mux + UDP）共 8 个合法交叉。新增测试不验证内层 TLS 1.3 直拷标志、不穷举 pool/IPv6/大 UDP/故障恢复/恶意输入/取消时序；已有专门测试不能等同于这些维度的完整笛卡尔积。

## 本次执行结果

- 初次矩阵 46/47 通过；Hysteria2 / Encryption=false / Vision=false / TCP / off 并发半关闭回显出现 `unexpected EOF`，精确重跑 10/10 复现。单独补 CloseWrite 后仍失败，未跳过或降低断言。
- 根因：QUIC 包装器缺少写侧半关闭，同时拨号端结束流后立即关闭整个连接，丢弃尚未送达的响应。修复为流级 FIN；正常读 EOF 后等待反向服务端消费响应 FIN 并关闭连接，受运行上下文取消及 1 分钟空闲超时约束，异常路径立即清理。不增加自定义协议确认帧。
- 修复后原失败组合 `-count=30` 通过（0.779s）。`go test ./internal/tunnel -run 'TestProtocolMatrixRoundTrip|TestHysteriaGracefulCleanupBounded' -count=2 -timeout=5m` 全部通过（196.993s），共 94 次矩阵组合；附加测试覆盖对端结束、运行取消、超时三条释放路径。
- 最终 `go test ./...`、`go vet ./...`、tunnel/node/control/httpapi/store race、integration（138.974s）全部通过。生产验收汇总见 `production-gaps-347.md`。
