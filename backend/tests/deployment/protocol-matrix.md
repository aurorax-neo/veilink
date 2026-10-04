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
