# Veilink 本地性能夹具

最新 BBR 后实现优化及串行 Xray 对照见 [optimization.md](optimization.md)，原始逐次测量见 [optimization-measurements.json](optimization-measurements.json)。`results.md` 是优化前的历史完整矩阵，不代表当前树。

新增 [mihomo Alpha HY2 三方实测](mihomo.md)：当前 Veilink/Xray/mihomo 同轮 TCP、mihomo UDP 与 cwnd/窗口/P4/MTU A/B；逐轮数据见 [mihomo-measurements.json](mihomo-measurements.json)。Xray 仍为主参考，HY2 整体目标未达成。

复测代表路径时使用 `VEILINK_PERF_BLOCKS=8192`（512 MiB）、`VEILINK_PERF_ROUNDS=3`、`VEILINK_PERF_POOL=1`，分别选择 `TLS`、`TLS-Vision`、`HY2`；不要与 Xray、profile 或 race 并行执行。裸 QUIC 单/多 stream 控制使用 `-run '^TestQUICStreamsPerformance$'`。
该夹具默认跳过；运行完整有限矩阵：

```sh
VEILINK_PERF=1 go test ./internal/tunnel -run '^TestLocalPerformance$' -count=1 -v -timeout=30m
```

可用环境变量：

- `VEILINK_PERF_CASE`：精确选择一个协议格，例如 `HY2` 或 `TLS-Vision-native-x25519-1rtt`。
- `VEILINK_PERF_NETWORK`：`tcp` 或 `udp`。
- `VEILINK_PERF_ROUNDS`：默认 3。
- `VEILINK_PERF_BLOCKS`：TCP 每轮计时的 64 KiB 块数，默认 1024（64 MiB）。
- `VEILINK_PERF_POOL`：映射连接池，默认 1。

每轮先建立并认证 Client↔Server 连接，完成预热后才计时。TCP 使用内层 TLS 1.3 回显，UDP 使用本地 UDP 回显和 1200 字节 datagram；握手和预热不计入吞吐。吞吐是回显 payload 的单份 MiB/s，延迟是 200 次顺序 64 字节往返的 p50/p95。UDP 测量是每批 16 个 datagram 的窗口回显，会校验序号、完整 payload、重复和超时；它不是公网最大线速声明。

## 有限协议格

代码当前允许的外层传输为：

- `tls`：TCP Client↔Server，允许无 Encryption、VLESS Encryption；允许 Vision。
- `plain`：TCP，必须有 VLESS Encryption；禁止 REALITY、Hysteria2、Vision。
- `REALITY`：TCP Client↔Server，允许无 Encryption、VLESS Encryption；允许 Vision。
- `Hysteria2`：UDP 外层上的 QUIC/TLS，禁止 VLESS Encryption、REALITY、Vision。其映射数据仍进入 Veilink 反向会话、mux 和可靠 QUIC stream。

Encryption 的性能维度是实现提供的三种模式（`native`、`xorpub`、`random`）、两种密钥（X25519、ML-KEM）和两种配置标签（0-RTT、1-RTT），共 12 格。0-RTT/1-RTT 是配置策略标签；本夹具排除握手，不能把它解释为每轮都完成了 fresh connection ticket resumption。无 Encryption 的基准格另测。组合必须由 Client 的 public tunnel 元数据和 Server 私有配置共同匹配。

因此当前 TCP/UDP 夹具枚举 65 个合法外层格：TLS 26、plain 12、REALITY 26、Hysteria2 1。非法格应由 `CheckBootstrap`/运行时校验拒绝，不进入吞吐表；已有 transport、Vision、Encryption、REALITY、HY2 rejection tests 覆盖这些限制。

## 结果解释

这是同机 macOS loopback、Go 非 race 测量。QUIC 的 UDP `sendmsg`/`recvmsg`、调度和系统调用成本会显著影响 HY2；不能直接外推公网。HY2 映射目前不使用 QUIC DATAGRAM，UDP 映射仍通过可靠 stream 和 XUDP 字节编码；因此该结果不代表 native QUIC DATAGRAM 性能。

性能日志属于临时测量产物，应写入会话 scratch 目录，不应提交 profile、证书、数据库、日志或生成的二进制。
