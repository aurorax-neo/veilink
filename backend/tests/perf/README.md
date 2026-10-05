# Veilink 本地性能夹具

2026-10-05 全协议矩阵、Xmux 资源修复与负载统计修正见 [protocol-regression.md](protocol-regression.md)。

2026-10-06 XHTTP 实现对照、滑动窗口修复与同口径前后复测见 [xhttp-optimization.md](xhttp-optimization.md)，包含回环未显著提速的结果与受控响应延迟对照，不代表公网或 Xray 同配置吞吐。

最新 BBR 后实现优化及串行 Xray 对照见 [optimization.md](optimization.md)，原始逐次测量见 [optimization-measurements.json](optimization-measurements.json)。`results.md` 是优化前的历史完整矩阵，不代表当前树。

新增 [mihomo Alpha HY2 三方实测](mihomo.md)：当前 Veilink/Xray/mihomo 同轮 TCP、mihomo UDP 与 cwnd/窗口/P4/MTU A/B；逐轮数据见 [mihomo-measurements.json](mihomo-measurements.json)。Xray 仍为主参考，HY2 整体目标未达成。

复测代表路径时使用 `VEILINK_PERF_BLOCKS=8192`（512 MiB）、`VEILINK_PERF_ROUNDS=3`、`VEILINK_PERF_POOL=1`，分别选择 `TLS`、`TLS-Vision`、`HY2`；不要与 Xray、profile 或 race 并行执行。裸 QUIC 单/多 stream 控制使用 `-run '^TestQUICStreamsPerformance$'`。
性能夹具默认跳过。原有 65 个外层配置的 TCP/UDP 三轮基线：

2026-10-05 修正了 TCP 负载统计：原夹具每块实际发送 69632 字节，却按 65536 字节计算吞吐；现在负载固定为 65536 字节并有大小断言。此前文档中的 TCP/QUIC 吞吐低估约 5.88%，历史数值保持原样，不能直接与修正口径的结果比较。本次最终结果需使用修正后重新运行的日志。

```sh
VEILINK_PERF=1 go test ./internal/tunnel -run '^TestLocalPerformance$' -count=1 -v -timeout=30m
```

扩展有限矩阵包含 579 个配置，每个分别测试独立 TCP、smux、yamux、h2mux 和 UDP，共 2895 格。默认每格一轮；基础传输、ML-DSA、XHTTP security/HTTP version/mode 与完整 12 种 Encryption 策略均交叉枚举。测量必须串行，不要同时运行 race、构建或其他基准。

```sh
VEILINK_PERF=1 go test ./internal/tunnel -run '^TestAllProtocolPerformance$' \
  -count=1 -v -timeout=2h > /tmp/veilink-matrix.log
python3 tests/perf/summarize_matrix.py /tmp/veilink-matrix.log \
  --cases 579 --rounds 1 > /tmp/veilink-matrix.json
```

汇总器拒绝失败、中断、重复、缺格、缺轮、字节数不匹配或非法数值，不把部分运行算成完整矩阵。汇总器测试：`python3 -m unittest discover -s tests/perf -p 'test_*.py'`。

`TestParameterPerformance` 另测 34 个代表配置，包括 XHTTP Xmux、缓冲并发、header/cookie 数据、元数据与 padding、PUT、pacing、stream-up/stream-one 去除默认头。建议 Pool=1、4 各跑三轮。它不是所有数值参数的穷举。

```sh
VEILINK_PERF=1 VEILINK_PERF_ROUNDS=3 VEILINK_PERF_POOL=4 \
  go test ./internal/tunnel -run '^TestParameterPerformance$' -count=1 -v -timeout=30m
```

可用环境变量：

- `VEILINK_PERF_CASE`：精确选择一个协议格，例如 `HY2` 或 `TLS-Vision-native-x25519-1rtt`。
- `VEILINK_PERF_NETWORK`：`tcp` 或 `udp`。
- `VEILINK_PERF_ROUNDS`：基础矩阵默认 3，扩展/参数矩阵默认 1。
- `VEILINK_PERF_BLOCKS`：TCP 每轮计时的 64 KiB 块数，默认 1024（64 MiB）。
- `VEILINK_PERF_POOL`：映射连接池，默认 1。
- `VEILINK_PERF_DATAGRAMS`：UDP 计时的 datagram 数量，默认 16384。
- `VEILINK_PERF_GROUP`：扩展矩阵分组，可选 `TLS`、`plain`、`REALITY`、`HY2`、`XHTTP-TLS`、`XHTTP-plain`、`XHTTP-REALITY`。
- `VEILINK_PERF_MUX`：扩展/参数矩阵精确选择 `off`、`smux`、`yamux`、`h2mux` 或 `udp`。

每轮先建立并认证 Client↔Server 连接，完成预热后才计时。TCP 使用内层 TLS 1.3 回显，UDP 使用本地 UDP 回显和 1200 字节 datagram；握手和预热不计入吞吐。吞吐是回显 payload 的单份 MiB/s，延迟是 200 次顺序 64 字节往返的 p50/p95。UDP 测量是每批 16 个 datagram 的窗口回显，会校验序号、完整 payload、重复和超时；它不是公网最大线速声明。

## 有限协议格

代码当前允许的外层传输为：

- `tls`：TCP Client↔Server，允许无 Encryption、VLESS Encryption；允许 Vision。
- `plain`：TCP，必须有 VLESS Encryption；禁止 REALITY、Hysteria2、Vision。
- `REALITY`：TCP Client↔Server，允许无 Encryption、VLESS Encryption；允许 Vision。
- `Hysteria2`：UDP 外层上的 QUIC/TLS，禁止 VLESS Encryption、REALITY、Vision。其映射数据仍进入 Veilink 反向会话、mux 和可靠 QUIC stream。

Encryption 的性能维度是实现提供的三种模式（`native`、`xorpub`、`random`）、两种密钥（X25519、ML-KEM）和两种配置标签（0-RTT、1-RTT），共 12 格。0-RTT/1-RTT 是配置策略标签；本夹具排除握手，不能把它解释为每轮都完成了 fresh connection ticket resumption。无 Encryption 的基准格另测。组合必须由 Client 的 public tunnel 元数据和 Server 私有配置共同匹配。

基础 TCP/UDP 夹具枚举 65 个合法外层格：TLS 26、plain 12、REALITY 26、Hysteria2 1。扩展矩阵 REALITY 增加 ML-DSA 开关后为 52 格；XHTTP 增加 TLS 182、plain 72、REALITY 234 格，总计 579。XHTTP 的默认/1.1/2/3、packet-up/auto/stream-up/stream-one 只纳入实际合法选择，禁止 Vision；plain 必须 Encryption；REALITY 不支持 HTTP/3。非法格应由 `CheckBootstrap`/运行时校验拒绝，不进入吞吐表；已有 transport、Vision、Encryption、REALITY、HY2 rejection tests 覆盖这些限制。

扩展性能夹具共享真实本地证书、回显目标和两个 REALITY 伪装站（普通/大证书链），减少上游重复探测等待；每格仍独立生成密钥、创建授权运行时。不会预填或修改上游探测缓存，不改变生产握手逻辑。ML-DSA、0rtt/1rtt 影响握手的成本不包含在本吞吐计时内，不能据此比较握手延迟。Mux 和 Encryption 下断言不会错误切换到裸传。

## 结果解释

这是同机 macOS loopback、Go 非 race 测量。QUIC 的 UDP `sendmsg`/`recvmsg`、调度和系统调用成本会显著影响 HY2；不能直接外推公网。HY2 映射目前不使用 QUIC DATAGRAM，UDP 映射仍通过可靠 stream 和 XUDP 字节编码；因此该结果不代表 native QUIC DATAGRAM 性能。

性能日志属于临时测量产物，应写入会话 scratch 目录，不应提交 profile、证书、数据库、日志或生成的二进制。
