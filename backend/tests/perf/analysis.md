# HY2 性能排查与外部对照

## 合法矩阵

依据 `internal/tunnel/transport.go`、`validate.go`、`hysteria.go:checkExclusive` 和 Vision/Encryption 校验：

| C↔S 匹配的外层 | 不启用 Encryption | 启用 Encryption（12格） | Vision | TCP映射 | UDP/XUDP映射 |
|---|---|---|---|---|---|
| TCP/TLS | 允许 | 允许 | 允许 | 支持 | 支持，始终加密 |
| TCP/plain | 禁止 | 必须 | 禁止 | 支持 | 支持 |
| TCP/REALITY | 允许 | 允许 | 允许 | 支持 | 支持，始终加密 |
| QUIC/Hysteria2 | 允许 | 允许 | 禁止 | 支持 | 支持，经可靠stream |

Encryption = native/xorpub/random × x25519/mlkem × 0rtt/1rtt。TLS、REALITY分别26格，plain12格，HY2共13格，合计77格。任意密钥、padding长度和票据寿命不作为独立吞吐维度。双方需匹配公开模板、密钥及认证材料；不同外层互配不是合法格。

禁止 plain无Encryption、plain+REALITY/HY2、HY2+REALITY、REALITY+证书PEM、plain/HY2+Vision、无效或不匹配的Encryption/认证材料。相关拒绝测试见 `transport_test.go`、`hysteria_test.go`、`vision_regression_test.go` 等；完整Go测试通过。Vision仅对独立认证TCP连接中满足结构/边界条件的内层TLS1.3直拷；配置了Vision的Server仍能承载UDP，但UDP绝不直拷。矩阵测试会检查直拷计数，Encryption回退和UDP必须为0。

## 结果和方法

完整77行结果见 [results.md](results.md)，由462条实际测量校验并汇总。Apple M4、10 CPU、macOS arm64、Go1.27.0、GOMAXPROCS10。三轮中位数、同机loopback、非race、排除握手和预热。内层TCP是TLS1.3回显；UDP是1200B、窗口16的校验回显，不是原生QUIC DATAGRAM或最大线速。

补充Pool=4（仍是单业务连接，不是四路并发）：

| 配置 | TCP MiB/s | TCP RTT p50/p95 µs | UDP MiB/s | UDP RTT p50/p95 µs |
|---|---:|---:|---:|---:|
| TLS | 678.28 | 51.1/80.0 | 63.28 | 64.3/77.5 |
| TLS-Vision | 943.25 | 39.7/49.5 | 60.12 | 64.5/78.4 |
| HY2 | 134.24 | 77.0/85.8 | 47.42 | 85.5/94.0 |

## HY2证据链

纯QUIC控制实验移除私有认证、mux、XUDP和两端TCP转发；使用同版本quic-go、证书验证、64KiB块、1MiB预热、64MiB有效payload及200次64B RTT。控制组不是完整拓扑等价对照，吞吐差不能完全归因于mux。

| 路径 | TCP MiB/s | RTT p50/p95 µs |
|---|---:|---:|
| 纯quic-go stream echo | 154.38 | 35.7/39.9 |
| 纯quic-go + 内层TLS1.3 | 150.70 | 37.3/42.5 |
| 同上，放大收流控窗口 | 151.08 | 37.2/42.0 |
| Veilink HY2完整隧道 | 132.29 | 78.0/85.0 |
| Veilink TCP/TLS完整隧道 | 625.44 | 50.6/86.0 |

- **主导证据是macOS QUIC逐包系统调用与调度成本**：HY2短时CPU profile（704ms墙钟、2.85s聚合样本）中 `syscall.rawsyscalln` 占60% flat，另有 `usleep`11.93%、`kevent`11.58%、`pthread_cond_wait`4.21%。这些是聚合采样，不是全部sendmsg，也不是墙钟占比。AES-GCM解密flat约1.4%；没有发现大额copy热点，未对所有加密/拷贝路径做精确归因。
- **GSO平台限制**：quic-go v0.59.0 的 `sys_conn_helper_darwin.go:isGSOEnabled` 明确返回false；Linux另有能力探测。并非Veilink漏开一个跨平台开关。
- **socket buffer已由库处理**：`sys_conn.go` 调用 `setReceiveBuffer`/`setSendBuffer`，目标各7MiB；目标不等于内核最终分配值，本轮没有测有效socket容量。重复设置相同值没有已证实收益。
- **流控非本次主要限制**：库自动增长窗口，最大stream默认6MiB、connection默认15MiB。控制组把初始stream/connection设为4/8MiB、最大16/32MiB后只变化+0.25%，不足以声称提升。
- **双层加密存在但不是主因**：外层QUIC的TLS密钥保护加内层应用TLS；去掉内层TLS仅从150.70升到154.38 MiB/s（约2.4%损失），无法解释相对TCP/TLS的巨大差距。不能移除用户应用TLS。
- **隧道仍有开销**：完整HY2比QUIC+内层TLS控制组低约12.2%，包含两端TCP、mux/排队/拷贝/认证路径差异，未将其拆成可相加的独立比例。`tunnel.go` 数据读取块上限32KiB，`writeFrame` 将7字节头部和payload复制到同一个缓冲后一次Write；不存在逐字节发送或头部单独Write的问题，QUIC再自行组帧分包。
- **额外Encryption有真实稳态成本**：HY2从132.29降到约111.70–115.65 MiB/s。排除握手后，ML-KEM没有持续显著慢于X25519，0/1RTT标签也不能解释成握手速度。
- **拥塞控制不同**：上游quic-go使用CubicSender；Xray HY2采用apernet fork，本次显式BBR。无拥塞loopback不能确定公网丢包、RTT下的最优选择。

结论：没有找到足以支持生产参数改动的证据，**本轮不修改HY2生产实现**。最小可落地成果是完整夹具与控制实验，而不是无收益扩大窗口。下一步若追求Linux生产吞吐，应在真实Linux确认GSO与有效socket容量后复测；减少mux分配/拷贝须先有profile热点和A/B收益。改为QUIC DATAGRAM会改变可靠性、授权及映射语义，不是本轮安全的小优化。

## Xray独立进程对照

Xray 26.9.9，commit `d562d8947d3175db86b4fa849742433a9876cb63`，同机Go1.27.0构建。独立两进程：Go TLS1.3应用 → dokodemo-door → VLESS/TCP/TLS（无Vision）或原生HY2/QUIC（BBR） → freedom → Go TLS1.3 echo。mux关闭，单应用连接；64KiB块、1MiB预热、64MiB计时，200×64B RTT，三轮。每轮新应用连接，但HY2可能复用QUIC连接。只允许本轮loopback动态echo端口，不开放代理。

| 场景 | Xray三轮 MiB/s | Xray中位 MiB/s | Xray RTT中位 µs | Veilink中位 MiB/s | (Veilink/Xray−1) |
|---|---|---:|---:|---:|---:|
| TLS，无Vision | 993.548 / 1015.076 / 1131.912 | 1015.08 | 49.08 | 625.44 | −38.38% |
| HY2，无额外Encryption | 109.717 / 104.592 / 110.517 | 109.72 | 78.42 | 132.29 | +20.58% |

HY2已达到本次Xray同机参考量级，并非落后它；普通TLS还有明显差距。Veilink TLS-Vision为923.49 MiB/s，但不能拿它与Xray无Vision直接宣称协议等价。Xray是正向、无mux的独立进程，Veilink是反向pool/mux，QUIC实现及拥塞控制也不同；以上是应用路径参考，不是严格内核排名。未测Xray UDP映射、Vision或全部Encryption档，不给这些场景编造数字。

Xray参考源码未修改、未复制实现或界面到Veilink、未嵌入Xray依赖。构建初次下载超时后以 `GOPROXY=https://goproxy.cn,direct` 成功，代理环境变量均清空；全局代理设置未改。

## 复现

```sh
unset ALL_PROXY HTTP_PROXY HTTPS_PROXY all_proxy http_proxy https_proxy
VEILINK_PERF=1 go test ./internal/tunnel -run '^TestLocalPerformance$' -count=1 -v -timeout=30m > "$PI_SCRATCH_DIR/matrix.log"
python3 tests/perf/summarize.py "$PI_SCRATCH_DIR/matrix.log"
VEILINK_PERF=1 go test ./internal/tunnel -run '^TestQUICPerformanceControl$' -count=1 -v
VEILINK_PERF=1 VEILINK_PERF_CASE=HY2 VEILINK_PERF_NETWORK=tcp VEILINK_PERF_ROUNDS=1 go test ./internal/tunnel -run '^TestLocalPerformance$' -count=1 -cpuprofile "$PI_SCRATCH_DIR/hy2.cpu" -o "$PI_SCRATCH_DIR/tunnel.test"
go tool pprof -top "$PI_SCRATCH_DIR/hy2.cpu"
```

Xray独立夹具及配置属于临时产物，测后删除；上述版本、路径拓扑和参数记录用于重新构造对照，不声称保留了一键Xray复跑工具。三轮较短测试不足以给出统计显著性或公网预测。

## 验收

已执行并通过 `cd backend && go test ./...`、`cd backend && go vet ./...`、tunnel/node/control/master race、`cd backend && go test -tags integration ./tests/integration -count=1`、前端27项测试、生产构建、`git diff --check`。本机无Docker CLI，以Podman完成master/server/client目标构建及内容检查：仅Master有html/curl/sqlite，三角色均有可执行文件和/data。镜像运行仅作内容检查，不是远端部署。
