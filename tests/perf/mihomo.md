# mihomo Alpha HY2 实测辅证（2026-09-25）

## 结论

**实际构建并运行了 mihomo Alpha，不是仅阅读代码。Xray 仍为实现主参考，mihomo 仅辅证；整体 HY2 绝对吞吐目标仍未达成。** 本轮不改生产代码，不复制 mihomo 实现，不 commit/push/部署。

Apple M4 / darwin arm64 / Go 1.27.0 / 10 CPU。mihomo `Alpha@f103639c808d93a2c34cae56757b458862871b22`，没有使用 main；Xray 26.9.9 `d562d8947d3175db86b4fa849742433a9876cb63`。两个 reference 工作树均保持干净。

## 同轮三方对照

单位 MiB/s，三轮中位；这些是本轮新测量，不是上一轮数字重贴。

| 实现/配置 | TCP 三轮 | TCP 中位 | UDP 三轮 | UDP 中位 |
|---|---|---:|---|---:|
| Veilink 当前树、Pool=1 | 132.892 / 130.398 / 133.356 | 132.892 | 48.823 / 48.194 / 49.761 | 48.823 |
| Xray standard BBR | 107.035 / 99.944 / 97.225 | 99.944 | 两次尝试均首批预热 14/16 后超时 | 无有效值 |
| mihomo standard BBR | 101.494 / 101.981 / 97.100 | 101.494 | 29.084 / 28.802 / 28.814 | 28.814 |
| mihomo standard 独立回测 | 102.672 / 97.086 / 101.404 | 101.404 | 28.753 / 30.154 / 30.506 | 30.154 |

前轮 Veilink HY2 134.908/50.066、Xray TCP 97.329 仅作历史背景，见 optimization.md。当前结果没有改变“HY2 绝对瓶颈尚在”的判断。

### 口径和限制

- 同机 loopback，非 race 串行；无基准/编译/profile/race 重叠。清除本命令的六种代理环境变量，不修改全局设置。
- TCP：内层 TLS 1.3 echo，64 KiB 块，16 块预热，8192 块共 512 MiB；并发读写、完整负载校验，握手不计时，echo 负载只计一份。随后 200 次 64 字节 RTT。
- UDP：256 报文预热、16384×1200 字节计时，每批 16，完整内容/序号/重复校验，无应用重传，超时即失败；这是有限窗口 goodput，不是线速。
- mihomo/Xray 独立客户端和服务端进程，固定目标入站转发到 loopback echo；Veilink 测试进程内运行双端，经过反向授权连接、私有 mux。负载对齐，不是逐层同拓扑。
- mihomo 默认复用 QUIC 连接、TCP 请求使用 QUIC stream，无额外 sing-mux；Veilink Pool=1 是一条反向 session，并非逐块重建连接。
- mihomo UDP 使用原生 QUIC DATAGRAM，Veilink 为 XUDP→mux→可靠 QUIC stream，丢包语义不同。无受控丢包、Linux 同硬件或本轮多 stream 实测，不能由 loopback 排名外推公网。

## 配置与 A/B

双端显式 `up: "0"`, `down: "0"`, `cwnd: 32`, `bbr-profile: standard`；服务端 `ignore-client-bandwidth: true`。按 sing-quic 认证协商分支，双端选择 BBR，**不走 Brutal**。`cwnd` 是初始拥塞窗口参数，不是接收流控窗口。未配置混淆、端口跳跃、额外 mux。默认 `udp-mtu=1197`，stream 初始/最大接收窗口均 8 MiB，connection 均 20 MiB。

外层使用 SHA-256 叶证书 pin；配置不设置 skip-cert-verify。mihomo 内部由 VerifyConnection 指纹验证替代默认 CA 验证；内层 TLS 仍验证 CA+gateway.test。初次路径沙箱、误用出站 certificate 字段、全局 CA 未生效的失败均发生于有效测量前，未算作吞吐数据。

| mihomo 变体（其余同 standard） | TCP 中位 | UDP 中位 | 判断 |
|---|---:|---:|---|
| cwnd=128，双端 | 103.053 | 30.014 | TCP +1.54%，轮次重叠，不足以证实收益 |
| stream initial/max=16/32 MiB，connection=32/64 MiB | 102.469 | 29.261 | TCP +0.96%，未见实质收益 |
| GOMAXPROCS=4，客户端/服务端/驱动均设置 | 102.668 | 29.043 | TCP +1.16%，不支持全局硬编码 P=4 |
| udp-mtu=1400，双端 | 103.913 | 39.132 | UDP 比标准回测 30.154 高 29.8%；TCP 无稳定证据 |

每个变体均三轮，全部轮次保存在 mihomo-measurements.json。顺序：standard→cwnd128→windows→P4→Veilink→Xray→MTU1400→standard 回测→独立重启 Xray UDP 复核。没有挑选最快一轮替代中位。

### 从数字与路径得到的可借鉴点

1. **BBR 挂载**：`adapter/outbound/hysteria2.go` 和 `listener/sing_hysteria2/server.go` 通过 `SetBBRCongestion` 回调；依赖 `sing-quic/hysteria2/{client,service}.go` 在认证成功后选择 BBR/Brutal。Veilink 已按 Xray 在相同阶段双端挂载 standard BBR，没有“漏挂 BBR”的新证据。mihomo `transport/tuic/common/congestion.go` 使用其 congestion_v2，不因名字同为 standard 就宣称实现逐字相同。
2. **窗口**：实际扩大接收窗口和初始 cwnd 后约 1% 级变化、轮次重叠；与前轮 Veilink 大窗口无收益一致。没有理由增加生产内存预算。
3. **调度**：mihomo 三进程 P4 变化很小；不能用前轮 Veilink 单进程 P4 收益去推断所有实现或硬编码全局运行时策略。仍需局部 packet-worker/唤醒实验及 CPU、包率、公平性证据。
4. **多 stream**：mihomo 独立 TCP 请求各开 stream，区别于 Veilink 私有 mux；本轮没有四 stream 压测。前轮 Veilink 裸 QUIC 同连接 1/4 streams=153.969/147.681 是历史辅证，不是本轮 mihomo 数字，不能据此声称多 stream 已解决瓶颈。
5. **DATAGRAM/分片**：sing-quic `hysteria2/packet.go` 在 payload 大于 `udpMTU-headerSize` 时分片，最终调用 SendDatagram。默认 1197 小于本测试 1200 字节加头，必经分片；MTU1400 A/B 的明显收益支持减少此类分片成本。路径过小仍可能由 QUIC DatagramTooLarge 回退分片；未抓包，不能宣称所有报文都只发一个 QUIC 包。1400 是本机实验值，不是任意公网安全 MTU。
6. **不直接移植**：Veilink 当前不是原生 DATAGRAM，改一个 MTU 参数不会产生此收益。需要 association 授权隔离、PMTU/分片/重组、乱序、过期、关闭和丢包测试后再设计协议。可靠流 loopback 较快不代表公网 UDP 更好。

因此本轮只落地可复现夹具和证据，没有保留未经证明的生产小优化。仍以 Xray 行为为主，不因 mihomo 辅证改换 BBR 实现。

## Xray UDP 限制

固定目标 dokodemo-door 的 network 扩为 tcp,udp，复用同一 16×1200 驱动；首次尝试和独立重启复核都在第一批预热收到 14/16 后 5 秒超时。没有有效计时轮次，无中位数；不重传、不减少窗口来凑成功。当前 warning 日志不能定位具体丢包环节，因此不是“Xray UDP 不支持”或性能为零的结论。

## 复现

从仓库根目录执行，工具输出、证书和状态均放 scratch。仅用于开发对照，不是 Veilink 生产部署指南。

```sh
unset ALL_PROXY HTTP_PROXY HTTPS_PROXY all_proxy http_proxy https_proxy
D="$PI_SCRATCH_DIR/mihomo-hy2-repro"
mkdir -p "$D/server" "$D/client"
test "$(git -C ref/mihomo branch --show-current)" = Alpha
test "$(git -C ref/mihomo rev-parse HEAD)" = f103639c808d93a2c34cae56757b458862871b22
(cd ref/mihomo && GOPROXY=https://goproxy.cn go build -mod=readonly -o "$D/mihomo" .)
go build -o "$D/hy2bench" ./tests/perf/hy2bench
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj '/CN=gateway.test' -addext 'subjectAltName=DNS:gateway.test' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -keyout "$D/key.pem" -out "$D/cert.pem"
cp "$D/cert.pem" "$D/key.pem" "$D/server/"
bash tests/perf/run-mihomo.sh "$D" standard
bash tests/perf/run-mihomo.sh "$D" cwnd128
bash tests/perf/run-mihomo.sh "$D" windows
GOMAXPROCS=4 bash tests/perf/run-mihomo.sh "$D" standard p4
bash tests/perf/run-mihomo.sh "$D" mtu1400
bash tests/perf/run-mihomo.sh "$D" standard recheck
VEILINK_PERF=1 VEILINK_PERF_CASE=HY2 VEILINK_PERF_ROUNDS=3 \
  VEILINK_PERF_BLOCKS=8192 VEILINK_PERF_POOL=1 \
  go test ./internal/tunnel -run '^TestLocalPerformance$' -count=1 -v
```

要求 19080 TCP/UDP、19443 TCP/UDP 和 19444 UDP 空闲，无其它压测。脚本配置校验后运行，失败立即停止，并清理其子进程。大小写错误的 `VEILINK_PERF_CASE=hy2` 会零子项通过；本轮发现后改为 HY2，确认六条 PERF 记录。Xray 使用前轮保留的配置生成器，唯一负载入口差异是 network=tcp,udp；见 optimization.md 的复现来源。

## 验证与清理

本轮已执行并通过 go test ./...、go vet ./...、相关 tunnel/node/control/master race（普通/race 部分缓存命中）；integration 强制重跑 138.384 秒；前端 27 测试和生产构建/类型检查（输出 scratch，未覆盖历史 html）；三角色 Podman 构建与内容检查。Docker CLI 不可用，Podman OCI 忽略 HEALTHCHECK，不声称 Docker healthcheck 验证通过。

原始吞吐轮次存入 JSON，并已与实际日志逐轮核对中位数；Python/Bash 语法、gofmt 和 git diff --check 通过。已删除本轮 mihomo-hy2 scratch（含二进制、证书/私钥、配置、日志、前端构建输出）、三个 veilink-mihomo-check 镜像及本轮新中间层；复查无本轮参考进程或新镜像残留，三个既有外部构建容器保留。未触碰已有历史 html 恢复问题，未全局 prune，不清除共享 Go 模块/构建缓存或旧镜像。
