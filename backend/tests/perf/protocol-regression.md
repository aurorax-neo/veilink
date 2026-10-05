# 全协议性能回归记录

日期：2026-10-05。代码基线：v0.4.4（e5ebb78），包含本地未提交修复。

## 覆盖与口径

扩展矩阵枚举 579 个合法配置，每个运行独立 TCP、smux、yamux、h2mux 和 UDP 五条路径，共 2895 项。TLS、plain、REALITY、HY2、Vision、ML-DSA 开关，以及 XHTTP 的 security、HTTP version、mode 与 12 种 Encryption 策略按合法约束交叉覆盖；不是任意数值参数的无限穷举。

环境：macOS arm64、Go 1.27.0、GOMAXPROCS=10，本机回环，非 race。全部测量串行执行，不与构建或其他重测试并行。TCP 每次计时传输 64 MiB 内层 TLS 1.3 回显，UDP 每次计时 16384 个 1200 字节 datagram；校验完整负载、UDP 序号和重复，并采样 200 次 64 字节往返。握手和预热不计入吞吐。

## 已确认问题

1. **Xmux 空闲资源泄漏**：会话关闭只减少租约计数，没有回收未过期的共享 HTTP transport 与配置键。频繁重连、编辑或删除隧道后会积累空闲连接和旧配置。现在最后一个租约关闭时按 entry 身份移除并关闭 transport；其他活跃租约和同键的新 transport 不受影响。失败创建不保留空键，HTTP/3 transport 的慢关闭不持有全局池锁。
2. **吞吐统计口径错误**：原 TCP 负载每块实际为 69632 字节，计算却按 65536 字节，历史吞吐低估约 5.88%。现在固定负载为 65536 字节，基础 TCP、扩展矩阵及裸 QUIC 使用相同 helper，并有大小断言。历史数据不改写，也不直接拿旧绝对值与新数据比较。
3. **测试端 15 秒误断开**：性能测试复用了功能测试回显服务器的 15 秒连接总时限；XHTTP pacing + yamux 等较慢路径尚未传完就被测试端关闭，表现为约 15 秒的 unexpected EOF。性能回显服务器现在使用与负载端一致的 90 秒预算，功能测试仍为 15 秒，生产超时未放宽。定向十轮全部通过，包含超过 17 秒的完整传输。

此前 REALITY 握手取消/超时和认证查找回归的依据见 [reality-regression.md](reality-regression.md)。没有修改 Vision 安全边界、授权、加密回退或用户持久化数据。

## 实测结果

修正字节口径后，完整扩展矩阵 **2895/2895 通过**，耗时约 2109 秒。该矩阵使用默认 Xmux 关闭配置；最后租约的锁外关闭由参数矩阵与专项资源回归验证。汇总器校验 PASS、无失败、无缺格/重复/缺轮，以及期望与实际字节一致，不接受中断日志。

34 个代表参数配置分别以 Pool=1、4 运行五条路径、各三轮，**510+510 项全部通过**，严格汇总检查通过。加上故障组合的十轮，最终完成 3925 次有效测量；此前失败或主动中断的诊断运行不计入。

独立 TCP 路径三轮吞吐中位数（单位 MiB/s，前者 Pool=1，后者 Pool=4）：

- TLS：828.912 / 759.829。
- TLS + Vision：937.929 / 865.821。
- REALITY：821.656 / 788.855。
- REALITY + Vision + ML-DSA：862.305 / 844.980。
- HY2：123.067 / 119.381。
- XHTTP TLS HTTP/1.1 packet-up：324.000 / 337.770。
- XHTTP TLS HTTP/2 stream-one + Xmux：685.578 / 666.327。
- XHTTP TLS HTTP/3 packet-up：81.565 / 84.878。

这些数字仅代表同机、同负载的三轮样本；Pool=4 是多条授权连接的池配置，不是四条应用流的聚合吞吐测试。

不能把单轮性能差异视为稳定的版本回退。本次最低吞吐集中在 HTTP/3 packet-up/auto 的 UDP 路径，约 10 MiB/s，但负载校验通过；它包含 QUIC、逐 POST 确认及可靠流上的 XUDP 成本。pacing 按配置限制 POST 间隔，带 mux 的小记录会增加 POST 数量，降速属于预期，不能自动视为协议故障。

## 回归与复现

Xmux 回归包含 256 个配置键反复释放、共享租约不互相关闭、八个并发 worker、retired entry 不驱逐 replacement、失败创建与已取消请求无资源、慢关闭不阻塞其他键，以及 HTTP/1.1、2、3 的真实 runtime 停止后回收。

## 最终验收

- `go test ./... -json -count=1 -timeout=15m` 通过，1431 个通过用例，无失败；隧道包约 439 秒，350 项 XHTTP 功能组合全部通过。
- `go vet ./...` 通过；整个隧道包 `go test -race` 通过，约 170 秒。
- 新增 Xmux、负载大小和矩阵覆盖回归以 `-count=3` 重复通过。
- `go test -tags integration ./tests/integration -count=1 -timeout=10m` 通过，包含 CLI 实际 TCP/UDP 流量与控制传输检查；其中已有 `TestThreeRolesCoordinated` 协议子项仍是 TODO，不把其空子项作为协议验收依据。
- 前端 114 项测试、TypeScript 检查及 Vite 生产构建通过；汇总器三项测试通过。
- 统一镜像 `veilink:protocol-perf-fix` 实际构建并加载成功；临时 master/server/client 三角色启动、镜像内容、健康、授权接入、已应用修订及 Web 监听隔离检查通过，测试容器已清理。健康检查不等同数据面性能测试。
- `gofmt` 与 `git diff --check` 通过。临时诊断日志输出已删除，无生成产物或私密材料提交到仓库。

没有执行 Git 提交、标签、release、镜像推送或远端部署，没有改动用户持久化数据。

运行命令与参数见 [README.md](README.md)。原始日志、密钥及 profile 只留在临时目录，不提交。公网吞吐、丢包和高 RTT 表现需要两机同配置复测；本地回环结果不是公网线速承诺，吞吐计时也不能用于比较 ML-DSA 或 0rtt/1rtt 的握手成本。
