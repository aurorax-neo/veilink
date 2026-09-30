# 实现优化复测（BBR 后）

## 结论与范围

本轮修复了普通 TLS 被 Vision 记录边界适配器拖慢、TLS/mux/UDP 热路径重复分配的问题。TLS TCP 明显改善；Vision TCP 未证实改善，HY2 绝对吞吐问题仍未解决。不能以“回环正常”或“超过本次 Xray HY2”宣布整体性能目标完成。

历史 77 配置矩阵见 results.md；它没有在本轮补丁后全量重跑。所有本轮逐次测量见 optimization-measurements.json，包含负面实验而非只保留最快值。

## 口径

Apple M4，darwin/arm64，Go 1.27.0，10 CPU，默认 GOMAXPROCS=10，Pool=1。非 race 串行压测。TCP 每轮 8192×64 KiB=512 MiB，16 块预热和握手不计时，内层 TLS 1.3 echo，并发读写且校验负载；200 次独立小包 RTT。吞吐按单向有效负载计算，不将双向 echo 重复计数。

UDP 每批 16×1200 字节、共 16384 报文，全负载和序号校验，无应用重传。这是有限在途窗口 echo goodput，不是 UDP 线速。Xray 本轮仅有 TCP 对照，没有同口径 UDP 数字。

Xray 26.9.9，ref commit d562d8947d3175db86b4fa849742433a9876cb63，Go 1.27 构建，mux 禁用，HY2 显式 standard BBR，内层 TLS/负载相同。Veilink 使用反向授权隧道及私有 mux，Xray 使用独立客户端/服务端进程；因此是同负载实际路径对照，不是逐层完全相同拓扑。最终顺序为 Veilink HY2、TLS、Vision，再 Xray TLS、HY2、Vision，无基准并行运行。

## 三轮中位数（MiB/s）

| 路径 | 修改前 TCP | 最终 TCP | 变化 | 修改前 UDP | 最终 UDP | Xray TCP | TCP 相对 Xray |
|---|---:|---:|---:|---:|---:|---:|---:|
| TLS | 675.818 | 999.780 | +47.94% | 65.143 | 82.435 | 1048.870 | -4.68% |
| TLS-Vision | 873.224 | 856.204 | -1.95% | 64.451 | 79.265 | 946.791* | -9.57%* |
| HY2 | 128.818 | 134.908 | +4.73% | 47.958 | 50.066 | 97.329 | +38.61% |

*Vision 对照不稳定：初次串行 Xray 三轮为 981.550/473.526/457.955，中位 473.526；单独复测为 946.791/456.026/948.511，中位 946.791。表中使用明确标记的复测值，不以低速批次宣称胜出，也不将 -9.57% 作为稳定差距。Veilink 每轮 switch=1/1，UDP=0/0；Xray 最终 warning 日志不足以解释其双态，原因仍待定位。

## 已落地的生产修改

1. `vision_transport.go`：ownedTLSConn 在既有读锁内复用 18432 字节明文缓冲，未消费明文和错误保持原语义。单独 A/B TLS 中位由 675.818 到 762.803（+12.9%）。
2. `tunnel.go`：mux 在既有写锁内复用 7+32768 字节帧缓冲，保持同步写入和帧顺序，不复用交给异步消费者的负载。
3. `udp.go`：客户端 UDP 按需分配并复用 64 KiB 缓冲，新增读锁确保所有权；超大报文迭代跳过而非递归，空读取立即返回。缓冲组合实验 TLS TCP/UDP=870.263/77.581，HY2=132.244/49.636。
4. 普通 TLS 在握手前明确设置 ordinary，跳过仅 Vision 需要的逐 TLS 记录底层读边界与明文暂存。ordinary 两个方向均明确禁止 raw handoff；REALITY/Vision 保留安全边界与加密回退。首次 A/B TLS=975.670，最终独立复测=999.780。

代价：每个 session 常驻约 32 KiB 写缓冲，每个 ownedTLSConn 约 18 KiB 读缓冲；每个活跃客户端 UDP association 按需 64 KiB。没有引入无界池或更大流控窗口。

回归覆盖普通 TLS 禁止 handoff、8 路并发 mux 帧不串写、逐字节读取保留 TLS pending、UDP 超大报文跳过/连续记录/碎片读取/关闭解除读取。macOS 测试发送 socket 显式设置 128 KiB 缓冲以允许发出待丢弃的大报文。

## HY2 的硬证据、失败候选和剩余补丁

- TLS profile：2 GiB 测量分配约 16.9 GiB，ownedTLSConn.Read 占 42.7%、mux 写 31.4%、读帧 25.5%；前两类分配已处理，读帧因异步所有权没有草率复用。
- standard BBR 控制：裸 QUIC 143.555、QUIC+内层 TLS 141.143、扩大窗口约 140.540 MiB/s；没有窗口收益。控制拓扑不同，不能当作平台理论天花板。
- 新增 `TestQUICStreamsPerformance`：同连接相同总量，独立 stream 并发读写，全部预热后共同计时。1 stream 三轮中位 153.969，4 streams 总吞吐 147.681；去私有 mux 和增加 QUIC stream 均未得到数量级改善。
- HY2 GOMAXPROCS2=139.703，GOMAXPROCS4=173.418；默认优化后约 132–135。未硬编码全局 GOMAXPROCS：它影响整个 Master/Client/Server 进程，不能从单一 macOS echo 工作负载外推。
- HY2 profile：默认约 8.21 秒 wall/39.87 秒聚合 CPU samples，rawsyscalln 61.85%、kevent 11.54%、usleep 8.33%，findRunnable 累计 25.31%；P=4 时约 6.04 秒计时/19.1 秒聚合 samples，usleep 约 0.33 秒。rawsyscalln 是聚合符号，不等价于全部 sendmsg 开销。
- 本轮继续尝试仅对 QUIC mux 使用 32 KiB bufio.Reader 合并帧头小读：135.699；立即回退复测为 134.908，差约 0.6%，不足以证明收益，已撤回。
- HY2 建链/认证在计时之外；当前每条反向 session 一条 QUIC 连接，而不是每个数据块重建连接。macOS 不具备该库的 Linux UDP GSO 路径，库已申请 7 MiB socket 缓冲；但本轮没有 Linux 同硬件基准，不能声称 Linux 已解决。

下一步可证伪补丁候选：先做 QUIC 包处理 worker/唤醒的局部调度实验（同时量化 CPU、包率与多连接公平性），再做显式 acquire/release 的 mux chunk 池；后者必须覆盖 enqueue 失败、reset、close、半关闭、阻塞 writer 和取消时的精确一次释放。暂未实现这两项，不能声称 HY2 已达到目标。

## UDP 语义

当前是 XUDP → 私有 mux → HY2 可靠 QUIC stream，不是原生 QUIC DATAGRAM。VLESS/XUDP 的 stream 承载本身不等于编码错误，但 HY2 丢包时会产生可靠流队头阻塞，不能宣传原生 HY2 UDP 性能。缓冲优化已改善 TLS UDP 与 HY2 UDP，但 16 报文批次结果也不能推导最大线速。

原生 HY2 DATAGRAM 需要独立的 association ID、授权隔离、MTU/分片、乱序/丢失/过期和双端生命周期协议；仅开 EnableDatagrams 不会改变当前 XUDP 走向。本轮未进行这个协议重写。后续应先补相同报文/窗口的 Xray UDP 夹具与受控丢包测试，再决定兼容语义，不能为了跑分削弱目标授权。

## 验证

当前优化树实际通过：

- `go test ./...`
- `go vet ./...`
- `go test -race ./internal/tunnel ./internal/node ./internal/control ./internal/master`
- `go test -tags integration ./tests/integration -count=1`（138.518 秒）
- `node --test frontend/tests/*.mjs`（27/27）
- `npm run build -- --outDir <scratch>/perf-fix/frontend-html`（含 Vue typecheck）
- Podman 三角色构建及内容检查；Master 包含 html/curl/sqlite，Client/Server 不含 html/curl。Master 首次下载 Alpine 包超时，缓存重试成功。没有 Docker CLI；Podman OCI 构建提示忽略 HEALTHCHECK，未声称 Docker healthcheck 已验证。
- `git diff --check`，Xray reference 工作树为空。

一次 HY2 profile 曾遇到 connection reset，重试成功；本轮最终基准、普通测试、race 与集成都通过，但未定位该偶发 reset 根因。

未 commit、push 或部署。历史 html 产物无法精确恢复的问题见 verification.md，本轮构建没有再次写该目录。

## 本轮清理

已删除本轮 `perf-fix/`、`perf-fix-xray/`（含二进制、profile、临时证书/私钥、配置、日志、独立工具链及模块缓存）、三角色 `localhost/veilink-perf-fix:*` 镜像、本轮超时留下的外部构建容器与新中间层。复查未发现本轮运行程序或上述镜像；更早的三个其他项目外部构建容器未动，未执行全局 prune。

逐次性能输出已保存在 optimization-measurements.json；无密钥的 Xray bench.go、配置生成器、证书请求说明及运行脚本另保留在会话 scratch 的 `perf-fix-reproduction/` 作为复测证据（重新运行需重建二进制并生成证书）。最终 gofmt 检查、`git diff --check` 与 reference 工作树检查通过。历史 html 恢复问题仍未解决，不能宣称整个会话零遗留。
