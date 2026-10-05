# XHTTP 性能诊断与优化（2026-10-06）

## 结论

低吞吐不是同一个原因。packet-up 的逐块远端确认限制高 RTT 吞吐；pacing 主动限制 POST 频率；header/cookie 受请求头预算和 Base64 成本影响；HTTP/3 还包含 QUIC 成本。本轮确认并修复显式并发上传的整批等待问题，同时移除串行上传不必要的本地管道与 ACK，并修复待处理 HTTP 请求及 pacing 期间无法及时更新写超时的问题。

没有证实回环环境全面提速。人工响应延迟下的滑动窗口收益明确，但不能外推为公网提升百分比。没有进行本轮同配置 Xray 吞吐对照，也没有用 CPU profile 定位 HTTP/3 的具体热点。

## 对照 Xray 与实现边界

参考 `ref/Xray-core/transport/internet/splithttp/dialer.go` 的 packet-up 实现：有界上传 pipe 合并多次小写入，分块 POST，利用 `httptrace.WroteRequest` 在请求发出后继续流水发送，而不是每次都等待响应完成。

Veilink 保留自身交付语义：成功的 Write 必须收到远端确认，不仅仅写入本地缓冲。本轮独立实现，没有复制上游源码，也没有嵌入 Xray 或宣称互通。默认块大小、并发配置、服务器有界窗口、头预算和授权校验不变。

- 所有 packet-up 上传统一直接走 HTTP，串行路径不再通过两组 net.Pipe 往返数据与 ACK。
- 显式并发从“整批完成后才发送下一批”改为环形有界滑动窗口，按序收取 ACK，保持连续确认前缀和服务器序号窗口上界。
- 出错会取消其他上传，等待 worker 退出后才返回，避免调用方复用 payload 后后台仍读取它。
- 写 deadline 更新可中断已阻塞的 POST 与 pacing，清除 deadline 会撤销定时取消。
- 未改 stream-one、stream-up 的传输实现；未加隐式异步上传或自动扩大并发数。

## 同口径回环前后复测

macOS arm64、Go 1.27.0、GOMAXPROCS=10、非 race，本机回环；Pool=1、独立 TCP，每格串行三轮，每轮 64 MiB 内层 TLS 1.3 回显，握手与预热不计入。吞吐只计一份回显负载。原始日志为临时产物 `/private/tmp/veilink-xhttp-before-direct.log` 与 `/private/tmp/veilink-xhttp-after-direct.log`。

| 配置 | 优化前中位数 MiB/s | 优化后中位数 MiB/s | 前三轮范围 | 后三轮范围 | 变化 |
| --- | ---: | ---: | --- | --- | ---: |
| H1.1 packet-up | 303.366 | 311.540 | 256.756–313.427 | 278.150–321.695 | +2.7% |
| H1.1 packet-up 并发 | 309.312 | 287.834 | 288.695–317.612 | 266.950–316.513 | -6.9% |
| H2 packet-up | 285.346 | 288.195 | 276.419–293.263 | 283.622–298.581 | +1.0% |
| H2 packet-up 并发 | 288.714 | 287.122 | 287.066–295.184 | 259.516–288.301 | -0.6% |
| H2 stream-one Xmux | 676.222 | 659.256 | 672.042–685.053 | 629.253–661.843 | -2.5% |
| H3 packet-up | 89.861 | 87.827 | 85.851–90.642 | 85.243–89.138 | -2.3% |
| H3 packet-up 并发 | 88.049 | 88.313 | 87.887–89.112 | 86.297–90.441 | +0.3% |
| H3 stream-one Xmux | 118.009 | 118.701 | 109.175–119.003 | 115.749–120.840 | +0.6% |

各格均通过 payload/回显校验，共 24 次前测和 24 次后测。以上含回环下降值，不只挑提升。三轮不足以进行严格统计推断；未修改的 stream-one 也有波动，不能将每个变化都归因于代码。

随后同 8 配置增加独立 TCP、smux、yamux、h2mux、UDP 全部路径各三轮，120/120 测量通过。日志 `/private/tmp/veilink-xhttp-after-allpaths.log` 经严格汇总器校验 8 配置与 3 轮，没有缺格或字节数不一致。这次补测不替代上表同一组前后对照。

```sh
VEILINK_PERF=1 VEILINK_PERF_ROUNDS=3 go test ./internal/tunnel \
  -run '^TestParameterPerformance$/round[123]/XHTTP-TLS-h(1\.1|2|3)-(baseline|buffered|stream-one-xmux)$/off$' \
  -count=1 -v -timeout=5m
```

## 滑动窗口受控延迟对照

`TestXHTTPDelayedResponsePerformance` 使用真实 HTTP/1.1 与服务器有序重组，1 MiB 上传、每块 16 KiB、并发 2。响应按照序号 mod 4 加入 5/30/30/5 ms 延迟，专门制造不均匀响应。本实验不等同完整网络 RTT、丢包或公网场景。

旧版仅在临时源码副本恢复优化前的 `xhttp_buffer.go`，不改工作树或用户数据；相同新测试串行运行三轮。结果：

- 旧整批屏障：1.033887 / 1.034398 / 1.034271 秒，中位数 1.034271 秒，0.967 MiB/s。
- 新滑动窗口：0.618733 / 0.608196 / 0.618318 秒，中位数 0.618318 秒，1.617 MiB/s。
- 中位数吞吐提高约 67.2%，传输耗时减少约 40.2%。

```sh
VEILINK_PERF=1 go test ./internal/tunnel \
  -run '^TestXHTTPDelayedResponsePerformance$' -count=1 -v -timeout=1m
```

## 已执行验收

- `go test ./... -count=1 -timeout=10m`：通过，tunnel 428.039 秒。
- `go vet ./...`：通过。
- 全部 XHTTP 功能测试：通过；全部 XHTTP race 测试：通过；追加的滑动窗口、动态/清除 deadline、pacing timeout、未确认写入失败测试单独 race 重跑通过。
- `go test -tags integration ./tests/integration -count=1 -timeout=10m`：通过，22.323 秒。
- 前端 `node --test tests/*.mjs`：114/114；`npm run build`（含 vue-tsc）：通过。
- 性能日志汇总器 unittest：3/3；`git diff --check`：通过。
- 统一镜像 buildx 构建成功；同一镜像 master/server/client 三种启动、非空预置 Web、相同二进制 hash、健康脚本与 Docker healthy 检查通过。Master `/healthz` 和根路径 HTML 返回成功。节点使用假令牌和不可达 Master，healthy 只证明进程存活，业务由 integration 验证。
- HTML 报告以本机 Brave/Playwright 检查 1440×1000 与 390×844，表格渲染、过滤和页面无横向溢出通过，无 pageerror。

临时 Docker 容器和镜像标签已清理。未 release、push 或远端部署，未修改持久化用户数据。

## 配置建议与未覆盖范围

当反代允许双向流式传输时优先评估 H2 stream-one + body；不需要 header/cookie 上传时使用 body；不需要主动 pacing 时将 POST 间隔设为 0。修改这些参数会改变请求形态，需要符合实际反代限制，不适合直接套用到所有部署。

packet-up 的并发仅在单次 Write 足够大、有多块可发时生效，小写入不会自动合并。完整公网 RTT/丢包、H3 CPU profile、多应用流聚合和长期稳定性本轮未测；不能宣称已解决全部 XHTTP 性能瓶颈或达到 Xray 水平。
