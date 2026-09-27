# XHTTP 本机验收

## 实现与参考边界

- 原生 HTTP/1.1 packet-up：随机会话 GET 下行、32 KiB 有序 POST 上行、私有空 POST `X-Veilink-EOF: 1` 半关闭。HTTPS 验证证书链与候选名称；支持 HTTP-only 与 HTTPS 终止后 HTTP 回源，不要求 L4/TLS 透传。
- 行为参考 `ref/Xray-core/transport/internet/splithttp/{config.go,config.proto}` 及 `infra/conf/transport_internet.go`。参考 LICENSE 声明 MPL-2.0；独立实现，不复制参考代码或 AGPL 代码，不宣称 Xray 互通。
- 地址语义对照 `ref/frp-panel/idl/common.proto` 的 `frps_url/frps_urls`：Client 拨号地址与 Server 监听分离、多个候选。本项目保留 JSON host/port 候选，不复制其 URL 配置或实现。
- Server 唯一可编辑源配置，自动派生 Client 公共模板；API/SQLite/快照/状态均为 JSON。没有 YAML、本地 Client 覆盖、私钥下发、认证或 CSRF 放宽。
- 仅 packet-up、HTTP/1.1；不支持其它 XHTTP 模式、HTTP/2/3、REALITY/Vision 组合。CDN 必须路径透传、禁用缓存和响应缓冲、支持流式 GET 与 EOF 头，并将同一会话路由到同一源站。详细配置在 README。

## 测试覆盖与执行

以下均在本机临时资源上实际执行，不代表公网 CDN 或跨机 WAN 验收。

- `internal/tunnel/protocol_matrix_test.go`：总计 **62 个组合**，其中新增 XHTTP **15 个**＝HTTPS / HTTPS+Encryption / HTTP+Encryption × TCP off/smux/yamux/h2mux、UDP off。每组 3 个并发 peer，TCP 每 peer 64 KiB 加 CloseWrite，UDP 每 peer 1 KiB，校验完整内容。
- `internal/tunnel/xhttp_test.go`：**6 个顶层测试**；往返的 3 个子场景为 HTTP、HTTPS、本机 HTTPS 代理→HTTP；另含不可信证书拒绝、读 deadline/取消、写 deadline、8 个上传输入用例及重复 GET、128 会话上限（第 129 个拒绝）。不是所有恶意输入的穷举。
- `internal/tunnel/xhttp_runtime_test.go`：**2 个子场景**，完整 VLESS Encryption 业务经 HTTP-only 代理或 HTTPS 终止代理→HTTP 源站，首候选不可达后切换、二进制回显和半关闭。
- `internal/store/xhttp_test.go`：持久化重开、派生模板/私密字段隔离、映射与授权快照、候选顺序、JSON 往返、模板不可编辑；另有 **15 个非法配置子用例**，检查不推进修订。
- `internal/httpapi/xhttp_test.go`：真实 JSON API 保存与派生、未登录/无 CSRF 拒绝、**4 个错误请求子用例**（未知字段、模式、类型、独立 client_tunnel）。
- `frontend/tests/node-editor.mjs`：新增 **2 个行为测试**，覆盖 XHTTP 保存/恢复、HTTPS 与源站安全分离、HTTP 强制 Encryption、8 个非法路径、切回 TCP 清除 XHTTP；全部前端 **34/34** 通过，`npm run build` 通过。

实际执行命令：

```text
go test ./... -count=1
go vet ./...
go test -race ./internal/tunnel ./internal/store ./internal/httpapi ./internal/control ./internal/node -count=1 -timeout=6m
go test -race ./internal/tunnel -run '^TestXHTTP|^TestProtocolMatrixRoundTrip$/^xhttp-' -count=3 -timeout=3m
go test -race ./internal/tunnel -run '^TestXHTTPRuntimeThroughProxy$' -count=3 -timeout=60s
go test -tags integration ./tests/integration -count=1
cd frontend && node --test tests/*.mjs
cd frontend && npm run build
git diff --check
```

结果：均通过。全量 tunnel 161.429s，完整相关 race 的 tunnel 94.072s，integration 138.051s。首次检查发现并修复 `//` 路径校验、GET EOF 提前关闭上传半边导致 mux-off EOF、Encryption 票据指针 Read/Write 竞态；未跳过失败组合。部署契约要求说明只放 README，因此未恢复 docs 目录。原有 8 个 Encryption+Vision 未测交叉不在本次范围。

## 统一镜像本机检查

- 实际构建：`veilink:xhttp-check`，镜像 ID 前缀 `6cd1a936e5a8`，VERSION=`dev-xhttp`、COMMIT=`working-tree`。构建来自含既有 CLI help 工作的工作区，**不是最终提交的精确源码身份证明**。
- 执行 `tests/deployment/soak.py --image veilink:xhttp-check --duration 60`，实际 259.8 秒（包括故障恢复），2 次 rollout、12 次稳态业务探测。
- master/server/client 三种角色均 healthy，均有静态资源，同一二进制 SHA256：`dccde6f647227b1d93b7a8acb58d3009fac6f26b6c60041147ca1a18bd150b7b`。测试容器/网络已清理，剩余容器为空。
- 镜像脚本沿用既有业务传输做三角色通用回归，不冒充 xhttp/CDN 镜像端到端测试；xhttp 业务/CDN 类转发证据来自上述 Go runtime 测试。原始日志位于本次 session scratch 的 `xhttp-*.log` 与 `xhttp-image-check/result.json`，未将令牌/运行数据库提交。

## 未做与保留项

未 push、未远端部署、未公网 CDN 厂商验证、未多机长稳或容量压测；未新增浏览器截图验收。nginx 配置是说明示例，本次真实代理测试使用 Go httputil。CLI help 的 `internal/cli/cli.go`、`internal/config/config.go`、`internal/cli/help_test.go` 保持原工作区改动，不纳入 xhttp 提交；其它既有未跟踪文件同样保留。没有 hard reset。
