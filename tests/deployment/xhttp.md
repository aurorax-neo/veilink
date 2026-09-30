# XHTTP 本机验收

## 实现与参考边界

- 原生 HTTP/1.1、HTTP/2/h2c、HTTP/3 packet-up，以及 HTTP/2/HTTP/3 TLS stream-up/stream-one：GET 下行、POST/PUT 上行、私有 EOF/完成确认和取消回收均为 Veilink 双端原生行为，不宣称 Xray 对端互通。
- Server 是唯一可编辑源配置，自动派生 Client 公共模板；API/SQLite/快照/状态均为 JSON。Client 不维护本地隧道覆盖，不下发 Server 私钥、REALITY 私钥或 VLESS decryption 材料。
- `download_endpoint_id` 仅引用 Server 已启用的授权连接入口。packet-up/auto 的 GET/下行使用独立授权 transport，POST/PUT/上行继续使用主入口；显式主入口绑定会保留下行入口，主/下行 xmux 池按入口隔离。未知、禁用、流模式、任意 URL 或拨号器缺失均 fail closed。
- REALITY 可作为 TCP 外层安全层；XHTTP 自身 TLS 必须关闭，不能经过 CDN 边缘 TLS 终止。`auto` 在 REALITY 下明确选择 packet-up，避免降级到未认证流模式；这不是完整参考实现或 Xray 兼容声明。
- 普通 XHTTP 可使用 HTTP/HTTPS 路径透传；CDN 必须路径透传、禁用缓存和响应缓冲、支持流式 GET/EOF，并将同一会话路由到同一源站。以下均为本机或隔离 Docker 证据，不代表公网 CDN 或跨机 WAN 验收。

## 测试覆盖与执行

以下均在本机临时资源上实际执行，不代表公网 CDN 或跨机 WAN 验收。

- `internal/tunnel/protocol_matrix_test.go`：覆盖 TCP/UDP、TCP mux、XHTTP 及授权协议组合；本轮全量 Go 测试通过。
- `internal/tunnel/xhttp_test.go`、`xhttp_runtime_test.go`、`xhttp_auto_test.go`、`xhttp_downlink_test.go`：覆盖 HTTP/1.1、HTTP/2/h2c、HTTP/3、代理回源、缓冲并发、取消/EOF、REALITY auto、授权主/下行入口和 fail-closed。
- `internal/store/xhttp_test.go`、`internal/httpapi/xhttp_test.go`：覆盖 XHTTP 持久化、Server 派生 Client 模板、快照隔离、下载入口合法性、未知/禁用入口拒绝和 API 保存。
- `frontend/tests/node-editor.mjs`：覆盖 XHTTP 字段回填、分离下行入口筛选、模式切换清理和 Client 隔离；本轮前端全部 **93/93** 通过，`npm run typecheck` 与生产构建通过。
- 本轮额外回归：`go test -race ./internal/tunnel ./internal/store ./internal/httpapi ./internal/control ./internal/node`、`go test -tags integration ./tests/integration`、`go vet ./...` 和 `git diff --check` 均通过。

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
- 实际构建：`veilink:rc-20260930`，镜像 ID `sha256:c0a2a8e21c71fc66be72157bd499d696424371e276faac64c22b68f09c21ccaf`；镜像内统一二进制 SHA-256 `289fe7def69d290054902f5f02b3863e243e6648ef0c4a0ffd2b9ec9b1c186e4`。
- 执行 `tests/deployment/soak.py --image veilink:rc-20260930 --duration 60`，实际约 184 秒（含故障恢复），2 次 rollout、12 次稳态业务采样；初始收敛、100 秒分区、配置漂移、恢复和三角色重启均通过。
- master/server/client 三种角色均 healthy，统一二进制摘要一致；测试容器/网络已清理，`cleanup_remaining` 为空。结果：`$PI_SCRATCH_DIR/rc-soak/result.json`。
- 执行 `tests/deployment/proxy_check.py --image veilink:rc-20260930`：TLS/CA、Cookie、Origin、CSRF、证书候选拒绝、证书热更新、h2c 心跳和重连均通过；结果：`$PI_SCRATCH_DIR/rc-proxy/result.json`。
- 本地隔离证据不代表真实 WAN/NAT、生产 CDN、容量压测或 24–72 小时长期稳定性。
## 未做与保留项

未 push、未远端部署、未公网 CDN 厂商验证、未多机长稳或容量压测；未新增浏览器截图验收。nginx 配置是说明示例，本次真实代理测试使用 Go httputil。CLI help 的 `internal/cli/cli.go`、`internal/config/config.go`、`internal/cli/help_test.go` 保持原工作区改动，不纳入 xhttp 提交；其它既有未跟踪文件同样保留。没有 hard reset。
